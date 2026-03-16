import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import argon2 from 'argon2';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import {
  ACCESS_COOKIE_NAME,
  DEFAULT_ACCESS_TTL_MINUTES,
  DEFAULT_REFRESH_TTL_DAYS,
  DEFAULT_TRUSTED_DEVICE_TTL_DAYS,
  REFRESH_COOKIE_NAME,
  TRUSTED_DEVICE_COOKIE_NAME,
} from './auth.constants';
import { LoginRequestDto } from './dto/login-request.dto';
import {
  AccessTokenPayload,
  AuthenticatedUser,
  RefreshTokenPayload,
  UserRoleValue,
} from './types/auth.types';

const AUDIT_LOGIN_FAILED = 'USER_LOGIN_FAILED';
const AUDIT_LOGIN_SUCCESS = 'USER_LOGIN_SUCCESS';
const AUDIT_SUPER_ADMIN_LOGIN = 'SUPER_ADMIN_LOGIN';
const INSECURE_SECRET_VALUES = new Set([
  'replace-me',
  'replace_me',
  'changeme',
  'change-me',
  'change_me',
  'your-secret',
  'your_secret',
  'secret',
  'default',
  'test',
  'example',
  'replace_with_64_byte_hex_string_for_access_token',
  'replace_with_different_64_byte_hex_string_for_refresh_token',
]);

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly auditService: AuditService,
  ) {}

  async login(
    payload: LoginRequestDto,
    res: Response,
    requestMeta: { ip?: string; userAgent?: string; trustedDeviceToken?: string },
  ) {
    const user = await this.prisma.user.findUnique({
      where: { email: payload.email },
    });

    if (!user) {
      await this.auditService.logEvent({
        action: AUDIT_LOGIN_FAILED,
        entityType: 'User',
        metadata: {
          email: payload.email,
          ip: requestMeta.ip,
          userAgent: requestMeta.userAgent,
          reason: 'user_not_found',
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is disabled');
    }

    if (!user.passwordHash) {
      throw new UnauthorizedException('Password setup is pending');
    }

    const isValidPassword = await argon2.verify(user.passwordHash, payload.password);

    if (!isValidPassword) {
      await this.auditService.logEvent({
        actorUserId: user.id,
        action: AUDIT_LOGIN_FAILED,
        entityType: 'User',
        entityId: user.id,
        candidateId: user.candidateId ?? undefined,
        metadata: {
          ip: requestMeta.ip,
          userAgent: requestMeta.userAgent,
          reason: 'invalid_password',
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const session = await this.issueSessionForUser(user, res);

    await this.auditService.logEvent({
      actorUserId: user.id,
      action: AUDIT_LOGIN_SUCCESS,
      entityType: 'User',
      entityId: user.id,
      candidateId: user.candidateId ?? undefined,
      metadata: {
        ip: requestMeta.ip,
        userAgent: requestMeta.userAgent,
      },
    });

    if (user.role === 'SUPER_ADMIN') {
      await this.auditService.logEvent({
        actorUserId: user.id,
        action: AUDIT_SUPER_ADMIN_LOGIN,
        entityType: 'User',
        entityId: user.id,
        metadata: {
          ip: requestMeta.ip,
          userAgent: requestMeta.userAgent,
        },
      });
    }

    return {
      mfaRequired: false,
      user: session.user,
    };
  }

  async refresh(
    refreshToken: string | undefined,
    res: Response,
    requestMeta?: { ip?: string; userAgent?: string },
  ) {
    if (!refreshToken) {
      throw new UnauthorizedException('Missing refresh token');
    }

    let payload;
    try {
      payload = await this.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const now = new Date();
    const refreshTokenHash = this.hashToken(refreshToken);

    const storedToken = await this.prisma.refreshToken.findFirst({
      where: {
        userId: payload.sub,
        tokenHash: refreshTokenHash,
      },
    });

    // ========================================================================
    // CRITICAL SECURITY: Refresh Token Reuse Detection
    // ========================================================================
    // If token not found, expired, or already revoked, it indicates:
    // - Token replay attack
    // - Device compromise
    // - Token reuse after logout
    //
    // ACTION: Revoke all tokens and force logout all sessions
    // ========================================================================

    if (!storedToken) {
      // Token doesn't exist - possible attack or corruption
      await this.auditService.logEvent({
        actorUserId: payload.sub,
        action: 'REFRESH_TOKEN_REUSE_DETECTED',
        entityType: 'User',
        entityId: payload.sub,
        candidateId: payload.candidateId ?? undefined,
        metadata: {
          reason: 'token_not_found',
          ip: requestMeta?.ip,
          userAgent: requestMeta?.userAgent,
        },
      });

      // Force logout all sessions
      await this.prisma.refreshToken.updateMany({
        where: { userId: payload.sub },
        data: { revokedAt: now },
      });

      throw new UnauthorizedException('Invalid refresh token');
    }

    if (storedToken.revokedAt) {
      // CRITICAL: Token was already revoked and is being reused
      // This indicates token replay or device compromise
      await this.auditService.logEvent({
        actorUserId: payload.sub,
        action: 'REFRESH_TOKEN_REUSE_DETECTED',
        entityType: 'User',
        entityId: payload.sub,
        candidateId: storedToken.candidateId ?? undefined,
        metadata: {
          reason: 'token_already_revoked',
          revokedAt: storedToken.revokedAt.toISOString(),
          ip: requestMeta?.ip,
          userAgent: requestMeta?.userAgent,
          severity: 'CRITICAL',
        },
      });

      // Force logout: revoke ALL refresh tokens immediately
      await this.prisma.refreshToken.updateMany({
        where: { userId: payload.sub, revokedAt: null },
        data: { revokedAt: now },
      });

      this.logger.warn(
        `Refresh token reuse detected for user ${payload.sub}. All sessions revoked.`,
      );

      throw new UnauthorizedException('Invalid refresh token');
    }

    if (storedToken.expiresAt <= now) {
      // Token expired - log as expired (non-critical)
      await this.auditService.logEvent({
        actorUserId: payload.sub,
        action: 'REFRESH_TOKEN_REUSE_DETECTED',
        entityType: 'User',
        entityId: payload.sub,
        candidateId: storedToken.candidateId ?? undefined,
        metadata: {
          reason: 'token_expired',
          expiresAt: storedToken.expiresAt.toISOString(),
          ip: requestMeta?.ip,
          userAgent: requestMeta?.userAgent,
        },
      });

      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Valid token: mark old token as revoked and issue new session
    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { revokedAt: now },
    });

    const session = await this.issueSessionForUser(user, res);

    return {
      refreshed: true,
      user: session.user,
    };
  }

  async validatePasswordSetupToken(token: string) {
    const tokenValue = token?.trim();
    if (!tokenValue) {
      throw new BadRequestException('Token is required');
    }

    const tokenHash = this.hashToken(tokenValue);
    const record = await this.prisma.passwordSetupToken.findFirst({
      where: {
        tokenHash,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            isActive: true,
            passwordHash: true,
          },
        },
      },
    });

    if (!record) {
      throw new UnauthorizedException('Invalid or expired setup link');
    }

    if (!record.user.isActive) {
      throw new UnauthorizedException('Account is disabled');
    }

    if (record.user.passwordHash) {
      throw new ConflictException('Password is already set for this account');
    }

    return {
      valid: true,
      email: record.user.email,
    };
  }

  async setupPassword(token: string, password: string) {
    const tokenValue = token?.trim();
    if (!tokenValue) {
      throw new BadRequestException('Token is required');
    }

    const tokenHash = this.hashToken(tokenValue);
    const record = await this.prisma.passwordSetupToken.findFirst({
      where: {
        tokenHash,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
    });

    if (!record) {
      throw new UnauthorizedException('Invalid or expired setup link');
    }

    if (!record.user.isActive) {
      throw new UnauthorizedException('Account is disabled');
    }

    if (record.user.passwordHash) {
      throw new ConflictException('Password is already set for this account');
    }

    const passwordHash = await argon2.hash(password);

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { passwordHash },
      }),
      this.prisma.passwordSetupToken.update({
        where: { id: record.id },
        data: { used: true },
      }),
      this.prisma.passwordSetupToken.deleteMany({
        where: {
          userId: record.userId,
          id: {
            not: record.id,
          },
        },
      }),
    ]);

    await this.auditService.logEvent({
      actorUserId: record.userId,
      action: 'PASSWORD_SETUP_COMPLETED',
      entityType: 'User',
      entityId: record.userId,
      candidateId: record.user.candidateId ?? undefined,
      metadata: {
        source: 'setup_link',
      },
    });

    return {
      message: 'Password has been set successfully. You can now login.',
    };
  }

  async logout(
    refreshToken: string | undefined,
    trustedDeviceToken: string | undefined,
    res: Response,
  ) {
    if (refreshToken) {
      try {
        const payload = await this.verifyRefreshToken(refreshToken);
        const refreshTokenHash = this.hashToken(refreshToken);

        await this.prisma.refreshToken.updateMany({
          where: {
            userId: payload.sub,
            tokenHash: refreshTokenHash,
            revokedAt: null,
          },
          data: { revokedAt: new Date() },
        });

        if (trustedDeviceToken) {
          await this.revokeTrustedDevice(payload.sub, trustedDeviceToken);
        }
      } catch {
        // Ignore invalid refresh token on logout and still clear client cookies.
      }
    }

    this.clearAuthCookies(res);

    return {
      loggedOut: true,
    };
  }

  async me(accessToken: string | undefined) {
    if (!accessToken) {
      throw new UnauthorizedException('Missing access token');
    }

    const payload = await this.verifyAccessToken(accessToken);

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: {
        candidate: {
          select: {
            id: true,
            fullName: true,
            email: true,
            electionType: true,
            contestingFor: true,
            state: true,
            district: true,
            constituency: true,
            partyName: true,
          },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid access token');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is disabled');
    }

    return {
      user: this.toAuthenticatedUser(user),
      candidate: user.candidate,
    };
  }

  async resolveUserFromAccessToken(accessToken: string | undefined) {
    if (!accessToken) {
      throw new UnauthorizedException('Missing access token');
    }

    const payload = await this.verifyAccessToken(accessToken);
    const user = await this.prisma.user.findUnique({ where: { id: payload.sub } });

    if (!user) {
      throw new UnauthorizedException('Invalid access token');
    }

    return this.toAuthenticatedUser(user);
  }

  private async issueSessionForUser(
    user: { id: string; username: string; role: UserRoleValue; mfaEnabled: boolean; candidateId: string | null },
    res: Response,
  ) {
    const tokens = await this.issueSessionTokens(this.toAuthenticatedUser(user));
    this.setAuthCookies(res, tokens.accessToken, tokens.refreshToken);
    return { user: this.toAuthenticatedUser(user) };
  }

  private async issueSessionTokens(user: AuthenticatedUser) {
    const normalizedCandidateId = user.candidateId && user.candidateId.trim().length > 0
      ? user.candidateId
      : null;

    const accessTokenPayload: AccessTokenPayload = {
      sub: user.id,
      username: user.username,
      role: user.role,
      candidateId: normalizedCandidateId,
    };

    const refreshTokenPayload: RefreshTokenPayload = {
      ...accessTokenPayload,
      jti: randomUUID(),
      type: 'refresh',
    };

    const accessToken = await this.jwtService.signAsync(accessTokenPayload, {
      secret: this.getAccessSecret(),
      expiresIn: `${this.getAccessTtlMinutes()}m`,
    });

    const refreshToken = await this.jwtService.signAsync(refreshTokenPayload, {
      secret: this.getRefreshSecret(),
      expiresIn: `${this.getRefreshTtlDays()}d`,
    });

    const refreshExpiresAt = new Date(
      Date.now() + this.getRefreshTtlDays() * 24 * 60 * 60 * 1000,
    );

    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        candidateId: normalizedCandidateId,
        tokenHash: this.hashToken(refreshToken),
        expiresAt: refreshExpiresAt,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  private async verifyAccessToken(token: string) {
    try {
      return await this.jwtService.verifyAsync<AccessTokenPayload>(token, {
        secret: this.getAccessSecret(),
      });
    } catch {
      throw new UnauthorizedException('Invalid access token');
    }
  }

  private async verifyRefreshToken(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(token, {
        secret: this.getRefreshSecret(),
      });

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid refresh token');
      }

      return payload;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private toAuthenticatedUser(user: {
    id: string;
    username: string;
    role: UserRoleValue;
    mfaEnabled: boolean;
    candidateId: string | null;
    electionLevel?: string | null;
  }): AuthenticatedUser {
    return {
      id: user.id,
      username: user.username,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
      candidateId: user.candidateId ?? '',
      electionLevel: user.electionLevel ?? null,
    };
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    const cookieDomain = this.getCookieDomain();
    const secure = this.getCookieSecure();
    const sameSite = this.getCookieSameSite();

    res.cookie(ACCESS_COOKIE_NAME, accessToken, {
      httpOnly: true,
      secure,
      sameSite,
      domain: cookieDomain,
      path: '/',
      maxAge: this.getAccessTtlMinutes() * 60 * 1000,
    });

    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure,
      sameSite,
      domain: cookieDomain,
      path: '/',
      maxAge: this.getRefreshTtlDays() * 24 * 60 * 60 * 1000,
    });
  }

  private setTrustedDeviceCookie(res: Response, trustedDeviceToken: string) {
    const cookieDomain = this.getCookieDomain();
    const secure = this.getCookieSecure();
    const sameSite = this.getCookieSameSite();

    res.cookie(TRUSTED_DEVICE_COOKIE_NAME, trustedDeviceToken, {
      httpOnly: true,
      secure,
      sameSite,
      domain: cookieDomain,
      path: '/',
      maxAge: this.getTrustedDeviceTtlDays() * 24 * 60 * 60 * 1000,
    });
  }

  private clearAuthCookies(res: Response) {
    const cookieDomain = this.getCookieDomain();
    const secure = this.getCookieSecure();
    const sameSite = this.getCookieSameSite();

    res.clearCookie(ACCESS_COOKIE_NAME, {
      httpOnly: true,
      secure,
      sameSite,
      domain: cookieDomain,
      path: '/',
    });

    res.clearCookie(REFRESH_COOKIE_NAME, {
      httpOnly: true,
      secure,
      sameSite,
      domain: cookieDomain,
      path: '/',
    });

    res.clearCookie(TRUSTED_DEVICE_COOKIE_NAME, {
      httpOnly: true,
      secure,
      sameSite,
      domain: cookieDomain,
      path: '/',
    });
  }

  private getCookieSameSite(): 'lax' | 'strict' {
    if (process.env.NODE_ENV === 'production') {
      return 'strict';
    }
    return 'lax';
  }

  private async validateTrustedDevice(userId: string, token: string) {
    const trustedDevice = await this.prisma.trustedDevice.findFirst({
      where: {
        userId,
        tokenHash: this.hashToken(token),
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!trustedDevice) {
      return false;
    }

    await this.prisma.trustedDevice.update({
      where: { id: trustedDevice.id },
      data: { lastUsedAt: new Date() },
    });

    return true;
  }

  private async createTrustedDevice(userId: string, res: Response, label?: string) {
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + this.getTrustedDeviceTtlDays() * 24 * 60 * 60 * 1000);

    await this.prisma.trustedDevice.create({
      data: {
        userId,
        tokenHash: this.hashToken(token),
        expiresAt,
        label,
      },
    });

    this.setTrustedDeviceCookie(res, token);
  }

  private async revokeTrustedDevice(userId: string, token: string) {
    await this.prisma.trustedDevice.updateMany({
      where: {
        userId,
        tokenHash: this.hashToken(token),
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  private validateJwtSecret(
    secretName: 'JWT_ACCESS_SECRET' | 'JWT_REFRESH_SECRET',
    value: string,
  ) {
    const normalized = value.trim();
    const isProduction = process.env.NODE_ENV === 'production';

    if (!normalized) {
      throw new InternalServerErrorException(`${secretName} is missing`);
    }

    if (isProduction && INSECURE_SECRET_VALUES.has(normalized.toLowerCase())) {
      throw new InternalServerErrorException(
        `${secretName} must be replaced with a strong secret`,
      );
    }

    if (isProduction && normalized.length < 64) {
      throw new InternalServerErrorException(
        `${secretName} must be at least 64 characters in production`,
      );
    }

    return normalized;
  }

  private getAccessSecret() {
    const secret = this.configService.get<string>('JWT_ACCESS_SECRET');
    if (!secret) {
      throw new InternalServerErrorException('JWT_ACCESS_SECRET is missing');
    }

    const validated = this.validateJwtSecret('JWT_ACCESS_SECRET', secret);
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');
    if (
      process.env.NODE_ENV === 'production' &&
      refreshSecret &&
      validated === refreshSecret.trim()
    ) {
      throw new InternalServerErrorException(
        'JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be different in production',
      );
    }

    return validated;
  }

  private getRefreshSecret() {
    const secret = this.configService.get<string>('JWT_REFRESH_SECRET');
    if (!secret) {
      throw new InternalServerErrorException('JWT_REFRESH_SECRET is missing');
    }

    const validated = this.validateJwtSecret('JWT_REFRESH_SECRET', secret);
    const accessSecret = this.configService.get<string>('JWT_ACCESS_SECRET');
    if (
      process.env.NODE_ENV === 'production' &&
      accessSecret &&
      validated === accessSecret.trim()
    ) {
      throw new InternalServerErrorException(
        'JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be different in production',
      );
    }

    return validated;
  }

  private getAccessTtlMinutes() {
    const value = Number(this.configService.get('ACCESS_TOKEN_TTL_MINUTES'));
    if (Number.isNaN(value) || value <= 0) {
      return DEFAULT_ACCESS_TTL_MINUTES;
    }
    return value;
  }

  private getRefreshTtlDays() {
    const value = Number(this.configService.get('REFRESH_TOKEN_TTL_DAYS'));
    if (Number.isNaN(value) || value <= 0) {
      return DEFAULT_REFRESH_TTL_DAYS;
    }
    return value;
  }

  private getTrustedDeviceTtlDays() {
    const value = Number(this.configService.get('TRUSTED_DEVICE_TTL_DAYS'));
    if (Number.isNaN(value) || value <= 0) {
      return DEFAULT_TRUSTED_DEVICE_TTL_DAYS;
    }
    return value;
  }

  private getCookieSecure() {
    if (process.env.NODE_ENV === 'production') {
      return true;
    }
    return false;
  }

  private getCookieDomain() {
    const configured = this.configService.get<string>('COOKIE_DOMAIN');
    if (!configured || configured === 'localhost') {
      return undefined;
    }
    return configured;
  }
}
