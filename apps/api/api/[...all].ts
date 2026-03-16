import { ValidationPipe, Logger, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import * as Sentry from '@sentry/node';
import { AppModule } from '../src/app.module';
import { HttpExceptionFilter } from '../src/filters/http-exception.filter';

type ServerHandler = (req: unknown, res: unknown) => unknown;

let cachedHandler: ServerHandler | null = null;
let sentryInitialized = false;

async function bootstrapServer(): Promise<ServerHandler> {
  const logger = new Logger('VercelBootstrap');
  const isProduction = process.env.NODE_ENV === 'production';

  const app = await NestFactory.create(AppModule, {
    logger: isProduction
      ? ['error', 'warn', 'log']
      : ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  const configService = app.get(ConfigService);

  const sentryDsn = configService.get<string>('SENTRY_DSN');
  if (sentryDsn && isProduction && !sentryInitialized) {
    Sentry.init({
      dsn: sentryDsn,
      environment: configService.get<string>('SENTRY_ENVIRONMENT', 'production'),
      tracesSampleRate: parseFloat(
        configService.get<string>('SENTRY_TRACES_SAMPLE_RATE', '0.1'),
      ),
      integrations: [Sentry.httpIntegration()],
      beforeSend(event) {
        if (event.request?.cookies) {
          event.request.cookies = {};
        }
        if (event.request?.headers?.authorization) {
          event.request.headers.authorization = '[REDACTED]';
        }
        return event;
      },
    });

    sentryInitialized = true;
    logger.log('Sentry error monitoring initialized');
  }

  app.use(
    helmet({
      contentSecurityPolicy: isProduction
        ? {
            directives: {
              defaultSrc: ["'self'"],
              scriptSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              imgSrc: ["'self'", 'data:', 'https:'],
              connectSrc: ["'self'"],
              fontSrc: ["'self'"],
              objectSrc: ["'none'"],
              frameAncestors: ["'self'"],
            },
          }
        : false,
      crossOriginEmbedderPolicy: isProduction,
      hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true } : false,
    }),
  );

  app.use(cookieParser());

  const frontendOrigin = configService.get<string>(
    'FRONTEND_ORIGIN',
    'http://localhost:5173',
  );

  app.enableCors({
    origin: frontendOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400,
  });

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
    prefix: 'api/v',
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      disableErrorMessages: isProduction,
    }),
  );

  app.useGlobalFilters(new HttpExceptionFilter(isProduction));

  const enableSwagger = configService.get<string>('ENABLE_SWAGGER', 'true');
  if (!isProduction && enableSwagger === 'true') {
    const config = new DocumentBuilder()
      .setTitle('Voter Management System API')
      .setDescription('Multi-tenant election management API')
      .setVersion('1.0')
      .addCookieAuth('vms_access')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }

  await app.init();

  return app.getHttpAdapter().getInstance() as ServerHandler;
}

export default async function handler(req: unknown, res: unknown) {
  if (!cachedHandler) {
    cachedHandler = await bootstrapServer();
  }

  return cachedHandler(req, res);
}