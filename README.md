# Voter Management System

Security-first web application for collaborative voter tracking across Red, Green, and Orange zones.

## Current Status

This repository has been initialized from scratch with a monorepo structure and baseline app scaffolding.

### Implemented now

- Monorepo root with npm workspaces (`apps/api`, `apps/web`)
- Backend scaffold with NestJS module structure
- Frontend scaffold with React + Vite + TypeScript + Tailwind
- Initial Prisma data model for users, voters, zones, auth sessions, MFA, and audit logs
- Working auth foundation (`/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me`)
- Prisma service wiring and database-backed refresh token storage
- Rotation + revocation flow for refresh tokens
- Working MFA foundation (TOTP setup/verify, challenge verify, recovery-code verify, trusted devices)
- RBAC guard foundation (cookie auth guard + role guard)
- Admin-only sub-user management (`GET/POST /users/sub-users`)
- Voter workflow APIs (create, list, update, delete, voted list, bulk actions, CSV export)
- Zone workflow APIs (`GET /zones`, `GET /zones/:zoneId/voters` with filtering)
- Dashboard live stats API (`GET /dashboard/stats`)
- Frontend integration for login + MFA, dashboard, zone details, voted section, and sub-user management
- Centralized data entry page (`/entry`) to add voters without zone-by-zone navigation
- Unvote UX support (mark voters back to not-voted)
- Profile management for both roles:
  - Admin editable fields: `fullName`, `phone`, `email`, `officeAddress`, `electionLevel`,
    `constituencyName`, `positionContesting`, `partyName`, `profilePhoto`, `bio`
  - Sub-user editable fields: `fullName`, `phone`, `email`, `managedWard`, `profilePhoto`, `bio`
- New profile APIs: `GET /users/profile`, `PATCH /users/profile`
- Extended sub-user management fields in admin UI + API (`fullName`, `phone`, `email`, `managedWard`)
- Security baseline in API bootstrap:
  - `helmet`
  - `cookie-parser`
  - CORS with credentials
  - global validation pipe

### Not implemented yet (next development steps)

- Fine-grained UI polish (toasts/inline validation states/advanced table UX)

---

## Finalized Technical Stack

### Frontend

- React
- TypeScript
- Vite
- React Router
- TanStack Query
- Tailwind CSS

### Backend

- NestJS
- TypeScript
- Prisma ORM
- class-validator + class-transformer

### Database

- PostgreSQL (self-managed or hosted)

### Authentication & Security

- Cookie-based auth (`HttpOnly`, `Secure`, `SameSite=Strict`)
- Short-lived access token + rotating refresh token
- MFA: TOTP authenticator app (Google Authenticator/Authy/Microsoft Authenticator)
- Recovery codes
- Optional trusted devices
- Audit logging for sensitive actions

---

## Why this architecture

- PostgreSQL fits relational voter workflows (search/filter/report/bulk updates)
- NestJS gives modular security boundaries (auth, RBAC, voters, zones)
- Prisma gives controlled schema evolution and safer query ergonomics
- Cookie transport reduces token exposure in browser JS versus localStorage
- TOTP MFA avoids SMS attack surface and delivery dependency

---

## Repository Structure

```text
.
├── apps
│   ├── api
│   │   ├── prisma
│   │   │   └── schema.prisma
│   │   └── src
│   │       ├── app.module.ts
│   │       ├── main.ts
│   │       └── modules
│   │           ├── audit
│   │           ├── auth
│   │           ├── dashboard
│   │           ├── health
│   │           ├── mfa
│   │           ├── users
│   │           ├── voters
│   │           └── zones
│   └── web
│       ├── src
│       │   ├── pages
│       │   │   ├── DashboardPage.tsx
│       │   │   └── LoginPage.tsx
│       │   ├── App.tsx
│       │   ├── index.css
│       │   └── main.tsx
│       ├── tailwind.config.ts
│       └── vite.config.ts
├── .env.example
├── package.json
├── tsconfig.base.json
└── README.md
```

---

## Domain Model (Prisma)

### Core entities

- `User`
  - username, password hash, role (`ADMIN`, `SUB_USER`), MFA enabled flag
- `Zone`
  - enum type (`RED`, `GREEN`, `ORANGE`), display metadata
- `Voter`
  - person profile, unique voter ID, ward/street, zone relation, voted flag, `addedBy`
- `AuditLog`
  - actor, action, entity, metadata, timestamp

### Auth/session entities

- `RefreshToken`
  - token hash, expiry, revocation
- `TrustedDevice`
  - hashed device token, expiry, revocation, last usage

### MFA entities

- `MfaMethod`
  - type (`TOTP`), encrypted secret, verification state
- `MfaChallenge`
  - challenge lifecycle (attempt limits, expiry, usage)
- `RecoveryCode`
  - hashed one-time backup codes

---

## Target API Surface (planned)

### Auth

- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

### MFA

- `GET /auth/mfa/status`
- `POST /auth/mfa/setup/totp/start`
- `POST /auth/mfa/setup/totp/verify`
- `POST /auth/mfa/verify`
- `POST /auth/mfa/recovery/verify`

### Dashboard/Zones/Voters

- `GET /dashboard/stats`
- `GET /zones`
- `GET /zones/:id/voters`
- `POST /voters`
- `PATCH /voters/:id`
- `DELETE /voters/:id` (admin)
- `POST /voters/bulk/move-zone`
- `POST /voters/bulk/mark-voted`
- `POST /voters/bulk/delete` (admin)
- `GET /voters/voted`
- `GET /voters/export.csv` (admin)

### User Management

- `GET /users/profile` (authenticated)
- `PATCH /users/profile` (authenticated, role-scoped editable fields)
- `GET /users/sub-users`
- `POST /users/sub-users` (admin)

---

## Authentication + MFA Design

## 1) Primary login

1. User submits username/password.
2. Backend validates credentials.
3. If MFA disabled:
   - Issue access + refresh cookies.
4. If MFA enabled:
   - Return `mfaRequired: true` + `challengeId`.

## 2) TOTP verification

1. User submits `challengeId` + 6-digit TOTP.
2. Backend validates code with attempt limits and expiry.
3. On success:
   - mark challenge used
   - issue auth cookies
   - optionally register trusted device

## 3) TOTP setup

1. Authenticated user calls setup start.
2. Backend creates secret and QR payload.
3. User scans QR in authenticator app.
4. User submits first valid code.
5. Backend enables MFA and generates recovery codes.

## 4) Trusted device (optional)

1. User checks "remember this device".
2. Backend issues opaque device token in secure cookie.
3. DB stores only a hash + expiry.
4. On future login, if trusted device is valid, skip MFA step.

---

## RBAC Model

- `ADMIN`
  - Full access: manage users, voters, zones, exports, deletes
- `SUB_USER`
  - Restricted access: add voters, update status, read assigned views, maintain own profile

Enforcement layers:

- Route guards
- Service-level authorization checks
- Action-level audit logs

---

## Local Setup

## Prerequisites

- Node.js 20+
- npm 10+
- PostgreSQL 15+

Recommended Node runtime: LTS (`>=20 <25`).
Node 25 is currently not recommended for this repo (Prisma client generation/runtime issues were observed).

## Installation

```bash
npm install
```

## Environment

```bash
cp .env.example .env
```

Set valid values for secrets and database URL.

Important auth env values:

- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `ACCESS_TOKEN_TTL_MINUTES` (default `15`)
- `REFRESH_TOKEN_TTL_DAYS` (default `7`)
- `MFA_CHALLENGE_TTL_MINUTES` (default `5`)
- `TRUSTED_DEVICE_TTL_DAYS` (default `30`)
- `COOKIE_SECURE` (`true` in production)

## Prisma

```bash
npm run prisma:generate --workspace api
npm run prisma:migrate --workspace api
npm run prisma:seed --workspace api
```

`prisma:migrate` (`migrate dev`) is interactive and intended for local development terminals.
For non-interactive deployment flows, use:

```bash
cd apps/api && npx prisma migrate deploy
```

Seed will create:

- 3 default zones (Red/Green/Orange)
- default admin user from `.env` (`DEFAULT_ADMIN_USERNAME`, `DEFAULT_ADMIN_EMAIL`)
- secure random admin password if `DEFAULT_ADMIN_PASSWORD` is empty (printed once during seed)

## Run development servers

```bash
npm run dev:api
npm run dev:web
```

API: `http://localhost:4000`
Web: `http://localhost:5173`

Health check endpoint: `GET /health`

Important for cookie auth in dev:
- Use the same hostname for web and API (for example `localhost` + `localhost`).
- Mixing `localhost` web with `127.0.0.1` API can cause auth cookies to be excluded.

---

## Implementation Roadmap

## Phase 1: Auth foundation

- Prisma service wiring in NestJS
- credential login and token issuance
- refresh rotation + revocation
- cookie utility helpers

Phase 1 status: completed.

## Phase 2: MFA foundation

- TOTP secret encryption/decryption
- QR setup endpoints
- challenge + verification flow
- recovery codes and trusted device handling

Phase 2 status: completed.

## Phase 3: RBAC and user administration

- auth guards and role decorators
- admin-only sub-user management APIs
- audit log instrumentation for auth and user events

Phase 3 status: completed.

## Phase 4: Voter and zone workflows

- voter CRUD with validations
- zone transfer with transaction safety
- bulk mark voted/delete/move
- dashboard stats and filter/search endpoints

Phase 4 status: completed.

## Phase 5: Frontend feature integration

- real login flow with MFA screens
- dashboard metrics and zone details
- bulk selection UX
- voted section and export trigger

Phase 5 status: completed.

---

## Security Checklist (to enforce during build)

- Password hashing with `argon2`
- Access token short TTL
- Refresh token rotation + reuse detection
- CSRF strategy for cookie auth
- Brute-force protection and rate limits
- MFA challenge expiry + attempt caps
- Full audit trail for high-risk actions

---

## Future Plan (deferred by request)

- Infrastructure/DevOps: Docker, deployment pipeline, production secrets management
- Testing: unit, integration, E2E coverage

---

## Notes for Review

This bootstrap is intentionally structured for quick feature implementation without rework:

- Module boundaries reflect final system capabilities.
- Schema includes security entities from day one.
- MFA is designed for authenticator apps only (no SMS dependencies).

After your review, the next step is testing hardening (unit/integration/e2e) and deployment setup.
