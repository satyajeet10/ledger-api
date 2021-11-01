# Ledger API

A production-grade REST API for users, accounts, and transactions, with banking-grade authentication.
Statement imports run through a background job queue.

## Concepts
Dependency injection, layered architecture (controller → service → repository), Postgres transactions,
indexes and `EXPLAIN ANALYZE`, migrations, JWT access + refresh tokens, RBAC, rate limiting,
idempotency keys, background jobs with retries and backoff, structured logging, OpenAPI docs,
integration tests against a real database.

## Libraries
NestJS · Prisma · Postgres · argon2 · @nestjs/jwt · @nestjs/throttler · Zod · Redis · BullMQ · Pino · Swagger · Vitest + SWC · Supertest · Docker Compose · GitHub Actions

## Run
```bash
cp .env.example .env
docker compose up -d
npm install
npm run db:migrate     # creates tables and generates the Prisma client
npm run start:dev
npm test      # http://localhost:3000/health, docs at /docs
```

## Authentication and authorization (implemented)

| Endpoint | Access | Purpose |
|---|---|---|
| `POST /auth/register` | Public, 5/min | Create account, returns access + refresh tokens |
| `POST /auth/login` | Public, 5/min | Returns access + refresh tokens |
| `POST /auth/refresh` | Public, 5/min | Rotates the refresh token, returns a new pair |
| `POST /auth/logout` | Public, 5/min | Revokes the session |
| `GET /users/me` | Any signed-in user | Own profile |
| `GET /users` | `ADMIN` only | List users |
| `GET /health` | Public | Health check |

How it works:
1. **Passwords** are hashed with argon2id. Login returns the same error for unknown email and wrong password, and spends the same time on both, so attackers can't discover which emails exist.
2. **Access tokens** are JWTs valid for 15 minutes, signed with `JWT_ACCESS_SECRET`, carrying the user's id, email, and role.
3. **Refresh tokens** are JWTs valid for 7 days, signed with a *different* secret. Only a SHA-256 hash is stored in the `RefreshToken` table.
4. **Rotation with reuse detection:** each refresh token works once. Replaying a used token revokes the whole login session (the token "family"), because it signals the token was stolen. The revoke is atomic, so two concurrent refreshes can't both succeed.
5. **Guards run globally** in order: rate limit (`ThrottlerGuard`) → authenticate (`JwtAuthGuard`) → authorize (`RolesGuard`). Every route is protected unless marked `@Public()`; restrict by role with `@Roles('ADMIN')`; read the user with `@CurrentUser()`.
6. **Validation:** request bodies go through Zod schemas (`ZodValidationPipe`); the app refuses to start with missing, short, or identical JWT secrets.

Try it:
```bash
curl -s -X POST localhost:3000/auth/register -H 'content-type: application/json' \
  -d '{"email":"demo@example.com","password":"correct-horse-battery"}'
curl -s localhost:3000/users/me -H "Authorization: Bearer <accessToken>"
```

Tests: `npm test` runs 13 end-to-end tests against Postgres covering registration, login, protected routes,
token rotation and reuse detection, logout, RBAC, and rate limiting.

## Done when
Auth, accounts, transactions, and async imports work; integration tests run in CI on every push;
the whole stack starts with `docker compose up`.
