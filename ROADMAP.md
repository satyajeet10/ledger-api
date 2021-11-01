# Roadmap

## v0.1 (current)
- [x] NestJS app, Swagger, Prisma schema, Docker Compose (Postgres + Redis)
- [x] Auth: argon2 passwords, JWT access + rotating refresh tokens with reuse detection, logout
- [x] Global guards: rate limit → authenticate → authorize (RBAC); Zod validation; env validation
- [x] 13 end-to-end tests against Postgres

## v0.2: core banking
- [ ] Accounts and transactions: CRUD scoped to the signed-in user (test that users can't read each other's data), pagination, filters
- [ ] `POST /transfers` inside a Prisma `$transaction`; prove rollback with a test
- [ ] `Idempotency-Key` header on POSTs, results cached in Redis

## v0.3: async and auth extensions
- [ ] Statement import: upload CSV → BullMQ job with retries and exponential backoff
- [ ] Change password (revokes all sessions), email verification, `GET /auth/sessions`
- [ ] OTP second factor for sensitive actions

## v1.0: production
- [ ] Structured logging (pino) with request IDs; OpenTelemetry traces
- [ ] Seed 50k transactions; `EXPLAIN ANALYZE` before/after indexes, numbers in the README
- [ ] Dockerfile, GitHub Actions (lint, typecheck, tests with Testcontainers), deploy to AWS ECS
