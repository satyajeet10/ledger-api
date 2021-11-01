/**
 * End-to-end auth tests against a real Postgres (DATABASE_URL from .env).
 * Run `docker compose up -d` and `npm run db:migrate` first.
 */
import 'dotenv/config';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';

let app: INestApplication;
let prisma: PrismaService;
const email = `user-${Date.now()}@example.com`;
const adminEmail = `admin-${Date.now()}@example.com`;
const password = 'correct-horse-battery';
const http = () => request(app.getHttpServer());

beforeAll(async () => {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  app = moduleRef.createNestApplication();
  await app.init();
  prisma = app.get(PrismaService);
});

afterAll(async () => {
  await prisma.user.deleteMany({ where: { email: { in: [email, adminEmail] } } });
  await app.close();
});

describe('authentication', () => {
  let refreshToken: string;

  it('registers a user and returns a token pair', async () => {
    const res = await http().post('/auth/register').send({ email, password }).expect(201);
    expect(res.body).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });
    refreshToken = res.body.refreshToken;
  });

  it('rejects a duplicate email', () => http().post('/auth/register').send({ email, password }).expect(409));

  it('rejects a weak password', async () => {
    const res = await http().post('/auth/register').send({ email: 'x@example.com', password: 'short' }).expect(400);
    expect(res.body.errors.password).toBeDefined();
  });

  it('rejects a wrong password with a generic message', async () => {
    const res = await http().post('/auth/login').send({ email, password: 'wrong-password!!' }).expect(401);
    expect(res.body.message).toBe('Invalid email or password');
  });

  it('logs in (email is case-insensitive) and reaches a protected route', async () => {
    const login = await http().post('/auth/login').send({ email: email.toUpperCase(), password }).expect(200);
    const me = await http().get('/users/me').set('Authorization', `Bearer ${login.body.accessToken}`).expect(200);
    expect(me.body).toMatchObject({ email, role: 'USER' });
    expect(me.body.passwordHash).toBeUndefined();
  });

  it('blocks protected routes without a token', () => http().get('/users/me').expect(401));

  it('does not accept a refresh token as an access token', () =>
    http().get('/users/me').set('Authorization', `Bearer ${refreshToken}`).expect(401));

  it('rotates refresh tokens and detects reuse', async () => {
    const first = await http().post('/auth/refresh').send({ refreshToken }).expect(200);
    const rotated = first.body.refreshToken as string;
    expect(rotated).not.toBe(refreshToken);

    // Replaying the old token = theft signal: rejected, and the whole family is revoked.
    await http().post('/auth/refresh').send({ refreshToken }).expect(401);
    await http().post('/auth/refresh').send({ refreshToken: rotated }).expect(401);
  });

  it('logout revokes the session', async () => {
    const login = await http().post('/auth/login').send({ email, password }).expect(200);
    await http().post('/auth/logout').send({ refreshToken: login.body.refreshToken }).expect(204);
    await http().post('/auth/refresh').send({ refreshToken: login.body.refreshToken }).expect(401);
  });
});

describe('authorization (RBAC)', () => {
  it('forbids non-admins from listing users', async () => {
    const login = await http().post('/auth/login').send({ email, password }).expect(200);
    await http().get('/users').set('Authorization', `Bearer ${login.body.accessToken}`).expect(403);
  });

  it('allows admins to list users', async () => {
    await http().post('/auth/register').send({ email: adminEmail, password }).expect(201);
    await prisma.user.update({ where: { email: adminEmail }, data: { role: 'ADMIN' } });
    // Role is in the access token, so log in again to get a token with the new role.
    const login = await http().post('/auth/login').send({ email: adminEmail, password }).expect(200);
    const res = await http().get('/users').set('Authorization', `Bearer ${login.body.accessToken}`).expect(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('health', () => {
  it('is public', () => http().get('/health').expect(200));
});

describe('rate limiting', () => {
  it('blocks repeated login attempts with 429', async () => {
    let status = 0;
    for (let i = 0; i < 10 && status !== 429; i++) {
      status = (await http().post('/auth/login').send({ email, password: 'wrong-password!!' })).status;
    }
    expect(status).toBe(429);
  });
});
