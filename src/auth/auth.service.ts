import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import type { Role } from '../generated/prisma/enums';
import type { LoginDto, RegisterDto } from './auth.schemas';
import type { RefreshPayload, TokenPair } from './auth.types';

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

@Injectable()
export class AuthService {
  /** Used to spend the same time on unknown emails as on wrong passwords (no user enumeration by timing). */
  private dummyHash: Promise<string> | undefined;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async register(dto: RegisterDto): Promise<TokenPair> {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) throw new ConflictException('Email already registered');

    const user = await this.prisma.user.create({
      data: { email: dto.email, passwordHash: await argon2.hash(dto.password) },
    });
    return this.issueTokens(user, randomUUID());
  }

  async login(dto: LoginDto): Promise<TokenPair> {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    this.dummyHash ??= argon2.hash('timing-equalizer');
    const valid = await argon2.verify(user?.passwordHash ?? (await this.dummyHash), dto.password);
    if (!user || !valid) throw new UnauthorizedException('Invalid email or password');

    return this.issueTokens(user, randomUUID());
  }

  /**
   * Refresh-token rotation with reuse detection:
   * each refresh token works once. Presenting an already-used token means it was stolen
   * (or replayed), so the whole family is revoked and the user must log in again.
   */
  async refresh(refreshToken: string): Promise<TokenPair> {
    const payload = await this.verifyRefresh(refreshToken);
    const stored = await this.prisma.refreshToken.findUnique({ where: { id: payload.jti } });
    if (!stored || stored.userId !== payload.sub || stored.tokenHash !== sha256(refreshToken)) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (stored.expiresAt <= new Date()) throw new UnauthorizedException('Refresh token expired');

    // Atomic: only one concurrent request can revoke (and therefore use) this token.
    const { count } = await this.prisma.refreshToken.updateMany({
      where: { id: stored.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (count === 0) {
      await this.revokeFamily(stored.family);
      throw new UnauthorizedException('Refresh token reuse detected; please log in again');
    }

    const user = await this.prisma.user.findUnique({ where: { id: stored.userId } });
    if (!user) throw new UnauthorizedException('Invalid refresh token');
    return this.issueTokens(user, stored.family);
  }

  /** Revokes the session (token family). Idempotent: an invalid token still returns success. */
  async logout(refreshToken: string): Promise<void> {
    try {
      const payload = await this.verifyRefresh(refreshToken);
      await this.revokeFamily(payload.family);
    } catch {
      // Nothing to revoke.
    }
  }

  private async revokeFamily(family: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { family, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private async verifyRefresh(token: string): Promise<RefreshPayload> {
    let payload: RefreshPayload;
    try {
      payload = await this.jwt.verifyAsync<RefreshPayload>(token, {
        secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    if (payload.type !== 'refresh') throw new UnauthorizedException('Invalid refresh token');
    return payload;
  }

  private async issueTokens(user: { id: string; email: string; role: Role }, family: string): Promise<TokenPair> {
    const jti = randomUUID();
    const accessToken = await this.jwt.signAsync(
      { sub: user.id, email: user.email, role: user.role, type: 'access' },
      { secret: this.config.getOrThrow<string>('JWT_ACCESS_SECRET'), expiresIn: ACCESS_TTL_SECONDS },
    );
    const refreshToken = await this.jwt.signAsync(
      { sub: user.id, jti, family, type: 'refresh' },
      { secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'), expiresIn: REFRESH_TTL_SECONDS },
    );
    await this.prisma.refreshToken.create({
      data: {
        id: jti,
        userId: user.id,
        family,
        tokenHash: sha256(refreshToken),
        expiresAt: new Date(Date.now() + REFRESH_TTL_SECONDS * 1000),
      },
    });
    return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: ACCESS_TTL_SECONDS };
  }
}
