import type { Role } from '../generated/prisma/enums';

/** The user attached to the request after the access token is verified. */
export interface AuthUser {
  id: string;
  email: string;
  role: Role;
}

export interface AccessPayload {
  sub: string;
  email: string;
  role: Role;
  type: 'access';
}

export interface RefreshPayload {
  sub: string;
  jti: string;
  family: string;
  type: 'refresh';
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number; // access token lifetime in seconds
}

/** The minimal request shape the guards need (keeps them framework-light and easy to test). */
export interface AuthRequest {
  headers: { authorization?: string | undefined };
  user?: AuthUser;
}
