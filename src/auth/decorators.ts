import { createParamDecorator, ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Role } from '../generated/prisma/enums';
import type { AuthRequest, AuthUser } from './auth.types';

export const IS_PUBLIC_KEY = 'isPublic';
/** Skips authentication. Every route is protected unless marked @Public(). */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

export const ROLES_KEY = 'roles';
/** Restricts a route to the given roles. Checked by RolesGuard after authentication. */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

/** Injects the authenticated user: me(@CurrentUser() user: AuthUser). */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser | undefined => ctx.switchToHttp().getRequest<AuthRequest>().user,
);
