import { Controller, Get } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { PrismaService } from '../prisma/prisma.service';
import { CurrentUser, Roles } from '../auth/decorators';
import type { AuthUser } from '../auth/auth.types';

const publicFields = { id: true, email: true, role: true, createdAt: true } as const;

@ApiTags('users')
@ApiBearerAuth()
@Controller('users')
export class UsersController {
  constructor(private readonly prisma: PrismaService) {}

  /** Any signed-in user: their own profile. */
  @Get('me')
  me(@CurrentUser() user: AuthUser) {
    return this.prisma.user.findUniqueOrThrow({ where: { id: user.id }, select: publicFields });
  }

  /** Admins only: list users. */
  @Get()
  @Roles('ADMIN')
  list() {
    return this.prisma.user.findMany({ select: publicFields, orderBy: { createdAt: 'desc' }, take: 100 });
  }
}
