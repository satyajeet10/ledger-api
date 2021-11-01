import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { ZodValidationPipe } from '../common/zod-validation.pipe';
import { AuthService } from './auth.service';
import { Public } from './decorators';
import {
  LoginSchema, RefreshSchema, RegisterSchema,
  type LoginDto, type RefreshDto, type RegisterDto,
} from './auth.schemas';

const credentialsBody = {
  schema: {
    type: 'object',
    required: ['email', 'password'],
    properties: { email: { type: 'string', example: 'demo@example.com' }, password: { type: 'string', example: 'correct-horse-battery' } },
  },
};
const refreshBody = {
  schema: { type: 'object', required: ['refreshToken'], properties: { refreshToken: { type: 'string' } } },
};

@ApiTags('auth')
@Public()
@Throttle({ default: { limit: 5, ttl: 60_000 } }) // brute-force protection: 5 requests/minute per IP
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  @ApiBody(credentialsBody)
  register(@Body(new ZodValidationPipe(RegisterSchema)) dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Post('login')
  @HttpCode(200)
  @ApiBody(credentialsBody)
  login(@Body(new ZodValidationPipe(LoginSchema)) dto: LoginDto) {
    return this.auth.login(dto);
  }

  @Post('refresh')
  @HttpCode(200)
  @ApiBody(refreshBody)
  refresh(@Body(new ZodValidationPipe(RefreshSchema)) dto: RefreshDto) {
    return this.auth.refresh(dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(204)
  @ApiBody(refreshBody)
  async logout(@Body(new ZodValidationPipe(RefreshSchema)) dto: RefreshDto) {
    await this.auth.logout(dto.refreshToken);
  }
}
