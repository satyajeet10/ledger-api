import { z } from 'zod';

const email = z.email().max(254).transform((e) => e.toLowerCase());

export const RegisterSchema = z.object({
  email,
  password: z.string().min(12, 'Password must be at least 12 characters').max(128),
});
export type RegisterDto = z.infer<typeof RegisterSchema>;

export const LoginSchema = z.object({
  email,
  password: z.string().min(1).max(128),
});
export type LoginDto = z.infer<typeof LoginSchema>;

export const RefreshSchema = z.object({ refreshToken: z.string().min(1) });
export type RefreshDto = z.infer<typeof RefreshSchema>;
