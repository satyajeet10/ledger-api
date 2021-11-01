import { BadRequestException, PipeTransform } from '@nestjs/common';
import { z } from 'zod';

/** Validates and transforms a request body with a Zod schema: @Body(new ZodValidationPipe(Schema)). */
export class ZodValidationPipe<T extends z.ZodType> implements PipeTransform<unknown, z.infer<T>> {
  constructor(private readonly schema: T) {}

  transform(value: unknown): z.infer<T> {
    const result = this.schema.safeParse(value);
    if (!result.success) {
      throw new BadRequestException({ message: 'Validation failed', errors: z.flattenError(result.error).fieldErrors });
    }
    return result.data;
  }
}
