import type { Context } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { z } from 'zod';
import type { ErrorCode } from '@vpass/shared';

export class ApiError extends Error {
  constructor(
    public readonly status: ContentfulStatusCode,
    public readonly code: ErrorCode,
    public readonly extra?: Record<string, unknown>,
  ) {
    super(code);
  }
}

export const err = (status: ContentfulStatusCode, code: ErrorCode, extra?: Record<string, unknown>) => new ApiError(status, code, extra);

const MAX_BODY = 32 * 1024 * 1024;

/** Parse and validate a JSON body. Never echoes the body back in errors. */
export async function body<T extends z.ZodType>(c: Context, schema: T): Promise<z.infer<T>> {
  const len = Number(c.req.header('content-length') ?? '0');
  if (len > MAX_BODY) throw err(413, 'bad_request');
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    throw err(400, 'bad_request');
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw err(400, 'bad_request');
  return parsed.data;
}

export const now = () => Date.now();
