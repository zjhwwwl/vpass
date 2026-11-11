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

/** Read the body with a hard size cap that also holds for chunked requests without Content-Length. */
async function readCapped(c: Context): Promise<string> {
  const len = Number(c.req.header('content-length') ?? '0');
  if (len > MAX_BODY) throw err(413, 'bad_request');
  const stream = c.req.raw.body;
  if (!stream) return '';
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY) {
      await reader.cancel();
      throw err(413, 'bad_request');
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const ch of chunks) {
    all.set(ch, off);
    off += ch.byteLength;
  }
  return new TextDecoder().decode(all);
}

/** Parse and validate a JSON body. Never echoes the body back in errors. */
export async function body<T extends z.ZodType>(c: Context, schema: T): Promise<z.infer<T>> {
  const text = await readCapped(c);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw err(400, 'bad_request');
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw err(400, 'bad_request');
  return parsed.data;
}

export const now = () => Date.now();
