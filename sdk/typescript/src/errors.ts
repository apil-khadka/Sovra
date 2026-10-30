/**
 * Typed Sovra API failure. Carries status, server code, and a
 * sanitized message — never the caller's token. Retryable marks
 * transport-level failures the caller may retry with a fresh
 * idempotency key; idempotent replays reuse the original key
 * instead (see idempotency.js).
 */
export class SovraError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;

  constructor(status: number, code: string, message: string, retryable: boolean) {
    super(message);
    this.name = "SovraError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

/** Fresh random key in the server alphabet (hex, no dashes). */
export function mintIdempotencyKey(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

/** True when the server would accept the key shape. */
export function validIdempotencyKey(key: string | undefined): boolean {
  return key !== undefined && /^[A-Za-z0-9_-]{1,128}$/.test(key);
}

/** Fetch one page, then follow its cursor until exhausted. */
export async function collectAll<T>(
  first: CursorPage<T>,
  next: (cursor: string) => Promise<CursorPage<T>>,
): Promise<T[]> {
  const out: T[] = [...first.items];
  let cursor = first.nextCursor;
  while (cursor !== undefined) {
    const page = await next(cursor);
    out.push(...page.items);
    cursor = page.nextCursor;
  }
  return out;
}

export interface CursorPage<T> {
  items: T[];
  nextCursor?: string;
}
