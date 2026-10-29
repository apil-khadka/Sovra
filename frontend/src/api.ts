// Shared BFF/machine API client. One seam for the two caller
// shapes: session callers ride the cookie on /api/bff/* with the
// CSRF echo on mutations; token callers use the machine path with
// a Bearer [REDACTED] Each domain supplies only its per-status messages.

import { sessionPath, xsrfToken } from './auth'
import type { Caller } from './auth'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

/** Per-status messages; told whether the call rode the session. */
export type StatusMessages = Record<number, (session: boolean) => string>

export const SESSION_TOKEN_MESSAGE = (session: boolean): string =>
  session ? 'session expired: log in again' : 'invalid or missing token'

export const SESSION_ROLE_MESSAGE = (session: boolean): string =>
  session ? 'session lacks the required role' : 'token lacks the required role'

export async function requestJson<T>(
  path: string,
  caller: Caller,
  init: RequestInit | undefined,
  messages: StatusMessages,
): Promise<T> {
  const session = caller.kind === 'session'
  const xsrf = session && init?.method !== undefined ? xsrfToken() : null
  const res = await fetch(session ? sessionPath(path) : path, {
    ...init,
    credentials: session ? 'include' : undefined,
    headers: {
      ...(session ? {} : { Authorization: `Bearer ${caller.token}` }),
      'Content-Type': 'application/json',
      ...(xsrf === null ? {} : { 'X-XSRF-TOKEN': xsrf }),
      ...(init?.headers ?? {}),
    },
  })
  const message = messages[res.status]
  if (message !== undefined) throw new ApiError(res.status, message(session))
  if (!res.ok) throw new ApiError(res.status, `backend responded ${res.status}`)
  return (await res.json()) as T
}
