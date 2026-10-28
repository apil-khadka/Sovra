// Browser-session authentication (SOV-006). The BFF holds OIDC
// tokens server-side; the browser keeps only the session cookie
// plus the readable CSRF cookie it echoes on mutations.

export interface SessionInfo {
  displayName: string
  tenantId: string
  roles: string[]
  amr: string[]
  authTime: string
}

export type Caller = { kind: 'token'; token: string } | { kind: 'session' }

export function login(): void {
  window.location.href = '/oauth2/authorization/sovra'
}

export async function fetchSession(): Promise<SessionInfo | null> {
  const res = await fetch('/api/bff/me', { credentials: 'include' })
  if (res.status === 401) return null
  if (!res.ok) throw new Error(`session check responded ${res.status}`)
  return (await res.json()) as SessionInfo
}

export function xsrfToken(): string | null {
  const match = document.cookie.split('; ').find((part) => part.startsWith('XSRF-TOKEN='))
  return match === undefined ? null : decodeURIComponent(match.slice('XSRF-TOKEN='.length))
}

export async function logout(): Promise<void> {
  const token = xsrfToken()
  const res = await fetch('/api/bff/logout', {
    method: 'POST',
    credentials: 'include',
    headers: token === null ? {} : { 'X-XSRF-TOKEN': token },
  })
  if (!res.ok) throw new Error(`logout responded ${res.status}`)
  const body = (await res.json()) as { endSessionUrl: string }
  // Kill the provider session too, or the next login silently
  // re-authenticates from the Keycloak SSO cookie.
  window.location.href = body.endSessionUrl
}

/** Rewrite a machine-chain path to its BFF twin for session callers. */
export function sessionPath(machinePath: string): string {
  return machinePath.replace('/api/', '/api/bff/')
}
