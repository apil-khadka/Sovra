// Public operations clients (SOV-029). Readiness and the trust snapshot
// are unauthenticated federation/ops metadata; both carry fixed codes
// and numbers only, never identity data or secrets.

export interface ReadinessCheck {
  name: string
  status: 'UP' | 'DEGRADED' | 'DOWN'
  code: string
  detail: Record<string, unknown>
  durationMs: number
}

export interface ReadinessReport {
  status: 'READY' | 'NOT_READY'
  checks: ReadinessCheck[]
}

export interface SnapshotIssuer {
  issuerId: string
  displayName: string
  scope: string
  credentialTypes: string[]
  keyId: string
  keyVersion: number
  validFrom: string
  validThrough: string
  status: string
}

export interface TrustSnapshot {
  version: number
  issuers: SnapshotIssuer[]
  policies: Array<{
    rpId: string
    purpose: string
    allowedTypes: string[]
    maxAssurance: string
  }>
}

export class OpsApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) throw new OpsApiError(res.status, `backend responded ${res.status}`)
  return (await res.json()) as T
}

export interface Health {
  status: string
  service: string
  version: string
}

/** Liveness probe; throws unless the backend reports UP. */
export async function fetchHealth(): Promise<Health> {
  const body = await get<Health>('/api/health')
  if (body.status !== 'UP') throw new Error('backend is not UP')
  return body
}

/** Liveness says the process answers; readiness says the flow can proceed. */
export function fetchReadiness(): Promise<ReadinessReport> {
  return get<ReadinessReport>('/api/health/ready')
}

/** Active trust snapshot, or null when none is activated yet. */
export async function fetchSnapshot(): Promise<TrustSnapshot | null> {
  const res = await fetch('/api/trust/snapshots/current')
  if (res.status === 404) return null
  if (!res.ok) throw new OpsApiError(res.status, `backend responded ${res.status}`)
  return (await res.json()) as TrustSnapshot
}
