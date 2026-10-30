// Developer portal and RP dashboard client (SOV-022/SOV-025).
// Session-only: members read capability discovery, onboard
// sandbox credentials, manage RP apps, and review verification
// outcomes and metrics. Paths use the /api/portal prefix so
// sessionPath maps them onto the BFF portal routes; every
// value renders as plain text.

import { SESSION_ROLE_MESSAGE, SESSION_TOKEN_MESSAGE, requestJson } from './api'
import type { StatusMessages } from './api'

const SESSION: { kind: 'session' } = { kind: 'session' }

const READ_MESSAGES: StatusMessages = {
  400: () => 'the server refused that filter',
  401: SESSION_TOKEN_MESSAGE,
  403: SESSION_ROLE_MESSAGE,
  404: () => 'not found',
}

const WRITE_MESSAGES: StatusMessages = {
  400: () => 'the server refused that shape',
  401: SESSION_TOKEN_MESSAGE,
  403: () => 'that action needs a tenant member',
  404: () => 'not found',
  409: () => 'revoked accounts stay revoked: create a new one',
}

export interface PortalDiscovery {
  service: string
  version: string
  profile: string
  contractVersion: string
  auth: string[]
  sandbox: {
    namePattern: string
    roles: string[]
    ttlHours: number
    demoProfiles: string[]
  }
  sdks: { java: string; typescript: string }
  rp: { outcomes: string; credentials: string }
}

export interface SandboxAccount {
  id: string
  name: string
  roles: string[]
  revoked: boolean
  expiresAt: string | null
  createdAt: string
}

export interface CreatedSandbox extends SandboxAccount {
  token: string
}

export interface RpApp {
  id: string
  name: string
  roles: string[]
  revoked: boolean
  expiresAt: string | null
  createdAt: string
}

export interface RotatedApp extends RpApp {
  token: string
}

export interface RpOutcome {
  decisionId: string
  requestId: string
  rpId: string
  outcome: string
  reasonCode: string
  decidedAt: string
}

export interface RpMetrics {
  total: number
  accepted: number
  rejected: number
  unknown: number
}

export function fetchDiscovery(): Promise<PortalDiscovery> {
  return requestJson<PortalDiscovery>('/api/portal/discovery', SESSION, undefined, READ_MESSAGES)
}

export function createSandbox(name: string): Promise<CreatedSandbox> {
  return requestJson(
    '/api/portal/sandbox/accounts',
    SESSION,
    { method: 'POST', body: JSON.stringify({ name }) },
    WRITE_MESSAGES,
  )
}

export function fetchSandboxAccounts(): Promise<SandboxAccount[]> {
  return requestJson<SandboxAccount[]>(
    '/api/portal/sandbox/accounts',
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchRpApps(): Promise<RpApp[]> {
  return requestJson<RpApp[]>('/api/portal/rp/apps', SESSION, undefined, READ_MESSAGES)
}

export function rotateRpCredential(id: string): Promise<RotatedApp> {
  return requestJson(
    `/api/portal/rp/credentials/${id}/rotate`,
    SESSION,
    { method: 'POST', body: JSON.stringify({}) },
    WRITE_MESSAGES,
  )
}

export function revokeRpCredential(id: string): Promise<RpApp> {
  return requestJson(
    `/api/portal/rp/credentials/${id}/revoke`,
    SESSION,
    { method: 'POST', body: JSON.stringify({}) },
    WRITE_MESSAGES,
  )
}

export function fetchRpOutcomes(limit: number): Promise<RpOutcome[]> {
  return requestJson<RpOutcome[]>(
    `/api/portal/rp/outcomes?limit=${limit}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchRpMetrics(): Promise<RpMetrics> {
  return requestJson<RpMetrics>('/api/portal/rp/metrics', SESSION, undefined, READ_MESSAGES)
}
