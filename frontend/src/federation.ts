// Federation and security-operations desk clients (SOV-026).
// Session-only: trust admins act as themselves through the BFF,
// never by pasting a token. Reads are sanitized operational
// evidence; the desk has no source, key, or decryption surface.

import { SESSION_ROLE_MESSAGE, SESSION_TOKEN_MESSAGE, requestJson } from './api'
import type { StatusMessages } from './api'
import type { TrustSnapshot } from './ops'

const SESSION: { kind: 'session' } = { kind: 'session' }

const READ_MESSAGES: StatusMessages = {
  401: SESSION_TOKEN_MESSAGE,
  403: SESSION_ROLE_MESSAGE,
  404: () => 'not found',
}

const WRITE_MESSAGES: StatusMessages = {
  400: () => 'the server refused that shape',
  401: SESSION_TOKEN_MESSAGE,
  403: () => 'that action needs a different admin',
  404: () => 'not found',
  409: () => 'already decided or no longer current',
}

export interface ProposalSummary {
  proposalId: string
  version: number
  state: 'PENDING' | 'APPROVED' | 'ACTIVATED'
  proposedBy: string
  approvedBy: string | null
  createdAt: string
}

export interface ProposeResult {
  version: string
  proposalId: string
}

export interface ApproveResult {
  proposalId: string
  personVerified: string
}

export interface AuditEvent {
  id: string
  occurredAt: string
  actorType: string
  actorId: string
  action: string
  resourceType: string
  resourceId: string
  decision: string
  reasonCode: string
  policyVersion: number
  correlationId: string
  detail: unknown
}

export interface OpsAlert {
  alert: string
  severity: string
  status: string
  code: string
  check: string
  firstObservedAt: string
  observedAt: string
}

export interface IssuerOnboarding {
  issuerId: string
  displayName: string
  scope: string
  credentialTypes: string[]
  keyId: string
  publicKeyJwk: Record<string, unknown>
  validFrom: string
  validThrough: string
  status: string
}

export function fetchSnapshot(): Promise<TrustSnapshot | null> {
  return requestJson<TrustSnapshot | null>(
    '/api/trust/snapshots/current',
    SESSION,
    undefined,
    READ_MESSAGES,
  ).catch((err: unknown) => {
    if (err instanceof Error && 'status' in err && err.status === 404) return null
    throw err
  })
}

export function fetchProposals(): Promise<ProposalSummary[]> {
  return requestJson<ProposalSummary[]>('/api/trust/proposals', SESSION, undefined, READ_MESSAGES)
}

export function proposeIssuers(issuers: IssuerOnboarding[], note: string): Promise<ProposeResult> {
  return requestJson<ProposeResult>(
    '/api/trust/proposals',
    SESSION,
    { method: 'POST', body: JSON.stringify({ issuers, policies: [], note }) },
    WRITE_MESSAGES,
  )
}

export function approveProposal(proposalId: string): Promise<ApproveResult> {
  return requestJson<ApproveResult>(
    `/api/trust/proposals/${proposalId}/approve`,
    SESSION,
    { method: 'POST' },
    WRITE_MESSAGES,
  )
}

export function activateSnapshot(version: number): Promise<{ version: string }> {
  return requestJson<{ version: string }>(
    `/api/trust/snapshots/${version}/activate`,
    SESSION,
    { method: 'POST' },
    WRITE_MESSAGES,
  )
}

export function fetchAudit(limit: number): Promise<AuditEvent[]> {
  return requestJson<AuditEvent[]>(
    `/api/audit/events?limit=${limit}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchAlerts(): Promise<OpsAlert[]> {
  return requestJson<OpsAlert[]>('/api/alerts', SESSION, undefined, READ_MESSAGES)
}
