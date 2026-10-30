// Holder dashboard client (SOV-024). Session-only: unlock with a
// holder-key proof, then read exactly that key's cases,
// disclosures, credentials, and recovery. No request carries a
// thumbprint; the server-side unlock selects the key. Paths use
// the /api/holder prefix so sessionPath maps them onto the BFF
// holder routes; every value renders as plain text.

import { SESSION_ROLE_MESSAGE, SESSION_TOKEN_MESSAGE, requestJson } from './api'
import type { StatusMessages } from './api'

const SESSION: { kind: 'session' } = { kind: 'session' }

const READ_MESSAGES: StatusMessages = {
  400: () => 'the server refused that shape',
  401: SESSION_TOKEN_MESSAGE,
  403: () => 'unlock the holder key first',
  404: () => 'not found',
}

const UNLOCK_MESSAGES: StatusMessages = {
  400: () => 'that proof did not verify — fetch a fresh challenge and try again',
  401: SESSION_TOKEN_MESSAGE,
  403: SESSION_ROLE_MESSAGE,
}

export interface HolderChallenge {
  challenge: string
  expiresAt: string
}

export interface HolderUnlock {
  thumbprint: string
  expiresAt: string
}

export interface HolderCase {
  enrollmentId: string
  subjectRef: string
  vaultObjectId: string
  extractionRecordId: string
  boundRevision: number
  state: 'PENDING' | 'IN_REVIEW' | 'APPROVED' | 'REJECTED'
  createdBy: string
  decidedBy: string | null
  eligible: boolean
  eligibilityReason: string
  createdAt: string
}

export interface CaseReview {
  revision: number
  decision: string
  bindingProofOk: boolean
  reviewer: string
}

export interface CaseRevision {
  revNo: number
  observed: Record<string, string>
  normalized: Record<string, string>
  confidence: number
  supersedes: number | null
  createdBy: string
}

export interface CaseDetail extends HolderCase {
  reviews: CaseReview[]
  approvedRevision: number | null
  revisions: CaseRevision[]
}

export interface Disclosure {
  requestId: string
  rpId: string
  audience: string
  purpose: string
  credentialId: string
  claims: Record<string, unknown>
  state: string
  createdAt: string
  expiresAt: string
  decidedAt: string | null
  verificationOutcome: string | null
  trustSnapshot: number
}

export interface HolderCredential {
  credentialId: string
  issuerId: string
  vct: string
  keyRef: string
  issuedAt: string
  expiresAt: string
  status: string
  trustSnapshot: number
}

export interface RecoveryAttempt {
  recoveryId: string
  reason: string
  state: string
  newThumbprint: string | null
  createdAt: string
}

export interface RecoveryStatus {
  keyId: string | null
  thumbprint: string
  status: string
  recoveries: RecoveryAttempt[]
}

export function fetchHolderChallenge(): Promise<HolderChallenge> {
  return requestJson<HolderChallenge>('/api/holder/challenge', SESSION, undefined, READ_MESSAGES)
}

export function unlockHolder(
  holderJwk: Record<string, unknown>,
  proof: string,
): Promise<HolderUnlock> {
  return requestJson<HolderUnlock>(
    '/api/holder/unlock',
    SESSION,
    { method: 'POST', body: JSON.stringify({ holderJwk, proof }) },
    UNLOCK_MESSAGES,
  )
}

export function lockHolder(): Promise<{ locked: string }> {
  return requestJson('/api/holder/lock', SESSION, { method: 'POST' }, READ_MESSAGES)
}

export function fetchHolderCases(): Promise<HolderCase[]> {
  return requestJson<HolderCase[]>('/api/holder/cases', SESSION, undefined, READ_MESSAGES)
}

export function fetchHolderCase(enrollmentId: string): Promise<CaseDetail> {
  return requestJson<CaseDetail>(
    `/api/holder/cases/${enrollmentId}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchHolderConsents(): Promise<Disclosure[]> {
  return requestJson<Disclosure[]>('/api/holder/consents', SESSION, undefined, READ_MESSAGES)
}

export function fetchHolderCredentials(): Promise<HolderCredential[]> {
  return requestJson<HolderCredential[]>('/api/holder/credentials', SESSION, undefined, READ_MESSAGES)
}

export function fetchHolderRecovery(): Promise<RecoveryStatus> {
  return requestJson<RecoveryStatus>('/api/holder/recovery', SESSION, undefined, READ_MESSAGES)
}
