// Issuer information-management desk client (SOV-023).
// Session-only: operators review extraction and enrollment queues,
// correct and approve revisions, decide cases, check credential
// status, and view originals under purpose-bound grants. Paths use
// the /api/issuer prefix so sessionPath maps them onto the BFF
// issuer routes; every value renders as plain text.

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
  403: () => 'that action needs an issuer operator',
  404: () => 'not found',
  409: () => 'already decided, self-approval, or no longer current',
}

export interface RecordSummary {
  recordId: string
  vaultObjectId: string
  objectVersion: number
  engineId: string
  schemaId: string
  approvedRevision: number | null
  latestRevision: number
  createdBy: string
  createdAt: string
}

export interface RecordPage {
  items: RecordSummary[]
  nextCursor: string | null
}

export interface RevisionView {
  revNo: number
  observed: Record<string, string>
  normalized: Record<string, string>
  canonicalDigests: Record<string, string>
  exactDigests: Record<string, string>
  confidence: number
  supersedes: number | null
  createdBy: string
}

export interface RecordDetail {
  recordId: string
  vaultObjectId: string
  objectVersion: number
  sourceDigestHex: string
  engineId: string
  schemaId: string
  normalizerId: string
  canonId: string
  approvedRevision: number | null
  revisions: RevisionView[]
}

export interface EnrollmentSummary {
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

export interface EnrollmentPage {
  items: EnrollmentSummary[]
  nextCursor: string | null
}

export interface EnrollmentReview {
  revision: number
  decision: string
  bindingProofOk: boolean
  reviewer: string
}

export interface EnrollmentDetail {
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
  reviews: EnrollmentReview[]
}

export interface CredentialDetail {
  credentialId: string
  issuerId: string
  vct: string
  keyRef: string
  issuedAt: string
  expiresAt: string
  status: string
  trustSnapshot: number
}

export interface CredentialStatus {
  status: string
  version: number
  fetchedAt: string
  maxAgeSeconds: number
}

export interface ReviewViewResult {
  objectId: string
  version: number
  contentType: string
  contentBase64: string
  sha256Hex: string
}

export interface DeskAuditEvent {
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

export function fetchExtractionQueue(state: string): Promise<RecordPage> {
  return requestJson<RecordPage>(
    `/api/issuer/extraction/records?state=${encodeURIComponent(state)}&limit=50`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchExtractionRecord(recordId: string): Promise<RecordDetail> {
  return requestJson<RecordDetail>(
    `/api/issuer/extraction/records/${recordId}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function correctExtraction(
  recordId: string,
  fields: Record<string, string>,
  confidence: number,
): Promise<{ recordId: string; revision: number }> {
  return requestJson(
    `/api/issuer/extraction/records/${recordId}/revisions`,
    SESSION,
    { method: 'POST', body: JSON.stringify({ fields, confidence }) },
    WRITE_MESSAGES,
  )
}

export function approveExtraction(
  recordId: string,
  revision: number,
): Promise<{ recordId: string; approvedRevision: number }> {
  return requestJson(
    `/api/issuer/extraction/records/${recordId}/approval`,
    SESSION,
    { method: 'POST', body: JSON.stringify({ revision }) },
    WRITE_MESSAGES,
  )
}

export function fetchEnrollmentQueue(state: string): Promise<EnrollmentPage> {
  return requestJson<EnrollmentPage>(
    `/api/issuer/enrollments?state=${encodeURIComponent(state)}&limit=50`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchEnrollmentCase(enrollmentId: string): Promise<EnrollmentDetail> {
  return requestJson<EnrollmentDetail>(
    `/api/issuer/enrollments/${enrollmentId}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function createEnrollmentCase(
  vaultObjectId: string,
  extractionRecordId: string,
  holderJwk: Record<string, unknown>,
): Promise<{ enrollmentId: string; subjectRef: string; state: string }> {
  return requestJson(
    '/api/issuer/enrollments',
    SESSION,
    { method: 'POST', body: JSON.stringify({ vaultObjectId, extractionRecordId, holderJwk }) },
    WRITE_MESSAGES,
  )
}

export function submitEnrollment(enrollmentId: string): Promise<{ enrollmentId: string; state: string }> {
  return requestJson(
    `/api/issuer/enrollments/${enrollmentId}/submit`,
    SESSION,
    { method: 'POST' },
    WRITE_MESSAGES,
  )
}

export function decideEnrollment(
  enrollmentId: string,
  revision: number,
  decision: 'approve' | 'reject',
  bindingProof?: string,
): Promise<{ enrollmentId: string; state: string; boundRevision: number }> {
  return requestJson(
    `/api/issuer/enrollments/${enrollmentId}/decision`,
    SESSION,
    {
      method: 'POST',
      body: JSON.stringify(
        bindingProof === undefined
          ? { revision, decision }
          : { revision, decision, bindingProof },
      ),
    },
    WRITE_MESSAGES,
  )
}

export function fetchCredential(credentialId: string): Promise<CredentialDetail> {
  return requestJson<CredentialDetail>(
    `/api/issuer/credentials/${credentialId}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function fetchCredentialStatus(credentialId: string): Promise<CredentialStatus> {
  return requestJson<CredentialStatus>(
    `/api/issuer/credentials/${credentialId}/status`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}

export function revokeCredential(credentialId: string): Promise<{ credentialId: string; status: string }> {
  return requestJson(
    `/api/issuer/credentials/${credentialId}/revoke`,
    SESSION,
    { method: 'POST' },
    WRITE_MESSAGES,
  )
}

export function fetchReviewView(objectId: string, version: number): Promise<ReviewViewResult> {
  return requestJson<ReviewViewResult>(
    '/api/issuer/vault/review-view',
    SESSION,
    { method: 'POST', body: JSON.stringify({ objectId, version }) },
    WRITE_MESSAGES,
  )
}

export function fetchDeskAudit(limit: number): Promise<DeskAuditEvent[]> {
  return requestJson<DeskAuditEvent[]>(
    `/api/issuer/audit/events?limit=${limit}`,
    SESSION,
    undefined,
    READ_MESSAGES,
  )
}
