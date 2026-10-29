// Minimal holder consent client (SOV-010, G1 synthetic profile only).
// The holder reviews the exact bound request, then signs an explicit
// approve/deny decision with the credential's P-256 holder key. The
// canonical message mirrors ConsentService.consentMessage line for line.

import { SESSION_ROLE_MESSAGE, SESSION_TOKEN_MESSAGE, requestJson } from './api'
import type { StatusMessages } from './api'
import { signMessage } from './crypto'
import type { HolderKey } from './crypto'
import type { Caller } from './auth'

export interface ConsentReview {
  requestId: string
  rpId: string
  audience: string
  purpose: string
  credentialId: string
  claims: Record<string, unknown>
  planHash: string
  challenge: string
  holderThumbprint: string
  state: 'PENDING' | 'DENIED' | 'UNAVAILABLE' | 'VERIFIED'
  stateReason: string
  createdAt: string
  expiresAt: string
  trustSnapshot: number
}

export interface ConsentPresentation {
  requestId: string
  state: string
  synthetic: boolean
  profile: string
  presentation: string
  claims: Record<string, unknown>
  expiresAt: string
  trustSnapshot: number
}

export const CONSENT_LABEL = 'sovra-consent/v1'
export const CLAIMS_CANONICAL = 'adultOver18=true'

const MESSAGES: StatusMessages = {
  404: () => 'unknown, refused, or expired request',
  401: SESSION_TOKEN_MESSAGE,
  403: SESSION_ROLE_MESSAGE,
  409: () => 'this request was already decided',
}

export function consentMessage(review: ConsentReview, decision: 'approve' | 'deny'): string {
  return [
    CONSENT_LABEL,
    review.requestId,
    decision,
    review.rpId,
    review.audience,
    review.purpose,
    CLAIMS_CANONICAL,
    review.planHash,
    review.challenge,
    review.expiresAt,
    review.holderThumbprint,
  ].join('\n')
}

export async function signConsent(
  holder: HolderKey,
  review: ConsentReview,
  decision: 'approve' | 'deny',
): Promise<string> {
  return signMessage(holder, consentMessage(review, decision))
}

export function fetchReview(base: string, caller: Caller, requestId: string): Promise<ConsentReview> {
  return requestJson<ConsentReview>(
    `${base}/api/consent/requests/${requestId}`,
    caller,
    undefined,
    MESSAGES,
  )
}

export async function postDecision(
  base: string,
  caller: Caller,
  holder: HolderKey,
  review: ConsentReview,
  decision: 'approve' | 'deny',
): Promise<ConsentReview> {
  const consentProof = await signConsent(holder, review, decision)
  return requestJson<ConsentReview>(
    `${base}/api/consent/requests/${review.requestId}/decision`,
    caller,
    { method: 'POST', body: JSON.stringify({ decision, holderJwk: holder.jwk, consentProof }) },
    MESSAGES,
  )
}

export function fetchPresentation(
  base: string,
  caller: Caller,
  requestId: string,
): Promise<ConsentPresentation> {
  return requestJson<ConsentPresentation>(
    `${base}/api/consent/requests/${requestId}/presentation`,
    caller,
    undefined,
    MESSAGES,
  )
}
