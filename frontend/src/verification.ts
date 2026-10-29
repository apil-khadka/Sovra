// Minimal verifier client (SOV-011, G1 synthetic profile only).
// The verifier submits one proof request, one fresh nonce, the session
// audience, and a holder-signed binding proof. The canonical message
// mirrors VerificationService.presentationMessage line for line.

import { SESSION_ROLE_MESSAGE, SESSION_TOKEN_MESSAGE, requestJson } from './api'
import type { StatusMessages } from './api'
import { signMessage } from './crypto'
import type { HolderKey } from './crypto'
import type { Caller } from './auth'

export interface VerificationDecision {
  decisionId: string
  requestId: string
  outcome: 'ACCEPTED' | 'REJECTED' | 'UNKNOWN'
  reasonCode: string
  synthetic: boolean
  profile: string
  trustSnapshot: number
  decidedAt: string
}

export const PRESENTATION_LABEL = 'sovra-presentation/v1'

const MESSAGES: StatusMessages = {
  404: () => 'unknown or other-tenant object',
  401: SESSION_TOKEN_MESSAGE,
  403: SESSION_ROLE_MESSAGE,
  409: () => 'this nonce already decided different content',
}

export function presentationMessage(
  requestId: string,
  nonce: string,
  audience: string,
  holderThumbprint: string,
): string {
  return [PRESENTATION_LABEL, requestId, nonce, audience, holderThumbprint].join('\n')
}

export function signPresentation(
  holder: HolderKey,
  requestId: string,
  nonce: string,
  audience: string,
): Promise<string> {
  return signMessage(
    holder,
    presentationMessage(requestId, nonce, audience, holder.thumbprint),
  )
}

export async function submitVerification(
  base: string,
  caller: Caller,
  holder: HolderKey,
  requestId: string,
  nonce: string,
  audience: string,
): Promise<VerificationDecision> {
  const bindingProof = await signPresentation(holder, requestId, nonce, audience)
  return requestJson<VerificationDecision>(
    `${base}/api/verification/presentations`,
    caller,
    {
      method: 'POST',
      body: JSON.stringify({ requestId, nonce, audience, holderJwk: holder.jwk, bindingProof }),
    },
    MESSAGES,
  )
}

export function fetchDecision(
  base: string,
  caller: Caller,
  decisionId: string,
): Promise<VerificationDecision> {
  return requestJson<VerificationDecision>(
    `${base}/api/verification/decisions/${decisionId}`,
    caller,
    undefined,
    MESSAGES,
  )
}
