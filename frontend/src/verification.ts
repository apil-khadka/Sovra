// Minimal verifier client (SOV-011, G1 synthetic profile only).
// The verifier submits one proof request, one fresh nonce, the session
// audience, and a holder-signed binding proof. The canonical message
// mirrors VerificationService.presentationMessage line for line.

import { signMessage } from './consent'
import type { HolderKey } from './consent'

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

export class VerifyApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
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

async function request<T>(path: string, token: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  })
  if (res.status === 404) throw new VerifyApiError(404, 'unknown or other-tenant object')
  if (res.status === 401) throw new VerifyApiError(401, 'invalid or missing token')
  if (res.status === 403) throw new VerifyApiError(403, 'token lacks the required role')
  if (res.status === 422)
    throw new VerifyApiError(422, 'this nonce already decided different content')
  if (!res.ok) throw new VerifyApiError(res.status, `backend responded ${res.status}`)
  return (await res.json()) as T
}

export function submitVerification(
  base: string,
  token: string,
  holder: HolderKey,
  requestId: string,
  nonce: string,
  audience: string,
): Promise<VerificationDecision> {
  return signPresentation(holder, requestId, nonce, audience).then((bindingProof) =>
    request<VerificationDecision>(`${base}/api/verification/presentations`, token, {
      method: 'POST',
      body: JSON.stringify({
        requestId,
        nonce,
        audience,
        holderJwk: holder.jwk,
        bindingProof,
      }),
    }),
  )
}

export function fetchDecision(
  base: string,
  token: string,
  decisionId: string,
): Promise<VerificationDecision> {
  return request<VerificationDecision>(
    `${base}/api/verification/decisions/${decisionId}`,
    token,
  )
}
