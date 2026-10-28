// Minimal holder consent client (SOV-010, G1 synthetic profile only).
// The holder reviews the exact bound request, then signs an explicit
// approve/deny decision with the credential's P-256 holder key. The
// canonical message mirrors ConsentService.consentMessage line for line.

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

export interface HolderKey {
  privateKey: CryptoKey
  jwk: JsonWebKey
  thumbprint: string
}

export const CONSENT_LABEL = 'sovra-consent/v1'
export const CLAIMS_CANONICAL = 'adultOver18=true'

export class ConsentApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function base64Url(bytes: ArrayBuffer | Uint8Array): string {
  const raw = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (const byte of raw) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function base64UrlEncodeText(text: string): string {
  return base64Url(new TextEncoder().encode(text))
}

/** RFC 7638 SHA-256 JWK thumbprint over {"crv","kty","x","y"}. */
export async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return base64Url(digest)
}

/** Fresh P-256 holder key (synthetic demo; extractable for JWK export). */
export async function generateHolder(): Promise<HolderKey> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { privateKey: pair.privateKey, jwk, thumbprint: await thumbprint(jwk) }
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

/** ES256 JWS over an arbitrary canonical message (consent, presentation). */
export async function signMessage(holder: HolderKey, message: string): Promise<string> {
  const header = base64UrlEncodeText('{"alg":"ES256"}')
  const payload = base64UrlEncodeText(message)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    holder.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  // WebCrypto ECDSA yields raw r||s (IEEE P1363), already JWS-sized.
  const raw = new Uint8Array(signature)
  if (raw.length !== 64) throw new Error('unexpected signature size')
  return `${header}.${payload}.${base64Url(raw)}`
}

/** Export the private half so the verifier demo can import the same key. */
export async function exportPrivateKey(holder: HolderKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', holder.privateKey)
}

/** Import a previously exported holder private key. */
export async function importHolder(privateJwk: JsonWebKey): Promise<HolderKey> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )
  const full = await crypto.subtle.exportKey('jwk', privateKey)
  const publicJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: full.x, y: full.y }
  return { privateKey, jwk: publicJwk, thumbprint: await thumbprint(publicJwk) }
}

export function randomNonce(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(24)))
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
  if (res.status === 404) throw new ConsentApiError(404, 'unknown, refused, or expired request')
  if (res.status === 401) throw new ConsentApiError(401, 'invalid or missing token')
  if (res.status === 403) throw new ConsentApiError(403, 'token lacks the required role')
  if (res.status === 409) throw new ConsentApiError(409, 'this request was already decided')
  if (!res.ok) throw new ConsentApiError(res.status, `backend responded ${res.status}`)
  return (await res.json()) as T
}

export function fetchReview(base: string, token: string, requestId: string): Promise<ConsentReview> {
  return request<ConsentReview>(`${base}/api/consent/requests/${requestId}`, token)
}

export function postDecision(
  base: string,
  token: string,
  holder: HolderKey,
  review: ConsentReview,
  decision: 'approve' | 'deny',
): Promise<ConsentReview> {
  return signConsent(holder, review, decision).then((consentProof) =>
    request<ConsentReview>(`${base}/api/consent/requests/${review.requestId}/decision`, token, {
      method: 'POST',
      body: JSON.stringify({ decision, holderJwk: holder.jwk, consentProof }),
    }),
  )
}

export function fetchPresentation(
  base: string,
  token: string,
  requestId: string,
): Promise<ConsentPresentation> {
  return request<ConsentPresentation>(
    `${base}/api/consent/requests/${requestId}/presentation`,
    token,
  )
}
