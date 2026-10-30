// G1 synthetic wallet: all protocol calls stay on this application origin.
// JOSE owns JWS/JWE; Sovra pins the supported profile and consent boundaries.
import { CompactEncrypt, SignJWT, base64url, calculateJwkThumbprint, createLocalJWKSet, importJWK, jwtVerify } from 'jose'
import type { JWK, JSONWebKeySet, JWTPayload } from 'jose'
import type { HolderKey } from './crypto'
import type { ConsentReview } from './consent'
import type { VerificationDecision } from './verification'

const CONFIGURATION = 'sovra-adult-status-1'
const VCT = 'https://sovra.example/vct/adult-status/1'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export interface WalletCredential { id: string; artifact: string; holder: string }
export interface WalletRequest { id: string; audience: string; nonce: string; encryptionKey: JWK }

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, credentials: 'omit' })
  if (!response.ok) throw new Error(`Wallet request refused (${response.status}).`)
  return response.json() as Promise<T>
}
function publicJwk(holder: HolderKey): JWK {
  return { kty: 'EC', crv: 'P-256', x: holder.jwk.x, y: holder.jwk.y }
}
function requireText(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error('Incomplete protocol response.')
  return value
}

export interface AuthorizationRequest { verifier: string; challenge: string }

/** Browser-owned PKCE pair: the verifier never leaves wallet memory except to the token endpoint. */
export async function newAuthorizationRequest(): Promise<AuthorizationRequest> {
  const raw = new Uint8Array(32)
  crypto.getRandomValues(raw)
  const verifier = base64url.encode(raw)
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: base64url.encode(new Uint8Array(digest)) }
}

export async function receiveCredential(holder: HolderKey, code: string): Promise<WalletCredential> {
  const token = await redeemToken(new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }))
  return issueWithToken(holder, token)
}

export async function receiveCredentialWithCode(holder: HolderKey, code: string, verifier: string): Promise<WalletCredential> {
  const token = await redeemToken(new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier }))
  return issueWithToken(holder, token)
}

async function redeemToken(form: URLSearchParams): Promise<{ access_token: string; c_nonce: string }> {
  return json<{ access_token: string; c_nonce: string }>('/api/vci/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  })
}

async function issueWithToken(holder: HolderKey, token: { access_token: string; c_nonce: string }): Promise<WalletCredential> {
  const metadata = await json<{ credential_issuer: string }>('/.well-known/openid-credential-issuer')
  const proof = await new SignJWT({ aud: requireText(metadata.credential_issuer), nonce: requireText(token.c_nonce) })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk(holder) })
    .setIssuedAt().sign(holder.privateKey)
  const issued = await json<{ credentials: Array<{ credential: string }> }>('/api/vci/credential', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${requireText(token.access_token)}` },
    body: JSON.stringify({ format: 'dc+sd-jwt', credential_configuration_id: CONFIGURATION, proof: { proof_type: 'jwt', jwt: proof } }),
  })
  if (issued.credentials?.length !== 1) throw new Error('Expected one credential.')
  const artifact = requireText(issued.credentials[0]?.credential)
  const issuerKeys = await json<JSONWebKeySet>('/api/issuance/jwks.json')
  const { payload } = await jwtVerify(artifact.split('~')[0], createLocalJWKSet(issuerKeys), {
    algorithms: ['ES256'], typ: 'dc+sd-jwt', issuer: metadata.credential_issuer,
    requiredClaims: ['exp', 'iat', 'jti', 'cnf', 'vct'],
  })
  const cnf = payload.cnf as { jwk?: JWK } | undefined
  if (payload.vct !== VCT || !cnf?.jwk || await calculateJwkThumbprint(cnf.jwk) !== holder.thumbprint) {
    throw new Error('Credential does not match this holder or profile.')
  }
  const id = requireText(payload.jti)
  if (!UUID.test(id)) throw new Error('Credential identifier is malformed.')
  // Full SD-JWT disclosure/eligibility validation remains server-enforced.
  return { id, artifact, holder: holder.thumbprint }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const object = value as Record<string, unknown>
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}
const QUERY = { credentials: [{ id: 'sovra-adult-status', format: 'dc+sd-jwt', meta: { vct_values: [VCT] },
  claims: [{ id: 'adult-flag', path: ['claims', 'adultOver18'], values: [true] }] }] }

export async function reviewWalletRequest(id: string, consent: ConsentReview): Promise<WalletRequest> {
  if (!UUID.test(id)) throw new Error('Enter a valid presentation session identifier.')
  const response = await fetch(`/api/vp/requests/${id}/object`, { credentials: 'omit' })
  if (!response.ok) throw new Error('Presentation request unavailable.')
  const keys = await json<JSONWebKeySet>('/api/vp/jwks.json')
  const { payload } = await jwtVerify(await response.text(), createLocalJWKSet(keys), {
    algorithms: ['ES256'], typ: 'JWT', issuer: consent.audience, maxTokenAge: '5m',
    requiredClaims: ['exp', 'iat', 'nonce', 'state', 'client_id'],
  })
  validateRequest(payload, id, consent)
  const encryptionKey = keys.keys.find((key) => key.kid === 'sovra-vp-synth-1' && key.kty === 'EC' && key.crv === 'P-256')
  if (!encryptionKey) throw new Error('Verifier encryption key unavailable.')
  return { id, audience: consent.audience, nonce: requireText(payload.nonce), encryptionKey }
}
function validateRequest(payload: JWTPayload, id: string, consent: ConsentReview): void {
  if (consent.state !== 'VERIFIED' || Date.parse(consent.expiresAt) <= Date.now()
    || canonical(consent.claims) !== canonical({ adultOver18: true })
    || payload.state !== id || payload.client_id !== consent.audience || payload.response_type !== 'vp_token'
    || payload.response_mode !== 'direct_post.jwt'
    || payload.response_uri !== `${window.location.origin}/api/vp/responses/${id}`
    || canonical(payload.dcql_query) !== canonical(QUERY)) {
    throw new Error('Presentation request differs from the supported consented profile.')
  }
  const metadata = payload.client_metadata as Record<string, unknown> | undefined
  if (metadata?.authorization_encrypted_response_alg !== 'ECDH-ES+A256KW'
    || metadata?.authorization_encrypted_response_enc !== 'A256GCM'
    || metadata?.jwks_uri !== `${window.location.origin}/api/vp/jwks.json`) {
    throw new Error('Verifier transport is outside the supported profile.')
  }
}

export async function encryptWalletPresentation(holder: HolderKey, credential: WalletCredential, request: WalletRequest): Promise<string> {
  if (holder.thumbprint !== credential.holder) throw new Error('Credential belongs to another holder.')
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(credential.artifact))
  const kb = await new SignJWT({ aud: request.audience, nonce: request.nonce, sd_hash: base64url.encode(new Uint8Array(digest)) })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).setIssuedAt().sign(holder.privateKey)
  const submission = { id: 'sovra-presentation', definition_id: 'sovra-adult-status', descriptor_map: [{
    id: 'adult-flag', format: 'dc+sd-jwt', path: '$', path_nested: { format: 'dc+sd-jwt', path: '$.vp_token' },
  }] }
  const body = { state: request.id, vp_token: `${credential.artifact}~${kb}`, presentation_submission: submission }
  const key = await importJWK(request.encryptionKey, 'ECDH-ES+A256KW')
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(body)))
    .setProtectedHeader({ alg: 'ECDH-ES+A256KW', enc: 'A256GCM', kid: request.encryptionKey.kid }).encrypt(key)
}
export function sendWalletPresentation(id: string, encrypted: string): Promise<VerificationDecision> {
  if (!UUID.test(id)) throw new Error('Invalid presentation session.')
  return json<VerificationDecision>(`/api/vp/responses/${id}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response: encrypted }),
  })
}
