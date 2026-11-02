// Shared demo engine (isomorphic: runs in browsers and in Node 22
// smoke tests — no DOM here). Holder keys live in page memory;
// every signature is ES256/P-256 over Sovra's canonical messages.

const VCT = 'https://sovra.example/vct/adult-status/1'

function b64u(bytes) {
  const raw = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (const byte of raw) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function b64uText(text) {
  return b64u(new TextEncoder().encode(text))
}

/** RFC 7638 SHA-256 thumbprint over {"crv","kty","x","y"}. */
export async function thumbprint(jwk) {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return b64u(digest)
}

/** Fresh extractable P-256 holder key. */
export async function generateHolder() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
  return { privateKey: pair.privateKey, jwk: pub, thumbprint: await thumbprint(pub) }
}

/** Compact ES256 JWS over a canonical message. */
export async function signMessage(holder, message) {
  const header = b64uText('{"alg":"ES256"}')
  const payload = b64uText(message)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    holder.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  const raw = new Uint8Array(signature)
  if (raw.length !== 64) throw new Error('unexpected signature size')
  return `${header}.${payload}.${b64u(raw)}`
}

export function randomHex(bytes = 16) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function randomNonce() {
  return b64u(crypto.getRandomValues(new Uint8Array(24)))
}

export function issuanceMessage(idem, holderThumbprint) {
  return ['sovra-issuance-proof/v1', idem, VCT, holderThumbprint, 'adultOver18=true'].join('\n')
}

export function consentMessage(review, decision, holderThumbprint) {
  return [
    'sovra-consent/v1',
    review.requestId,
    decision,
    review.rpId,
    review.audience,
    review.purpose,
    'adultOver18=true',
    review.planHash,
    review.challenge,
    review.expiresAt,
    holderThumbprint,
  ].join('\n')
}

export function bindingMessage(requestId, nonce, audience, holderThumbprint) {
  return ['sovra-presentation/v1', requestId, nonce, audience, holderThumbprint].join('\n')
}

export class DemoError extends Error {
  constructor(message) {
    super(message)
  }
}

async function call(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok || data.ok === false) {
    throw new DemoError(data.error ?? `demo backend responded ${res.status}`)
  }
  return data
}

/**
 * Full check for one app: key → credential → request → signed
 * decision → signed verification. onStep reports progress labels
 * for the page; decide picks approve/deny after showing review.
 */
export async function runCheck(app, { onStep = () => {}, decide = async () => 'approve' } = {}) {
  onStep('Preparing your check…')
  const holder = await generateHolder()
  const idem = `demo-${randomHex()}`
  const holderProof = await signMessage(holder, issuanceMessage(idem, holder.thumbprint))

  onStep('Requesting your proof…')
  const { credentialId } = await call(`/api/${app}/setup`, { holderJwk: holder.jwk, holderProof, idem })

  onStep('Opening your decision…')
  const { requestId, review } = await call(`/api/${app}/request`, { credentialId })

  const decision = await decide({ holder, credentialId, requestId, review })
  // 'back' is a local abort: no /decision call, nothing recorded.
  // Any request artefact already created expires unused within the hour.
  if (decision === 'back') {
    return { holder, credentialId, requestId, review, decision: null, denied: false, backedOut: true }
  }
  if (decision !== 'approve' && decision !== 'deny') throw new DemoError('invalid_decision')

  onStep(decision === 'approve' ? 'Recording your approval…' : 'Recording your decline…')
  const consentProof = await signMessage(holder, consentMessage(review, decision, holder.thumbprint))
  const decided = await call(`/api/${app}/decision`, {
    requestId, decision, holderJwk: holder.jwk, consentProof,
  })
  if (decision === 'deny' || decided.state?.state === 'DENIED') {
    return { holder, credentialId, requestId, review, decision: null, denied: true }
  }

  onStep('Confirming with Sovra…')
  const nonce = randomNonce()
  const bindingProof = await signMessage(
    holder, bindingMessage(requestId, nonce, review.audience, holder.thumbprint),
  )
  const verified = await call(`/api/${app}/verify`, {
    requestId, nonce, holderJwk: holder.jwk, bindingProof,
  })
  return { holder, credentialId, requestId, review, decision: verified.decision, denied: false }
}

export async function fetchOps(app) {
  const [outcomes, metrics] = await Promise.all([
    fetch(`/api/${app}/outcomes?limit=5`).then((r) => r.json()),
    fetch(`/api/${app}/metrics`).then((r) => r.json()),
  ])
  return { outcomes: outcomes.outcomes ?? [], metrics: metrics.metrics ?? null }
}

export async function fetchDiscovery() {
  const res = await fetch('/api/discovery').then((r) => r.json())
  return res.discovery
}
