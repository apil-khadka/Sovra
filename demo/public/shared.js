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

export function issuanceMessage(idem, holderThumbprint, vct = VCT, claimsCanonical = 'adultOver18=true') {
  return ['sovra-issuance-proof/v1', idem, vct, holderThumbprint, claimsCanonical].join('\n')
}

export function consentMessage(review, decision, holderThumbprint, claimsCanonical = 'adultOver18=true') {
  return [
    'sovra-consent/v1',
    review.requestId,
    decision,
    review.rpId,
    review.audience,
    review.purpose,
    claimsCanonical,
    review.planHash,
    review.challenge,
    review.expiresAt,
    holderThumbprint,
  ].join('\n')
}

/**
 * Credential type named by a RETURNED plan. Fails closed on anything
 * but the exact guarded wire shape — the caller must never substitute
 * a fixed type.
 */
export function plannedVct(plan) {
  if (plan === null || typeof plan !== 'object' || typeof plan.credential_type !== 'string') {
    throw new DemoError('plan_type_missing', { stage: 'plan' })
  }
  return plan.credential_type
}

/**
 * Sorted key=value canonical form from a RETURNED plan's exact
 * claim_paths. G1 carries one boolean claim asserted true; any other
 * shape fails closed here rather than guessing wire values.
 */
export function plannedClaimsCanonical(plan) {
  if (plan === null || typeof plan !== 'object'
    || !Array.isArray(plan.claim_paths) || plan.claim_paths.length !== 1
    || typeof plan.claim_paths[0] !== 'string' || plan.claim_paths[0] === '') {
    throw new DemoError('plan_claims_not_minimal', { stage: 'plan' })
  }
  return `${plan.claim_paths[0]}=true`
}

export function bindingMessage(requestId, nonce, audience, holderThumbprint) {
  return ['sovra-presentation/v1', requestId, nonce, audience, holderThumbprint].join('\n')
}

export class DemoError extends Error {
  constructor(message, details = {}) {
    super(message)
    this.name = 'DemoError'
    this.stage = details.stage ?? null
    this.decision = details.decision ?? null
    this.requestId = details.requestId ?? null
  }
}

/** Rejection when a run is cancelled before its decision commits. */
export class RunCancelledError extends Error {
  constructor(message = 'run_cancelled') {
    super(message)
    this.name = 'RunCancelledError'
    this.code = 'RUN_CANCELLED'
  }
}

export function isRunCancelled(err) {
  return err instanceof RunCancelledError
    || err?.code === 'RUN_CANCELLED'
    || err?.name === 'AbortError'
}

/**
 * Single-flight generation owner for demo pages (DOM-free, so the
 * Node regression test exercises the same code the pages use).
 * begin() refuses overlaps — it returns null while a run is active,
 * so double-clicks cannot start two runs. cancelActive() aborts the
 * active run and retires its generation, so every late callback from
 * the cancelled run fails isCurrent() and cannot overwrite UI owned
 * by a restarted run.
 */
export function createRunOwner() {
  let seq = 0
  let activeId = 0
  let controller = null
  return {
    begin() {
      if (controller) return null
      const id = ++seq
      activeId = id
      controller = new AbortController()
      const signal = controller.signal
      return {
        id,
        signal,
        isCurrent: () => activeId === id,
        finish: () => {
          if (activeId === id) {
            activeId = 0
            controller = null
          }
        },
      }
    },
    cancelActive() {
      if (!controller) return false
      const stopped = controller
      activeId = 0
      controller = null
      stopped.abort()
      return true
    },
    get active() {
      return controller !== null
    },
  }
}

async function call(path, body, { signal, stage } = {}) {
  let res
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      ...(signal ? { signal } : {}),
    })
  } catch (err) {
    if (signal?.aborted || err?.name === 'AbortError') throw new RunCancelledError()
    throw new DemoError(err?.message ?? 'demo backend unreachable', { stage })
  }
  let data
  try {
    data = await res.json()
  } catch {
    throw new DemoError(`demo backend responded ${res.status}`, { stage })
  }
  if (!res.ok || data.ok === false) {
    throw new DemoError(data.error ?? `demo backend responded ${res.status}`, { stage })
  }
  return data
}

function throwIfCancelled(signal) {
  if (signal?.aborted) throw new RunCancelledError()
}

/** Race the user decision against cancellation; abort wins, sending nothing. */
function awaitDecision(decide, args, signal) {
  if (!signal || signal.aborted) {
    if (signal?.aborted) return Promise.reject(new RunCancelledError())
    return decide(args)
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new RunCancelledError())
    signal.addEventListener('abort', onAbort, { once: true })
    Promise.resolve().then(() => decide(args)).then(
      (d) => { signal.removeEventListener('abort', onAbort); resolve(d) },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e) },
    )
  })
}

/**
 * Full check for one app: key → credential → request → signed
 * decision → signed verification. onStep reports progress labels
 * for the page; decide picks approve/deny after showing review.
 * signal aborts pre-commit work (setup/request/decision wait) with
 * RunCancelledError and sends no /decision. Once the user has
 * approved or declined, /decision and /verify are detached from the
 * signal: stopping local follow-up cannot retract committed consent,
 * so the flow runs to its honest outcome instead.
 */
export async function runCheck(app, { onStep = () => {}, decide = async () => 'approve', signal } = {}) {
  throwIfCancelled(signal)
  onStep('Preparing your check…')
  const holder = await generateHolder()
  throwIfCancelled(signal)
  const idem = `demo-${randomHex()}`
  const holderProof = await signMessage(holder, issuanceMessage(idem, holder.thumbprint))

  onStep('Requesting your proof…')
  const { credentialId } = await call(
    `/api/${app}/setup`,
    { holderJwk: holder.jwk, holderProof, idem },
    { signal, stage: 'setup' },
  )

  onStep('Opening your decision…')
  const { requestId, review } = await call(
    `/api/${app}/request`, { credentialId }, { signal, stage: 'request' },
  )

  const decision = await awaitDecision(decide, { holder, credentialId, requestId, review }, signal)
  // 'back' is a local abort: no /decision call, nothing recorded.
  // Any request artefact already created expires unused within the hour.
  if (decision === 'back') {
    return { holder, credentialId, requestId, review, decision: null, denied: false, backedOut: true }
  }
  if (decision !== 'approve' && decision !== 'deny') {
    throw new DemoError('invalid_decision', { stage: 'decide', requestId })
  }
  // Cancellation noticed after the user decided but before anything
  // is signed still sends nothing: the commit point is below.
  throwIfCancelled(signal)

  onStep(decision === 'approve' ? 'Recording your approval…' : 'Recording your decline…')
  const consentProof = await signMessage(holder, consentMessage(review, decision, holder.thumbprint))
  let decided
  try {
    decided = await call(`/api/${app}/decision`, {
      requestId, decision, holderJwk: holder.jwk, consentProof,
    }, { stage: 'decision' })
  } catch (err) {
    if (err instanceof DemoError) {
      err.decision = decision
      err.requestId = requestId
    }
    throw err
  }
  if (decision === 'deny' || decided.state?.state === 'DENIED') {
    return { holder, credentialId, requestId, review, decision: null, denied: true }
  }

  onStep('Confirming with Sovra…')
  const nonce = randomNonce()
  const bindingProof = await signMessage(
    holder, bindingMessage(requestId, nonce, review.audience, holder.thumbprint),
  )
  let verified
  try {
    verified = await call(`/api/${app}/verify`, {
      requestId, nonce, holderJwk: holder.jwk, bindingProof,
    }, { stage: 'verify' })
  } catch (err) {
    if (err instanceof DemoError) {
      err.decision = decision
      err.requestId = requestId
    }
    throw err
  }
  return { holder, credentialId, requestId, review, decision: verified.decision, denied: false }
}

/**
 * Full planned check for one interop case: plan → key → credential →
 * request → signed decision → signed verification. Same pre-commit
 * abort, detached-commit, and generation-owner semantics as runCheck:
 * signal aborts pre-commit work with RunCancelledError and sends no
 * /decision, while committed /decision + /verify run detached to
 * their honest outcome. Every issuance/consent input derives from the
 * RETURNED guarded plan (vct + claims); nothing is fixed. Refusals
 * (NO_PATH) and backend-pending unavailability return structured
 * outcomes — never a fabricated credential.
 */
export async function runPlannedCheck(caseId, { onStep = () => {}, decide = async () => 'approve', signal } = {}) {
  throwIfCancelled(signal)
  onStep('Asking Sovra to plan…')
  const planned = await call('/api/interop/plan', { case: caseId }, { signal, stage: 'plan' })
  if (planned.available === false) {
    return {
      unavailable: true, refusal: false, reason: planned.reason ?? 'backend_pending',
      caps: planned.caps ?? null, caseId,
    }
  }
  if (planned.refusal === true) {
    return {
      unavailable: false, refusal: true, meta: planned.meta ?? null, plan: planned.plan ?? null,
      guard: planned.guard ?? null, echo: planned.echo ?? null, caps: planned.caps ?? null, caseId,
    }
  }
  if (!planned.tx || planned.plan === null || typeof planned.plan !== 'object') {
    throw new DemoError('plan_unusable', { stage: 'plan' })
  }
  const { tx, plan, meta, guard } = planned
  const vct = plannedVct(plan)
  const claimsCanonical = plannedClaimsCanonical(plan)

  onStep('Preparing your check…')
  const holder = await generateHolder()
  throwIfCancelled(signal)
  const idem = `demo-${randomHex()}`
  const holderProof = await signMessage(holder, issuanceMessage(idem, holder.thumbprint, vct, claimsCanonical))

  onStep('Requesting your proof…')
  const { credentialId } = await call(
    '/api/interop/setup',
    { tx, holderJwk: holder.jwk, holderProof, idem },
    { signal, stage: 'setup' },
  )

  onStep('Opening your decision…')
  const { requestId, review } = await call(
    '/api/interop/request', { tx, credentialId }, { signal, stage: 'request' },
  )

  const decision = await awaitDecision(decide, {
    holder, credentialId, requestId, review, plan, meta, guard, tx, caseId,
  }, signal)
  if (decision === 'back') {
    return {
      holder, credentialId, requestId, review, plan, meta, guard, tx, caseId,
      decision: null, denied: false, backedOut: true,
    }
  }
  if (decision !== 'approve' && decision !== 'deny') {
    throw new DemoError('invalid_decision', { stage: 'decide', requestId })
  }
  throwIfCancelled(signal)

  onStep(decision === 'approve' ? 'Recording your approval…' : 'Recording your decline…')
  const consentProof = await signMessage(
    holder, consentMessage(review, decision, holder.thumbprint, claimsCanonical),
  )
  let decided
  try {
    decided = await call('/api/interop/decision', {
      tx, requestId, decision, holderJwk: holder.jwk, consentProof,
    }, { stage: 'decision' })
  } catch (err) {
    if (err instanceof DemoError) {
      err.decision = decision
      err.requestId = requestId
    }
    throw err
  }
  if (decision === 'deny' || decided.state?.state === 'DENIED') {
    return {
      holder, credentialId, requestId, review, plan, meta, guard, tx, caseId,
      decision: null, denied: true,
    }
  }

  onStep('Confirming with Sovra…')
  const nonce = randomNonce()
  const bindingProof = await signMessage(
    holder, bindingMessage(requestId, nonce, review.audience, holder.thumbprint),
  )
  let verified
  try {
    verified = await call('/api/interop/verify', {
      tx, requestId, nonce, holderJwk: holder.jwk, bindingProof,
    }, { stage: 'verify' })
  } catch (err) {
    if (err instanceof DemoError) {
      err.decision = decision
      err.requestId = requestId
    }
    throw err
  }
  return {
    holder, credentialId, requestId, review, plan, meta, guard, tx, caseId,
    decision: verified.decision, denied: false,
  }
}

export async function fetchInteropStatus() {
  const res = await fetch('/api/interop/status').then((r) => r.json())
  return res.status
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
