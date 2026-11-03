// Sovra KYC demo server (synthetic only, zero dependencies).
//
// One tiny RP backend serving two mock verifier apps — NovaBank
// (neobank onboarding) and CornerCellar (age-gated shop). The server
// holds the sandbox RP tokens; browsers never see them. Holder keys
// stay in the page: the browser signs issuance/consent/binding
// messages with WebCrypto and the server forwards the signed bytes.
//
// Refuses to boot unless Sovra reports the synthetic profile.

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRateLimiter, originAllowed } from './limit.mjs'
import { parseEnvFile, resolveDemoConfig } from './config.mjs'
import {
  ISSUER_SYNTH1,
  OUTCOME,
  POLICY_LEGACY,
  POLICY_VERSION,
  VCT_ADULT,
  canonicalPlanHash,
  checkPlanShape,
  claimsForPlan,
  createInteropService,
  scopeAllows,
} from './interop.mjs'

const ROOT = dirname(fileURLToPath(import.meta.url))
const PUBLIC = join(ROOT, 'public')
const PORT = Number(process.env.PORT ?? 5174)
// PROD-006: coarse per-IP abuse protection (600 burst, 600/min
// sustained) and a hard upstream deadline. Not a production WAF —
// just enough that a stray loop cannot melt the sandbox.
const apiLimiter = createRateLimiter({ capacity: 600, refillPerSec: 10 })
const UPSTREAM_TIMEOUT_MS = 10_000

const APPS = {
  novabank: {
    rpId: 'https://novabank.demo.sovra.example/onboarding',
    audience: 'https://novabank.demo.sovra.example/onboarding/callback',
    purpose: 'synthetic age eligibility for demo bank onboarding',
  },
  cornercellar: {
    rpId: 'https://cornercellar.demo.sovra.example/shop',
    audience: 'https://cornercellar.demo.sovra.example/shop/callback',
    purpose: 'synthetic age check at checkout',
  },
}

// Secure config seam: process environment wins, demo/.env.local (ignored,
// mode 0600) supplies the rest, per-node token files apply ONLY when
// SOVRA_DEMO_TOKENS_DIR is explicitly set. No token is ever committed,
// printed, or sent to a browser. Names only are logged on boot.
function loadEnvFileOptional() {
  try {
    return parseEnvFile(readFileSync(join(ROOT, '.env.local'), 'utf-8'))
  } catch {
    return {}
  }
}

const ENV_FILE = loadEnvFileOptional()
function readTokenByName(name) {
  const dir = process.env.SOVRA_DEMO_TOKENS_DIR ?? ENV_FILE.SOVRA_DEMO_TOKENS_DIR ?? ''
  if (dir === '') return ''
  try {
    return readFileSync(join(dir, name), 'utf-8').trim()
  } catch {
    return ''
  }
}

const CONFIG = resolveDemoConfig({ env: process.env, envFile: ENV_FILE, readToken: readTokenByName })
if (CONFIG.mode === 'unconfigured') {
  throw new Error('demo config unconfigured: need legacy .env.local (run: pnpm --dir demo run setup) or explicit interop SOVRA_BASE + node tokens')
}

// Central ledger (node A) plus optional second issuer node (node B).
// Single-node default keeps the legacy :8080 behavior; the dual-issuer
// topology sets SOVRA_BASE=http://127.0.0.1:8280 and
// SOVRA_BASE_SYNTH2=http://127.0.0.1:8281 with explicit
// SOVRA_DEMO_TOKENS_DIR (or inline SOVRA_A/B_* tokens).
const SOVRA = CONFIG.sovraBase
const SOVRA_SYNTH2 = CONFIG.sovraSynth2
const LEGACY_AVAILABLE = CONFIG.legacy.configured
const INTEROP_AVAILABLE = CONFIG.nodeA.configured

const TOKENS = {
  SETUP_TOKEN: CONFIG.legacy.setupToken,
  NOVABANK_RP_TOKEN: CONFIG.legacy.novabankToken,
  CORNERCELLAR_RP_TOKEN: CONFIG.legacy.cornercellarToken,
}
const RP_TOKEN = { novabank: TOKENS.NOVABANK_RP_TOKEN, cornercellar: TOKENS.CORNERCELLAR_RP_TOKEN }

function isoPlus(hours) {
  return new Date(Date.now() + hours * 3600_000).toISOString().replace('.000Z', 'Z')
}

// Legacy RP paths below request the ACTUAL planner + deterministic
// guard for the known case and bind the RETURNED plan and its canonical
// hash (canonicalPlanHash, byte-identical to the old fixed planHash for
// legacy plans). No fixed plan template remains anywhere: planner
// failure is an honest 502, never a silent fallback.

async function sovra(method, path, token, body) {
  let res
  try {
    res = await fetch(SOVRA + path, {
      method,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(body?.idem ? { 'Idempotency-Key': body.idem } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify({ ...body, idem: undefined }),
    })
  } catch {
    // Timeout or connection failure: status 0 flows into the
    // callers' existing upstream-failure branches.
    return { status: 0, json: null }
  }
  const text = await res.text()
  let json = null
  try {
    json = text === '' ? null : JSON.parse(text)
  } catch {
    json = null
  }
  return { status: res.status, json }
}

// Per-node upstream adapter for the interop service: same deadline and
// idempotency shape as sovra(), but addressed per node so synth-2 flows
// reach node B with node B's own tokens.
async function interopCall(node, method, path, token, body) {
  let res
  try {
    res = await fetch(node.base + path, {
      method,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(body?.idem ? { 'Idempotency-Key': body.idem } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify({ ...body, idem: undefined }),
    })
  } catch {
    return { status: 0, json: null }
  }
  const text = await res.text()
  let json = null
  try {
    json = text === '' ? null : JSON.parse(text)
  } catch {
    json = null
  }
  return { status: res.status, json }
}

const interop = INTEROP_AVAILABLE ? createInteropService({
  nodes: {
    default: { base: SOVRA, rpToken: CONFIG.nodeA.rpToken, issuerToken: CONFIG.nodeA.issuerToken },
    synth2: { base: SOVRA_SYNTH2, rpToken: CONFIG.nodeB.rpToken, issuerToken: CONFIG.nodeB.issuerToken },
  },
  call: interopCall,
}) : null

function send(res, status, value, headers = {}) {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers })
  res.end(body)
}

function readBody(req, res) {
  return new Promise((resolve) => {
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 65536) {
        send(res, 413, { ok: false, error: 'body_too_large' })
        req.destroy()
      }
    })
    req.on('end', () => {
      try {
        resolve(raw === '' ? {} : JSON.parse(raw))
      } catch {
        send(res, 400, { ok: false, error: 'invalid_json' })
        resolve(null)
      }
    })
  })
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function publicJwk(value) {
  if (value === null || typeof value !== 'object') return null
  const { kty, crv, x, y } = value
  if (kty !== 'EC' || crv !== 'P-256' || typeof x !== 'string' || typeof y !== 'string') return null
  return { kty, crv, x, y }
}

function interopHttpForSetup(error) {
  if (error === 'issuance_failed' || error === 'issuance_uncertain') return 502
  if (error === 'tx_issuance_in_progress' || error === 'tx_issuance_conflict'
    || error === 'issuance_conflict' || error === 'tx_issuance_bound') return 409
  if (error === 'issuer_node_unconfigured' || error === 'tx_issuance_uncertain') return 503
  return 400
}

function interopHttpForRequest(error) {
  if (error === 'request_failed' || error === 'request_uncertain'
    || error === 'request_review_unavailable' || error === 'consent_echo_mismatch') return 502
  if (error === 'request_not_found') return 404
  if (error === 'issuer_node_unconfigured') return 503
  return 400
}

async function handleInterop(req, res, segments) {
  const action = segments[1]
  if (!INTEROP_AVAILABLE || !interop) {
    send(res, 503, { ok: false, error: 'interop_unconfigured' })
    return
  }

  if (req.method === 'GET' && action === 'status') {
    // Read-only capability probe: the service only GETs /api/plans/status
    // here and never POSTs /propose, so opening the page spends no
    // model call even with live armed.
    const caps = await interop.getStatus()
    send(res, 200, { ok: true, status: caps })
    return
  }

  if (req.method === 'POST' && action === 'plan') {
    const body = await readBody(req, res)
    if (body === null) return
    if (typeof body.case !== 'string') {
      send(res, 400, { ok: false, error: 'invalid_plan_body' })
      return
    }
    const result = await interop.postPlan(body.case)
    if (!result.ok) {
      const http = result.error === 'unknown_case' ? 400
        : result.error === 'planner_unavailable' ? 503 : 502
      send(res, http, { ok: false, ...result })
      return
    }
    send(res, 200, { ok: true, ...result })
    return
  }

  if (req.method === 'POST' && action === 'setup') {
    const body = await readBody(req, res)
    if (body === null) return
    const holderJwk = publicJwk(body.holderJwk)
    if (holderJwk === null || typeof body.holderProof !== 'string'
      || typeof body.idem !== 'string' || typeof body.tx !== 'string') {
      send(res, 400, { ok: false, error: 'invalid_setup_body' })
      return
    }
    const result = await interop.postSetup({
      tx: body.tx, holderJwk, holderProof: body.holderProof, idem: body.idem,
    })
    if (!result.ok) {
      send(res, interopHttpForSetup(result.error), { ok: false, ...result })
      return
    }
    send(res, 200, { ok: true, ...result })
    return
  }

  if (req.method === 'POST' && action === 'request') {
    const body = await readBody(req, res)
    if (body === null) return
    if (typeof body.tx !== 'string'
      || typeof body.credentialId !== 'string' || !UUID.test(body.credentialId)) {
      send(res, 400, { ok: false, error: 'invalid_request_body' })
      return
    }
    const result = await interop.postRequest({ tx: body.tx, credentialId: body.credentialId })
    if (!result.ok) {
      send(res, interopHttpForRequest(result.error), { ok: false, ...result })
      return
    }
    send(res, 200, { ok: true, ...result })
    return
  }

  if (req.method === 'POST' && action === 'decision') {
    const body = await readBody(req, res)
    if (body === null) return
    const holderJwk = publicJwk(body.holderJwk)
    if (
      typeof body.tx !== 'string'
      || typeof body.requestId !== 'string' || !UUID.test(body.requestId)
      || (body.decision !== 'approve' && body.decision !== 'deny')
      || holderJwk === null || typeof body.consentProof !== 'string'
    ) {
      send(res, 400, { ok: false, error: 'invalid_decision_body' })
      return
    }
    const result = await interop.postDecision({
      tx: body.tx, requestId: body.requestId, decision: body.decision,
      holderJwk, consentProof: body.consentProof,
    })
    if (!result.ok && result.error) {
      const http = result.error === 'issuer_node_unconfigured' ? 503 : 400
      send(res, http, { ok: false, ...result })
      return
    }
    send(res, 200, { ...result })
    return
  }

  if (req.method === 'POST' && action === 'verify') {
    const body = await readBody(req, res)
    if (body === null) return
    const holderJwk = publicJwk(body.holderJwk)
    if (
      typeof body.tx !== 'string'
      || typeof body.requestId !== 'string' || !UUID.test(body.requestId)
      || typeof body.nonce !== 'string' || holderJwk === null
      || typeof body.bindingProof !== 'string'
    ) {
      send(res, 400, { ok: false, error: 'invalid_verify_body' })
      return
    }
    const result = await interop.postVerify({
      tx: body.tx, requestId: body.requestId, nonce: body.nonce,
      holderJwk, bindingProof: body.bindingProof,
    })
    if (!result.ok && result.error) {
      const http = result.error === 'issuer_node_unconfigured' ? 503 : 400
      send(res, http, { ok: false, ...result })
      return
    }
    send(res, 200, { ...result })
    return
  }

  send(res, 404, { ok: false, error: 'unknown_interop_action' })
}

async function handleApi(req, res, segments) {
  const [app] = segments
  if (!(app in APPS)) {
    send(res, 404, { ok: false, error: 'unknown_demo_app' })
    return
  }
  if (!LEGACY_AVAILABLE) {
    send(res, 503, { ok: false, error: 'legacy_unconfigured' })
    return
  }
  const config = APPS[app]
  const rpToken = RP_TOKEN[app]
  const action = segments[1]

  if (req.method === 'POST' && action === 'setup') {
    // Mint a holder credential for a browser-generated key. The
    // browser signs the issuance proof; the server only forwards.
    const body = await readBody(req, res)
    if (body === null) return
    const holderJwk = publicJwk(body.holderJwk)
    if (holderJwk === null || typeof body.holderProof !== 'string' || typeof body.idem !== 'string') {
      send(res, 400, { ok: false, error: 'invalid_setup_body' })
      return
    }
    const issued = await sovra('POST', '/api/issuance/credentials', TOKENS.SETUP_TOKEN, {
      issuerId: ISSUER_SYNTH1,
      vct: VCT_ADULT,
      holderJwk,
      holderProof: body.holderProof,
      claims: { adultOver18: true },
      expiresAt: isoPlus(2),
      idem: body.idem,
    })
    if (issued.status !== 201) {
      send(res, 502, { ok: false, error: 'issuance_failed', status: issued.status })
      return
    }
    send(res, 200, { ok: true, credentialId: issued.json.credentialId })
    return
  }

  if (req.method === 'POST' && action === 'request') {
    const body = await readBody(req, res)
    if (body === null) return
    if (typeof body.credentialId !== 'string' || !UUID.test(body.credentialId)) {
      send(res, 400, { ok: false, error: 'invalid_credential_id' })
      return
    }
    // Honest planning for the known case: propose on the central
    // ledger (legacy-pinned scope once the backend supports it),
    // validate the RETURNED plan with the deterministic guard, and
    // bind the returned plan + canonical hash into consent. Any
    // planner/guard failure is an honest 502 — the old fixed plan is
    // gone and is never substituted back.
    const caps = INTEROP_AVAILABLE && interop ? await interop.getStatus() : null
    const legacyScope = caps?.primary?.scopeSupported === true
      ? { scopeIssuerIds: [ISSUER_SYNTH1], scopeCredentialTypes: [VCT_ADULT] }
      : {}
    const proposed = await sovra('POST', '/api/plans/propose', rpToken, {
      rpId: config.rpId,
      audience: config.audience,
      purpose: config.purpose,
      outcome: OUTCOME,
      policyId: POLICY_LEGACY,
      policyVersion: POLICY_VERSION,
      requestedClaims: ['adultOver18'],
      ...legacyScope,
    })
    if (proposed.status === 503 || proposed.status === 0) {
      send(res, 502, { ok: false, error: 'planner_unavailable', status: proposed.status })
      return
    }
    if (proposed.status !== 200 || !proposed.json) {
      send(res, 502, { ok: false, error: 'proposal_failed', status: proposed.status })
      return
    }
    const returned = proposed.json.plan ?? null
    if (returned === null || proposed.json.recommendation !== 'CANDIDATE_ONLY') {
      send(res, 502, { ok: false, error: 'no_plan_path' })
      return
    }
    let plan
    try {
      plan = checkPlanShape(returned)
    } catch {
      send(res, 502, { ok: false, error: 'proposal_malformed' })
      return
    }
    if (legacyScope.scopeIssuerIds !== undefined && !scopeAllows(legacyScope, plan)) {
      send(res, 502, { ok: false, error: 'no_plan_path' })
      return
    }
    if (plan.policy_id !== POLICY_LEGACY || plan.policy_version !== POLICY_VERSION) {
      send(res, 502, { ok: false, error: 'proposal_policy_mismatch' })
      return
    }
    const guarded = await sovra('POST', '/api/guard/validate', rpToken, {
      plan, policyId: POLICY_LEGACY, policyVersion: POLICY_VERSION,
    })
    if (guarded.status !== 200 || !guarded.json) {
      send(res, 502, { ok: false, error: 'guard_unavailable', status: guarded.status })
      return
    }
    if (!guarded.json.accepted) {
      send(res, 502, { ok: false, error: 'guard_rejected', code: guarded.json.code ?? null })
      return
    }
    let planHashValue
    let planClaims
    try {
      planHashValue = canonicalPlanHash(plan)
      planClaims = claimsForPlan(plan)
    } catch {
      send(res, 502, { ok: false, error: 'proposal_unusable' })
      return
    }
    const challenge = randomBytes(24).toString('base64url')
    const created = await sovra('POST', '/api/consent/requests', rpToken, {
      rpId: config.rpId,
      audience: config.audience,
      purpose: config.purpose,
      credentialId: body.credentialId,
      claims: planClaims,
      plan,
      policyId: POLICY_LEGACY,
      policyVersion: POLICY_VERSION,
      planHash: planHashValue,
      challenge,
      expiresAt: isoPlus(1),
    })
    if (created.status !== 201) {
      send(res, 502, { ok: false, error: 'request_failed', status: created.status })
      return
    }
    const requestId = created.json.requestId
    const review = await sovra('GET', `/api/consent/requests/${requestId}`, rpToken)
    send(res, 200, { ok: true, requestId, review: review.json })
    return
  }

  if (req.method === 'POST' && action === 'decision') {
    const body = await readBody(req, res)
    if (body === null) return
    const holderJwk = publicJwk(body.holderJwk)
    if (
      typeof body.requestId !== 'string' || !UUID.test(body.requestId)
      || (body.decision !== 'approve' && body.decision !== 'deny')
      || holderJwk === null || typeof body.consentProof !== 'string'
    ) {
      send(res, 400, { ok: false, error: 'invalid_decision_body' })
      return
    }
    const decided = await sovra(
      'POST', `/api/consent/requests/${body.requestId}/decision`, rpToken,
      { decision: body.decision, holderJwk, consentProof: body.consentProof },
    )
    send(res, 200, { ok: decided.status === 200, status: decided.status, state: decided.json })
    return
  }

  if (req.method === 'POST' && action === 'verify') {
    const body = await readBody(req, res)
    if (body === null) return
    const holderJwk = publicJwk(body.holderJwk)
    if (
      typeof body.requestId !== 'string' || !UUID.test(body.requestId)
      || typeof body.nonce !== 'string' || holderJwk === null
      || typeof body.bindingProof !== 'string'
    ) {
      send(res, 400, { ok: false, error: 'invalid_verify_body' })
      return
    }
    // The audience is the app's own constant, never client input.
    const submitted = await sovra('POST', '/api/verification/presentations', rpToken, {
      requestId: body.requestId,
      nonce: body.nonce,
      audience: config.audience,
      holderJwk,
      bindingProof: body.bindingProof,
    })
    send(res, 200, { ok: submitted.status === 200, status: submitted.status, decision: submitted.json })
    return
  }

  if (req.method === 'GET' && action === 'decision' && segments.length === 3) {
    const id = segments[2]
    if (!UUID.test(id)) {
      send(res, 400, { ok: false, error: 'invalid_decision_id' })
      return
    }
    const found = await sovra('GET', `/api/verification/decisions/${id}`, rpToken)
    send(res, 200, { ok: found.status === 200, status: found.status, decision: found.json })
    return
  }

  if (req.method === 'GET' && action === 'outcomes') {
    const url = new URL(req.url, 'http://demo')
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get('limit')) || 20))
    const outcomes = await sovra('GET', `/api/rp/outcomes?limit=${limit}`, rpToken)
    send(res, 200, { ok: true, outcomes: outcomes.json })
    return
  }

  if (req.method === 'GET' && action === 'metrics') {
    const metrics = await sovra('GET', '/api/rp/metrics', rpToken)
    send(res, 200, { ok: true, metrics: metrics.json })
    return
  }

  send(res, 404, { ok: false, error: 'unknown_demo_action' })
}

const STATIC = {
  '/': 'index.html',
  '/novabank': 'novabank.html',
  '/cornercellar': 'cornercellar.html',
  '/interoperability': 'interoperability.html',
  '/shared.js': null,
  '/style.css': null,
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' }

function extOf(path) {
  const dot = path.lastIndexOf('.')
  return dot === -1 ? '' : path.slice(dot)
}

createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://demo')
    if (url.pathname === '/api/discovery' && req.method === 'GET') {
      let upstream
      try {
        upstream = await fetch(`${SOVRA}/api/discovery`, {
          signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
        })
      } catch {
        send(res, 502, { ok: false, error: 'upstream_unavailable' })
        return
      }
      send(res, 200, { ok: true, discovery: await upstream.json() })
      return
    }
    if (url.pathname.startsWith('/api/')) {
      // PROD-006: cheap rejects first — origin, then quota — before
      // any body is read or token spent.
      if (req.method === 'POST' && !originAllowed(req.headers.origin)) {
        send(res, 403, { ok: false, error: 'forbidden_origin' })
        return
      }
      const quota = apiLimiter.allow(req.socket.remoteAddress ?? 'unknown')
      if (!quota.allowed) {
        send(res, 429, { ok: false, error: 'rate_limited' }, { 'Retry-After': String(quota.retryAfterSec) })
        return
      }
      const segments = url.pathname.slice('/api/'.length).split('/')
      if (segments[0] === 'interop') {
        await handleInterop(req, res, segments)
        return
      }
      await handleApi(req, res, segments)
      return
    }
    const file = STATIC[url.pathname]
    if (req.method === 'GET' && file !== undefined) {
      const name = file ?? url.pathname.slice(1)
      res.writeHead(200, { 'Content-Type': TYPES[extOf(name)] })
      res.end(readFileSync(join(PUBLIC, name)))
      return
    }
    send(res, 404, { ok: false, error: 'not_found' })
  } catch (err) {
    console.error('demo request failed:', err instanceof Error ? err.message : err)
    if (!res.headersSent) send(res, 500, { ok: false, error: 'demo_error' })
  }
}).listen(PORT, async () => {
  const upstream = await fetch(`${SOVRA}/api/discovery`).then((r) => r.json()).catch(() => null)
  if (upstream?.profile !== 'synthetic') {
    console.error(`refusing to boot: ${SOVRA} does not report the synthetic profile`)
    process.exit(1)
  }
  if (SOVRA_SYNTH2 !== SOVRA && CONFIG.nodeB.configured) {
    const upstream2 = await fetch(`${SOVRA_SYNTH2}/api/discovery`).then((r) => r.json()).catch(() => null)
    if (upstream2?.profile !== 'synthetic') {
      console.error(`refusing to boot: ${SOVRA_SYNTH2} does not report the synthetic profile`)
      process.exit(1)
    }
  }
  const second = SOVRA_SYNTH2 === SOVRA ? 'single-node'
    : CONFIG.nodeB.configured ? `+ synth2 ${SOVRA_SYNTH2}` : `+ synth2 ${SOVRA_SYNTH2} (unconfigured)`
  const mode = `mode=${CONFIG.mode}`
  console.log(`demo up on http://localhost:${PORT} (novabank, cornercellar, interoperability) → ${SOVRA} [${upstream.profile}] ${second} ${mode}`)
})
