// Sovra KYC demo server (synthetic only, zero dependencies).
//
// One tiny RP backend serving two mock verifier apps — NovaBank
// (neobank onboarding) and CornerCellar (age-gated shop). The server
// holds the sandbox RP tokens; browsers never see them. Holder keys
// stay in the page: the browser signs issuance/consent/binding
// messages with WebCrypto and the server forwards the signed bytes.
//
// Refuses to boot unless Sovra reports the synthetic profile.

import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRateLimiter, originAllowed } from './limit.mjs'

const ROOT = dirname(fileURLToPath(import.meta.url))
const PUBLIC = join(ROOT, 'public')
const SOVRA = process.env.SOVRA_BASE ?? 'http://localhost:8080'
const PORT = Number(process.env.PORT ?? 5174)
// PROD-006: coarse per-IP abuse protection (600 burst, 600/min
// sustained) and a hard upstream deadline. Not a production WAF —
// just enough that a stray loop cannot melt the sandbox.
const apiLimiter = createRateLimiter({ capacity: 600, refillPerSec: 10 })
const UPSTREAM_TIMEOUT_MS = 10_000

const ISSUER_ID = 'https://sovra.example/issuers/synth-1'
const VCT = 'https://sovra.example/vct/adult-status/1'
const POLICY_ID = 'sovra-synthetic-policy/age-check'
const POLICY_VERSION = '1'
const SECTION_ID = 'age_eligibility'

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

function loadEnv() {
  const tokens = {}
  for (const line of readFileSync(join(ROOT, '.env.local'), 'utf-8').split('\n')) {
    const match = line.match(/^([A-Z_]+)=(.*)$/)
    if (match !== null) tokens[match[1]] = match[2].trim()
  }
  const required = ['SETUP_TOKEN', 'NOVABANK_RP_TOKEN', 'CORNERCELLAR_RP_TOKEN']
  for (const key of required) {
    if (!tokens[key]) throw new Error(`demo/.env.local lacks ${key} (run: pnpm --dir demo run setup)`)
  }
  return tokens
}

const TOKENS = loadEnv()
const RP_TOKEN = { novabank: TOKENS.NOVABANK_RP_TOKEN, cornercellar: TOKENS.CORNERCELLAR_RP_TOKEN }

function isoPlus(hours) {
  return new Date(Date.now() + hours * 3600_000).toISOString().replace('.000Z', 'Z')
}

function planHash(planId) {
  const canonical = [
    'sovra-plan/v1',
    planId,
    'age_over_18',
    ISSUER_ID,
    VCT,
    'adultOver18',
    `${POLICY_ID}#${SECTION_ID}`,
    POLICY_ID,
    POLICY_VERSION,
    'CANDIDATE_ONLY',
    '',
  ].join('\n')
  return createHash('sha256').update(canonical, 'utf-8').digest('hex')
}

function planWire(planId) {
  return {
    plan_id: planId,
    requested_outcome: 'age_over_18',
    candidate_issuer_id: ISSUER_ID,
    credential_type: VCT,
    claim_paths: ['adultOver18'],
    evidence: [{ document_id: POLICY_ID, section_id: SECTION_ID }],
    policy_id: POLICY_ID,
    policy_version: POLICY_VERSION,
    recommendation: 'CANDIDATE_ONLY',
  }
}

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

async function handleApi(req, res, segments) {
  const [app] = segments
  if (!(app in APPS)) {
    send(res, 404, { ok: false, error: 'unknown_demo_app' })
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
      issuerId: ISSUER_ID,
      vct: VCT,
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
    const planId = `pln_demo_${randomBytes(6).toString('hex')}`
    const challenge = randomBytes(24).toString('base64url')
    const created = await sovra('POST', '/api/consent/requests', rpToken, {
      rpId: config.rpId,
      audience: config.audience,
      purpose: config.purpose,
      credentialId: body.credentialId,
      claims: { adultOver18: true },
      plan: planWire(planId),
      policyId: POLICY_ID,
      policyVersion: POLICY_VERSION,
      planHash: planHash(planId),
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
      await handleApi(req, res, url.pathname.slice('/api/'.length).split('/'))
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
  console.log(`demo up on http://localhost:${PORT} (novabank, cornercellar) → ${SOVRA} [${upstream.profile}]`)
})
