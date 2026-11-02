// Minimal Sovra relying party — COPY THIS.
//
// The smallest honest RP: one page, one server, zero dependencies.
// Your server holds the RP token; the browser holds the holder key
// and signs; Sovra verifies. The NovaBank/CornerCellar demos are
// this file plus a shop/bank fiction.
//
// Run: MINIMAL_RP_TOKEN=… SETUP_TOKEN=… node server.mjs (or reuse
// demo/.env.local via `pnpm --dir demo run setup`, which also mints
// sandbox-minimal). Needs the synthetic Sovra stack on :8080.

import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRateLimiter, originAllowed } from '../limit.mjs'

const ROOT = dirname(fileURLToPath(import.meta.url))
const SOVRA = process.env.SOVRA_BASE ?? 'http://localhost:8080'
const PORT = Number(process.env.PORT ?? 5175)
// PROD-006, template edition: the same origin/quota/body/timeout
// controls as the showcase server, kept inline so the file stays a
// readable starting point.
const apiLimiter = createRateLimiter({ capacity: 600, refillPerSec: 10 })
const UPSTREAM_TIMEOUT_MS = 10_000
const MAX_BODY_BYTES = 65536

// 1. Load tokens: prefer env, fall back to the shared demo env file.
const envFile = (() => {
  try {
    return readFileSync(join(ROOT, '..', '.env.local'), 'utf-8')
  } catch {
    return ''
  }
})()
const fromFile = (key) => envFile.match(new RegExp(`^${key}=(.*)$`, 'm'))?.[1]?.trim() ?? ''
const RP_TOKEN = process.env.MINIMAL_RP_TOKEN || fromFile('MINIMAL_RP_TOKEN')
const SETUP_TOKEN = process.env.SETUP_TOKEN || fromFile('SETUP_TOKEN')
if (!RP_TOKEN || !SETUP_TOKEN) throw new Error('need MINIMAL_RP_TOKEN + SETUP_TOKEN (see header)')

// 2. Your RP identity. Audience is YOUR constant — never client input.
const RP_ID = 'https://minimal.demo.sovra.example/age-check'
const AUDIENCE = 'https://minimal.demo.sovra.example/age-check/callback'
const PURPOSE = 'synthetic age check (minimal RP)'
const ISSUER_ID = 'https://sovra.example/issuers/synth-1'
const VCT = 'https://sovra.example/vct/adult-status/1'
const POLICY_ID = 'sovra-synthetic-policy/age-check'

function isoPlus(hours) {
  return new Date(Date.now() + hours * 3600_000).toISOString().replace('.000Z', 'Z')
}

function plan(planId) {
  return {
    plan_id: planId,
    requested_outcome: 'age_over_18',
    candidate_issuer_id: ISSUER_ID,
    credential_type: VCT,
    claim_paths: ['adultOver18'],
    evidence: [{ document_id: POLICY_ID, section_id: 'age_eligibility' }],
    policy_id: POLICY_ID,
    policy_version: '1',
    recommendation: 'CANDIDATE_ONLY',
  }
}

function planHash(planId) {
  const canonical = ['sovra-plan/v1', planId, 'age_over_18', ISSUER_ID, VCT,
    'adultOver18', `${POLICY_ID}#age_eligibility`, POLICY_ID, '1', 'CANDIDATE_ONLY', ''].join('\n')
  return createHash('sha256').update(canonical, 'utf-8').digest('hex')
}

// 3. Forward signed holder bytes to Sovra under your RP token.
async function sovra(method, path, token, body, idem) {
  let res
  try {
    res = await fetch(SOVRA + path, {
      method,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(idem ? { 'Idempotency-Key': idem } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    return { status: 0, json: null }
  }
  return { status: res.status, json: await res.json().catch(() => null) }
}

const send = (res, status, value, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers })
  res.end(JSON.stringify(value))
}

async function bodyOf(req, res) {
  let raw = ''
  for await (const chunk of req) {
    raw += chunk
    if (raw.length > MAX_BODY_BYTES) {
      send(res, 413, { ok: false, error: 'body_too_large' })
      req.destroy()
      return null
    }
  }
  try {
    return JSON.parse(raw || '{}')
  } catch {
    send(res, 400, { ok: false, error: 'invalid_json' })
    return null
  }
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://minimal')
    // Cheap rejects first — origin, then quota — before any body
    // is read or token spent.
    if (url.pathname.startsWith('/api/') && req.method === 'POST' && !originAllowed(req.headers.origin)) {
      send(res, 403, { ok: false, error: 'forbidden_origin' })
      return
    }
    if (url.pathname.startsWith('/api/')) {
      const quota = apiLimiter.allow(req.socket.remoteAddress ?? 'unknown')
      if (!quota.allowed) {
        send(res, 429, { ok: false, error: 'rate_limited' }, { 'Retry-After': String(quota.retryAfterSec) })
        return
      }
    }
    // Accept the shared engine's /api/minimal/* paths as well as short ones.
    const api = url.pathname.replace(/^\/api\/minimal\//, '/api/')
    // Static page + the shared engine/stylesheet from demo/public.
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(readFileSync(join(ROOT, 'public', 'index.html')))
      return
    }
    if (req.method === 'GET' && url.pathname === '/shared.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' })
      res.end(readFileSync(join(ROOT, '..', 'public', 'shared.js')))
      return
    }
    if (req.method === 'GET' && url.pathname === '/style.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' })
      res.end(readFileSync(join(ROOT, '..', 'public', 'style.css')))
      return
    }
    if (req.method === 'GET' && url.pathname === '/api/discovery') {
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
    // The four RP calls, in order. Every one forwards bytes the
    // browser signed; the server never sees the holder private key.
    if (req.method === 'POST' && api === '/api/setup') {
      const b = await bodyOf(req, res)
      if (b === null) return
      const r = await sovra('POST', '/api/issuance/credentials', SETUP_TOKEN, {
        issuerId: ISSUER_ID, vct: VCT, holderJwk: b.holderJwk, holderProof: b.holderProof,
        claims: { adultOver18: true }, expiresAt: isoPlus(2),
      }, b.idem)
      send(res, r.status === 201 ? 200 : 502, { ok: r.status === 201, credentialId: r.json?.credentialId })
      return
    }
    if (req.method === 'POST' && api === '/api/request') {
      const b = await bodyOf(req, res)
      if (b === null) return
      const planId = `pln_min_${randomBytes(6).toString('hex')}`
      const r = await sovra('POST', '/api/consent/requests', RP_TOKEN, {
        rpId: RP_ID, audience: AUDIENCE, purpose: PURPOSE, credentialId: b.credentialId,
        claims: { adultOver18: true }, plan: plan(planId), policyId: POLICY_ID,
        policyVersion: '1', planHash: planHash(planId),
        challenge: randomBytes(24).toString('base64url'), expiresAt: isoPlus(1),
      })
      if (r.status !== 201) {
        send(res, 502, { ok: false })
        return
      }
      const review = await sovra('GET', `/api/consent/requests/${r.json.requestId}`, RP_TOKEN)
      send(res, 200, { ok: true, requestId: r.json.requestId, review: review.json })
      return
    }
    if (req.method === 'POST' && api === '/api/decision') {
      const b = await bodyOf(req, res)
      if (b === null) return
      const r = await sovra('POST', `/api/consent/requests/${b.requestId}/decision`, RP_TOKEN, {
        decision: b.decision, holderJwk: b.holderJwk, consentProof: b.consentProof,
      })
      send(res, 200, { ok: r.status === 200, status: r.status, state: r.json })
      return
    }
    if (req.method === 'GET' && api === '/api/outcomes') {
      const limit = Math.min(50, Math.max(1, Number(url.searchParams.get('limit')) || 20))
      const r = await sovra('GET', `/api/rp/outcomes?limit=${limit}`, RP_TOKEN)
      send(res, 200, { ok: true, outcomes: r.json })
      return
    }
    if (req.method === 'GET' && api === '/api/metrics') {
      const r = await sovra('GET', '/api/rp/metrics', RP_TOKEN)
      send(res, 200, { ok: true, metrics: r.json })
      return
    }
    if (req.method === 'POST' && api === '/api/verify') {
      const b = await bodyOf(req, res)
      if (b === null) return
      const r = await sovra('POST', '/api/verification/presentations', RP_TOKEN, {
        requestId: b.requestId, nonce: b.nonce, audience: AUDIENCE,
        holderJwk: b.holderJwk, bindingProof: b.bindingProof,
      })
      send(res, 200, { ok: r.status === 200, status: r.status, decision: r.json })
      return
    }
    send(res, 404, { ok: false })
  } catch (err) {
    console.error('minimal request failed:', err instanceof Error ? err.message : err)
    if (!res.headersSent) send(res, 500, { ok: false })
  }
})

server.listen(PORT, async () => {
  const d = await fetch(`${SOVRA}/api/discovery`, { signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) }).then((r) => r.json()).catch(() => null)
  if (d?.profile !== 'synthetic') {
    console.error(`refusing to boot: ${SOVRA} is not synthetic`)
    process.exit(1)
  }
  console.log(`minimal RP on http://localhost:${PORT} → ${SOVRA} [${d.profile}]`)
})
