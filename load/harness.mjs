// Synthetic arrival-rate workload (PROD-016). Drives the consent-
// to-verification flow plus readiness probes at a fixed offered
// rate with seeded tenant skew, and reports per-endpoint
// p50/p95/p99 with offered/completed/error/rejection counts.
//
// Usage:
//   node load/provision.mjs --tenants=3
//   node load/harness.mjs --base=http://localhost:8080 --rps=5 \
//     --duration-s=30 --seed=20261102 --out=load/results/smoke.json
//
// Results are sanitized by construction: latencies and status
// classes only — no tokens, bodies, or tenant data.

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { cpus, totalmem } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  generateHolder, signMessage, randomNonce,
  issuanceMessage, consentMessage, bindingMessage,
} from '../demo/public/shared.js'

const ROOT = dirname(fileURLToPath(import.meta.url))
const ISSUER_ID = 'https://sovra.example/issuers/synth-1'
const VCT = 'https://sovra.example/vct/adult-status/1'
const POLICY_ID = 'sovra-synthetic-policy/age-check'
const SECTION_ID = 'age_eligibility'
const RP_ID = 'https://load.example/shop'
const AUDIENCE = 'https://load.example/shop/callback'

// Plan wire format, mirroring demo/server.mjs (the harness cannot
// import the demo server: it listens on import).
function planWire(planId) {
  return {
    plan_id: planId,
    requested_outcome: 'age_over_18',
    candidate_issuer_id: ISSUER_ID,
    credential_type: VCT,
    claim_paths: ['adultOver18'],
    evidence: [{ document_id: POLICY_ID, section_id: SECTION_ID }],
    policy_id: POLICY_ID,
    policy_version: '1',
    recommendation: 'CANDIDATE_ONLY',
  }
}

function planHash(planId) {
  const canonical = [
    'sovra-plan/v1', planId, 'age_over_18', ISSUER_ID, VCT, 'adultOver18',
    `${POLICY_ID}#${SECTION_ID}`, POLICY_ID, '1', 'CANDIDATE_ONLY', '',
  ].join('\n')
  return createHashHex(canonical)
}

function createHashHex(text) {
  return createHash('sha256').update(text, 'utf-8').digest('hex')
}

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const m = a.match(/^--([a-z-]+)(?:=(.*))?$/)
    return m ? [m[1], m[2] ?? 'true'] : [a, 'true']
  }),
)
const BASE = args.base ?? 'http://localhost:8080'
const RPS = Math.max(1, parseFloat(args.rps ?? '5'))
const DURATION_S = Math.max(1, parseInt(args['duration-s'] ?? '30', 10))
const SEED = parseInt(args.seed ?? '20261102', 10)
const FLOW_WEIGHT = Math.min(1, Math.max(0, parseFloat(args['flow-weight'] ?? '0.7')))
const MAX_INFLIGHT = Math.max(1, parseInt(args['max-inflight'] ?? '200', 10))
const OUT = args.out ?? `load/results/run-${Date.now()}.json`
const HOLDERS = Math.max(1, parseInt(args.holders ?? '16', 10))

// Deterministic skew: tenant i takes weight 1/(i+1), normalized.
function mulberry32(seed) {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const tokens = JSON.parse(readFileSync(join(ROOT, '.tokens.json'), 'utf-8'))
const tenants = tokens.tenants
const weights = tenants.map((_, i) => 1 / (i + 1))
const weightSum = weights.reduce((x, y) => x + y, 0)

const rand = mulberry32(SEED)
function pickTenant() {
  let r = rand() * weightSum
  for (let i = 0; i < weights.length; i++) {
    r -= weights[i]
    if (r <= 0) return tenants[i]
  }
  return tenants[tenants.length - 1]
}

const samples = new Map() // endpoint -> [{ms, status}]
const abortedByStep = new Map()
const flowsByTenant = new Map()
let offered = 0
let completedFlows = 0
let shed = 0
let inFlight = 0

function record(endpoint, ms, status) {
  if (!samples.has(endpoint)) samples.set(endpoint, [])
  samples.get(endpoint).push({ ms, status })
}

async function call(endpoint, method, path, token, body, idem) {
  const headers = { 'Content-Type': 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  if (idem) headers['Idempotency-Key'] = idem
  const start = performance.now()
  let status = -1
  let json = null
  try {
    const res = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    })
    status = res.status
    const text = await res.text()
    try {
      json = text ? JSON.parse(text) : null
    } catch {
      json = null
    }
  } catch {
    status = -1 // timeout or connection failure
  }
  record(endpoint, performance.now() - start, status)
  return { status, json }
}

const isoPlus = (hours) => new Date(Date.now() + hours * 3600_000).toISOString()

function noteAbort(step, status) {
  // Capacity denials are honest limiter verdicts, not defects: count
  // them apart from real step failures.
  const key = status === 429 ? `${step}:denied` : step
  abortedByStep.set(key, (abortedByStep.get(key) ?? 0) + 1)
}

async function fullFlow(holderPool, cursor) {
  const tenant = pickTenant()
  const holder = holderPool[cursor % holderPool.length]
  // 1. Issue.
  const idem = `load-${SEED}-${cursor}-${Date.now()}`
  const issued = await call('issue', 'POST', '/api/issuance/credentials', tenant.issuerToken, {
    issuerId: ISSUER_ID,
    vct: VCT,
    holderJwk: holder.jwk,
    holderProof: await signMessage(holder, issuanceMessage(idem, holder.thumbprint)),
    claims: { adultOver18: true },
    expiresAt: isoPlus(2),
  }, idem)
  if (issued.status !== 201 || !issued.json?.credentialId) {
    noteAbort('issue', issued.status)
    return
  }
  // 2. Consent request.
  const planId = `pln_load_${SEED}_${cursor}`
  const created = await call('consent.create', 'POST', '/api/consent/requests', tenant.rpToken, {
    rpId: RP_ID,
    audience: AUDIENCE,
    purpose: 'synthetic load probe',
    credentialId: issued.json.credentialId,
    claims: { adultOver18: true },
    plan: planWire(planId),
    policyId: POLICY_ID,
    policyVersion: '1',
    planHash: planHash(planId),
    challenge: randomNonce(),
    expiresAt: isoPlus(1),
  })
  if (created.status !== 201 || !created.json?.requestId) {
    noteAbort('consent.create', created.status)
    return
  }
  const requestId = created.json.requestId
  // 3. Review.
  const review = await call(
    'consent.review', 'GET', `/api/consent/requests/${requestId}`, tenant.rpToken)
  if (review.status !== 200 || !review.json?.challenge) {
    noteAbort('consent.review', review.status)
    return
  }
  // 4. Decide (RP token holds DECIDE_CONSENT).
  const decided = await call(
    'consent.decide', 'POST', `/api/consent/requests/${requestId}/decision`, tenant.rpToken, {
      decision: 'approve',
      holderJwk: holder.jwk,
      consentProof: await signMessage(
        holder, consentMessage(review.json, 'approve', holder.thumbprint)),
    })
  if (decided.status !== 200) {
    noteAbort('consent.decide', decided.status)
    return
  }
  // 5. Verify.
  const nonce = randomNonce()
  const verified = await call('verify', 'POST', '/api/verification/presentations', tenant.rpToken, {
    requestId,
    nonce,
    audience: AUDIENCE,
    holderJwk: holder.jwk,
    bindingProof: await signMessage(
      holder, bindingMessage(requestId, nonce, AUDIENCE, holder.thumbprint)),
  })
  if (verified.status !== 200 || verified.json?.outcome !== 'ACCEPTED') {
    noteAbort('verify', verified.status)
  } else {
    flowsByTenant.set(tenant.slug, (flowsByTenant.get(tenant.slug) ?? 0) + 1)
  }
}

function percentile(sorted, p) {
  if (sorted.length === 0) return null
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]
}

// --- main -----------------------------------------------------------------
const holderPool = []
for (let i = 0; i < HOLDERS; i++) holderPool.push(await generateHolder())

const startedAt = new Date().toISOString()
const intervalMs = 1000 / RPS
const deadline = Date.now() + DURATION_S * 1000
let cursor = 0
let nextAt = Date.now()

async function probe() {
  if (rand() < 0.5) {
    await call('probe.ready', 'GET', '/api/health/ready')
  } else {
    await call('probe.discovery', 'GET', '/api/discovery')
  }
}

async function iterate(n) {
  inFlight++
  try {
    if (rand() < FLOW_WEIGHT) {
      await fullFlow(holderPool, n)
    } else {
      await probe()
    }
  } finally {
    inFlight--
  }
}

const pending = new Set()
while (Date.now() < deadline) {
  offered++
  if (inFlight >= MAX_INFLIGHT) {
    shed++
  } else {
    const p = iterate(cursor++)
    pending.add(p)
    p.finally(() => pending.delete(p))
  }
  nextAt += intervalMs
  const sleep = Math.max(0, nextAt - Date.now())
  await new Promise((r) => setTimeout(r, sleep))
}
await Promise.allSettled([...pending])
const endedAt = new Date().toISOString()

completedFlows =
  (samples.get('verify') ?? []).filter((s) => s.status === 200).length

const endpoints = {}
for (const [name, rows] of samples) {
  const ms = rows.map((r) => r.ms).sort((x, y) => x - y)
  endpoints[name] = {
    n: rows.length,
    ok2xx: rows.filter((r) => r.status >= 200 && r.status < 300).length,
    denied429: rows.filter((r) => r.status === 429).length,
    denied503: rows.filter((r) => r.status === 503).length,
    failed: rows.filter((r) => r.status < 0 || r.status >= 500).length,
    p50: Math.round(percentile(ms, 50) ?? -1),
    p95: Math.round(percentile(ms, 95) ?? -1),
    p99: Math.round(percentile(ms, 99) ?? -1),
    max: Math.round(ms[ms.length - 1] ?? -1),
  }
}

const summary = {
  harness: 'load/harness.mjs',
  config: {
    base: BASE, rps: RPS, durationS: DURATION_S, seed: SEED,
    flowWeight: FLOW_WEIGHT, maxInflight: MAX_INFLIGHT,
    tenants: tenants.map((t) => t.slug),
    tenantSkew: weights.map((w) => +(w / weightSum).toFixed(3)),
    holders: HOLDERS,
  },
  resources: {
    node: process.version, cpus: cpus().length,
    memMB: Math.round(totalmem() / 1048576),
  },
  window: { startedAt, endedAt },
  offered,
  completedFlows,
  abortedFlowsByStep: Object.fromEntries(abortedByStep),
  flowsByTenant: Object.fromEntries(flowsByTenant),
  shed,
  endpoints,
}
mkdirSync(dirname(OUT), { recursive: true })
writeFileSync(OUT, JSON.stringify(summary, null, 2) + '\n')
console.log(JSON.stringify(summary, null, 2))
const failed = Object.values(endpoints).reduce((n, e) => n + e.failed, 0)
if (failed > 0) {
  console.error(`LOAD RESULT: ${failed} failed calls (5xx/timeout) — investigate, do not sign off`)
  process.exitCode = 1
} else {
  console.log('LOAD RESULT: no 5xx/timeouts')
}
