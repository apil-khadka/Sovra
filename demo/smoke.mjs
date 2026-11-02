// Headless demo-flow check (no browser). Exercises the shared
// engine against a running demo server: discovery, approve →
// ACCEPTED, deny → no decision, ops feed. DEMO_BASE/DEMO_APP select
// the target (defaults: NovaBank on :5174).
// Prints PASS/FAIL lines only — never tokens or key material.

import { fetchDiscovery, fetchOps, runCheck } from './public/shared.js'
import { createRateLimiter, originAllowed } from './limit.mjs'

const BASE = process.env.DEMO_BASE ?? 'http://localhost:5174'
const APP = process.env.DEMO_APP ?? 'novabank'
const nativeFetch = globalThis.fetch
globalThis.fetch = (input, init) =>
  nativeFetch(typeof input === 'string' && input.startsWith('/') ? BASE + input : input, init)

let failures = 0
function check(label, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'} ${label}`)
  if (!condition) failures += 1
}

// PROD-006: the shared limiter is pure and clock-injectable, so its
// exact behavior is asserted here without timing flakes.
{
  let now = 1_000_000
  const limiter = createRateLimiter({ capacity: 2, refillPerSec: 1, now: () => now })
  check('limiter starts full', limiter.allow('ip').allowed && limiter.allow('ip').allowed)
  const denied = limiter.allow('ip')
  check('limiter denies past capacity', !denied.allowed && denied.retryAfterSec >= 1)
  check('limiter isolates keys', limiter.allow('other').allowed)
  now += 2500
  check('limiter refills over time', limiter.allow('ip').allowed)
  check('origin allows missing and localhost', originAllowed(undefined) && originAllowed('http://localhost:5174'))
  check('origin rejects foreign and malformed', !originAllowed('https://evil.example') && !originAllowed('::not-a-url::'))
}

const discovery = await fetchDiscovery()
check('discovery reports synthetic profile', discovery?.profile === 'synthetic')

const approved = await runCheck(APP, {})
check(`${APP} approve reaches a decision`, approved.decision !== null && !approved.denied)
check(
  `${APP} outcome is ACCEPTED`,
  approved.decision?.outcome === 'ACCEPTED'
    && approved.decision?.profile === 'sovra-g1-synthetic/0.2',
)

const declined = await runCheck(APP, { decide: async () => 'deny' })
check(`${APP} deny shares nothing`, declined.denied && declined.decision === null)

const setupPath = APP === 'minimal' ? '/api/setup' : `/api/${APP}/setup`
{
  // PROD-006: foreign origins and oversized bodies are rejected
  // before any body is read or token spent.
  const foreign = await nativeFetch(BASE + setupPath, {
    method: 'POST',
    headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
    body: '{}',
  })
  check('foreign origin is rejected', foreign.status === 403)
  let hugeVerdict = 'no-response'
  try {
    const huge = await nativeFetch(BASE + setupPath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: `{"pad":"${'x'.repeat(100_000)}"}`,
    })
    hugeVerdict = huge.status === 413 ? 'rejected' : `status-${huge.status}`
    await huge.text().catch(() => null)
  } catch (err) {
    // The server destroys the socket mid-upload after answering 413;
    // a reset uploader proves the same refusal as a clean 413.
    const code = err?.cause?.code ?? err?.code ?? ''
    hugeVerdict = /RESET|ABORT|HANGUP|DESTROYED/i.test(String(code)) ? 'rejected' : `threw-${code}`
  }
  check('oversized body is rejected', hugeVerdict === 'rejected')
}

const ops = await fetchOps(APP)
check('ops feed lists outcomes', ops.outcomes.length >= 1)
check('ops metrics count decisions', (ops.metrics?.total ?? 0) >= 1)
check(
  'ops feed contains the approved decision',
  ops.outcomes.some(
    (o) => o.decisionId === approved.decision.decisionId && o.outcome === 'ACCEPTED',
  ),
)

if (failures > 0) {
  console.error(`${failures} demo smoke check(s) failed`)
  process.exit(1)
}
console.log('demo smoke: all checks passed')
