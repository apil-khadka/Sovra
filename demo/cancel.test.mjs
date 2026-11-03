// Deterministic cancel/restart race coverage for the demo engine.
// No server, no browser, no live calls, no timing sleeps: fetch is
// mocked with deferred barriers, so a cancelled run's late responses
// overlap a restarted run exactly, on every run.
import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  DemoError, RunCancelledError, createRunOwner, isRunCancelled, runCheck, runPlannedCheck,
} from './public/shared.js'

const REVIEW = {
  requestId: 'req-fixture', rpId: 'rp', audience: 'aud', purpose: 'p',
  planHash: 'h', challenge: 'c', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
}

function deferred() {
  let resolve
  const promise = new Promise((r) => { resolve = r })
  return { promise, resolve }
}

// Mock demo RP backend. The first /request can wait on a caller-held
// gate (optionally ignoring abort, like a hostile/slow backend), and
// every call is recorded so tests prove which run sent /decision.
// Request ids are per-call (req-1, req-2, …) to attribute decisions.
function mockBackend({
  firstRequestGate = null,
  firstRequestIgnoresAbort = false,
  onFirstRequestStart,
  decisionStatus = 200,
  verifyStatus = 200,
  onDecision,
} = {}) {
  const calls = []
  let requests = 0
  const fetch = async (path, init) => {
    const body = init?.body ? JSON.parse(init.body) : {}
    const signal = init?.signal
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    if (String(path).endsWith('/setup')) {
      calls.push({ endpoint: 'setup' })
      return { ok: true, status: 200, json: async () => ({ credentialId: 'cred-fixture' }) }
    }
    if (String(path).endsWith('/request')) {
      requests += 1
      const n = requests
      const review = { ...REVIEW, requestId: `req-${n}` }
      calls.push({ endpoint: 'request', n })
      if (n === 1) {
        await onFirstRequestStart?.()
        if (firstRequestGate) {
          if (firstRequestIgnoresAbort) {
            await firstRequestGate
            calls.push({ endpoint: 'request-late-delivered', n })
          } else {
            await Promise.race([
              firstRequestGate,
              new Promise((_, reject) => signal?.addEventListener(
                'abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true },
              )),
            ])
          }
        }
      }
      return { ok: true, status: 200, json: async () => ({ requestId: `req-${n}`, review }) }
    }
    if (String(path).endsWith('/decision')) {
      calls.push({ endpoint: 'decision', decision: body.decision, requestId: body.requestId })
      await onDecision?.()
      if (decisionStatus !== 200) {
        return { ok: false, status: decisionStatus, json: async () => ({ ok: false, error: 'decision_failed' }) }
      }
      return { ok: true, status: 200, json: async () => ({ state: { state: 'APPROVED' } }) }
    }
    if (String(path).endsWith('/verify')) {
      calls.push({ endpoint: 'verify' })
      if (verifyStatus !== 200) {
        return { ok: false, status: verifyStatus, json: async () => ({ ok: false, error: 'verify_failed' }) }
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          decision: { decisionId: 'd', outcome: 'ACCEPTED', trustSnapshot: 1, profile: 'p', reasonCode: 'ok' },
        }),
      }
    }
    throw new Error(`unexpected ${path}`)
  }
  return { fetch, calls }
}

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

describe('demo cancel/restart races', () => {
  it('cancel while deciding sends no /decision', async () => {
    const { fetch, calls } = mockBackend({})
    globalThis.fetch = fetch
    const controller = new AbortController()
    const gate = deferred()
    const reached = deferred()
    const run = runCheck('novabank', {
      signal: controller.signal,
      decide: () => {
        reached.resolve() // barrier: runCheck is now parked in decide
        return gate.promise.then(() => 'approve')
      },
    })
    await reached.promise
    controller.abort()
    gate.resolve()
    const err = await run.then(() => null, (e) => e)
    assert.ok(err instanceof RunCancelledError)
    assert.equal(isRunCancelled(err), true)
    assert.deepEqual(calls.map((c) => c.endpoint), ['setup', 'request'])
  })

  it('delayed cancelled run cannot commit after a restart', async () => {
    const late = deferred()
    const started = deferred()
    const { fetch, calls } = mockBackend({
      firstRequestGate: late.promise,
      firstRequestIgnoresAbort: true, // hostile backend: abort signal ignored
      onFirstRequestStart: () => started.resolve(),
    })
    globalThis.fetch = fetch
    const owner = createRunOwner()
    const ui = []

    // Old run wired like the demo pages: every callback checks its
    // generation before touching UI.
    const oldRun = owner.begin()
    assert.ok(oldRun)
    const first = runCheck('novabank', {
      signal: oldRun.signal,
      onStep: (label) => {
        ui.push(oldRun.isCurrent() ? `old step: ${label}` : `old stale step suppressed: ${label}`)
      },
      decide: () => {
        ui.push('old decide invoked')
        return Promise.resolve(oldRun.isCurrent() ? 'approve' : 'back')
      },
    }).then(
      () => { ui.push(oldRun.isCurrent() ? 'old result shown' : 'old stale result suppressed') },
      (err) => { ui.push(oldRun.isCurrent() ? `old error shown: ${err.name}` : `old stale error suppressed: ${err.name}`) },
    )
    await started.promise // barrier: old run provably in-flight in /request
    owner.cancelActive() // user cancels; generation retired
    assert.equal(oldRun.isCurrent(), false)

    const newRun = owner.begin() // user restarts; single-flight, overlap-free
    assert.ok(newRun)
    const out = await runCheck('novabank', {
      signal: newRun.signal,
      onStep: (label) => { if (newRun.isCurrent()) ui.push(`new step: ${label}`) },
      decide: () => Promise.resolve('approve'),
    })
    newRun.finish()
    assert.equal(out.decision?.outcome, 'ACCEPTED')
    assert.equal(out.requestId, 'req-2')

    late.resolve() // hostile backend finally delivers the cancelled run's response
    await first // settles; stale handlers must suppress everything

    assert.ok(
      calls.some((c) => c.endpoint === 'request-late-delivered' && c.n === 1),
      'late response really arrived after the restart',
    )
    assert.ok(!ui.includes('old decide invoked'), 'cancelled run must never reach decide')
    assert.ok(
      !ui.some((e) => e.startsWith('old step: Recording') || e.startsWith('old step: Confirming')),
      'cancelled run must never reach signing/verification steps',
    )
    assert.ok(!ui.includes('old result shown') && !ui.some((e) => e.startsWith('old error shown')),
      `stale outcome must not render: ${JSON.stringify(ui)}`)
    assert.ok(ui.includes('old stale error suppressed: RunCancelledError'))
    const decisions = calls.filter((c) => c.endpoint === 'decision')
    assert.equal(decisions.length, 1)
    assert.equal(decisions[0].requestId, 'req-2')
  })

  it('abort after the decision commits cannot revoke it', async () => {
    const controller = new AbortController()
    const { fetch, calls } = mockBackend({
      // Simulates a stop racing the commit: by the time the abort
      // lands, /decision is already being recorded.
      onDecision: async () => { controller.abort() },
    })
    globalThis.fetch = fetch
    const out = await runCheck('novabank', {
      signal: controller.signal,
      decide: async () => 'approve',
    })
    assert.equal(out.decision?.outcome, 'ACCEPTED')
    assert.equal(calls.filter((c) => c.endpoint === 'decision').length, 1)
    assert.equal(calls.filter((c) => c.endpoint === 'verify').length, 1)
  })

  it('back sends no /decision and denies nothing', async () => {
    const { fetch, calls } = mockBackend({})
    globalThis.fetch = fetch
    const out = await runCheck('novabank', { decide: async () => 'back' })
    assert.equal(out.backedOut, true)
    assert.equal(out.denied, false)
    assert.equal(out.decision, null)
    assert.deepEqual(calls.map((c) => c.endpoint), ['setup', 'request'])
  })

  it('decision/verify failures carry stage for honest messaging', async () => {
    const failingDecision = mockBackend({ decisionStatus: 500 })
    globalThis.fetch = failingDecision.fetch
    const decisionErr = await runCheck('novabank', { decide: async () => 'approve' })
      .then(() => null, (e) => e)
    assert.ok(decisionErr instanceof DemoError)
    assert.equal(decisionErr.stage, 'decision')
    assert.equal(decisionErr.decision, 'approve')
    assert.equal(decisionErr.requestId, 'req-1')

    const failingVerify = mockBackend({ verifyStatus: 503 })
    globalThis.fetch = failingVerify.fetch
    const verifyErr = await runCheck('novabank', { decide: async () => 'approve' })
      .then(() => null, (e) => e)
    assert.ok(verifyErr instanceof DemoError)
    assert.equal(verifyErr.stage, 'verify')
    assert.equal(verifyErr.decision, 'approve')
  })
})

describe('runPlannedCheck cancel/plan races', () => {
  const PLAN = {
    plan_id: 'pln_test_known',
    requested_outcome: 'age_over_18',
    candidate_issuer_id: 'https://sovra.example/issuers/synth-1',
    credential_type: 'https://sovra.example/vct/adult-status/1',
    claim_paths: ['adultOver18'],
    evidence: [{ document_id: 'sovra-synthetic-policy/age-check', section_id: 'age_eligibility' }],
    policy_id: 'sovra-synthetic-policy/age-check',
    policy_version: '1',
    recommendation: 'CANDIDATE_ONLY',
  }
  const META = { mode: 'FIXTURE', recommendation: 'CANDIDATE_ONLY', reason: 'fixture', toolCalls: 0 }
  const GUARD = { accepted: true, code: 'GUARD_ACCEPTED', rulesVersion: 'sovra-guard/2' }

  // Wraps the runCheck mock backend with the interop plan leg: the
  // setup/request/decision/verify paths are shared suffixes.
  function plannedFetch({ plan = null, backendOpts = {} } = {}) {
    const { fetch, calls } = mockBackend(backendOpts)
    const planBody = plan ?? {
      ok: true, available: true, refusal: false, tx: 'itx-test', plan: PLAN, meta: META, guard: GUARD,
    }
    const wrapped = async (path, init) => {
      if (String(path).endsWith('/api/interop/plan')) {
        calls.push({ endpoint: 'plan' })
        if (init?.signal?.aborted) throw new DOMException('aborted', 'AbortError')
        return { ok: true, status: 200, json: async () => planBody }
      }
      return fetch(path, init)
    }
    return { fetch: wrapped, calls }
  }

  it('cancel while deciding sends no /decision', async () => {
    const { fetch, calls } = plannedFetch()
    globalThis.fetch = fetch
    const controller = new AbortController()
    const gate = deferred()
    const reached = deferred()
    const run = runPlannedCheck('known', {
      signal: controller.signal,
      decide: () => {
        reached.resolve()
        return gate.promise.then(() => 'approve')
      },
    })
    await reached.promise
    controller.abort()
    gate.resolve()
    const err = await run.then(() => null, (e) => e)
    assert.ok(err instanceof RunCancelledError)
    assert.deepEqual(calls.map((c) => c.endpoint), ['plan', 'setup', 'request'])
  })

  it('back sends no /decision and denies nothing', async () => {
    const { fetch, calls } = plannedFetch()
    globalThis.fetch = fetch
    const out = await runPlannedCheck('known', { decide: async () => 'back' })
    assert.equal(out.backedOut, true)
    assert.equal(out.denied, false)
    assert.equal(out.decision, null)
    assert.deepEqual(calls.map((c) => c.endpoint), ['plan', 'setup', 'request'])
  })

  it('refusal returns before any setup or consent call', async () => {
    const { fetch, calls } = plannedFetch({
      plan: { ok: true, available: true, refusal: true, meta: { ...META, recommendation: 'NO_PATH', reason: 'no path' }, plan: null, guard: null },
    })
    globalThis.fetch = fetch
    const out = await runPlannedCheck('employment', { decide: async () => 'approve' })
    assert.equal(out.refusal, true)
    assert.deepEqual(calls.map((c) => c.endpoint), ['plan'])
  })

  it('unavailable returns before any setup call', async () => {
    const { fetch, calls } = plannedFetch({
      plan: { ok: true, available: false, reason: 'backend_scope_pending', caps: null },
    })
    globalThis.fetch = fetch
    const out = await runPlannedCheck('fjord', { decide: async () => 'approve' })
    assert.equal(out.unavailable, true)
    assert.equal(out.reason, 'backend_scope_pending')
    assert.deepEqual(calls.map((c) => c.endpoint), ['plan'])
  })

  it('abort after the decision commits cannot revoke it', async () => {
    const controller = new AbortController()
    const { fetch, calls } = plannedFetch({
      backendOpts: { onDecision: async () => { controller.abort() } },
    })
    globalThis.fetch = fetch
    const out = await runPlannedCheck('known', {
      signal: controller.signal,
      decide: async () => 'approve',
    })
    assert.equal(out.decision?.outcome, 'ACCEPTED')
    assert.equal(calls.filter((c) => c.endpoint === 'decision').length, 1)
    assert.equal(calls.filter((c) => c.endpoint === 'verify').length, 1)
  })
})

describe('createRunOwner', () => {
  it('refuses overlaps so double-start cannot run twice', () => {
    const owner = createRunOwner()
    const first = owner.begin()
    assert.ok(first)
    assert.equal(owner.active, true)
    assert.equal(owner.begin(), null) // second click while active: ignored
    first.finish()
    assert.equal(owner.active, false)
    assert.ok(owner.begin()) // released after settle
  })

  it('cancel retires the generation; stale finish is a no-op', () => {
    const owner = createRunOwner()
    const oldRun = owner.begin()
    assert.equal(owner.cancelActive(), true)
    assert.equal(oldRun.isCurrent(), false)
    assert.equal(owner.cancelActive(), false) // nothing left to stop
    oldRun.finish() // stale settle must not disturb the next run
    const next = owner.begin()
    assert.ok(next)
    assert.equal(next.isCurrent(), true)
    assert.equal(oldRun.isCurrent(), false)
  })
})
