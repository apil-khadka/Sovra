// Interop service tests over a fake backend (no network, no model).
// Pins the actual backend contract: flat scope intents with the canonical
// hint (never the discovered wire field), central planning on nodes.default,
// issuer-routed issuance/consent/verify with per-node tokens, exact plan
// propagation + canonical hash, scope/echo binding, tx capacity/expiry/
// identifier binding, and honest unavailable/refusal outcomes.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  ISSUER_SYNTH1,
  ISSUER_SYNTH2,
  OUTCOME,
  POLICY_LEGACY,
  POLICY_MAPPED,
  POLICY_VERSION,
  VCT_ADULT,
  VCT_EMPLOYMENT,
  VCT_FJORD,
  VCT_HARBOR,
  buildIntent,
  canonicalPlanHash,
  caseNeedsScope,
  checkPlanShape,
  claimsForPlan,
  createInteropService,
  createTxStore,
  isCase,
  scopeAllows,
  scopeFor,
} from './interop.mjs'

const NODES = {
  default: { base: 'http://central', rpToken: 'rp-central', issuerToken: 'issuer-central' },
  synth2: { base: 'http://issuer2', rpToken: 'rp-2', issuerToken: 'issuer-2' },
}

function planFor({ issuer, type, claim, policy, planId = 'pln_fake_0001' }) {
  return {
    plan_id: planId,
    requested_outcome: OUTCOME,
    candidate_issuer_id: issuer,
    credential_type: type,
    claim_paths: [claim],
    evidence: [{
      document_id: policy,
      section_id: policy === POLICY_MAPPED ? 'mapped_age_eligibility' : 'age_eligibility',
    }],
    policy_id: policy,
    policy_version: POLICY_VERSION,
    recommendation: 'CANDIDATE_ONLY',
  }
}

function newStatus({ scope = true, mapped = true, mode = 'FIXTURE' } = {}) {
  return {
    mode,
    liveEnabled: false,
    modelConfigured: false,
    promptVersion: 'sovra-planner-prompts/3',
    toolContractVersion: 'sovra-planner-tools/1',
    toolSchemaHash: 'fake-tool-hash',
    baselineVersion: 'sovra-baseline-planner/1',
    tools: ['compareEvidence', 'getCredentialSchema'],
    discoveryScopeSupported: scope,
    schemaRegistryVersion: 'sovra-synthetic-schemas/1',
    guardRulesVersion: 'sovra-guard/2',
    supportedPolicyBindings: [
      { policyId: POLICY_LEGACY, policyVersion: POLICY_VERSION },
      ...(mapped ? [{ policyId: POLICY_MAPPED, policyVersion: POLICY_VERSION }] : []),
    ],
  }
}

function proposalFor(plan, intent, { recommendation = 'CANDIDATE_ONLY', reason = 'fake candidate' } = {}) {
  return {
    mode: 'FIXTURE',
    liveAcceptance: false,
    model: 'none (fixture)',
    promptVersion: 'sovra-planner-prompts/3',
    toolContractVersion: 'sovra-planner-tools/1',
    toolSchemaHash: 'fake-tool-hash',
    toolCalls: 0,
    recommendation,
    reason,
    snapshotVersion: 7,
    plan,
    scopeIssuerIds: intent.scopeIssuerIds ?? [],
    scopeCredentialTypes: intent.scopeCredentialTypes ?? [],
    scopeJurisdictions: intent.scopeJurisdictions ?? [],
  }
}

const ACCEPT = { accepted: true, code: 'GUARD_ACCEPTED', reason: 'ok', rulesVersion: 'sovra-guard/2' }

// Fake upstream. Handlers receive (body, { node, token }) and return
// { status, json }. Every call is recorded for routing assertions.
function fakeBackend({
  status = newStatus(),
  statusFor = null,
  onPropose = null,
  onGuard = null,
  credentialId = '11111111-1111-4111-8111-111111111111',
  requestId = '22222222-2222-4222-8222-222222222222',
  reviewPlanHash = null, // null = echo the stored plan hash honestly
} = {}) {
  const calls = []
  let lastConsentBody = null
  const call = async (node, method, path, token, body) => {
    calls.push({ base: node.base, token, method, path, body })
    if (method === 'GET' && path === '/api/plans/status') {
      return { status: 200, json: statusFor ? statusFor(node) : status }
    }
    if (method === 'POST' && path === '/api/plans/propose') {
      if (!onPropose) throw new Error('unexpected propose')
      return onPropose(body, { node, token })
    }
    if (method === 'POST' && path === '/api/guard/validate') {
      if (!onGuard) throw new Error('unexpected guard')
      return onGuard(body, { node, token })
    }
    if (method === 'POST' && path === '/api/issuance/credentials') {
      return { status: 201, json: { credentialId } }
    }
    if (method === 'POST' && path === '/api/consent/requests') {
      lastConsentBody = body
      return { status: 201, json: { requestId } }
    }
    if (method === 'GET' && path === `/api/consent/requests/${requestId}`) {
      return {
        status: 200,
        json: {
          requestId, rpId: 'rp', audience: 'aud', purpose: 'p',
          planHash: reviewPlanHash ?? lastConsentBody?.planHash ?? 'echo-unset',
          challenge: 'c', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        },
      }
    }
    if (method === 'POST' && path.endsWith('/decision')) {
      return { status: 200, json: { state: 'APPROVED' } }
    }
    if (method === 'POST' && path === '/api/verification/presentations') {
      return { status: 200, json: { decisionId: 'd', outcome: 'ACCEPTED', trustSnapshot: 7, profile: 'p', reasonCode: 'ok' } }
    }
    throw new Error(`unexpected ${method} ${path}`)
  }
  return { call, calls }
}

const proposes = (calls) => calls.filter((c) => c.path === '/api/plans/propose')
const guards = (calls) => calls.filter((c) => c.path === '/api/guard/validate')

describe('interop intents', () => {
  it('unfamiliar cases send the canonical hint plus flat scope, never the wire field', () => {
    for (const caseId of ['fjord', 'harbor', 'employment']) {
      const intent = buildIntent(caseId, { scopeSupported: true })
      assert.deepEqual(intent.requestedClaims, ['adultOver18'])
      const raw = JSON.stringify(intent)
      assert.ok(!raw.includes('isAdult'), `${caseId} leaks isAdult`)
      assert.ok(!raw.includes('qualifiesAsAdult'), `${caseId} leaks qualifiesAsAdult`)
      assert.ok(!raw.includes('yearsInEmployment'), `${caseId} leaks yearsInEmployment`)
      assert.ok(!('discoveryScope' in intent), `${caseId} has nested discoveryScope`)
      assert.ok(Array.isArray(intent.scopeIssuerIds) && Array.isArray(intent.scopeCredentialTypes))
      assert.equal(intent.policyId, POLICY_MAPPED)
    }
  })

  it('known uses the legacy policy with legacy-pinned scope', () => {
    const intent = buildIntent('known', { scopeSupported: true })
    assert.equal(intent.policyId, POLICY_LEGACY)
    assert.deepEqual(intent.requestedClaims, ['adultOver18'])
    assert.deepEqual(intent.scopeIssuerIds, [ISSUER_SYNTH1])
    assert.deepEqual(intent.scopeCredentialTypes, [VCT_ADULT])
    const legacy = buildIntent('known', { scopeSupported: false })
    assert.ok(!('scopeIssuerIds' in legacy))
  })

  it('inherited property names are never cases', () => {
    for (const name of ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty']) {
      assert.equal(isCase(name), false)
      assert.throws(() => buildIntent(name, { scopeSupported: true }), /unknown_interop_case/)
      assert.throws(() => scopeFor(name), /unknown_interop_case/)
    }
    assert.equal(isCase('known'), true)
    assert.equal(caseNeedsScope('known'), false)
    assert.equal(caseNeedsScope('fjord'), true)
  })
})

describe('canonical plan hash', () => {
  it('matches the backend sovra-plan/v1 form and the legacy bytes', () => {
    const plan = planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY, planId: 'pln_legacy_bytes' })
    // Byte copy of the retired server planHash for the legacy shape.
    const legacyCanonical = [
      'sovra-plan/v1', 'pln_legacy_bytes', 'age_over_18', ISSUER_SYNTH1, VCT_ADULT,
      'adultOver18', `${POLICY_LEGACY}#age_eligibility`, POLICY_LEGACY, POLICY_VERSION,
      'CANDIDATE_ONLY', '',
    ].join('\n')
    const legacy = createHash('sha256').update(legacyCanonical, 'utf-8').digest('hex')
    assert.equal(canonicalPlanHash(plan), legacy)
    // Unfamiliar plans hash their own exact values, not a fallback.
    const fjord = planFor({ issuer: ISSUER_SYNTH2, type: VCT_FJORD, claim: 'isAdult', policy: POLICY_MAPPED, planId: 'pln_legacy_bytes' })
    assert.notEqual(canonicalPlanHash(fjord), legacy)
    assert.throws(() => canonicalPlanHash(null), /plan_missing/)
  })

  it('claims derive from the returned plan, single boolean only', () => {
    const plan = planFor({ issuer: ISSUER_SYNTH2, type: VCT_FJORD, claim: 'isAdult', policy: POLICY_MAPPED })
    assert.deepEqual(claimsForPlan(plan), { isAdult: true })
    assert.throws(() => claimsForPlan({ ...plan, claim_paths: ['a', 'b'] }), /plan_claims_not_minimal/)
    assert.throws(() => checkPlanShape({ ...plan, plan_id: undefined }), /plan_malformed/)
  })

  it('scope binding checks issuer, type, and jurisdiction hints', () => {
    const plan = planFor({ issuer: ISSUER_SYNTH2, type: VCT_FJORD, claim: 'isAdult', policy: POLICY_MAPPED })
    assert.equal(scopeAllows(scopeFor('fjord'), plan), true)
    assert.equal(scopeAllows(scopeFor('harbor'), plan), false)
    assert.equal(scopeAllows(null, plan), true)
    assert.equal(scopeAllows({ scopeJurisdictions: ['fjord'] }, plan, 'issuer scope mentions fjord waters'), true)
    assert.equal(scopeAllows({ scopeJurisdictions: ['fjord'] }, plan, 'harbor scope'), false)
    assert.equal(scopeAllows({ scopeJurisdictions: ['fjord'] }, plan, null), true)
  })
})

describe('interop status', () => {
  it('is read-only: zero propose calls, full capability metadata', async () => {
    const { call, calls } = fakeBackend({})
    const svc = createInteropService({ nodes: NODES, call })
    const caps = await svc.getStatus()
    assert.ok(calls.length > 0)
    assert.ok(calls.every((c) => c.method === 'GET' && c.path === '/api/plans/status'))
    assert.equal(caps.primary.mode, 'FIXTURE')
    assert.equal(caps.primary.discoveryScopeSupported, true)
    assert.equal(caps.primary.schemaRegistryVersion, 'sovra-synthetic-schemas/1')
    assert.equal(caps.primary.guardRulesVersion, 'sovra-guard/2')
    assert.deepEqual(caps.primary.supportedPolicyBindings, [
      { policyId: POLICY_LEGACY, policyVersion: POLICY_VERSION },
      { policyId: POLICY_MAPPED, policyVersion: POLICY_VERSION },
    ])
    assert.equal(caps.primary.scopeSupported, true)
    assert.equal(caps.primary.mappedSupported, true)
    assert.equal(caps.liveAvailable, false)
    assert.equal(caps.synth2Configured, true)
  })

  it('derives mapped support from bindings, unknown on old backends', async () => {
    const old = { mode: 'FIXTURE', liveEnabled: false, modelConfigured: false, promptVersion: 'sovra-planner-prompts/2', tools: [] }
    const { call } = fakeBackend({ status: old })
    const svc = createInteropService({ nodes: NODES, call })
    const caps = await svc.getStatus()
    assert.equal(caps.primary.scopeSupported, null)
    assert.equal(caps.primary.mappedSupported, null)
    assert.equal(caps.primary.guardRulesVersion, null)
  })
})

describe('known full flow', () => {
  async function runKnown() {
    const backend = fakeBackend({
      onPropose: (intent) => {
        const plan = planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY })
        return { status: 200, json: proposalFor(plan, intent) }
      },
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const planned = await svc.postPlan('known')
    return { svc, planned, calls: backend.calls }
  }

  it('plans + guards centrally and propagates the exact plan and hash', async () => {
    const { svc, planned, calls } = await runKnown()
    assert.equal(planned.ok, true)
    assert.equal(planned.refusal, false)
    assert.ok(planned.tx)
    assert.equal(planned.meta.mode, 'FIXTURE')
    assert.equal(planned.echo.scopeIssuerIds[0], ISSUER_SYNTH1)

    const [propose] = proposes(calls)
    assert.equal(propose.base, 'http://central')
    assert.equal(propose.token, 'rp-central')
    assert.deepEqual(propose.body.requestedClaims, ['adultOver18'])
    const [guard] = guards(calls)
    assert.equal(guard.base, 'http://central')
    assert.equal(guard.token, 'rp-central')
    assert.deepEqual(guard.body.plan, planned.plan)

    // The tx holds the EXACT guarded plan, policy, and canonical hash;
    // the opaque id reveals none of it.
    assert.ok(planned.tx.startsWith('itx_'))
    const stored = svc.txStore.get(planned.tx)
    assert.deepEqual(stored.plan, planned.plan)
    assert.equal(stored.policyId, POLICY_LEGACY)
    assert.equal(stored.planHash, canonicalPlanHash(planned.plan))
    assert.deepEqual(stored.claims, { adultOver18: true })
  })

  it('binds issuance/consent/decision/verify to the stored tx on the issuer node', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const seen = {}
    const call = async (node, method, path, token, body) => {
      if (path === '/api/issuance/credentials') seen.issue = { base: node.base, token, body }
      if (path === '/api/consent/requests' && method === 'POST') seen.consent = { base: node.base, token, body }
      if (path.endsWith('/decision')) seen.decision = { base: node.base, token, body }
      if (path === '/api/verification/presentations') seen.verify = { base: node.base, token, body }
      return backend.call(node, method, path, token, body)
    }
    const svc = createInteropService({ nodes: NODES, call })
    const planned = await svc.postPlan('known')
    const storedTx = svc.txStore.get(planned.tx)
    const setup = await svc.postSetup({ tx: planned.tx, holderJwk: { k: 1 }, holderProof: 'p', idem: 'idem-1' })
    assert.equal(setup.ok, true)
    assert.equal(seen.issue.base, 'http://central')
    assert.equal(seen.issue.token, 'issuer-central')
    assert.equal(seen.issue.body.issuerId, ISSUER_SYNTH1)
    assert.equal(seen.issue.body.vct, VCT_ADULT)
    assert.deepEqual(seen.issue.body.claims, { adultOver18: true })

    const req = await svc.postRequest({ tx: planned.tx, credentialId: setup.credentialId })
    assert.equal(req.ok, true)
    assert.equal(seen.consent.base, 'http://central')
    assert.equal(seen.consent.token, 'rp-central')
    assert.deepEqual(seen.consent.body.plan, storedTx.plan)
    assert.equal(seen.consent.body.planHash, storedTx.planHash)
    assert.equal(seen.consent.body.policyId, POLICY_LEGACY)

    const dec = await svc.postDecision({ tx: planned.tx, requestId: req.requestId, decision: 'approve', holderJwk: { k: 1 }, consentProof: 'c' })
    assert.equal(dec.ok, true)
    assert.equal(seen.decision.base, 'http://central')
    const ver = await svc.postVerify({ tx: planned.tx, requestId: req.requestId, nonce: 'n', holderJwk: { k: 1 }, bindingProof: 'b' })
    assert.equal(ver.ok, true)
    assert.equal(seen.verify.base, 'http://central')
  })
})

describe('unfamiliar compatible flows', () => {
  it('fjord routes planning centrally and issuance to node B with its tokens', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH2, type: VCT_FJORD, claim: 'isAdult', policy: POLICY_MAPPED }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const seen = {}
    const call = async (node, method, path, token, body) => {
      if (path === '/api/issuance/credentials') seen.issue = { base: node.base, token, body }
      if (path === '/api/consent/requests' && method === 'POST') seen.consent = { base: node.base, token, body }
      if (path === '/api/verification/presentations') seen.verify = { base: node.base, token }
      return backend.call(node, method, path, token, body)
    }
    const svc = createInteropService({ nodes: NODES, call })
    const planned = await svc.postPlan('fjord')
    assert.equal(planned.ok, true)
    assert.equal(planned.refusal, false)
    assert.deepEqual(svc.txStore.get(planned.tx).claims, { isAdult: true })

    const [propose] = proposes(backend.calls)
    assert.equal(propose.base, 'http://central')
    assert.equal(propose.token, 'rp-central')
    assert.ok(!JSON.stringify(propose.body).includes('isAdult'))
    const [guard] = guards(backend.calls)
    assert.equal(guard.base, 'http://central')

    const setup = await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i1' })
    assert.equal(seen.issue.base, 'http://issuer2')
    assert.equal(seen.issue.token, 'issuer-2')
    assert.deepEqual(seen.issue.body.claims, { isAdult: true })
    const req = await svc.postRequest({ tx: planned.tx, credentialId: setup.credentialId })
    assert.equal(seen.consent.base, 'http://issuer2')
    assert.equal(seen.consent.token, 'rp-2')
    await svc.postVerify({ tx: planned.tx, requestId: req.requestId, nonce: 'n', holderJwk: {}, bindingProof: 'b' })
    assert.equal(seen.verify.base, 'http://issuer2')
    assert.equal(seen.verify.token, 'rp-2')
  })

  it('harbor discovers qualifiesAsAdult from the returned plan only', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH2, type: VCT_HARBOR, claim: 'qualifiesAsAdult', policy: POLICY_MAPPED }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const planned = await svc.postPlan('harbor')
    assert.equal(planned.ok, true)
    assert.deepEqual(planned.plan.claim_paths, ['qualifiesAsAdult'])
    const [propose] = proposes(backend.calls)
    assert.ok(!JSON.stringify(propose.body).includes('qualifiesAsAdult'))
  })
})

describe('employment refusal', () => {
  it('is an actual 200 NO_PATH with null plan: no guard, no tx, no consent', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(null, intent, { recommendation: 'NO_PATH', reason: 'tenure cannot prove age' }),
      }),
      onGuard: () => { throw new Error('guard must not run without a candidate') },
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('employment')
    assert.equal(out.ok, true)
    assert.equal(out.available, true)
    assert.equal(out.refusal, true)
    assert.equal(out.plan, null)
    assert.equal(out.tx, null)
    assert.equal(out.meta.recommendation, 'NO_PATH')
    assert.deepEqual(out.echo.scopeCredentialTypes, [VCT_EMPLOYMENT])
    const [propose] = proposes(backend.calls)
    assert.ok(!JSON.stringify(propose.body).includes('yearsInEmployment'))
    assert.equal(guards(backend.calls).length, 0)
    assert.equal(svc.txStore.size, 0)
  })
})

describe('scope and echo binding', () => {
  it('out-of-scope candidates become NO_PATH without guard or tx', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_MAPPED }), intent),
      }),
      onGuard: () => { throw new Error('guard must not run for out-of-scope plans') },
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('fjord')
    assert.equal(out.refusal, true)
    assert.equal(out.meta.recommendation, 'NO_PATH')
    assert.match(out.meta.reason, /outside discovery scope/)
    assert.equal(out.tx, null)
    assert.equal(guards(backend.calls).length, 0)
  })

  it('mismatched backend scope echo fails closed', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => {
        const view = proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent)
        view.scopeCredentialTypes = [VCT_FJORD] // backend bound something else
        return { status: 200, json: view }
      },
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('known')
    assert.equal(out.ok, false)
    assert.equal(out.error, 'proposal_scope_mismatch')
  })
})

describe('guard outcomes', () => {
  it('denials surface with code and mint no tx', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH2, type: VCT_FJORD, claim: 'isAdult', policy: POLICY_MAPPED }), intent),
      }),
      onGuard: () => ({ status: 200, json: { accepted: false, code: 'GUARD_OVERBROAD_DISCLOSURE', reason: 'budget', rulesVersion: 'sovra-guard/2' } }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('fjord')
    assert.equal(out.refusal, true)
    assert.equal(out.guard.code, 'GUARD_OVERBROAD_DISCLOSURE')
    assert.ok(out.plan)
    assert.equal(out.tx, null)
  })

  it('malformed plans fail closed', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200, json: proposalFor({ plan_id: 'x' }, intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('known')
    assert.equal(out.ok, false)
    assert.equal(out.error, 'proposal_malformed')
  })
})

describe('legacy backend honesty', () => {
  const OLD_STATUS = {
    mode: 'FIXTURE', liveEnabled: false, modelConfigured: false,
    promptVersion: 'sovra-planner-prompts/2', toolContractVersion: 'sovra-planner-tools/1',
    toolSchemaHash: 'old', baselineVersion: 'sovra-baseline-planner/1', tools: [],
  }

  it('known retries once unscoped after a scoped 400', async () => {
    let n = 0
    const backend = fakeBackend({
      status: OLD_STATUS,
      onPropose: (intent) => {
        n += 1
        if (n === 1) {
          assert.ok('scopeIssuerIds' in intent)
          return { status: 400, json: { error: 'unknown field' } }
        }
        assert.ok(!('scopeIssuerIds' in intent))
        return { status: 200, json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent) }
      },
      onGuard: () => ({ status: 200, json: { ...ACCEPT, rulesVersion: 'sovra-guard/1' } }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('known')
    assert.equal(out.ok, true)
    assert.equal(out.refusal, false)
    assert.equal(proposes(backend.calls).length, 2)
  })

  it('unfamiliar 400 discriminates via guard with no second propose', async () => {
    const backend = fakeBackend({
      status: OLD_STATUS,
      onPropose: () => ({ status: 400, json: { error: 'unknown field' } }),
      onGuard: (body) => {
        if (body.policyId === POLICY_MAPPED) {
          return { status: 200, json: { accepted: false, code: 'GUARD_UNKNOWN_POLICY', reason: 'nope', rulesVersion: 'sovra-guard/1' } }
        }
        return { status: 200, json: ACCEPT }
      },
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('fjord')
    assert.equal(out.ok, true)
    assert.equal(out.available, false)
    assert.equal(out.reason, 'backend_mapped_policy_pending')
    assert.equal(proposes(backend.calls).length, 1)
  })

  it('non-400 failures are never relabeled scope-unsupported', async () => {
    for (const status of [500, 0]) {
      const backend = fakeBackend({
        status: OLD_STATUS,
        onPropose: () => ({ status, json: null }),
        onGuard: () => ({ status: 200, json: ACCEPT }),
      })
      const svc = createInteropService({ nodes: NODES, call: backend.call })
      const out = await svc.postPlan('fjord')
      assert.equal(out.ok, false)
      assert.equal(out.error, 'proposal_failed')
    }
    const down = fakeBackend({
      status: OLD_STATUS,
      onPropose: () => ({ status: 503, json: null }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: down.call })
    const out = await svc.postPlan('known')
    assert.equal(out.error, 'planner_unavailable')
  })
})

describe('mode honesty', () => {
  it('expectMode fails closed instead of relabeling fixture output', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    const out = await svc.postPlan('known', { expectMode: 'LIVE' })
    assert.equal(out.ok, false)
    assert.equal(out.error, 'mode_mismatch')
    assert.equal(out.mode, 'FIXTURE')
  })
})

describe('transaction store and binding', () => {
  async function plannedTx(overrides = {}) {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
      ...overrides.backend,
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call, ...(overrides.svc ?? {}) })
    const planned = await svc.postPlan('known')
    return { svc, planned, backend }
  }

  it('refuses unknown, tampered, and expired transactions', async () => {
    let t = 1_000_000
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({
      nodes: NODES, call: backend.call, now: () => t,
      txStore: createTxStore({ now: () => t, ttlMs: 60_000 }),
    })
    const planned = await svc.postPlan('known')
    assert.equal((await svc.postSetup({ tx: 'itx_nope', holderJwk: {}, holderProof: 'p', idem: 'i' })).error, 'invalid_tx')
    assert.equal((await svc.postSetup({ tx: planned.tx + 'x', holderJwk: {}, holderProof: 'p', idem: 'i' })).error, 'invalid_tx')
    t += 61_000
    assert.equal((await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i' })).error, 'invalid_tx')
  })

  it('refuses creation past capacity instead of growing', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes: NODES, call: backend.call, txStore: createTxStore({ maxEntries: 1 }) })
    assert.equal((await svc.postPlan('known')).ok, true)
    const full = await svc.postPlan('known')
    assert.equal(full.ok, false)
    assert.equal(full.error, 'tx_store_full')
  })

  it('binds credential/request ids and allows only one issuance per tx', async () => {
    const { svc, planned, backend } = await plannedTx()
    const issuanceCount = () => backend.calls.filter((c) => c.path === '/api/issuance/credentials').length
    const setup = await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i-1' })
    assert.equal(setup.ok, true)
    assert.equal(issuanceCount(), 1)
    // Same idem replays the bound id with no new upstream issuance.
    const replay = await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i-1' })
    assert.deepEqual(replay, setup)
    assert.equal(issuanceCount(), 1)
    const second = await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i-2' })
    assert.equal(second.error, 'tx_issuance_bound')
    assert.equal(issuanceCount(), 1)

    const wrongCred = await svc.postRequest({ tx: planned.tx, credentialId: '33333333-3333-4333-8333-333333333333' })
    assert.equal(wrongCred.error, 'credential_not_bound')

    // A fresh tx without setup cannot request.
    const other = fakeBackend({
      onPropose: (intent) => ({ status: 200, json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent) }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc2 = createInteropService({ nodes: NODES, call: other.call })
    const planned2 = await svc2.postPlan('known')
    const noCred = await svc2.postRequest({ tx: planned2.tx, credentialId: setup.credentialId })
    assert.equal(noCred.error, 'tx_no_credential')

    const req = await svc.postRequest({ tx: planned.tx, credentialId: setup.credentialId })
    assert.equal(req.ok, true)
    const wrongReq = await svc.postDecision({ tx: planned.tx, requestId: '44444444-4444-4444-8444-444444444444', decision: 'approve', holderJwk: {}, consentProof: 'c' })
    assert.equal(wrongReq.error, 'request_not_bound')
    const wrongVer = await svc.postVerify({ tx: planned.tx, requestId: '44444444-4444-4444-8444-444444444444', nonce: 'n', holderJwk: {}, bindingProof: 'b' })
    assert.equal(wrongVer.error, 'request_not_bound')
  })

  it('unknown cases spend zero upstream calls', async () => {
    const backend = fakeBackend({})
    const svc = createInteropService({ nodes: NODES, call: backend.call })
    for (const name of ['__proto__', 'constructor', 'toString', 'nope']) {
      const out = await svc.postPlan(name)
      assert.equal(out.error, 'unknown_case')
    }
    assert.equal(backend.calls.length, 0)
  })

  it('consent echo mismatch fails closed', async () => {
    const backend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const call = async (node, method, path, token, body) => {
      if (method === 'GET' && path.startsWith('/api/consent/requests/')) {
        return { status: 200, json: { requestId: 'r', planHash: 'deadbeef', challenge: 'c', expiresAt: new Date().toISOString(), rpId: 'rp', audience: 'aud', purpose: 'p' } }
      }
      return backend.call(node, method, path, token, body)
    }
    const svc = createInteropService({ nodes: NODES, call })
    const planned = await svc.postPlan('known')
    const setup = await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i' })
    const req = await svc.postRequest({ tx: planned.tx, credentialId: setup.credentialId })
    assert.equal(req.ok, false)
    assert.equal(req.error, 'consent_echo_mismatch')
  })
})

function deferred() {
  let resolve
  const promise = new Promise((r) => { resolve = r })
  return { promise, resolve }
}

async function plannedKnownTx(call) {
  const svc = createInteropService({ nodes: NODES, call })
  const planned = await svc.postPlan('known')
  assert.equal(planned.ok, true)
  return { svc, tx: planned.tx }
}

function knownProposeGuard() {
  return {
    onPropose: (intent) => ({
      status: 200,
      json: proposalFor(planFor({ issuer: ISSUER_SYNTH1, type: VCT_ADULT, claim: 'adultOver18', policy: POLICY_LEGACY }), intent),
    }),
    onGuard: () => ({ status: 200, json: ACCEPT }),
  }
}

describe('issuance concurrency and uncertainty', () => {
  it('simultaneous setup with different idem sends one issuance; second sees in-progress', async () => {
    const backend = fakeBackend(knownProposeGuard())
    const gate = deferred()
    const started = deferred()
    const issueBodies = []
    let issues = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/issuance/credentials') {
        issues += 1
        issueBodies.push({ ...body })
        started.resolve()
        await gate.promise
        return { status: 201, json: { credentialId: `11111111-1111-4111-8111-11111111111${issues}` } }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx } = await plannedKnownTx(call)
    const holder = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }
    const p1 = svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'first-idem' })
    const p2 = svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'second-idem' })
    await started.promise
    const r2 = await p2
    assert.equal(r2.ok, false)
    assert.equal(r2.error, 'tx_issuance_in_progress')
    gate.resolve()
    const r1 = await p1
    assert.equal(r1.ok, true)
    assert.equal(issues, 1)
    assert.equal(issueBodies[0].idem, 'first-idem')
    assert.equal(svc.txStore.get(tx).credentialId, r1.credentialId)
  })

  it('identical simultaneous setup coalesces onto one issuance', async () => {
    const backend = fakeBackend(knownProposeGuard())
    const gate = deferred()
    const started = deferred()
    let issues = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/issuance/credentials') {
        issues += 1
        started.resolve()
        await gate.promise
        return { status: 201, json: { credentialId: '11111111-1111-4111-8111-111111111111' } }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx } = await plannedKnownTx(call)
    const holder = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }
    const p1 = svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'same-idem' })
    const p2 = svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'same-idem' })
    await started.promise
    gate.resolve()
    const [r1, r2] = await Promise.all([p1, p2])
    assert.equal(r1.ok, true)
    assert.equal(r2.ok, true)
    assert.equal(r1.credentialId, r2.credentialId)
    assert.equal(issues, 1)
  })

  it('same idem with a changed holder conflicts instead of replaying success', async () => {
    const backend = fakeBackend(knownProposeGuard())
    let issues = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/issuance/credentials') issues += 1
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx } = await plannedKnownTx(call)
    const a = { kty: 'EC', crv: 'P-256', x: 'a', y: 'a' }
    const b = { kty: 'EC', crv: 'P-256', x: 'b', y: 'b' }
    const first = await svc.postSetup({ tx, holderJwk: a, holderProof: 'pa', idem: 'i-1' })
    assert.equal(first.ok, true)
    const changed = await svc.postSetup({ tx, holderJwk: b, holderProof: 'pb', idem: 'i-1' })
    assert.equal(changed.ok, false)
    assert.equal(changed.error, 'tx_issuance_conflict')
    assert.equal(issues, 1)
    const replay = await svc.postSetup({ tx, holderJwk: a, holderProof: 'pa', idem: 'i-1' })
    assert.deepEqual(replay, first)
    assert.equal(issues, 1)
  })

  it('uncertain issuance reuses the exact frozen request; new idem is refused', async () => {
    const backend = fakeBackend(knownProposeGuard())
    const issueBodies = []
    let issues = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/issuance/credentials') {
        issues += 1
        issueBodies.push(JSON.parse(JSON.stringify(body)))
        if (issues === 1) return { status: 0, json: null }
        return { status: 201, json: { credentialId: '11111111-1111-4111-8111-111111111111' } }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx } = await plannedKnownTx(call)
    const holder = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }
    const lost = await svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'i-9' })
    assert.equal(lost.ok, false)
    assert.equal(lost.error, 'issuance_uncertain')
    assert.equal(issues, 1)
    const replaced = await svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'i-other' })
    assert.equal(replaced.error, 'tx_issuance_uncertain')
    assert.equal(issues, 1)
    const changed = await svc.postSetup({
      tx, holderJwk: { kty: 'EC', crv: 'P-256', x: 'z', y: 'z' }, holderProof: 'pz', idem: 'i-9',
    })
    assert.equal(changed.error, 'tx_issuance_conflict')
    assert.equal(issues, 1)
    const retry = await svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'i-9' })
    assert.equal(retry.ok, true)
    assert.equal(issues, 2)
    assert.deepEqual(issueBodies[1], issueBodies[0])
    assert.equal(issueBodies[1].expiresAt, issueBodies[0].expiresAt)
  })

  it('upstream 409 surfaces as issuance_conflict without binding the tx', async () => {
    const backend = fakeBackend(knownProposeGuard())
    let issues = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/issuance/credentials') {
        issues += 1
        if (issues === 1) return { status: 409, json: { error: 'idempotency_conflict' } }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx } = await plannedKnownTx(call)
    const holder = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }
    const conflict = await svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'i-clash' })
    assert.equal(conflict.ok, false)
    assert.equal(conflict.error, 'issuance_conflict')
    assert.equal(svc.txStore.get(tx).credentialId, null)
    const retry = await svc.postSetup({ tx, holderJwk: holder, holderProof: 'p', idem: 'i-fresh' })
    assert.equal(retry.ok, true)
    assert.equal(issues, 2)
  })
})

describe('consent concurrency and review honesty', () => {
  async function setupTx(call) {
    const { svc, tx } = await plannedKnownTx(call)
    const setup = await svc.postSetup({ tx, holderJwk: {}, holderProof: 'p', idem: 'i-1' })
    assert.equal(setup.ok, true)
    return { svc, tx, credentialId: setup.credentialId }
  }

  it('simultaneous postRequest opens one consent and coalesces', async () => {
    const backend = fakeBackend(knownProposeGuard())
    const gate = deferred()
    const started = deferred()
    let creates = 0
    let reads = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/consent/requests') {
        creates += 1
        started.resolve()
        await gate.promise
      }
      if (method === 'GET' && path.startsWith('/api/consent/requests/')) reads += 1
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx, credentialId } = await setupTx(call)
    const p1 = svc.postRequest({ tx, credentialId })
    const p2 = svc.postRequest({ tx, credentialId })
    await started.promise
    gate.resolve()
    const [r1, r2] = await Promise.all([p1, p2])
    assert.equal(r1.ok, true)
    assert.equal(r2.ok, true)
    assert.equal(r1.requestId, r2.requestId)
    assert.equal(creates, 1)
    assert.equal(reads, 1)
  })

  it('lost create response marks the tx uncertain; retries never recreate', async () => {
    const backend = fakeBackend(knownProposeGuard())
    let creates = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/consent/requests') {
        creates += 1
        return { status: 0, json: null }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx, credentialId } = await setupTx(call)
    const lost = await svc.postRequest({ tx, credentialId })
    assert.equal(lost.ok, false)
    assert.equal(lost.error, 'request_uncertain')
    assert.equal(creates, 1)
    const retry = await svc.postRequest({ tx, credentialId })
    assert.equal(retry.error, 'request_uncertain')
    assert.equal(creates, 1)
    assert.equal(svc.txStore.get(tx).requestId, null)
  })

  it('201 then failed review saves the id; retry rereads without recreating', async () => {
    const backend = fakeBackend(knownProposeGuard())
    let creates = 0
    let reads = 0
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/consent/requests') creates += 1
      if (method === 'GET' && path.startsWith('/api/consent/requests/')) {
        reads += 1
        if (reads === 1) return { status: 503, json: null }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx, credentialId } = await setupTx(call)
    const first = await svc.postRequest({ tx, credentialId })
    assert.equal(first.ok, false)
    assert.equal(first.error, 'request_review_unavailable')
    assert.ok(first.requestId)
    assert.equal(creates, 1)
    assert.equal(reads, 1)
    assert.equal(svc.txStore.get(tx).requestId, first.requestId)
    const retry = await svc.postRequest({ tx, credentialId })
    assert.equal(retry.ok, true)
    assert.equal(retry.requestId, first.requestId)
    assert.equal(creates, 1)
    assert.equal(reads, 2)
  })

  it('reread requires 200 with matching request and hash', async () => {
    const backend = fakeBackend(knownProposeGuard())
    let creates = 0
    let reads = 0
    let nextRead = null
    const call = async (node, method, path, token, body) => {
      if (method === 'POST' && path === '/api/consent/requests') creates += 1
      if (method === 'GET' && path.startsWith('/api/consent/requests/')) {
        reads += 1
        if (nextRead) {
          const out = nextRead
          nextRead = null
          return out
        }
      }
      return backend.call(node, method, path, token, body)
    }
    const { svc, tx, credentialId } = await setupTx(call)
    const opened = await svc.postRequest({ tx, credentialId })
    assert.equal(opened.ok, true)
    const storedHash = svc.txStore.get(tx).planHash
    const cases = [
      [{ status: 404, json: null }, 'request_not_found'],
      [{ status: 503, json: null }, 'request_review_unavailable'],
      [{ status: 200, json: null }, 'request_review_unavailable'],
      [{ status: 200, json: { requestId: '00000000-0000-4000-8000-000000000000', planHash: storedHash } }, 'consent_echo_mismatch'],
      [{ status: 200, json: { requestId: opened.requestId, planHash: 'deadbeef'.padEnd(64, '0') } }, 'consent_echo_mismatch'],
    ]
    for (const [read, error] of cases) {
      nextRead = read
      const out = await svc.postRequest({ tx, credentialId })
      assert.equal(out.ok, false)
      assert.equal(out.error, error)
      assert.equal(out.requestId, opened.requestId)
    }
    assert.equal(creates, 1)
  })
})

describe('unconfigured issuer node', () => {
  it('fails closed before any synth2 upstream contact', async () => {
    const backend = fakeBackend(knownProposeGuard())
    const nodes = {
      default: { base: 'http://central', rpToken: 'rp-central', issuerToken: 'issuer-central' },
      synth2: { base: 'http://issuer2', rpToken: '', issuerToken: '' },
    }
    const fjordBackend = fakeBackend({
      onPropose: (intent) => ({
        status: 200,
        json: proposalFor(planFor({ issuer: ISSUER_SYNTH2, type: VCT_FJORD, claim: 'isAdult', policy: POLICY_MAPPED }), intent),
      }),
      onGuard: () => ({ status: 200, json: ACCEPT }),
    })
    const svc = createInteropService({ nodes, call: fjordBackend.call })
    const caps = await svc.getStatus()
    assert.equal(caps.synth2Unconfigured, true)
    assert.equal(caps.synth2.unconfigured, true)
    assert.ok(fjordBackend.calls.every((c) => c.base === 'http://central'))
    const planned = await svc.postPlan('fjord')
    assert.equal(planned.ok, true)
    const setup = await svc.postSetup({ tx: planned.tx, holderJwk: {}, holderProof: 'p', idem: 'i-1' })
    assert.equal(setup.ok, false)
    assert.equal(setup.error, 'issuer_node_unconfigured')
    assert.equal(fjordBackend.calls.filter((c) => c.base === 'http://issuer2').length, 0)
    assert.ok(backend.calls.length >= 0)
  })
})
