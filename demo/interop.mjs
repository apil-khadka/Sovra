// Interoperability demo core (importable, no boot side effects).
//
// Builds scoped planner intents with the backend's FLAT scope wire
// fields, validates returned proposals, binds plans to their discovery
// scope, and holds the exact guarded plan in a bounded server-side
// transaction the browser can only reference by id. The HTTP skin lives
// in server.mjs; the dishonest shortcuts live nowhere: every
// consent/issuance input derives from the returned, guarded plan, and
// unfamiliar wire fields are discovered from the proposal, never
// supplied by the UI.
//
// Backend wire contract (read from PlanningController/Intent/Intents in
// the backend worktree 2026-11-03; demo detects support, never assumes):
// - requestedClaims is REQUIRED and non-empty; each entry must be a
//   registry-approved spelling of age_over_18. Unseen cases send the
//   legacy ['adultOver18'] hint plus mapped policy plus issuer/type
//   scope — the unfamiliar wire field (isAdult/qualifiesAsAdult) is
//   never in the intent, so the planner must discover it from metadata.
// - Optional flat scope: scopeIssuerIds, scopeCredentialTypes,
//   scopeJurisdictions (each max 8, each <=512 chars, non-blank).
//   Null/empty means unscoped (legacy behavior). Unknown scope values
//   yield NO_PATH at planning time, never 400.
// - Scope binding + prompt /3 + guard /2 ship with the backend work;
//   the demo probes for them and labels unsupported cases honestly.

import { createHash, randomBytes } from 'node:crypto'

export const OUTCOME = 'age_over_18'

export const ISSUER_SYNTH1 = 'https://sovra.example/issuers/synth-1'
export const ISSUER_SYNTH2 = 'https://sovra.example/issuers/synth-2'
export const VCT_ADULT = 'https://sovra.example/vct/adult-status/1'
export const VCT_FJORD = 'https://sovra.example/vct/fjord-adult/1'
export const VCT_HARBOR = 'https://sovra.example/vct/harbor-adult/1'
export const VCT_EMPLOYMENT = 'https://sovra.example/vct/employment-tenure/1'

export const POLICY_LEGACY = 'sovra-synthetic-policy/age-check'
export const POLICY_MAPPED = 'sovra-synthetic-policy/age-check-mapped'
export const POLICY_VERSION = '1'

// Legacy semantic hint: a registry-approved spelling of age_over_18
// that names no unfamiliar wire field. Unseen cases pair this with
// mapped policy + issuer/type scope so discovery must happen inside
// the planner over approved metadata.
export const LEGACY_HINT_CLAIMS = ['adultOver18']

export const INTEROP_RP = {
  rpId: 'https://interop.demo.sovra.example/age-check',
  audience: 'https://interop.demo.sovra.example/age-check/callback',
  purpose: 'synthetic age check with unfamiliar-schema discovery (demo)',
}

// Four runnable cases. Unfamiliar cases request the SEMANTIC outcome
// via the legacy hint plus mapped policy plus a narrowing scope: the
// wire field (isAdult / qualifiesAsAdult) must be discovered from
// approved metadata and read back out of the returned plan. The
// employment case scopes to a tenure source that cannot satisfy
// age_over_18 and must end in NO_PATH refusal.
export const CASES = {
  known: {
    policyId: POLICY_LEGACY,
    requestedClaims: ['adultOver18'],
    // Legacy-pinned scope once the backend supports it; omitted on
    // legacy-only backends (feature-detected at runtime).
    scopeIssuerIds: [ISSUER_SYNTH1],
    scopeCredentialTypes: [VCT_ADULT],
    scopeJurisdictions: [],
    label: 'Known schema (adult-status)',
  },
  fjord: {
    policyId: POLICY_MAPPED,
    requestedClaims: [...LEGACY_HINT_CLAIMS],
    scopeIssuerIds: [ISSUER_SYNTH2],
    scopeCredentialTypes: [VCT_FJORD],
    scopeJurisdictions: [],
    label: 'Unfamiliar compatible schema (Fjord)',
  },
  harbor: {
    policyId: POLICY_MAPPED,
    requestedClaims: [...LEGACY_HINT_CLAIMS],
    scopeIssuerIds: [ISSUER_SYNTH2],
    scopeCredentialTypes: [VCT_HARBOR],
    scopeJurisdictions: [],
    label: 'Unfamiliar compatible schema (Harbor)',
  },
  employment: {
    policyId: POLICY_MAPPED,
    requestedClaims: [...LEGACY_HINT_CLAIMS],
    scopeIssuerIds: [ISSUER_SYNTH2],
    scopeCredentialTypes: [VCT_EMPLOYMENT],
    scopeJurisdictions: [],
    label: 'Incompatible schema (employment tenure)',
  },
}

export function isCase(value) {
  // Object.hasOwn, not `in`: inherited names (__proto__, constructor,
  // toString) must never pass as cases. Pinned by regression test.
  return typeof value === 'string' && Object.hasOwn(CASES, value)
}

/** Flat scope object for one case (backend wire shape). */
export function scopeFor(caseId) {
  if (!isCase(caseId)) throw new Error('unknown_interop_case')
  const def = CASES[caseId]
  return {
    scopeIssuerIds: [...def.scopeIssuerIds],
    scopeCredentialTypes: [...def.scopeCredentialTypes],
    scopeJurisdictions: [...def.scopeJurisdictions],
  }
}

/**
 * Intent for one case. scopeSupported=false omits the flat scope
 * members (legacy backends reject unknown members with 400);
 * unfamiliar cases then report honestly unavailable instead of
 * running scopeless.
 */
export function buildIntent(caseId, { scopeSupported }) {
  if (!isCase(caseId)) throw new Error('unknown_interop_case')
  const def = CASES[caseId]
  const intent = {
    rpId: INTEROP_RP.rpId,
    audience: INTEROP_RP.audience,
    purpose: INTEROP_RP.purpose,
    outcome: OUTCOME,
    policyId: def.policyId,
    policyVersion: POLICY_VERSION,
    requestedClaims: [...def.requestedClaims],
  }
  if (scopeSupported) {
    intent.scopeIssuerIds = [...def.scopeIssuerIds]
    intent.scopeCredentialTypes = [...def.scopeCredentialTypes]
    if (def.scopeJurisdictions.length > 0) intent.scopeJurisdictions = [...def.scopeJurisdictions]
  }
  return intent
}

/** Cases other than known require backend scope support to run honestly. */
export function caseNeedsScope(caseId) {
  return isCase(caseId) && caseId !== 'known'
}

/**
 * Generalized canonical plan hash (sovra-plan/v1). For the legacy plan
 * shape this renders byte-identically to the old planHash(planId) in
 * server.mjs — pinned by test — while unfamiliar plans hash their own
 * exact issuer/type/claims/evidence/policy values.
 */
export function canonicalPlanHash(plan) {
  if (plan === null || typeof plan !== 'object') throw new Error('plan_missing')
  const claimsCsv = [...(plan.claim_paths ?? [])].join(',')
  const evidenceCsv = [...(plan.evidence ?? [])]
    .map((c) => `${c.document_id}#${c.section_id}`).join(',')
  const canonical = [
    'sovra-plan/v1',
    plan.plan_id,
    plan.requested_outcome,
    plan.candidate_issuer_id,
    plan.credential_type,
    claimsCsv,
    evidenceCsv,
    plan.policy_id,
    plan.policy_version,
    plan.recommendation,
    '',
  ].join('\n')
  return createHash('sha256').update(canonical, 'utf-8').digest('hex')
}

/**
 * True when a returned plan sits inside the requested flat scope.
 * Jurisdiction hints need the issuer's scope string to check; the
 * server is authoritative for that leg, so callers without issuer
 * scope metadata pass null and the check is skipped client-side.
 */
export function scopeAllows(scope, plan, issuerScope = null) {
  if (scope === undefined || scope === null) return true
  if (plan === null || typeof plan !== 'object') return false
  const { scopeIssuerIds, scopeCredentialTypes, scopeJurisdictions } = scope
  if (Array.isArray(scopeIssuerIds) && scopeIssuerIds.length > 0
    && !scopeIssuerIds.includes(plan.candidate_issuer_id)) return false
  if (Array.isArray(scopeCredentialTypes) && scopeCredentialTypes.length > 0
    && !scopeCredentialTypes.includes(plan.credential_type)) return false
  if (Array.isArray(scopeJurisdictions) && scopeJurisdictions.length > 0 && issuerScope !== null) {
    if (typeof issuerScope !== 'string'
      || !scopeJurisdictions.some((h) => typeof h === 'string' && h !== '' && issuerScope.includes(h))) return false
  }
  return true
}

const PLAN_KEYS = [
  'plan_id', 'requested_outcome', 'candidate_issuer_id', 'credential_type',
  'claim_paths', 'evidence', 'policy_id', 'policy_version', 'recommendation',
]

/**
 * Strict shape check on a proposal's plan wire object. Returns the plan
 * when it is a well-formed object with every required member of the
 * expected JSON shape, else throws. Semantics (trust, budget, binding)
 * stay the guard's job; this only stops malformed data entering a tx.
 */
export function checkPlanShape(plan) {
  if (plan === null || typeof plan !== 'object' || Array.isArray(plan)) {
    throw new Error('plan_malformed')
  }
  for (const key of PLAN_KEYS) {
    if (!(key in plan)) throw new Error(`plan_malformed:${key}`)
  }
  if (typeof plan.plan_id !== 'string' || plan.plan_id === '') throw new Error('plan_malformed:plan_id')
  if (!Array.isArray(plan.claim_paths) || plan.claim_paths.length === 0
    || !plan.claim_paths.every((c) => typeof c === 'string' && c !== '')) {
    throw new Error('plan_malformed:claim_paths')
  }
  if (!Array.isArray(plan.evidence)
    || !plan.evidence.every((c) => c !== null && typeof c === 'object'
      && typeof c.document_id === 'string' && typeof c.section_id === 'string')) {
    throw new Error('plan_malformed:evidence')
  }
  for (const key of ['requested_outcome', 'candidate_issuer_id', 'credential_type', 'policy_id', 'policy_version', 'recommendation']) {
    if (typeof plan[key] !== 'string' || plan[key] === '') throw new Error(`plan_malformed:${key}`)
  }
  if (!['CANDIDATE_ONLY', 'NO_PATH', 'MANUAL_REVIEW'].includes(plan.recommendation)) {
    throw new Error('plan_malformed:recommendation')
  }
  return plan
}

/**
 * Claim object for issuance/consent, derived from the RETURNED plan's
 * exact claim_paths. G1 carries one boolean claim asserted true; any
 * other shape fails closed here rather than guessing wire values.
 */
export function claimsForPlan(plan) {
  checkPlanShape(plan)
  if (plan.claim_paths.length !== 1) throw new Error('plan_claims_not_minimal')
  return { [plan.claim_paths[0]]: true }
}

/** Sorted key=value canonical form for proof messages (single claim). */
export function claimsCanonicalForPlan(plan) {
  const claims = claimsForPlan(plan)
  return Object.keys(claims).sort().map((k) => `${k}=${claims[k]}`).join(',')
}

/**
 * Bounded in-memory plan transaction store. Entries expire lazily;
 * unknown, expired, or tampered ids read back as null so the caller
 * fails closed with invalid_tx. The store is finite: create() sweeps
 * expired entries first (a bounded scan — at most maxEntries), then
 * refuses with tx_store_full at capacity instead of growing without
 * end. Abandoned transactions therefore cannot leak indefinitely:
 * they are reclaimed by the next create sweep or their own get.
 */
export function createTxStore({
  ttlMs = 10 * 60_000, now = () => Date.now(),
  bytes = (n) => randomBytes(n), maxEntries = 500,
} = {}) {
  const entries = new Map()
  function pruneExpired() {
    for (const [id, entry] of entries) {
      if (now() >= entry.expiresAt) entries.delete(id)
    }
  }
  return {
    create(value) {
      pruneExpired()
      if (entries.size >= maxEntries) throw new Error('tx_store_full')
      const id = `itx_${bytes(12).toString('hex')}`
      entries.set(id, { value, expiresAt: now() + ttlMs })
      return id
    },
    get(id) {
      if (typeof id !== 'string') return null
      const found = entries.get(id)
      if (!found) return null
      if (now() >= found.expiresAt) {
        entries.delete(id)
        return null
      }
      return found.value
    },
    get size() {
      return entries.size
    },
  }
}

/**
 * Interop service: honest planner/guard/tx orchestration over injected
 * per-node upstreams. nodes: { default: {base, rpToken, issuerToken},
 * synth2: {...} } where synth2 defaults to default (single-node). call
 * is async (node, method, path, token, body) -> {status, json}.
 *
 * Routing is fixed by the topology contract: ALL planning and guard
 * calls go to the ONE central node/ledger (nodes.default, node A) —
 * never to the secondary by case. Issuance, consent, decision, and
 * verification route by the ACTUAL returned plan issuer to the node
 * holding that issuer's key, with that node's OWN base URL and tokens
 * (the independent DB cannot honor the other node's tokens).
 * issuerToken is the issuance-capable token (ISSUER_OPS +
 * TENANT_MEMBER, same tenant as the node's RP token) — never a
 * TRUST_ADMIN setup/maker/checker token, which the demo server must
 * not hold at all.
 */
export function createInteropService({
  nodes, call, txStore = createTxStore(),
  now = () => Date.now(),
  isoPlusHours = (h) => new Date(now() + h * 3600_000).toISOString().replace('.000Z', 'Z'),
  randomChallenge = () => randomBytes(24).toString('base64url'),
}) {
  if (typeof call !== 'function') throw new Error('upstream_missing')
  if (!nodes?.default?.rpToken || !nodes?.default?.issuerToken) throw new Error('node_tokens_missing')
  const synth2 = nodes.synth2 ?? nodes.default
  const synth2Configured = synth2.base !== nodes.default.base
    || synth2.rpToken !== nodes.default.rpToken
    || synth2.issuerToken !== nodes.default.issuerToken

  const nodeForIssuer = (issuerId) => (issuerId === ISSUER_SYNTH2 ? synth2 : nodes.default)
  const synth2BaseDiffers = synth2.base !== nodes.default.base
  const synth2TokensPresent = Boolean(synth2.rpToken) && Boolean(synth2.issuerToken)
  const synth2Unconfigured = synth2BaseDiffers && !synth2TokensPresent
  const isNodeUnconfigured = (node) => node === synth2 && synth2Unconfigured

  // Public-key fingerprint for issuance binding: same idem + different
  // holder must conflict, never replay cached success. The proof message
  // binds idem/vct/thumbprint/claims, so holder identity is part of the
  // idempotency hash upstream.
  function holderFingerprint(holderJwk, holderProof) {
    return `${JSON.stringify(holderJwk)}\n${holderProof}`
  }

  // Strict consent-review check: HTTP 200 + object + matching request id
  // + exact plan hash. Anything else fails closed with a distinct error
  // so known absence (404) never masquerades as success and transient
  // read failures never invent a review.
  function checkReview(review, expectedRequestId, expectedPlanHash) {
    if (review?.status === 404) return { ok: false, error: 'request_not_found', status: 404 }
    if (review?.status !== 200 || review?.json === null || typeof review?.json !== 'object'
      || Array.isArray(review.json)) {
      return { ok: false, error: 'request_review_unavailable', status: review?.status ?? 0 }
    }
    if (String(review.json.requestId) !== String(expectedRequestId)) {
      return { ok: false, error: 'consent_echo_mismatch', status: review.status }
    }
    if (review.json.planHash !== expectedPlanHash) {
      return { ok: false, error: 'consent_echo_mismatch', status: review.status }
    }
    return { ok: true }
  }

  async function safeCall(node, method, path, token, body) {
    try {
      return await call(node, method, path, token, body)
    } catch {
      return { status: 0, json: null }
    }
  }

  let capsCache = null
  let capsAt = 0
  const CAPS_TTL_MS = 60_000

  // Observed feature flags for the CENTRAL planner, learned ONLY from
  // declared demo actions (postPlan propose/guard outcomes), never from
  // hidden probes. null means unknown — not yet observed. Last
  // observation wins, so flags self-correct across backend upgrades.
  // Preferred source is the backend's own read-only status metadata;
  // observations only fill gaps on backends that predate it.
  const observed = { scopeSupported: null, mappedSupported: null, guardRulesVersion: null }
  const noteGuardVersion = (guard) => {
    if (guard?.rulesVersion) observed.guardRulesVersion = guard.rulesVersion
  }

  // True when the backend's advertised policy bindings include the
  // mapped unfamiliar-schema binding. null when the backend does not
  // advertise bindings at all (predates the capability metadata).
  function mappedInBindings(planner) {
    if (!Array.isArray(planner?.supportedPolicyBindings)) return null
    return planner.supportedPolicyBindings.some(
      (b) => b?.policyId === POLICY_MAPPED && b?.policyVersion === POLICY_VERSION,
    )
  }

  // Read-only node status. This is the ONLY upstream contact behind
  // GET status: it must NEVER call /plans/propose, because with live
  // armed each propose spends a real model call — opening a status
  // page must not burn the demo's action budget. Capability fields are
  // READ from the backend's own status metadata
  // (discoveryScopeSupported, supportedPolicyBindings, guardRulesVersion,
  // schemaRegistryVersion); only when the backend predates that metadata
  // do central planning observations fill the gap. No version string is
  // ever hardcoded as the support test.
  async function probeNode(node, { central }) {
    const status = await call(node, 'GET', '/api/plans/status', node.rpToken)
    const planner = status.status === 200 ? status.json : null
    const seen = central ? observed : null
    return {
      reachable: status.status === 200,
      mode: planner?.mode ?? null,
      liveEnabled: planner?.liveEnabled ?? false,
      modelConfigured: planner?.modelConfigured ?? false,
      promptVersion: planner?.promptVersion ?? null,
      toolContractVersion: planner?.toolContractVersion ?? null,
      toolSchemaHash: planner?.toolSchemaHash ?? null,
      baselineVersion: planner?.baselineVersion ?? null,
      tools: Array.isArray(planner?.tools) ? planner.tools : null,
      discoveryScopeSupported: planner?.discoveryScopeSupported ?? null,
      schemaRegistryVersion: planner?.schemaRegistryVersion ?? null,
      guardRulesVersion: planner?.guardRulesVersion ?? seen?.guardRulesVersion ?? null,
      supportedPolicyBindings: Array.isArray(planner?.supportedPolicyBindings)
        ? planner.supportedPolicyBindings
        : null,
      scopeSupported: planner?.discoveryScopeSupported ?? seen?.scopeSupported ?? null,
      mappedSupported: mappedInBindings(planner) ?? seen?.mappedSupported ?? null,
    }
  }

  // Every flag below is READ from a live upstream response in this
  // process (status fields) or OBSERVED from a declared action outcome
  // — never asserted from a hardcoded desired version string, and
  // never learned from a hidden model call.
  async function capabilities() {
    if (capsCache && now() - capsAt < CAPS_TTL_MS) return capsCache
    const primary = await probeNode(nodes.default, { central: true })
    let secondary = null
    if (synth2Unconfigured) {
      secondary = {
        unconfigured: true, reachable: false, mode: null, liveEnabled: false,
        modelConfigured: false, promptVersion: null, toolContractVersion: null,
        toolSchemaHash: null, baselineVersion: null, tools: null,
        discoveryScopeSupported: null, schemaRegistryVersion: null,
        guardRulesVersion: null, supportedPolicyBindings: null,
        scopeSupported: null, mappedSupported: null,
      }
    } else if (synth2Configured) {
      secondary = await probeNode(synth2, { central: false })
    }
    // Live is available only when a probed backend says so; the demo
    // never enables it and never substitutes fixture output for it.
    // Mode is backend-global: the UI only displays the returned mode.
    capsCache = {
      primary,
      synth2: secondary,
      synth2Configured,
      synth2Unconfigured,
      liveAvailable: primary.liveEnabled === true && primary.modelConfigured === true,
    }
    capsAt = now()
    return capsCache
  }

  // Model-free mapped-policy discriminator on the CENTRAL planner. When
  // a scoped+mapped propose 400s, the 400 is ambiguous (scope
  // unsupported? mapped unsupported? genuinely invalid?). The
  // deterministic guard settles the mapped leg without spending a model
  // call: a legacy backend answers accepted:false + GUARD_UNKNOWN_POLICY
  // for the mapped binding, while a contract backend adjudicates it.
  // Returns true / false / null (inconclusive — guard unreachable).
  // Called only inside the declared postPlan action, never from status.
  async function guardKnowsMapped() {
    const node = nodes.default
    const probe = await call(node, 'POST', '/api/guard/validate', node.rpToken, {
      plan: {
        plan_id: 'pln_probe_000000000000', requested_outcome: OUTCOME,
        candidate_issuer_id: ISSUER_SYNTH1, credential_type: VCT_ADULT,
        claim_paths: ['adultOver18'],
        evidence: [{ document_id: POLICY_MAPPED, section_id: 'mapped_age_eligibility' }],
        policy_id: POLICY_MAPPED, policy_version: POLICY_VERSION,
        recommendation: 'CANDIDATE_ONLY',
      },
      policyId: POLICY_MAPPED, policyVersion: POLICY_VERSION,
    })
    if (probe.status !== 200 || !probe.json) return null
    noteGuardVersion(probe.json)
    if (probe.json.code === 'GUARD_UNKNOWN_POLICY') return false
    return true
  }

  async function getStatus() {
    return capabilities()
  }

  function proposalMeta(proposal) {
    return {
      mode: proposal?.mode ?? null,
      liveAcceptance: proposal?.liveAcceptance ?? false,
      model: proposal?.model ?? null,
      promptVersion: proposal?.promptVersion ?? null,
      toolContractVersion: proposal?.toolContractVersion ?? null,
      toolSchemaHash: proposal?.toolSchemaHash ?? null,
      toolCalls: proposal?.toolCalls ?? 0,
      recommendation: proposal?.recommendation ?? null,
      reason: proposal?.reason ?? null,
      snapshotVersion: proposal?.snapshotVersion ?? null,
    }
  }

  // Backend scope echo from a proposal, or null when the backend does
  // not echo (predates the contract). Only what the backend returns.
  function scopeEchoOf(proposal) {
    if (!Array.isArray(proposal?.scopeIssuerIds)
      && !Array.isArray(proposal?.scopeCredentialTypes)
      && !Array.isArray(proposal?.scopeJurisdictions)) return null
    return {
      scopeIssuerIds: proposal.scopeIssuerIds ?? [],
      scopeCredentialTypes: proposal.scopeCredentialTypes ?? [],
      scopeJurisdictions: proposal.scopeJurisdictions ?? [],
    }
  }

  function sameList(a, b) {
    return Array.isArray(a) && Array.isArray(b)
      && a.length === b.length && a.every((v, i) => v === b[i])
  }

  function echoMatches(intent, echo) {
    return sameList(intent.scopeIssuerIds ?? [], echo.scopeIssuerIds)
      && sameList(intent.scopeCredentialTypes ?? [], echo.scopeCredentialTypes)
      && sameList(intent.scopeJurisdictions ?? [], echo.scopeJurisdictions)
  }

  // Plan one case on the CENTRAL ledger. expectMode (optional) fails
  // closed when the backend's returned mode differs: the demo can
  // require LIVE for a live-labelled run, but it can never relabel a
  // FIXTURE response — mode stays whatever the backend returned.
  async function postPlan(caseId, { expectMode } = {}) {
    if (!isCase(caseId)) return { ok: false, error: 'unknown_case' }
    const caps = await capabilities()
    const relearn = () => { capsCache = null }
    const central = caps.primary
    if (!central.reachable) {
      return { ok: false, error: 'planner_unavailable', status: 0, caps }
    }
    // Fast path from status metadata or prior observations: a planner
    // already known to lack scope or the mapped binding cannot run
    // unfamiliar cases, so no model call is spent relearning it.
    if (caseNeedsScope(caseId) && central.scopeSupported === false) {
      return { ok: true, available: false, reason: 'backend_scope_pending', caps }
    }
    if (CASES[caseId].policyId === POLICY_MAPPED && central.mappedSupported === false) {
      return { ok: true, available: false, reason: 'backend_mapped_policy_pending', caps }
    }
    // Attempt WITH scope unless known-unsupported. Unknown means try:
    // support can only be learned from a declared action, never from
    // a hidden status probe.
    const node = nodes.default
    let withScope = central.scopeSupported !== false
    let intent = buildIntent(caseId, { scopeSupported: withScope })
    let proposed = await call(node, 'POST', '/api/plans/propose', node.rpToken, intent)
    if (proposed.status === 503) {
      return { ok: false, error: 'planner_unavailable', status: 503, caps }
    }
    if (proposed.status !== 200 || !proposed.json) {
      // A non-200 here is a version signal or a bug — never refusal
      // evidence. Only a 400 carries the legacy-backend signature;
      // any other failure (500, timeout, unreachable) fails closed as
      // proposal_failed and is never relabeled scope-unsupported.
      if (proposed.status === 400 && withScope && caseId === 'known') {
        // Legacy policy is known-good, so a scoped legacy 400 means
        // flat scope fields unsupported: observe, retry once unscoped
        // inside this same declared action, and proceed.
        observed.scopeSupported = false
        relearn()
        const retryIntent = buildIntent(caseId, { scopeSupported: false })
        const retry = await call(node, 'POST', '/api/plans/propose', node.rpToken, retryIntent)
        if (retry.status === 503) return { ok: false, error: 'planner_unavailable', status: 503, caps }
        if (retry.status !== 200 || !retry.json) {
          return { ok: false, error: 'proposal_failed', status: retry.status, caps }
        }
        // The winning proposal came from the UNSCOPED retry: echo
        // verification, scope binding, and the stored tx scope must all
        // follow the retry, not the rejected scoped attempt.
        proposed = retry
        intent = retryIntent
        withScope = false
      } else if (proposed.status === 400 && withScope) {
        // Unfamiliar case: discriminate the mapped leg model-free via
        // the deterministic guard — no second model call is spent.
        const mapped = await guardKnowsMapped()
        if (mapped === false) {
          observed.mappedSupported = false
          observed.scopeSupported = false // legacy backend predates both; self-corrects on later success
          relearn()
          return { ok: true, available: false, reason: 'backend_mapped_policy_pending', caps }
        }
        if (mapped === true) {
          observed.mappedSupported = true
          observed.scopeSupported = false
          relearn()
          return { ok: true, available: false, reason: 'backend_scope_pending', caps }
        }
        return { ok: false, error: 'proposal_failed', status: proposed.status, caps }
      } else {
        return { ok: false, error: 'proposal_failed', status: proposed.status, caps }
      }
    }
    // Success observations (last wins, self-correcting across upgrades).
    if (withScope && observed.scopeSupported !== true) {
      observed.scopeSupported = true
      relearn()
    }
    if (intent.policyId === POLICY_MAPPED && observed.mappedSupported !== true) {
      observed.mappedSupported = true
      relearn()
    }
    const proposal = proposed.json
    const meta = proposalMeta(proposal)
    if (expectMode !== undefined && meta.mode !== expectMode) {
      return { ok: false, error: 'mode_mismatch', mode: meta.mode, caps }
    }
    const echo = scopeEchoOf(proposal)
    if (withScope && echo !== null && !echoMatches(intent, echo)) {
      // The backend bound a different scope than requested: fail
      // closed rather than consenting under a misunderstood scope.
      return { ok: false, error: 'proposal_scope_mismatch', caps }
    }
    const plan = proposal.plan ?? null
    if (plan === null || proposal.recommendation !== 'CANDIDATE_ONLY') {
      // Honest refusal or non-candidate: discovery ran over the scoped
      // source and found no acceptable path. No tx, no guard call (no
      // candidate exists to adjudicate), no consent. propose() 200ed,
      // so this is a real outcome — a 400 would be input validation,
      // never refusal, and is reported as proposal_failed above.
      return {
        ok: true, available: true, refusal: true, meta, plan: null, guard: null, tx: null,
        echo, caps,
      }
    }
    let checked
    try {
      checked = checkPlanShape(plan)
    } catch {
      return { ok: false, error: 'proposal_malformed', caps }
    }
    // Scope is ALWAYS checked when it was sent — never gated on a
    // capability flag. A candidate outside the requested scope is
    // treated as no path, never substituted or repaired. (The backend
    // binds too; this is defense in depth on our side.)
    if (withScope && !scopeAllows(scopeFor(caseId), checked)) {
      return {
        ok: true, available: true, refusal: true,
        meta: { ...meta, recommendation: 'NO_PATH', reason: 'candidate outside discovery scope' },
        plan: null, guard: null, tx: null, echo, caps,
      }
    }
    if (checked.policy_id !== intent.policyId || checked.policy_version !== intent.policyVersion) {
      return { ok: false, error: 'proposal_policy_mismatch', caps }
    }
    // Guard runs centrally alongside planning, over the same snapshot
    // content — never routed to the secondary.
    const guarded = await call(node, 'POST', '/api/guard/validate', node.rpToken, {
      plan: checked, policyId: intent.policyId, policyVersion: intent.policyVersion,
    })
    if (guarded.status !== 200 || !guarded.json) {
      return { ok: false, error: 'guard_unavailable', status: guarded.status, caps }
    }
    const guard = guarded.json
    noteGuardVersion(guard)
    if (!guard.accepted) {
      // Deterministic refusal of a real candidate: surfaced with the
      // guard code, still no tx and no consent.
      return {
        ok: true, available: true, refusal: true, meta, plan: checked, guard, tx: null,
        echo, caps,
      }
    }
    let planHash
    let claims
    try {
      planHash = canonicalPlanHash(checked)
      claims = claimsForPlan(checked)
    } catch {
      return { ok: false, error: 'proposal_unusable', caps }
    }
    let tx
    try {
      tx = txStore.create({
        caseId, plan: checked, policyId: intent.policyId, policyVersion: intent.policyVersion,
        planHash, claims, scope: withScope ? scopeFor(caseId) : null, meta,
        guard: { accepted: guard.accepted, code: guard.code, reason: guard.reason, rulesVersion: guard.rulesVersion },
        credentialId: null, requestId: null, idem: null,
        setupHolder: null, setupExpiresAt: null, setupFlight: null, setupUncertain: null,
        requestFlight: null, requestUncertain: null,
      })
    } catch (err) {
      if (err?.message === 'tx_store_full') return { ok: false, error: 'tx_store_full', caps }
      throw err
    }
    return {
      ok: true, available: true, refusal: false, meta, plan: checked, guard, tx,
      txExpiresAt: new Date(now() + 10 * 60_000).toISOString(),
      echo, caps,
    }
  }

  function txOrError(tx) {
    const found = txStore.get(tx)
    if (!found) return { ok: false, error: 'invalid_tx' }
    return { ok: true, tx: found }
  }

  async function postSetup({ tx, holderJwk, holderProof, idem }) {
    const held = txOrError(tx)
    if (!held.ok) return held
    if (holderJwk === null || typeof holderJwk !== 'object'
      || typeof holderProof !== 'string' || typeof idem !== 'string' || idem === '') {
      return { ok: false, error: 'invalid_setup_body' }
    }
    const ctx = held.tx
    const fingerprint = holderFingerprint(holderJwk, holderProof)
    if (ctx.credentialId !== null) {
      // One issuance per transaction: the same idem AND same holder
      // replays the bound id (safe retry). A new idem is refused, and
      // the same idem with a different holder conflicts — the backend
      // hashes holder+expiry into the key, so cached success for a
      // changed holder would be a bypass, never a replay.
      if (ctx.idem === idem) {
        if (ctx.setupHolder !== null && ctx.setupHolder !== fingerprint) {
          return { ok: false, error: 'tx_issuance_conflict' }
        }
        return { ok: true, credentialId: ctx.credentialId }
      }
      return { ok: false, error: 'tx_issuance_bound' }
    }
    // Uncertain delivery: a prior attempt may have committed upstream
    // (timeout after commit). The same idem+holder may retry with the
    // EXACT frozen request; a new idem or changed holder can never
    // replace the first — that would mint a second credential.
    if (ctx.setupUncertain) {
      if (ctx.setupUncertain.idem !== idem) {
        return { ok: false, error: 'tx_issuance_uncertain', status: ctx.setupUncertain.status ?? 0 }
      }
      if (ctx.setupUncertain.holder !== fingerprint) {
        return { ok: false, error: 'tx_issuance_conflict' }
      }
    }
    // In-flight ownership: identical retries coalesce onto the one
    // upstream call; a changed idem/holder sees honest in-progress and
    // cannot replace the first.
    if (ctx.setupFlight) {
      if (ctx.setupFlight.idem === idem && ctx.setupFlight.holder === fingerprint) {
        return ctx.setupFlight.promise
      }
      return { ok: false, error: 'tx_issuance_in_progress' }
    }
    // Issuance routes by the plan's issuer with that node's OWN issuer
    // token: the independent DB cannot honor the other node's tokens.
    // Issuer, type, and claims all come from the stored guarded plan —
    // the client supplies only holder key material plus idempotency.
    const node = nodeForIssuer(ctx.plan.candidate_issuer_id)
    if (isNodeUnconfigured(node)) {
      return { ok: false, error: 'issuer_node_unconfigured' }
    }
    // Freeze the exact upstream request — including expiry — BEFORE the
    // first send. Uncertain retries reuse this frozen body verbatim so
    // the backend sees the same request hash under the same key.
    const frozen = ctx.setupUncertain?.body ?? {
      issuerId: ctx.plan.candidate_issuer_id,
      vct: ctx.plan.credential_type,
      holderJwk, holderProof, claims: ctx.claims,
      expiresAt: isoPlusHours(2),
      idem,
    }
    let resolveFlight
    const flightPromise = new Promise((resolve) => { resolveFlight = resolve })
    ctx.setupFlight = { idem, holder: fingerprint, promise: flightPromise }
    const issued = await safeCall(node, 'POST', '/api/issuance/credentials', node.issuerToken, frozen)
    let result
    if (issued.status === 201 && issued.json?.credentialId) {
      ctx.credentialId = issued.json.credentialId
      ctx.idem = idem
      ctx.setupHolder = fingerprint
      ctx.setupExpiresAt = frozen.expiresAt
      ctx.setupUncertain = null
      result = { ok: true, credentialId: issued.json.credentialId }
    } else if (issued.status === 409) {
      // Known conflict: same key, different request upstream. No new
      // commit from this call, so the tx stays retryable with a fresh
      // idem — but never a cached success.
      result = { ok: false, error: 'issuance_conflict', status: 409 }
    } else if (issued.status === 0 || issued.status === 201) {
      // Uncertain commitment: timeout (or 201 without an id) may mean
      // the upstream committed. Lock the frozen identity for exact
      // retry; new idem is refused until this resolves.
      ctx.setupUncertain = { idem, holder: fingerprint, expiresAt: frozen.expiresAt, body: frozen, status: issued.status }
      result = { ok: false, error: 'issuance_uncertain', status: issued.status }
    } else {
      result = { ok: false, error: 'issuance_failed', status: issued.status }
    }
    ctx.setupFlight = null
    resolveFlight(result)
    return result
  }

  async function postRequest({ tx, credentialId }) {
    const held = txOrError(tx)
    if (!held.ok) return held
    const ctx = held.tx
    if (ctx.credentialId === null) return { ok: false, error: 'tx_no_credential' }
    if (credentialId !== ctx.credentialId) return { ok: false, error: 'credential_not_bound' }
    const node = nodeForIssuer(ctx.plan.candidate_issuer_id)
    if (isNodeUnconfigured(node)) {
      return { ok: false, error: 'issuer_node_unconfigured' }
    }
    // Uncertain creation: the backend offers no idempotency contract
    // for consent, so a lost create response must NEVER be retried as
    // a second create — that would open a duplicate request. The tx
    // restarts from a fresh plan; this tx stays explicitly uncertain.
    if (ctx.requestUncertain) {
      return { ok: false, error: 'request_uncertain', status: ctx.requestUncertain.status ?? 0 }
    }
    // In-flight creation: identical retries coalesce onto the one
    // upstream POST (credential binding was already checked above).
    if (ctx.requestFlight) {
      return ctx.requestFlight.promise
    }
    if (ctx.requestId !== null) {
      // Safe retry: the bound request is re-read, never duplicated.
      // The read must be HTTP 200 with the matching request id and
      // exact plan hash — a 404/503/null review is a failure, not a
      // review.
      const reread = await safeCall(node, 'GET', `/api/consent/requests/${ctx.requestId}`, node.rpToken)
      const checked = checkReview(reread, ctx.requestId, ctx.planHash)
      if (!checked.ok) {
        return { ...checked, requestId: ctx.requestId }
      }
      return {
        ok: true, requestId: ctx.requestId, review: reread.json,
        guard: ctx.guard, meta: ctx.meta,
      }
    }
    // Claim creation ownership synchronously so simultaneous callers
    // cannot open two consent requests for one tx.
    let resolveFlight
    const flightPromise = new Promise((resolve) => { resolveFlight = resolve })
    ctx.requestFlight = { promise: flightPromise }
    const frozen = {
      rpId: INTEROP_RP.rpId, audience: INTEROP_RP.audience, purpose: INTEROP_RP.purpose,
      credentialId, claims: ctx.claims, plan: ctx.plan,
      policyId: ctx.policyId, policyVersion: ctx.policyVersion,
      planHash: ctx.planHash, challenge: randomChallenge(),
      expiresAt: isoPlusHours(1),
    }
    const created = await safeCall(node, 'POST', '/api/consent/requests', node.rpToken, frozen)
    let result
    if (created.status === 201 && created.json?.requestId) {
      // Save the id BEFORE the review read: a failed read retries the
      // read, never recreates the request.
      const newId = created.json.requestId
      ctx.requestId = newId
      const review = await safeCall(node, 'GET', `/api/consent/requests/${newId}`, node.rpToken)
      const checked = checkReview(review, newId, ctx.planHash)
      if (!checked.ok) {
        result = { ...checked, requestId: newId }
      } else {
        result = { ok: true, requestId: newId, review: review.json, guard: ctx.guard, meta: ctx.meta }
      }
    } else if (created.status === 0 || created.status === 201) {
      // Lost create response with no id: the request may exist
      // upstream, and there is no safe way to find it. Mark the tx
      // uncertain and refuse further creates on it.
      ctx.requestUncertain = { status: created.status }
      result = { ok: false, error: 'request_uncertain', status: created.status }
    } else {
      result = { ok: false, error: 'request_failed', status: created.status }
    }
    ctx.requestFlight = null
    resolveFlight(result)
    return result
  }

  async function postDecision({ tx, requestId, decision, holderJwk, consentProof }) {
    const held = txOrError(tx)
    if (!held.ok) return held
    const ctx = held.tx
    if (ctx.requestId === null || requestId !== ctx.requestId) {
      return { ok: false, error: 'request_not_bound' }
    }
    if (decision !== 'approve' && decision !== 'deny') return { ok: false, error: 'invalid_decision' }
    if (holderJwk === null || typeof holderJwk !== 'object' || typeof consentProof !== 'string') {
      return { ok: false, error: 'invalid_decision_body' }
    }
    const node = nodeForIssuer(ctx.plan.candidate_issuer_id)
    if (isNodeUnconfigured(node)) {
      return { ok: false, error: 'issuer_node_unconfigured' }
    }
    const decided = await call(
      node, 'POST', `/api/consent/requests/${requestId}/decision`, node.rpToken,
      { decision, holderJwk, consentProof },
    )
    return { ok: decided.status === 200, status: decided.status, state: decided.json }
  }

  async function postVerify({ tx, requestId, nonce, holderJwk, bindingProof }) {
    const held = txOrError(tx)
    if (!held.ok) return held
    const ctx = held.tx
    if (ctx.requestId === null || requestId !== ctx.requestId) {
      return { ok: false, error: 'request_not_bound' }
    }
    if (typeof nonce !== 'string' || holderJwk === null || typeof holderJwk !== 'object'
      || typeof bindingProof !== 'string') {
      return { ok: false, error: 'invalid_verify_body' }
    }
    // The audience is the interop constant, never client input.
    const node = nodeForIssuer(ctx.plan.candidate_issuer_id)
    if (isNodeUnconfigured(node)) {
      return { ok: false, error: 'issuer_node_unconfigured' }
    }
    const submitted = await call(node, 'POST', '/api/verification/presentations', node.rpToken, {
      requestId, nonce, audience: INTEROP_RP.audience, holderJwk, bindingProof,
    })
    return { ok: submitted.status === 200, status: submitted.status, decision: submitted.json }
  }

  return {
    getStatus, postPlan, postSetup, postRequest, postDecision, postVerify,
    capabilities, txStore, nodeForIssuer,
  }
}
