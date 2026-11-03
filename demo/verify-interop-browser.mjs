// Durable dual-issuer browser verification for the interop demo page.
//
// Drives the REAL demo server + REAL backend nodes through a real
// Chromium (Playwright) with zero mocks: status, known/fjord/harbor
// end-to-end approvals, employment NO_PATH refusal, decline/back/cancel
// honesty, committed-decision lock, and a separately-labelled held-request
// interruption test. Captures screenshots + sanitized results JSON.
//
// Browser automation uses the repo's pinned frontend Playwright
// (@playwright/test 1.64.1) — no new dependency, no frontend/e2e
// global setup (which would mutate the root stack during profile
// flips). Install once:
//
//   pnpm --dir frontend install --frozen-lockfile
//   pnpm --dir frontend exec playwright install chromium
//
// Run (demo server already up, e.g. interop-only :5176):
//
//   DEMO_BASE=http://127.0.0.1:5176 \
//   ARTIFACT_DIR=/tmp/sovra-interop-browser \
//   node demo/verify-interop-browser.mjs
//
// ARTIFACT_DIR defaults to demo/.browser-artifacts (no .intel
// requirement: the public script works without private files).
// HEADLESS=0 watches the run. Every failure exits non-zero with the
// failing check named first.

import { mkdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEMO_BASE = process.env.DEMO_BASE ?? 'http://127.0.0.1:5176'
const ARTIFACT_DIR = process.env.ARTIFACT_DIR ?? join(HERE, '.browser-artifacts')
const HEADLESS = (process.env.HEADLESS ?? '1') !== '0'
const STEP_TIMEOUT = Number(process.env.STEP_TIMEOUT_MS ?? 20000)

const ISSUER_SYNTH1 = 'https://sovra.example/issuers/synth-1'
const ISSUER_SYNTH2 = 'https://sovra.example/issuers/synth-2'
const VCT_ADULT = 'https://sovra.example/vct/adult-status/1'
const VCT_FJORD = 'https://sovra.example/vct/fjord-adult/1'
const VCT_HARBOR = 'https://sovra.example/vct/harbor-adult/1'

const EXPECTED = {
  known: { issuer: ISSUER_SYNTH1, vct: VCT_ADULT, claims: ['adultOver18'], policy: 'sovra-synthetic-policy/age-check' },
  fjord: { issuer: ISSUER_SYNTH2, vct: VCT_FJORD, claims: ['isAdult'], policy: 'sovra-synthetic-policy/age-check-mapped' },
  harbor: { issuer: ISSUER_SYNTH2, vct: VCT_HARBOR, claims: ['qualifiesAsAdult'], policy: 'sovra-synthetic-policy/age-check-mapped' },
}

async function loadPlaywright() {
  // Resolve through the frontend package (pnpm layout) so the pinned
  // @playwright/test is found without a new dependency.
  const frontendRequire = createRequire(join(HERE, '..', 'frontend', 'package.json'))
  const attempts = []
  if (process.env.PLAYWRIGHT_TEST_PATH) {
    try {
      return frontendRequire(process.env.PLAYWRIGHT_TEST_PATH)
    } catch (err) {
      attempts.push(`PLAYWRIGHT_TEST_PATH: ${err?.message ?? err}`)
    }
  }
  try {
    return frontendRequire('@playwright/test')
  } catch (err) {
    attempts.push(`@playwright/test: ${err?.message ?? err}`)
  }
  console.error('Playwright not found. Install the repo-pinned browser tooling once:')
  console.error('  pnpm --dir frontend install --frozen-lockfile')
  console.error('  pnpm --dir frontend exec playwright install chromium')
  console.error(attempts.join('\n'))
  process.exit(2)
}

class CheckFailure extends Error {
  constructor(check, message, extra = {}) {
    super(`[${check}] ${message}`)
    this.check = check
    this.extra = extra
  }
}

function assert(check, condition, message, extra = {}) {
  if (!condition) throw new CheckFailure(check, message, extra)
}

// Results allowlist: decision/plan/provenance identifiers and verdicts
// only. Holder keys, proofs, and machine tokens are never collected,
// so they cannot leak into the artifact.
function sanitizePlan(plan) {
  if (plan === null || plan === undefined) return plan
  return {
    plan_id: plan.plan_id ?? null,
    candidate_issuer_id: plan.candidate_issuer_id ?? null,
    credential_type: plan.credential_type ?? null,
    claim_paths: plan.claim_paths ?? null,
    policy_id: plan.policy_id ?? null,
    policy_version: plan.policy_version ?? null,
  }
}

function sanitizeMeta(meta) {
  if (meta === null || meta === undefined) return meta
  return {
    mode: meta.mode ?? null,
    liveAcceptance: meta.liveAcceptance ?? null,
    recommendation: meta.recommendation ?? null,
    reason: meta.reason ?? null,
    snapshotVersion: meta.snapshotVersion ?? null,
    toolCalls: meta.toolCalls ?? null,
  }
}

function sanitizeGuard(guard) {
  if (guard === null || guard === undefined) return guard
  return {
    accepted: guard.accepted ?? null,
    code: guard.code ?? null,
    reason: guard.reason ?? null,
    rulesVersion: guard.rulesVersion ?? null,
  }
}

function sanitizeDecision(decision) {
  if (decision === null || decision === undefined) return decision
  return {
    decisionId: decision.decisionId ?? null,
    outcome: decision.outcome ?? null,
    trustSnapshot: decision.trustSnapshot ?? null,
    profile: decision.profile ?? null,
    reasonCode: decision.reasonCode ?? null,
  }
}

// Records every page-initiated request (method + path only — header
// VALUES are never stored) and flags secret leaks: the browser must
// never send Authorization and no demo JSON response may carry a
// *token* property (machine tokens stay server-side).
function createNetworkTracker() {
  const calls = []
  let sawBrowserAuthorization = false
  let sawTokenProperty = false
  const tokenKeyHits = []
  const findTokenKeys = (value, path) => {
    if (Array.isArray(value)) {
      value.forEach((entry, index) => findTokenKeys(entry, `${path}[${index}]`))
    } else if (value !== null && typeof value === 'object') {
      for (const [key, entry] of Object.entries(value)) {
        if (/token/i.test(key)) {
          sawTokenProperty = true
          tokenKeyHits.push(`${path}.${key}`)
        } else {
          findTokenKeys(entry, `${path}.${key}`)
        }
      }
    }
  }
  return {
    calls,
    attach(page) {
      page.on('request', (request) => {
        const headers = request.headers()
        if (headers.authorization !== undefined || headers.Authorization !== undefined) {
          sawBrowserAuthorization = true
        }
        calls.push({ method: request.method(), path: new URL(request.url()).pathname })
      })
      page.on('response', (response) => {
        const url = new URL(response.url())
        if (!url.pathname.startsWith('/api/')) return
        response.json().then((body) => findTokenKeys(body, url.pathname)).catch(() => {})
      })
    },
    scoped(mark) {
      return calls.slice(mark).filter((call) => call.path.startsWith('/api/interop/'))
    },
    get sawBrowserAuthorization() { return sawBrowserAuthorization },
    get sawTokenProperty() { return sawTokenProperty },
    get tokenKeyHits() { return tokenKeyHits },
  }
}

const dlText = (dlHandle) => dlHandle.innerText()
// innerText is empty inside a collapsed <details>; exact JSON/receipt
// values are asserted via textContent instead.
const rawText = (locator) => locator.evaluate((el) => el.textContent)

async function visibleInViewport(page, selector) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel)
    if (!el) return { found: false }
    const rect = el.getBoundingClientRect()
    const inViewport = rect.top >= 0 && rect.left >= 0
      && rect.bottom <= window.innerHeight && rect.right <= window.innerWidth
    const cx = Math.min(Math.max(rect.left + rect.width / 2, 0), window.innerWidth - 1)
    const cy = Math.min(Math.max(rect.top + rect.height / 2, 0), window.innerHeight - 1)
    const top = document.elementFromPoint(cx, cy)
    const obscured = top !== null && top !== el && !el.contains(top)
    const style = window.getComputedStyle(el)
    return {
      found: true,
      visible: style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0,
      inViewport,
      obscured,
      rect: { x: Math.round(rect.x), y: Math.round(rect.y), w: Math.round(rect.width), h: Math.round(rect.height) },
    }
  }, selector)
}

async function fetchJson(path) {
  const res = await fetch(DEMO_BASE + path)
  const body = await res.json()
  return { status: res.status, body }
}

async function checkStatusApi() {
  const name = 'status-api'
  const { status, body } = await fetchJson('/api/interop/status')
  assert(name, status === 200, `status HTTP ${status}, want 200`)
  assert(name, body.ok === true, 'status ok flag false')
  const primary = body.status?.primary ?? {}
  assert(name, primary.reachable === true, 'primary node unreachable')
  assert(name, primary.mode === 'FIXTURE', `mode ${primary.mode}, want FIXTURE`)
  assert(name, primary.liveEnabled === false, 'liveEnabled not false')
  assert(name, primary.discoveryScopeSupported === true, 'discovery scope not advertised')
  assert(name, primary.schemaRegistryVersion === 'sovra-synthetic-schemas/1', `registry ${primary.schemaRegistryVersion}`)
  assert(name, primary.guardRulesVersion === 'sovra-guard/2', `guard ${primary.guardRulesVersion}`)
  const bindings = (primary.supportedPolicyBindings ?? []).map((b) => `${b.policyId} v${b.policyVersion}`)
  assert(name, bindings.includes('sovra-synthetic-policy/age-check v1'), `bindings missing age-check: ${bindings}`)
  assert(name, bindings.includes('sovra-synthetic-policy/age-check-mapped v1'), `bindings missing mapped: ${bindings}`)
  assert(name, body.status?.synth2Configured === true, 'synth2 not configured')
  assert(name, body.status?.synth2?.reachable === true, 'synth2 node unreachable')
  assert(name, body.status?.synth2?.mode === 'FIXTURE', `synth2 mode ${body.status?.synth2?.mode}`)
  const discovery = await fetchJson('/api/discovery')
  assert(name, discovery.body?.discovery?.profile === 'synthetic', 'discovery profile not synthetic')
  return {
    name, pass: true,
    detail: {
      mode: primary.mode, liveEnabled: primary.liveEnabled,
      registry: primary.schemaRegistryVersion, guard: primary.guardRulesVersion,
      bindings, synth2Reachable: body.status.synth2.reachable,
    },
  }
}

async function selectCase(page, caseId) {
  await page.click(`[data-case="${caseId}"]`)
}

async function startRun(page) {
  await page.click('#b-start')
}

// Starts a case and waits for the consent screen, capturing the exact
// /plan response (returned plan + provenance + guard, unmocked).
async function runCaseToConsent(page, caseId) {
  const name = `${caseId}-plan`
  await selectCase(page, caseId)
  const planResponse = page.waitForResponse(
    (response) => response.url().endsWith('/api/interop/plan') && response.request().method() === 'POST',
    { timeout: STEP_TIMEOUT },
  )
  await startRun(page)
  const body = await (await planResponse).json()
  assert(name, body.ok === true, `plan ok=false: ${body.error ?? 'unknown'}`)
  assert(name, body.available !== false, `case unavailable: ${body.reason ?? 'unknown'}`)
  assert(name, body.refusal !== true, `unexpected refusal: ${body.meta?.recommendation ?? 'unknown'}`)
  const expected = EXPECTED[caseId]
  assert(name, body.plan?.candidate_issuer_id === expected.issuer, `issuer ${body.plan?.candidate_issuer_id}`)
  assert(name, body.plan?.credential_type === expected.vct, `vct ${body.plan?.credential_type}`)
  assert(name, JSON.stringify(body.plan?.claim_paths) === JSON.stringify(expected.claims),
    `claim_paths ${JSON.stringify(body.plan?.claim_paths)}`)
  assert(name, body.plan?.policy_id === expected.policy, `policy ${body.plan?.policy_id}`)
  assert(name, body.guard?.accepted === true, `guard rejected: ${body.guard?.code ?? 'unknown'}`)
  assert(name, body.guard?.rulesVersion === 'sovra-guard/2', `guard rules ${body.guard?.rulesVersion}`)
  assert(name, body.meta?.recommendation === 'CANDIDATE_ONLY', `recommendation ${body.meta?.recommendation}`)
  await page.waitForSelector('#s-consent:not([hidden])', { timeout: STEP_TIMEOUT })
  return body
}

async function checkConsentVisibility(page, caseId) {
  const name = `${caseId}-consent-visibility`
  const human = await dlText(page.locator('#consent-human'))
  for (const label of ['Who asks', 'What they learn', 'Expires']) {
    assert(name, human.includes(label), `consent context missing "${label}"`)
  }
  for (const selector of ['#consent-human', '#b-approve', '#b-decline', '#b-back', '#mode-pill']) {
    const state = await visibleInViewport(page, selector)
    assert(name, state.found && state.visible, `${selector} not visible`)
    assert(name, state.inViewport, `${selector} outside 1440x900 viewport: ${JSON.stringify(state.rect)}`)
    assert(name, !state.obscured, `${selector} obscured by another element`)
  }
  const pill = (await page.locator('#mode-pill').innerText()).trim()
  assert(name, pill === 'FIXTURE', `compact mode pill "${pill}", want FIXTURE`)
  const detailsOpen = await page.evaluate(() => document.querySelector('#status-details').open)
  assert(name, detailsOpen === false, 'full status disclosure should collapse once a run leaves the picker')
  const planJson = JSON.parse(await rawText(page.locator('#plan-json')))
  assert(name, typeof planJson.plan_id === 'string' && planJson.plan_id !== '', 'plan JSON missing plan_id')
  return { name, pass: true, detail: { modePill: pill, statusCollapsed: !detailsOpen, planId: planJson.plan_id } }
}

async function approveToAccepted(page, caseId, planned) {
  const name = `${caseId}-approve`
  const verifyResponse = page.waitForResponse(
    (response) => response.url().endsWith('/api/interop/verify') && response.request().method() === 'POST',
    { timeout: STEP_TIMEOUT },
  )
  await page.click('#b-approve')
  const verified = await (await verifyResponse).json()
  await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
  const verdict = (await page.locator('#verdict').innerText()).trim()
  assert(name, verdict === 'Eligibility evidence recorded.', `verdict "${verdict}"`)
  assert(name, verified.decision?.outcome === 'ACCEPTED', `outcome ${verified.decision?.outcome}`)
  assert(name, typeof verified.decision?.decisionId === 'string', 'receipt missing decisionId')
  const receipt = await rawText(page.locator('#receipt-fields'))
  assert(name, receipt.includes(verified.decision.decisionId), 'receipt missing decision id')
  assert(name, receipt.includes(planned.plan.plan_id), 'receipt missing plan id')
  return {
    name, pass: true,
    detail: {
      plan: sanitizePlan(planned.plan), meta: sanitizeMeta(planned.meta),
      guard: sanitizeGuard(planned.guard), decision: sanitizeDecision(verified.decision),
    },
  }
}

async function fullApproval(page, tracker, caseId, screenshotPrefix) {
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  const mark = tracker.calls.length
  const planned = await runCaseToConsent(page, caseId)
  const visibility = await checkConsentVisibility(page, caseId)
  await page.screenshot({ path: join(ARTIFACT_DIR, `${screenshotPrefix}-consent.png`) })
  const approved = await approveToAccepted(page, caseId, planned)
  await page.screenshot({ path: join(ARTIFACT_DIR, `${screenshotPrefix}-accepted.png`) })
  const scoped = tracker.scoped(mark).map((call) => `${call.method} ${call.path}`)
  for (const action of ['plan', 'setup', 'request', 'decision', 'verify']) {
    assert(`${caseId}-calls`, scoped.some((call) => call === `POST /api/interop/${action}`),
      `missing POST /api/interop/${action}; saw: ${scoped.join(', ')}`)
  }
  return { planned, visibility, approved }
}

async function checkEmployment(page, tracker) {
  const name = 'employment-refusal'
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  const mark = tracker.calls.length
  await selectCase(page, 'employment')
  const planResponse = page.waitForResponse(
    (response) => response.url().endsWith('/api/interop/plan') && response.request().method() === 'POST',
    { timeout: STEP_TIMEOUT },
  )
  await startRun(page)
  const body = await (await planResponse).json()
  assert(name, body.ok === true, `plan ok=false: ${body.error ?? 'unknown'}`)
  assert(name, body.refusal === true, 'employment should refuse with an actual NO_PATH')
  assert(name, body.meta?.recommendation === 'NO_PATH', `recommendation ${body.meta?.recommendation}`)
  assert(name, body.plan === null, 'employment refusal must carry a null plan')
  await page.waitForSelector('#s-refusal:not([hidden])', { timeout: STEP_TIMEOUT })
  const note = await page.locator('#refusal-note').innerText()
  assert(name, note.includes('NO_PATH'), `refusal note missing NO_PATH: "${note}"`)
  const refusalPlan = (await rawText(page.locator('#refusal-plan'))).trim()
  assert(name, refusalPlan === 'No candidate plan (null plan).', `refusal plan text: "${refusalPlan}"`)
  await page.screenshot({ path: join(ARTIFACT_DIR, 'employment-refusal.png') })
  const scoped = tracker.scoped(mark).map((call) => `${call.method} ${call.path}`)
  assert(name, scoped.includes('POST /api/interop/plan'), 'employment must still plan honestly')
  for (const forbidden of ['setup', 'request', 'decision', 'verify']) {
    assert(name, !scoped.some((call) => call === `POST /api/interop/${forbidden}`),
      `employment must not call ${forbidden}; saw: ${scoped.join(', ')}`)
  }
  return {
    name, pass: true,
    detail: {
      meta: sanitizeMeta(body.meta), plan: body.plan,
      networkAbsence: ['setup', 'request', 'decision', 'verify'],
      dbCensus: 'covered by standalone qualification 13/13 (artifactsUnchanged); browser asserts zero credential/consent/verify calls',
    },
  }
}

async function checkDecline(page, tracker) {
  const name = 'decline-honesty'
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  const mark = tracker.calls.length
  await runCaseToConsent(page, 'known')
  await page.click('#b-decline')
  await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
  const verdict = (await page.locator('#verdict').innerText()).trim()
  assert(name, verdict === 'You declined — nothing was shared.', `verdict "${verdict}"`)
  await page.screenshot({ path: join(ARTIFACT_DIR, 'decline-outcome.png') })
  const scoped = tracker.scoped(mark).map((call) => `${call.method} ${call.path}`)
  assert(name, scoped.includes('POST /api/interop/decision'), 'decline must record the decision')
  assert(name, !scoped.includes('POST /api/interop/verify'), 'decline must produce no verification call')
  return { name, pass: true, detail: { verdict, noVerifyCall: true } }
}

async function checkBack(page, tracker) {
  const name = 'back-without-deciding'
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  const mark = tracker.calls.length
  await runCaseToConsent(page, 'fjord')
  await page.click('#b-back')
  await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
  const pill = (await page.locator('#state-pill').innerText()).trim()
  assert(name, pill === 'Nothing shared yet', `state pill "${pill}"`)
  const scoped = tracker.scoped(mark).map((call) => `${call.method} ${call.path}`)
  assert(name, !scoped.includes('POST /api/interop/decision'), 'back must send no decision')
  assert(name, !scoped.includes('POST /api/interop/verify'), 'back must send no verification')
  return { name, pass: true, detail: { pill, noDecisionCall: true } }
}

async function checkCancel(page, tracker) {
  const name = 'cancel-before-decision'
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  // Hold the plan response briefly so the cancel lands in the real
  // progress window instead of racing it.
  await page.route('**/api/interop/plan', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1200))
    // The page may abort the parked call on cancel; a late continue
    // on a dead route must not fail the run.
    await route.continue().catch(() => {})
  })
  try {
    const mark = tracker.calls.length
    await selectCase(page, 'harbor')
    await startRun(page)
    await page.waitForSelector('#s-progress:not([hidden])', { timeout: STEP_TIMEOUT })
    await page.click('#b-cancel')
    await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
    const scoped = tracker.scoped(mark).map((call) => `${call.method} ${call.path}`)
    assert(name, !scoped.includes('POST /api/interop/decision'), 'cancel must send no decision')
    assert(name, !scoped.includes('POST /api/interop/verify'), 'cancel must send no verification')
  } finally {
    await page.unroute('**/api/interop/plan')
  }
  return { name, pass: true, detail: { noDecisionCall: true } }
}

async function checkCommitLock(page) {
  const name = 'committed-decision-cannot-cancel'
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  await runCaseToConsent(page, 'known')
  // Hold the decision commit so the lock is observable, not raced.
  await page.route('**/api/interop/decision', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500))
    await route.continue().catch(() => {})
  })
  try {
    await page.click('#b-approve')
    await page.waitForSelector('#s-progress:not([hidden])', { timeout: STEP_TIMEOUT })
    const disabled = await page.locator('#b-cancel').isDisabled()
    const label = (await page.locator('#b-cancel').innerText()).trim()
    assert(name, disabled === true, 'cancel must lock once the decision commits')
    assert(name, label === 'Finishing — cannot be cancelled', `cancel label "${label}"`)
    await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
    const verdict = (await page.locator('#verdict').innerText()).trim()
    assert(name, verdict === 'Eligibility evidence recorded.', `verdict "${verdict}"`)
  } finally {
    await page.unroute('**/api/interop/decision')
  }
  return { name, pass: true, detail: { cancelLocked: true } }
}

// SEPARATELY LABELLED interruption test: an adversarially HELD
// /request (caller-held barrier) is cancelled mid-flight. This run is
// never part of the positive proof recording.
async function checkInterruption(page, tracker) {
  const name = 'interruption-held-request-cancel'
  await page.goto(`${DEMO_BASE}/interoperability`)
  await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
  let release = null
  const gate = new Promise((resolve) => { release = resolve })
  await page.route('**/api/interop/request', async (route) => {
    await gate
    await route.continue().catch(() => {})
  })
  try {
    const mark = tracker.calls.length
    await selectCase(page, 'fjord')
    await startRun(page)
    await page.waitForSelector('#s-progress:not([hidden])', { timeout: STEP_TIMEOUT })
    // Wait until the request is provably parked upstream-side.
    await page.waitForFunction(
      () => document.querySelector('#progress-label')?.textContent === 'Opening your decision…',
      { timeout: STEP_TIMEOUT },
    )
    await page.screenshot({ path: join(ARTIFACT_DIR, 'interruption-held.png') })
    await page.click('#b-cancel')
    await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
    const scoped = tracker.scoped(mark).map((call) => `${call.method} ${call.path}`)
    assert(name, !scoped.includes('POST /api/interop/decision'), 'interrupted run must send no decision')
  } finally {
    release?.()
    await page.unroute('**/api/interop/request')
  }
  // A fresh run after the interruption must work: no stuck state.
  const planned = await runCaseToConsent(page, 'harbor')
  const approved = await approveToAccepted(page, 'harbor', planned)
  assert(name, approved.detail.decision.outcome === 'ACCEPTED', 'post-interruption run did not ACCEPT')
  return { name, pass: true, detail: { cancelledClean: true, recoveryDecision: approved.detail.decision.decisionId } }
}

async function checkSecretHygiene(page, tracker) {
  const name = 'secret-hygiene'
  assert(name, tracker.sawBrowserAuthorization === false, 'browser sent an Authorization header')
  assert(name, tracker.sawTokenProperty === false,
    `demo JSON carried token properties: ${tracker.tokenKeyHits.join(', ')}`)
  const storage = await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }))
  assert(name, storage.local.length === 0 && storage.session.length === 0,
    `page storage not empty: ${JSON.stringify(storage)}`)
  return { name, pass: true, detail: { browserAuthorization: false, tokenProperties: false, storage } }
}

async function main() {
  mkdirSync(ARTIFACT_DIR, { recursive: true })
  const { chromium } = await loadPlaywright()
  const startedAt = new Date().toISOString()
  const checks = []
  const record = (result) => {
    checks.push(result)
    console.log(`[PASS] ${result.name}`)
  }
  const browser = await chromium.launch({ headless: HEADLESS })
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
  const page = await context.newPage()
  const tracker = createNetworkTracker()
  tracker.attach(page)
  const pageErrors = []
  page.on('pageerror', (err) => pageErrors.push(String(err?.message ?? err)))
  try {
    record(await checkStatusApi())
    await page.goto(`${DEMO_BASE}/interoperability`)
    await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
    await page.screenshot({ path: join(ARTIFACT_DIR, 'cases-status.png') })

    for (const [caseId, prefix] of [['known', 'known'], ['fjord', 'fjord'], ['harbor', 'harbor']]) {
      const { visibility, approved } = await fullApproval(page, tracker, caseId, prefix)
      record({ name: `${caseId}-plan`, pass: true, detail: approved.detail.plan })
      record(visibility)
      record(approved)
    }
    record(await checkEmployment(page, tracker))
    record(await checkDecline(page, tracker))
    record(await checkBack(page, tracker))
    record(await checkCancel(page, tracker))
    record(await checkCommitLock(page))
    record(await checkInterruption(page, tracker))
    record(await checkSecretHygiene(page, tracker))
    assert('page-errors', pageErrors.length === 0, `page errors: ${pageErrors.join(' | ')}`)
    record({ name: 'page-errors', pass: true, detail: { count: 0 } })
  } catch (err) {
    if (err instanceof CheckFailure) {
      checks.push({ name: err.check, pass: false, detail: { message: err.message, ...err.extra } })
      console.error(`[FAIL] ${err.message}`)
    } else {
      checks.push({ name: 'harness', pass: false, detail: { message: String(err?.message ?? err) } })
      console.error(`[FAIL] harness: ${err?.stack ?? err}`)
    }
  } finally {
    const failed = checks.filter((check) => !check.pass)
    const results = {
      demoBase: DEMO_BASE, startedAt, finishedAt: new Date().toISOString(),
      viewport: { width: 1440, height: 900 }, headless: HEADLESS,
      pass: failed.length === 0, checks,
    }
    writeFileSync(join(ARTIFACT_DIR, 'results.json'), `${JSON.stringify(results, null, 2)}\n`)
    console.log(`checks: ${checks.length}, pass: ${checks.length - failed.length}, fail: ${failed.length}`)
    console.log(`artifacts: ${ARTIFACT_DIR}`)
    await context.close()
    await browser.close()
    if (failed.length > 0) process.exit(1)
  }
}

await main()
