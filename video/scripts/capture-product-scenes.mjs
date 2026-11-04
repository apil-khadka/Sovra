// Capture actual synthetic demo screens and redacted response evidence for
// the three-minute product story. This uses the local demo server and its
// synthetic Docker backends; it never prints or stores bearer tokens.

import { mkdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const VIDEO_DIR = dirname(dirname(fileURLToPath(import.meta.url)))
const OUTPUT_DIR = join(VIDEO_DIR, 'public', 'product-scenes')
const APP_DEMO_BASE = process.env.APP_DEMO_BASE ?? 'http://127.0.0.1:5174'
const INTEROP_DEMO_BASE = process.env.INTEROP_DEMO_BASE ?? process.env.DEMO_BASE ?? 'http://127.0.0.1:5176'
const TIMEOUT = Number(process.env.STEP_TIMEOUT_MS ?? 30_000)
const WIDTH = 1440
const HEIGHT = 900
const frontendRequire = createRequire(join(VIDEO_DIR, '..', 'frontend', 'package.json'))
const { chromium } = frontendRequire(process.env.PLAYWRIGHT_TEST_PATH ?? '@playwright/test')

mkdirSync(OUTPUT_DIR, { recursive: true })

const browser = await chromium.launch({ headless: true })
const page = await browser.newPage({ viewport: { width: WIDTH, height: HEIGHT }, deviceScaleFactor: 1 })
const pageErrors = []
page.on('pageerror', (error) => pageErrors.push(error.message))

async function save(name, locator) {
  if (locator) await page.locator(locator).scrollIntoViewIfNeeded()
  await page.screenshot({ path: join(OUTPUT_DIR, name), animations: 'disabled' })
}

async function saveElement(name, locator) {
  const element = page.locator(locator)
  await element.scrollIntoViewIfNeeded()
  await element.screenshot({ path: join(OUTPUT_DIR, name), animations: 'disabled' })
}

async function acceptedApp(path, app, prefix) {
  await page.goto(`${APP_DEMO_BASE}/${path}`, { waitUntil: 'domcontentloaded' })
  await page.waitForSelector('#b-start', { timeout: TIMEOUT })
  await save(`${prefix}-request.png`, 'main')
  await page.click('#b-start')
  await page.waitForSelector('#s-consent:not([hidden])', { timeout: TIMEOUT })
  const consent = await page.locator('#consent-human').innerText().catch(() => '')
  await save(`${prefix}-consent.png`, '#s-consent')
  await page.click('#b-approve')
  await page.waitForSelector('#s-outcome:not([hidden])', { timeout: TIMEOUT })
  const outcome = await page.locator('#verdict').innerText()
  const receipt = await page.locator('#receipt-fields').innerText().catch(() => '')
  await save(`${prefix}-accepted.png`, '#s-outcome')
  return { app, consent, outcome, receipt }
}

try {
  const statusResponse = await page.request.get(`${INTEROP_DEMO_BASE}/api/interop/status`)
  if (!statusResponse.ok()) throw new Error(`interop status returned HTTP ${statusResponse.status()}`)
  const statusEnvelope = await statusResponse.json()
  const status = statusEnvelope.status
  if (status.primary?.mode !== 'FIXTURE') throw new Error('demo planner is not in FIXTURE mode')
  if (status.primary?.liveEnabled !== false || status.primary?.modelConfigured !== false) {
    throw new Error('live planning must remain disabled and unconfigured')
  }
  if (status.synth2?.reachable !== true) throw new Error('second synthetic issuer is not reachable')

  await page.goto(`${APP_DEMO_BASE}/`, { waitUntil: 'domcontentloaded' })
  await page.waitForSelector('main', { timeout: TIMEOUT })
  await save('demo-hub.png', 'main')

  const novabank = await acceptedApp('novabank', 'NovaBank', 'novabank')
  const cornercellar = await acceptedApp('cornercellar', 'CornerCellar', 'cornercellar')

  await page.goto(`${INTEROP_DEMO_BASE}/interoperability`, { waitUntil: 'domcontentloaded' })
  await page.waitForSelector('#mode-pill', { timeout: TIMEOUT })
  await page.waitForFunction(() => document.querySelector('#mode-pill')?.textContent?.trim() === 'FIXTURE', null, { timeout: TIMEOUT })
  await page.click('[data-case="fjord"]')
  const fjordResponsePromise = page.waitForResponse(
    (response) => response.url().endsWith('/api/interop/plan') && response.request().method() === 'POST',
    { timeout: TIMEOUT },
  )
  await page.click('#b-start')
  const fjordResponse = await fjordResponsePromise
  const fjord = await fjordResponse.json()
  await page.waitForSelector('#s-consent:not([hidden])', { timeout: TIMEOUT })
  await save('fjord-consent.png', '#s-consent')
  await page.locator('#api-inspector > summary').click()
  const plan = JSON.parse(await page.locator('#plan-json').innerText())
  const guard = JSON.parse(await page.locator('#guard-json').innerText())
  const request = JSON.parse(await page.locator('#plan-request-json').innerText())
  if (plan.recommendation !== 'CANDIDATE_ONLY' || plan.claim_paths?.[0] !== 'isAdult') {
    throw new Error('Fjord response did not return the expected candidate claim')
  }
  if (guard.accepted !== true || guard.code !== 'GUARD_ACCEPTED') {
    throw new Error('Fjord plan was not accepted by the deterministic guard')
  }
  await page.locator('#plan-json').scrollIntoViewIfNeeded()
  await save('fjord-plan-and-guard.png')
  await page.click('#b-approve')
  await page.waitForSelector('#s-outcome:not([hidden])', { timeout: TIMEOUT })
  const fjordOutcome = await page.locator('#verdict').innerText()
  await save('fjord-accepted.png', '#s-outcome')

  await page.click('#b-restart')
  await page.waitForSelector('#s-cases:not([hidden])', { timeout: TIMEOUT })
  await page.click('[data-case="employment"]')
  const refusalResponsePromise = page.waitForResponse(
    (response) => response.url().endsWith('/api/interop/plan') && response.request().method() === 'POST',
    { timeout: TIMEOUT },
  )
  await page.click('#b-start')
  const refusalResponse = await refusalResponsePromise
  const refusal = await refusalResponse.json()
  await page.waitForSelector('#s-refusal:not([hidden])', { timeout: TIMEOUT })
  await page.locator('#s-refusal .api-inspector > summary').click()
  const refusalJson = JSON.parse(await page.locator('#refusal-json').innerText())
  if (refusalJson.recommendation !== 'NO_PATH' || refusalJson.plan !== null) {
    throw new Error('Employment response did not fail closed with NO_PATH and a null plan')
  }
  await saveElement('employment-no-path.png', '#s-refusal')

  const evidence = {
    capturedAt: new Date().toISOString(),
    demoBases: { apps: APP_DEMO_BASE, interoperability: INTEROP_DEMO_BASE },
    runtime: {
      mode: status.primary.mode,
      liveEnabled: status.primary.liveEnabled,
      modelConfigured: status.primary.modelConfigured,
      discoveryScopeSupported: status.primary.scopeSupported,
      secondIssuerReachable: status.synth2.reachable,
    },
    relyingPartyApps: [novabank, cornercellar],
    fjord: {
      request,
      recommendation: plan.recommendation,
      issuer: plan.candidate_issuer_id,
      claimPath: plan.claim_paths[0],
      credentialType: plan.credential_type,
      guard: { accepted: guard.accepted, code: guard.code, rulesVersion: guard.rulesVersion },
      outcome: fjordOutcome,
    },
    employment: {
      recommendation: refusalJson.recommendation,
      reason: refusalJson.reason,
      plan: refusalJson.plan,
      guard: refusalJson.guard,
    },
    pageErrors,
  }
  writeFileSync(join(OUTPUT_DIR, 'evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`)
  console.log(JSON.stringify({
    outputDir: OUTPUT_DIR,
    runtime: evidence.runtime,
    novabank: novabank.outcome,
    cornercellar: cornercellar.outcome,
    fjord: { claimPath: evidence.fjord.claimPath, guard: evidence.fjord.guard.code, outcome: fjordOutcome },
    employment: evidence.employment.recommendation,
    pageErrors,
  }, null, 2))
  if (pageErrors.length) throw new Error('one or more browser pages reported a JavaScript error')
} finally {
  await browser.close()
}
