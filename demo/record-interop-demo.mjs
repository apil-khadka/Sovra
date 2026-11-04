// Paced functional demo recording for the interop page.
//
// Drives the REAL demo server + REAL backend nodes through a real
// Chromium (Playwright) and records a clean browser video with a
// synchronized SRT sidecar:
// no invented events, no mocked responses, no terminals, no secrets
// on screen. Scope is the native-synthetic interop journey only
// (FIXTURE planner, two synthetic issuer nodes); it says nothing
// about the separate SD-JWT wallet profiles.
//
// Browser automation uses the repo's pinned frontend Playwright
// (@playwright/test 1.64.1); the final MP4 transcode uses a system
// ffmpeg. Install once:
//
//   pnpm --dir frontend install --frozen-lockfile
//   pnpm --dir frontend exec playwright install chromium
//
// Run (demo server already up, e.g. interop-only :5176):
//
//   DEMO_BASE=http://127.0.0.1:5176 \
//   ARTIFACT_DIR=/tmp/sovra-interop-demo \
//   node demo/record-interop-demo.mjs
//
// ARTIFACT_DIR defaults to demo/.browser-artifacts (no .intel
// requirement). Outputs: raw capture (webm), final H264 MP4,
// captions.srt + beats.json (caption timings + sanitized plan /
// decision identifiers per beat). HEADLESS=0 watches the run
// (video still records).

import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEMO_BASE = process.env.DEMO_BASE ?? 'http://127.0.0.1:5176'
const ARTIFACT_DIR = process.env.ARTIFACT_DIR ?? join(HERE, '.browser-artifacts')
const HEADLESS = (process.env.HEADLESS ?? '1') !== '0'
const STEP_TIMEOUT = Number(process.env.STEP_TIMEOUT_MS ?? 20000)
const WIDTH = 1440
const HEIGHT = 900

function loadPlaywright() {
  const frontendRequire = createRequire(join(HERE, '..', 'frontend', 'package.json'))
  try {
    return frontendRequire(process.env.PLAYWRIGHT_TEST_PATH ?? '@playwright/test')
  } catch (err) {
    console.error('Playwright not found. Install the repo-pinned browser tooling once:')
    console.error('  pnpm --dir frontend install --frozen-lockfile')
    console.error('  pnpm --dir frontend exec playwright install chromium')
    console.error(String(err?.message ?? err))
    process.exit(2)
  }
}

function srtTimestamp(ms) {
  const pad = (n, w = 2) => String(n).padStart(w, '0')
  const hours = Math.floor(ms / 3600000)
  const minutes = Math.floor((ms % 3600000) / 60000)
  const seconds = Math.floor((ms % 60000) / 1000)
  const millis = Math.floor(ms % 1000)
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)},${pad(millis, 3)}`
}

async function main() {
  mkdirSync(ARTIFACT_DIR, { recursive: true })
  const { chromium } = loadPlaywright()
  const browser = await chromium.launch({ headless: HEADLESS })
  const context = await browser.newContext({
    viewport: { width: WIDTH, height: HEIGHT },
    recordVideo: { dir: ARTIFACT_DIR, size: { width: WIDTH, height: HEIGHT } },
  })
  const page = await context.newPage()
  const video = page.video()
  let rawPath = null

  const beats = []
  const startedAt = new Date().toISOString()
  const t0 = Date.now()
  const evidence = []
  const note = (beat, data) => evidence.push({ beat, ...data })

  async function beat(text, ms) {
    const start = Date.now() - t0
    await page.waitForTimeout(ms)
    beats.push({ startMs: start, endMs: Date.now() - t0, text })
  }

  async function center(selector) {
    await page.evaluate((sel) => {
      document.querySelector(sel)?.scrollIntoView({ block: 'center', behavior: 'instant' })
    }, selector)
    await page.waitForTimeout(400)
  }

  async function expandAll(container) {
    const summaries = page.locator(`${container} details summary`)
    const count = await summaries.count()
    for (let i = 0; i < count; i += 1) {
      const details = page.locator(`${container} details`).nth(i)
      if (await details.evaluate((el) => el.open)) continue
      await summaries.nth(i).click()
      await page.waitForTimeout(300)
    }
  }

  async function planResponse() {
    const response = await page.waitForResponse(
      (res) => res.url().endsWith('/api/interop/plan') && res.request().method() === 'POST',
      { timeout: STEP_TIMEOUT },
    )
    return response.json()
  }

  async function verifyResponse() {
    const response = await page.waitForResponse(
      (res) => res.url().endsWith('/api/interop/verify') && res.request().method() === 'POST',
      { timeout: STEP_TIMEOUT },
    )
    return response.json()
  }

  try {
    // ---- Beat 1: purpose + FIXTURE mode ----
    await page.goto(`${DEMO_BASE}/interoperability`)
    await page.waitForSelector('#mode-pill', { timeout: STEP_TIMEOUT })
    await page.waitForFunction(
      () => document.querySelector('#mode-pill')?.textContent?.trim() !== '…',
      { timeout: STEP_TIMEOUT },
    )
    await center('.interop-hero')
    const modePill = (await page.locator('#mode-pill').innerText()).trim()
    const flags = (await page.locator('#status-flags').innerText()).trim()
    if (modePill !== 'FIXTURE') throw new Error(`mode pill "${modePill}", want FIXTURE`)
    note('status', { modePill, flags })
    await beat('Four issuer schemas. One central plan. A deterministic guard.', 6000)
    await beat('Synthetic functional demo — fixture planner. No Meta model invocation in this capture; eligible live evaluation pending account prerequisites.', 8000)

    // ---- Beat 2: known baseline, briefly ----
    await center('#s-cases')
    await beat('Baseline first: the known schema plans on the central ledger.', 4000)
    await page.click('[data-case="known"]')
    const knownPlanned = planResponse()
    await page.click('#b-start')
    const known = await knownPlanned
    await page.waitForSelector('#s-consent:not([hidden])', { timeout: STEP_TIMEOUT })
    note('known', {
      plan: known.plan?.plan_id, issuer: known.plan?.candidate_issuer_id,
      claims: known.plan?.claim_paths, guard: known.guard?.code,
    })
    await center('#s-consent')
    await beat('Known plan: adultOver18 on synth-1, guard accepted. Review shows exactly what is shared.', 6000)
    const knownVerified = verifyResponse()
    await page.click('#b-approve')
    const knownDone = await knownVerified
    await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
    note('known', { decision: knownDone.decision?.decisionId, outcome: knownDone.decision?.outcome })
    await center('#s-outcome')
    await beat('Known baseline accepted — decision and plan receipt recorded.', 5000)

    // ---- Beat 3: Fjord in detail ----
    await page.click('#b-restart')
    await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
    await page.click('[data-case="fjord"]')
    await center('#s-cases')
    await beat('Now the unfamiliar schema: Fjord. The page never names its wire field up front.', 5000)
    const fjordPlanned = planResponse()
    await page.click('#b-start')
    const fjord = await fjordPlanned
    await page.waitForSelector('#s-consent:not([hidden])', { timeout: STEP_TIMEOUT })
    note('fjord', {
      plan: fjord.plan?.plan_id, issuer: fjord.plan?.candidate_issuer_id,
      vct: fjord.plan?.credential_type, claims: fjord.plan?.claim_paths,
      policy: fjord.plan?.policy_id, guard: fjord.guard?.code,
      rules: fjord.guard?.rulesVersion, mode: fjord.meta?.mode,
    })
    await center('#s-consent')
    await beat('Fjord consent: who asks, what they learn, expiry — controls in view.', 5000)
    await expandAll('#s-consent')
    await center('#api-inspector')
    await beat('The inspector separates the browser request from the actual plan and guard JSON.', 6000)
    await center('#plan-json')
    await beat(`Returned plan discovers claim "${fjord.plan?.claim_paths?.[0]}" on synth-2 — issuance routes there.`, 7000)
    await center('#guard-json')
    await beat('Deterministic guard accepted under sovra-guard/2 before anything was minted.', 5000)
    await center('#consent-fields')
    await beat('Holder reviews exact claims, issuer, plan hash — then decides.', 4000)
    const fjordVerified = verifyResponse()
    await page.click('#b-approve')
    const fjordDone = await fjordVerified
    await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
    note('fjord', { decision: fjordDone.decision?.decisionId, outcome: fjordDone.decision?.outcome })
    await expandAll('#s-outcome')
    await center('#s-outcome')
    await beat('Fjord accepted: real ACCEPTED receipt with decision and plan identifiers.', 6000)

    // ---- Beat 4: Harbor second alias ----
    await page.click('#b-restart')
    await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
    await page.click('[data-case="harbor"]')
    await center('#s-cases')
    await beat('Second alias: Harbor discovers a different wire field for the same outcome.', 5000)
    const harborPlanned = planResponse()
    await page.click('#b-start')
    const harbor = await harborPlanned
    await page.waitForSelector('#s-consent:not([hidden])', { timeout: STEP_TIMEOUT })
    note('harbor', {
      plan: harbor.plan?.plan_id, claims: harbor.plan?.claim_paths, guard: harbor.guard?.code,
    })
    await expandAll('#s-consent')
    await center('#plan-json')
    await beat(`Harbor plan carries "${harbor.plan?.claim_paths?.[0]}" from the returned plan only — no echo.`, 7000)
    const harborVerified = verifyResponse()
    await page.click('#b-approve')
    const harborDone = await harborVerified
    await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
    note('harbor', { decision: harborDone.decision?.decisionId, outcome: harborDone.decision?.outcome })
    await expandAll('#s-outcome')
    await center('#s-outcome')
    await beat('Harbor accepted on its own issuer node — two stores, one outcome each.', 6000)

    // ---- Beat 5: employment grounded refusal ----
    await page.click('#b-restart')
    await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
    await page.click('[data-case="employment"]')
    await center('#s-cases')
    await beat('Incompatible schema: employment tenure cannot prove age.', 4000)
    const employmentPlanned = planResponse()
    await page.click('#b-start')
    const employment = await employmentPlanned
    await page.waitForSelector('#s-refusal:not([hidden])', { timeout: STEP_TIMEOUT })
    note('employment', { recommendation: employment.meta?.recommendation, plan: employment.plan })
    await expandAll('#s-refusal')
    await center('#s-refusal')
    await beat('Grounded NO_PATH with null plan: no credential, no consent, nothing shared.', 7000)

    // ---- Beat 6: decline honesty + limits ----
    await page.click('#b-refusal-restart')
    await page.waitForSelector('#s-cases:not([hidden])', { timeout: STEP_TIMEOUT })
    await page.click('[data-case="known"]')
    const declinePlanned = planResponse()
    await page.click('#b-start')
    await declinePlanned
    await page.waitForSelector('#s-consent:not([hidden])', { timeout: STEP_TIMEOUT })
    await center('#s-consent')
    await beat('Decline is honored: no presentation exists for a declined request.', 4000)
    await page.click('#b-decline')
    await page.waitForSelector('#s-outcome:not([hidden])', { timeout: STEP_TIMEOUT })
    await center('#s-outcome')
    await beat('Back and Cancel before a decision also share nothing; a committed decision cannot be cancelled.', 6000)
    await beat('Synthetic fixtures only; live AI is off. This walkthrough shows local browser behavior, not production deployment.', 7000)

    // ---- Sidecars ----
    const finishedAt = new Date().toISOString()
    const srt = beats.map((entry, index) =>
      `${index + 1}\n${srtTimestamp(entry.startMs)} --> ${srtTimestamp(entry.endMs)}\n${entry.text}\n`).join('\n')
    writeFileSync(join(ARTIFACT_DIR, 'captions.srt'), `${srt}\n`)
    writeFileSync(join(ARTIFACT_DIR, 'beats.json'), `${JSON.stringify({
      demoBase: DEMO_BASE, startedAt, finishedAt,
      viewport: { width: WIDTH, height: HEIGHT }, beats, evidence,
    }, null, 2)}\n`)
    console.log(`beats: ${beats.length}, wall: ${Math.round((Date.now() - t0) / 1000)}s`)
  } finally {
    await context.close()
    // Resolve this run's capture directly. Scanning ARTIFACT_DIR can
    // select an older WebM when the recorder is rerun in the same dir.
    rawPath = await video.path()
    await browser.close()
  }

  // ---- Transcode the raw capture to a playable H264 MP4 ----
  if (!rawPath) {
    console.error('no raw webm capture found; MP4 skipped')
    process.exit(1)
  }
  const mp4Path = join(ARTIFACT_DIR, 'sovra-synthetic-demo.mp4')
  try {
    execFileSync('ffmpeg', ['-y', '-i', rawPath, '-c:v', 'libx264', '-preset', 'medium', '-crf', '20',
      '-pix_fmt', 'yuv420p', '-movflags', '+faststart', mp4Path], { stdio: 'inherit' })
    console.log(`raw: ${rawPath}`)
    console.log(`mp4: ${mp4Path}`)
  } catch {
    console.error('ffmpeg transcode failed; raw capture retained')
    process.exit(1)
  }
}

await main()
