// Real-browser holder dashboard (SOV-024): members unlock with a
// holder-key proof and read exactly that key's cases,
// disclosures, credentials, and recovery. Strangers and locked
// sessions see nothing; hostile field values render as inert
// text.

import { createHash, generateKeyPairSync } from 'node:crypto'
import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import {
  MAKER,
  MEMBER,
  api,
  loginAs,
  machineSetup,
  mintExtraMachine,
  signCompact,
  thumbprint,
} from './sovra'
import type { EcJwk } from './sovra'

const FIXTURE =
  'SOVRA-FIXTURE/v1\nname: Ana Example\ndocument_number: X1234567\n' +
  'date_of_birth: 1990-01-02\ncountry: NL\n'

const ISSUER_ID = 'https://sovra.example/issuers/synth-1'
const ADULT_VCT = 'https://sovra.example/vct/adult-status/1'
const RP_ID = 'https://rp.example/synth-shop'
const AUDIENCE = 'https://rp.example/synth-shop/callback'
const PURPOSE = 'synthetic age check at checkout'
const POLICY_ID = 'sovra-synthetic-policy/age-check'
const POLICY_VERSION = '1'
const SECTION_ID = 'age_eligibility'

const HOSTILE_NAME = '<svg onload="window.__pwned3=1">'

interface Holder {
  publicJwk: { kty: string; crv: string; x: string; y: string }
  privateJwk: EcJwk & { kty: string; crv: string; x: string; y: string; d: string }
  thumb: string
}

function holderKeys(): Holder {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pub = publicKey.export({ format: 'jwk' })
  const priv = privateKey.export({ format: 'jwk' })
  const publicJwk = { kty: 'EC', crv: 'P-256', x: pub.x as string, y: pub.y as string }
  return {
    publicJwk,
    privateJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: pub.x as string,
      y: pub.y as string,
      d: priv.d as string,
    },
    thumb: thumbprint(publicJwk),
  }
}

async function approvedSource(
  base: string,
  token: string,
): Promise<{ objectId: string; recordId: string }> {
  const content = Buffer.from(FIXTURE, 'utf-8').toString('base64')
  const stored = await api(base, token, 'POST', '/api/vault/objects', {
    issuerId: 'https://issuer.example/holder-e2e',
    displayName: 'holder e2e source',
    purposes: ['extraction-run'],
    contentBase64: content,
    contentSha256Hex: createHash('sha256').update(FIXTURE, 'utf-8').digest('hex'),
  })
  expect(stored.status).toBe(201)
  const objectId = (stored.json as { objectId: string }).objectId
  const me = await api(base, token, 'GET', '/api/whoami')
  const granted = await api(base, token, 'POST', '/api/vault/grants', {
    objectId,
    objectVersion: 1,
    principalType: 'service_account',
    principalId: (me.json as { accountId: string }).accountId,
    purpose: 'extraction-run',
    workload: 'holder-e2e',
    ttlSeconds: 3600,
  })
  expect(granted.status).toBe(201)
  const run = await api(base, token, 'POST', '/api/extraction/records', {
    vaultObjectId: objectId,
    objectVersion: 1,
    grantId: (granted.json as { grantId: string }).grantId,
    purpose: 'extraction-run',
    workload: 'holder-e2e',
    schemaId: 'fixture-doc-v1',
  })
  expect(run.status).toBe(201)
  const recordId = (run.json as { recordId: string }).recordId
  const approval = await api(
    base,
    token,
    'POST',
    `/api/extraction/records/${recordId}/approval`,
    { revision: 1 },
  )
  expect(approval.status).toBe(200)
  return { objectId, recordId }
}

interface Journey {
  enrollmentId: string
  credentialId: string
  requestId: string
}

/** Enroll, approve, issue, disclose, and verify for one holder key. */
async function holderJourney(
  base: string,
  makerToken: string,
  checkerToken: string,
  rpToken: string,
  source: { objectId: string; recordId: string },
  holder: Holder,
): Promise<Journey> {
  const created = await api(base, makerToken, 'POST', '/api/enrollments', {
    vaultObjectId: source.objectId,
    extractionRecordId: source.recordId,
    holderJwk: holder.publicJwk,
  })
  expect(created.status).toBe(201)
  const enrollmentId = (created.json as { enrollmentId: string }).enrollmentId
  // Maker submits; a different operator approves with the holder proof.
  const submitter = await api(base, makerToken, 'POST', `/api/enrollments/${enrollmentId}/submit`, {})
  expect(submitter.status).toBe(200)
  const decided = await api(base, checkerToken, 'POST', `/api/enrollments/${enrollmentId}/decision`, {
    revision: 1,
    decision: 'approve',
    bindingProof: signCompact(
      holder.privateJwk,
      `enrollment-binding\n${enrollmentId}\n1`,
    ),
  })
  expect(decided.status).toBe(200)

  const key = `holder-${Date.now()}-${Math.floor(Math.random() * 1e9)}`
  const issued = await api(base, makerToken, 'POST', '/api/issuance/credentials', {
    issuerId: ISSUER_ID,
    vct: ADULT_VCT,
    holderJwk: holder.publicJwk,
    holderProof: signCompact(
      holder.privateJwk,
      `sovra-issuance-proof/v1\n${key}\n${ADULT_VCT}\n${holder.thumb}\nadultOver18=true`,
    ),
    claims: { adultOver18: true },
    expiresAt: new Date(Date.now() + 7200_000).toISOString(),
    enrollmentId,
  }, { 'Idempotency-Key': key })
  expect(issued.status).toBe(201)
  const credentialId = (issued.json as { credentialId: string }).credentialId

  const planId = `pln_holder_${Date.now()}`
  const plan = {
    plan_id: planId,
    requested_outcome: 'age_over_18',
    candidate_issuer_id: ISSUER_ID,
    credential_type: ADULT_VCT,
    claim_paths: ['adultOver18'],
    evidence: [{ document_id: POLICY_ID, section_id: SECTION_ID }],
    policy_id: POLICY_ID,
    policy_version: POLICY_VERSION,
    recommendation: 'CANDIDATE_ONLY',
  }
  const planHash = createHash('sha256')
    .update(
      [
        'sovra-plan/v1', planId, 'age_over_18', ISSUER_ID, ADULT_VCT, 'adultOver18',
        `${POLICY_ID}#${SECTION_ID}`, POLICY_ID, POLICY_VERSION, 'CANDIDATE_ONLY', '',
      ].join('\n'),
      'utf-8',
    )
    .digest('hex')
  const challenge = createHash('sha256').update(planId, 'utf-8').digest('base64url')
  const consent = await api(base, rpToken, 'POST', '/api/consent/requests', {
    rpId: RP_ID,
    audience: AUDIENCE,
    purpose: PURPOSE,
    credentialId,
    claims: { adultOver18: true },
    plan,
    policyId: POLICY_ID,
    policyVersion: POLICY_VERSION,
    planHash,
    challenge,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  })
  expect(consent.status).toBe(201)
  const requestId = (consent.json as { requestId: string }).requestId
  const review = await api(base, rpToken, 'GET', `/api/consent/requests/${requestId}`)
  const viewed = review.json as Record<string, string>
  const decision = await api(base, rpToken, 'POST', `/api/consent/requests/${requestId}/decision`, {
    decision: 'approve',
    holderJwk: holder.publicJwk,
    consentProof: signCompact(
      holder.privateJwk,
      `sovra-consent/v1\n${viewed['requestId']}\napprove\n${viewed['rpId']}\n` +
        `${viewed['audience']}\n${viewed['purpose']}\nadultOver18=true\n` +
        `${viewed['planHash']}\n${viewed['challenge']}\n${viewed['expiresAt']}\n${viewed['holderThumbprint']}`,
    ),
  })
  expect(decision.status).toBe(200)
  const nonce = `nonce-${Date.now()}`
  const verified = await api(base, rpToken, 'POST', '/api/verification/presentations', {
    requestId,
    nonce,
    audience: AUDIENCE,
    holderJwk: holder.publicJwk,
    bindingProof: signCompact(
      holder.privateJwk,
      `sovra-presentation/v1\n${requestId}\n${nonce}\n${AUDIENCE}\n${holder.thumb}`,
    ),
  })
  expect(verified.status).toBe(200)
  return { enrollmentId, credentialId, requestId }
}

async function unlockWith(page: Page, privateJwk: object): Promise<void> {
  await page.getByPlaceholder(/"kty":"EC"/).fill(JSON.stringify(privateJwk))
  await page.getByRole('button', { name: 'Unlock my history' }).click()
}

test('holder dashboard prompts anonymous visitors to log in', async ({ page }) => {
  await page.goto('/#/holder')
  await expect(page.getByText('Log in first')).toBeVisible()
})

test('holder dashboard refuses non-member sessions', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  await loginAs(page, base, MAKER)
  await page.goto('/#/holder')
  await expect(page.getByText('lacks the member role')).toBeVisible()
})

test('holders unlock and read their whole history', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const source = await approvedSource(base, setup.token)
  const holder = holderKeys()
  const checker = mintExtraMachine(`holder-e2e-checker-${Date.now()}`, 'ISSUER_OPS')
  const journey = await holderJourney(base, setup.token, checker.token, setup.token, source, holder)

  await loginAs(page, base, MEMBER)
  await page.goto('/#/holder')
  await unlockWith(page, holder.privateJwk)
  await expect(page.getByText('Unlocked key').first()).toBeVisible()

  await page.getByRole('button', { name: 'My cases', exact: true }).click()
  await page.getByRole('button', { name: 'Load my cases' }).click()
  await page.getByRole('button', { name: 'Open case', exact: true }).first().waitFor()
  await page.getByRole('button', { name: 'Open case', exact: true }).first().click()
  await expect(page.getByText(journey.enrollmentId).first()).toBeVisible()
  await expect(page.getByText('eligible').first()).toBeVisible()
  await expect(page.getByText('Ana Example').first()).toBeVisible()

  await page.getByRole('button', { name: 'Disclosures', exact: true }).click()
  await page.getByRole('button', { name: 'Load disclosures' }).click()
  await expect(page.getByText(PURPOSE).first()).toBeVisible()
  await expect(page.getByText(journey.requestId.slice(0, 8)).first()).toBeVisible()

  await page.getByRole('button', { name: 'Credentials', exact: true }).click()
  await page.getByRole('button', { name: 'Load credentials' }).click()
  await expect(page.getByText(journey.credentialId.slice(0, 8)).first()).toBeVisible()

  await page.getByRole('button', { name: 'Recovery', exact: true }).click()
  await page.getByRole('button', { name: 'Load recovery state' }).click()
  await expect(page.getByText('active').first()).toBeVisible()

  await page.getByRole('button', { name: 'Lock' }).click()
  await expect(page.getByRole('button', { name: 'Unlock my history' })).toBeVisible()
})

test('stranger keys see an empty history', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const stranger = holderKeys()
  await loginAs(page, base, MEMBER)
  await page.goto('/#/holder')
  await unlockWith(page, stranger.privateJwk)
  await expect(page.getByText('Unlocked key').first()).toBeVisible()
  await page.getByRole('button', { name: 'My cases', exact: true }).click()
  await page.getByRole('button', { name: 'Load my cases' }).click()
  await expect(page.getByText('No cases for this key.')).toBeVisible()
})

test('hostile correction values render as inert text', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const source = await approvedSource(base, setup.token)
  const holder = holderKeys()
  const created = await api(base, setup.token, 'POST', '/api/enrollments', {
    vaultObjectId: source.objectId,
    extractionRecordId: source.recordId,
    holderJwk: holder.publicJwk,
  })
  expect(created.status).toBe(201)
  const enrollmentId = (created.json as { enrollmentId: string }).enrollmentId
  const corrected = await api(
    base,
    setup.token,
    'POST',
    `/api/extraction/records/${source.recordId}/revisions`,
    {
      fields: { name: HOSTILE_NAME, document_number: 'X1234567', date_of_birth: '1990-01-02' },
      confidence: 0.5,
    },
  )
  expect(corrected.status).toBe(201)

  await loginAs(page, base, MEMBER)
  await page.goto('/#/holder')
  await unlockWith(page, holder.privateJwk)
  await expect(page.getByText('Unlocked key').first()).toBeVisible()
  await page.getByRole('button', { name: 'My cases', exact: true }).click()
  await page.getByRole('button', { name: 'Load my cases' }).click()
  const openers = page.getByRole('button', { name: 'Open case', exact: true })
  await openers.first().waitFor({ timeout: 15_000 })
  const count = await openers.count()
  for (let i = 0; i < Math.min(count, 25); i++) {
    await openers.nth(i).click()
    try {
      await page.getByText(enrollmentId).first().waitFor({ timeout: 3_000 })
      break
    } catch {
      // Not this card; keep walking.
    }
  }
  await expect(page.getByText(HOSTILE_NAME).first()).toBeVisible()
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>)['__pwned3'])).toBeUndefined()
  await expect(page.locator('main svg')).toHaveCount(0)
})
