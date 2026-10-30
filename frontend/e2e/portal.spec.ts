// Real-browser developer portal and RP dashboard (SOV-022,
// SOV-025): members onboard sandbox credentials, manage RP
// apps through rotate/revoke, and review verification
// outcomes and metrics. Strangers and non-member sessions
// see only the member gate.

import { createHash, generateKeyPairSync } from 'node:crypto'
import { expect, test } from '@playwright/test'
import { MAKER, MEMBER, api, loginAs, machineSetup, mintExtraMachine, signCompact, thumbprint } from './sovra'
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
    issuerId: 'https://issuer.example/portal-e2e',
    displayName: 'portal e2e source',
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
    workload: 'portal-e2e',
    ttlSeconds: 3600,
  })
  expect(granted.status).toBe(201)
  const run = await api(base, token, 'POST', '/api/extraction/records', {
    vaultObjectId: objectId,
    objectVersion: 1,
    grantId: (granted.json as { grantId: string }).grantId,
    purpose: 'extraction-run',
    workload: 'portal-e2e',
    schemaId: 'fixture-doc-v1',
  })
  expect(run.status).toBe(201)
  const recordId = (run.json as { recordId: string }).recordId
  const approval = await api(base, token, 'POST', `/api/extraction/records/${recordId}/approval`, {
    revision: 1,
  })
  expect(approval.status).toBe(200)
  return { objectId, recordId }
}

/** One ACCEPTED verification decision the dashboard can display. */
async function seedDecision(
  base: string,
  makerToken: string,
  checkerToken: string,
  rpToken: string,
  source: { objectId: string; recordId: string },
  holder: Holder,
): Promise<{ requestId: string; decisionId: string }> {
  const created = await api(base, makerToken, 'POST', '/api/enrollments', {
    vaultObjectId: source.objectId,
    extractionRecordId: source.recordId,
    holderJwk: holder.publicJwk,
  })
  expect(created.status).toBe(201)
  const enrollmentId = (created.json as { enrollmentId: string }).enrollmentId
  await api(base, makerToken, 'POST', `/api/enrollments/${enrollmentId}/submit`, {})
  const decided = await api(base, checkerToken, 'POST', `/api/enrollments/${enrollmentId}/decision`, {
    revision: 1,
    decision: 'approve',
    bindingProof: signCompact(holder.privateJwk, `enrollment-binding\n${enrollmentId}\n1`),
  })
  expect(decided.status).toBe(200)

  const key = `portal-${Date.now()}-${Math.floor(Math.random() * 1e9)}`
  const issued = await api(
    base,
    makerToken,
    'POST',
    '/api/issuance/credentials',
    {
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
    },
    { 'Idempotency-Key': key },
  )
  expect(issued.status).toBe(201)
  const credentialId = (issued.json as { credentialId: string }).credentialId

  const planId = `pln_portal_${Date.now()}`
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
  return { requestId, decisionId: (verified.json as { decisionId: string }).decisionId }
}

test('portal and dashboard prompt anonymous visitors to log in', async ({ page }) => {
  await page.goto('/#/portal')
  await expect(page.getByText('Log in first')).toBeVisible()
  await page.goto('/#/rpdash')
  await expect(page.getByText('Log in first')).toBeVisible()
})

test('portal and dashboard refuse non-member sessions', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  await loginAs(page, base, MAKER)
  await page.goto('/#/portal')
  await expect(page.getByText('lacks the tenant member role')).toBeVisible()
  await page.goto('/#/rpdash')
  await expect(page.getByText('lacks the tenant member role')).toBeVisible()
})

test('members onboard, rotate, and revoke sandbox credentials', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const appName = `sandbox-portal-${Date.now()}`
  await loginAs(page, base, MEMBER)
  await page.goto('/#/portal')
  await page.getByRole('button', { name: 'Load portal' }).click()
  await expect(page.getByText('Contract 0.16.0')).toBeVisible()

  await page.getByPlaceholder('sandbox-my-app').fill(appName)
  await page.getByRole('button', { name: 'Create sandbox credential' }).click()
  await expect(page.getByText('copy the token now')).toBeVisible()
  const created = page.getByText(appName)
  await expect(created.first()).toBeVisible()

  // The minted token works as a machine RP credential.
  const token = await page
    .locator('article', { hasText: 'copy the token now' })
    .locator('dd')
    .nth(1)
    .innerText()
  const metrics = await api(base, token.trim(), 'GET', '/api/rp/metrics')
  expect(metrics.status).toBe(200)

  // The RP dashboard rotates, then revokes, the same app.
  await page.goto('/#/rpdash')
  await page.getByRole('button', { name: 'Load dashboard' }).click()
  const card = page.locator('article', { hasText: appName })
  await expect(card).toBeVisible()
  await card.getByRole('button', { name: 'Rotate credential' }).click()
  await expect(page.getByText('copy the token now')).toBeVisible()
  const rotated = await page
    .locator('article', { hasText: 'copy the token now' })
    .locator('dd')
    .nth(1)
    .innerText()
  expect(rotated.trim()).not.toBe(token.trim())
  const stale = await api(base, token.trim(), 'GET', '/api/rp/metrics')
  expect(stale.status).toBe(401)
  const fresh = await api(base, rotated.trim(), 'GET', '/api/rp/metrics')
  expect(fresh.status).toBe(200)

  await card.getByRole('button', { name: 'Revoke credential' }).click()
  await expect(card.getByText('revoked')).toBeVisible()
  const dead = await api(base, rotated.trim(), 'GET', '/api/rp/metrics')
  expect(dead.status).toBe(401)
})

test('dashboard shows verification outcomes and metrics', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const source = await approvedSource(base, setup.token)
  const checker = mintExtraMachine(`portal-e2e-checker-${Date.now()}`, 'ISSUER_OPS')
  const seeded = await seedDecision(base, setup.token, checker.token, setup.token, source, holderKeys())

  await loginAs(page, base, MEMBER)
  await page.goto('/#/rpdash')
  await page.getByRole('button', { name: 'Load dashboard' }).click()
  await expect(page.getByText(seeded.decisionId.slice(0, 8)).first()).toBeVisible()
  await expect(page.getByText(seeded.requestId.slice(0, 8)).first()).toBeVisible()
  await expect(page.getByText(/^\d+ decisions?$/).first()).toBeVisible()
})
