// Real-browser issuer desk (SOV-023/SEC-37): operators review
// extraction and enrollment queues, decide cases through
// maker/checker, and see hostile field values as inert text.
// Members get the access notice instead of the queues.

import { createHash, generateKeyPairSync } from 'node:crypto'
import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import {
  CHECKER,
  MAKER,
  MEMBER,
  api,
  loginAs,
  machineSetup,
  signCompact,
} from './sovra'
import type { EcJwk } from './sovra'

const FIXTURE =
  'SOVRA-FIXTURE/v1\nname: Ana Example\ndocument_number: X1234567\n' +
  'date_of_birth: 1990-01-02\ncountry: NL\n'

const HOSTILE_NAME = '<img src=x onerror="window.__pwned=1">'
const HOSTILE_DOC = '<script>window.__pwned2=1</script>'

const PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='

function sha256HexText(text: string): string {
  return createHash('sha256').update(text, 'utf-8').digest('hex')
}

function sha256HexBytes(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex')
}

async function storeObject(
  base: string,
  token: string,
  contentBase64: string,
  contentSha256Hex: string,
  purposes: string[],
): Promise<string> {
  const { status, json } = await api(base, token, 'POST', '/api/vault/objects', {
    issuerId: 'https://issuer.example/desk-e2e',
    displayName: 'desk e2e source',
    purposes,
    contentBase64,
    contentSha256Hex,
  })
  expect(status).toBe(201)
  return (json as { objectId: string }).objectId
}

async function grantFor(
  base: string,
  token: string,
  objectId: string,
  purpose: string,
): Promise<string> {
  const me = await api(base, token, 'GET', '/api/whoami')
  const accountId = (me.json as { accountId: string }).accountId
  const { status, json } = await api(base, token, 'POST', '/api/vault/grants', {
    objectId,
    objectVersion: 1,
    principalType: 'service_account',
    principalId: accountId,
    purpose,
    workload: 'desk-e2e',
    ttlSeconds: 3600,
  })
  expect(status).toBe(201)
  return (json as { grantId: string }).grantId
}

async function approvedSource(
  base: string,
  token: string,
): Promise<{ objectId: string; recordId: string }> {
  const objectId = await storeObject(
    base,
    token,
    Buffer.from(FIXTURE, 'utf-8').toString('base64'),
    sha256HexText(FIXTURE),
    ['extraction-run'],
  )
  const grantId = await grantFor(base, token, objectId, 'extraction-run')
  const run = await api(base, token, 'POST', '/api/extraction/records', {
    vaultObjectId: objectId,
    objectVersion: 1,
    grantId,
    purpose: 'extraction-run',
    workload: 'desk-e2e',
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

function holderKeys(): { publicJwk: Record<string, string>; privateJwk: EcJwk } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pub = publicKey.export({ format: 'jwk' })
  const priv = privateKey.export({ format: 'jwk' })
  return {
    publicJwk: { kty: 'EC', crv: 'P-256', x: pub.x as string, y: pub.y as string },
    privateJwk: priv as EcJwk,
  }
}

async function gotoDesk(page: Page, area: string): Promise<void> {
  await page.goto('/#/issuer')
  await page.getByRole('button', { name: area, exact: true }).click()
}

/** Open queue cards newest-first until the card with id renders its detail. */
async function openCardById(page: Page, buttonName: string, id: string): Promise<void> {
  const openers = page.getByRole('button', { name: buttonName, exact: true })
  await openers.first().waitFor({ timeout: 15_000 })
  const count = await openers.count()
  for (let i = 0; i < Math.min(count, 25); i++) {
    await openers.nth(i).click()
    const detail = page.getByText(id, { exact: false }).first()
    try {
      await detail.waitFor({ timeout: 3_000 })
      return
    } catch {
      // Not this card; keep walking.
    }
  }
  throw new Error(`queue card for ${id} never rendered`)
}

test('issuer desk hides queues from members and strangers', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  await loginAs(page, base, MEMBER)
  await page.goto('/#/issuer')
  await expect(page.getByRole('heading', { name: 'Issuer desk' })).toBeVisible()
  await expect(page.getByText('Issuer operator session required')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Load extraction queue' })).toHaveCount(0)
})

test('issuer desk prompts anonymous visitors to log in', async ({ page }) => {
  await page.goto('/#/issuer')
  await expect(page.getByText('Log in first')).toBeVisible()
})

test('maker and checker decide a case through the desk', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const source = await approvedSource(base, setup.token)
  const holder = holderKeys()

  await loginAs(page, base, MAKER)
  await gotoDesk(page, 'Enrollments')
  await page.getByRole('button', { name: 'New case', exact: true }).click()
  await page.getByPlaceholder('source object UUID').fill(source.objectId)
  await page.getByPlaceholder('approved record UUID').fill(source.recordId)
  await page.getByPlaceholder(/"kty":"EC"/).fill(JSON.stringify(holder.publicJwk))
  await page.getByRole('button', { name: 'Open case', exact: true }).click()
  const opened = page.getByRole('alert').first()
  await expect(opened).toContainText('Case opened:')
  const enrollmentId = (await opened.textContent())?.match(/[0-9a-f-]{36}/)?.[0] ?? ''
  expect(enrollmentId).not.toBe('')

  await page.getByRole('button', { name: 'Load enrollment queue' }).click()
  await openCardById(page, 'Open case', enrollmentId)
  await expect(page.getByText('Case id')).toBeVisible()
  await page.getByRole('button', { name: 'Submit for review' }).click()
  await expect(page.getByText('A different operator must decide it.')).toBeVisible()

  // The maker cannot approve their own case, even with a valid
  // holder binding proof pasted in.
  const proof = signCompact(
    holder.privateJwk,
    `enrollment-binding\n${enrollmentId}\n1`,
  )
  await page.getByPlaceholder('Paste the holder-signed enrollment-binding proof').fill(proof)
  await page.getByRole('button', { name: 'Approve case' }).click()
  await expect(page.getByText('already decided, self-approval, or no longer current')).toBeVisible()

  await page.getByRole('button', { name: 'Log out' }).click()
  await page.getByRole('button', { name: 'Log in with Keycloak' }).waitFor()
  await loginAs(page, base, CHECKER)
  await gotoDesk(page, 'Enrollments')
  await page.getByRole('button', { name: 'Load enrollment queue' }).click()
  await openCardById(page, 'Open case', enrollmentId)
  await page.getByPlaceholder('Paste the holder-signed enrollment-binding proof').fill(proof)
  await page.getByRole('button', { name: 'Approve case' }).click()
  await expect(page.getByText('Case approved.')).toBeVisible()
  await expect(page.getByText('eligible').first()).toBeVisible()
})

test('hostile field values render as inert text', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const objectId = await storeObject(
    base,
    setup.token,
    Buffer.from(FIXTURE, 'utf-8').toString('base64'),
    sha256HexText(FIXTURE),
    ['extraction-run'],
  )
  const grantId = await grantFor(base, setup.token, objectId, 'extraction-run')
  const run = await api(base, setup.token, 'POST', '/api/extraction/records', {
    vaultObjectId: objectId,
    objectVersion: 1,
    grantId,
    purpose: 'extraction-run',
    workload: 'desk-e2e',
    schemaId: 'fixture-doc-v1',
  })
  const recordId = (run.json as { recordId: string }).recordId
  const corrected = await api(
    base,
    setup.token,
    'POST',
    `/api/extraction/records/${recordId}/revisions`,
    {
      fields: { name: HOSTILE_NAME, document_number: HOSTILE_DOC, date_of_birth: '1990-01-02' },
      confidence: 0.5,
    },
  )
  expect(corrected.status).toBe(201)

  await loginAs(page, base, MAKER)
  await gotoDesk(page, 'Extraction')
  await page.getByRole('button', { name: 'Load extraction queue' }).click()
  await openCardById(page, 'Open record', recordId)
  await expect(page.getByText(HOSTILE_NAME).first()).toBeVisible()
  await expect(page.getByText(HOSTILE_DOC).first()).toBeVisible()
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>)['__pwned'])).toBeUndefined()
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>)['__pwned2'])).toBeUndefined()
  // No image element smuggles in through the field text.
  await expect(page.locator('main img')).toHaveCount(0)
})

test('review view serves the original image to the session', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const pngBytes = Buffer.from(PNG_BASE64, 'base64')
  const objectId = await storeObject(
    base,
    setup.token,
    PNG_BASE64,
    sha256HexBytes(pngBytes),
    ['issuer-review'],
  )

  await loginAs(page, base, MAKER)
  await page.goto('/#/issuer')
  const viewed = await page.evaluate(async (id: string) => {
    const xsrf = document.cookie
      .split(';')
      .map((part) => part.trim().split('='))
      .find(([name]) => name === 'XSRF-TOKEN')?.[1]
    const res = await fetch('/api/bff/issuer/vault/review-view', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-XSRF-TOKEN': xsrf ?? '' },
      body: JSON.stringify({ objectId: id, version: 1 }),
    })
    return { status: res.status, json: (await res.json()) as Record<string, string> }
  }, objectId)
  expect(viewed.status).toBe(200)
  expect(viewed.json['contentType']).toBe('image/png')
  expect(viewed.json['contentBase64']).toBe(PNG_BASE64)
})

test('session conditional reads answer 304 when fresh', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  const source = await approvedSource(base, setup.token)

  await loginAs(page, base, MAKER)
  await page.goto('/#/issuer')
  const first = await page.evaluate(async (id: string) => {
    const res = await fetch(`/api/bff/issuer/extraction/records/${id}`, { credentials: 'include' })
    return { status: res.status, etag: res.headers.get('etag') }
  }, source.recordId)
  expect(first.status).toBe(200)
  expect(first.etag).toBeTruthy()
  const replay = await page.evaluate(
    async ({ id, etag }: { id: string; etag: string }) => {
      const res = await fetch(`/api/bff/issuer/extraction/records/${id}`, {
        credentials: 'include',
        headers: { 'If-None-Match': etag },
      })
      return res.status
    },
    { id: source.recordId, etag: first.etag ?? '' },
  )
  expect(replay).toBe(304)
})
