// Real-browser holder-consent evidence (SOV-010/SOV-041): the page
// generates the holder key, reviews exact bound values, and signs
// the decision with WebCrypto. Negatives cover denial, wrong
// holder, CSRF enforcement, and anonymous reads.

import { generateKeyPairSync } from 'node:crypto'
import { expect, test } from '@playwright/test'
import {
  MEMBER,
  createRequest,
  issueCredential,
  loginAs,
  machineSetup,
  publicJwkFromPrivate,
  thumbprint,
} from './sovra'
import type { EcJwk } from './sovra'
import { browserHolder, decideViaBrowser, reviewRequest } from './journey'

test.use({ permissions: ['clipboard-read', 'clipboard-write'] })

test('holder reviews exact bound values and approves in the browser', async ({
  page,
  baseURL,
}) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  await decideViaBrowser(page, setup, 'approve')
  const me = (await page.evaluate(async () => {
    const res = await fetch('/api/bff/me')
    return (await res.json()) as { tenantId: string }
  })) as { tenantId: string }
  expect(me.tenantId).toBe(setup.tenantId)
})

test('holder denial shares nothing', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  const approval = await decideViaBrowser(page, setup, 'deny')
  const res = await fetch(
    `${setup.base}/api/consent/requests/${approval.requestId}/presentation`,
    { headers: { Authorization: `Bearer ${setup.token}` } },
  )
  expect(res.status).not.toBe(200)
})

/** Setup-only holder key; the browser never sees this private half. */
function nodeHolder(): { holderJwk: Record<string, string>; privateJwk: EcJwk } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const exported = privateKey.export({ format: 'jwk' })
  if (
    typeof exported.x !== 'string' || typeof exported.y !== 'string'
    || typeof exported.d !== 'string'
  ) {
    throw new Error('node EC key export lacks coordinates')
  }
  const holderJwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y }
  const privateJwk: EcJwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y, d: exported.d }
  return { holderJwk, privateJwk }
}

test('a non-matching holder key disables approval', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  const browser = await browserHolder(page)
  const other = nodeHolder()
  expect(thumbprint(other.holderJwk)).not.toBe(browser.thumbprint)
  const credentialId = await issueCredential(setup, other.holderJwk, other.privateJwk)
  const created = await createRequest(setup, credentialId)
  await page.getByLabel('Proof request id').fill(created.requestId)
  await page.getByRole('button', { name: 'Load request' }).click()
  await expect(page.getByText('Pending — awaiting your decision')).toBeVisible()
  await page.getByRole('button', { name: 'Review details' }).click()
  await expect(
    page.getByText('Wrong holder: this key does not match the credential. Approval is disabled.'),
  ).toBeVisible()
  await expect(page.getByRole('button', { name: 'Approve and share' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Deny' })).toBeDisabled()
})

test('consent decision without the CSRF echo is rejected; the UI echo succeeds', async ({
  page,
  baseURL,
}) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  const holder = await browserHolder(page)
  const pub = publicJwkFromPrivate(holder.privateJwk.d)
  const holderJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y }
  const credentialId = await issueCredential(setup, holderJwk, holder.privateJwk)
  const created = await createRequest(setup, credentialId)
  const status = await page.evaluate(async (requestId: string) => {
    const res = await fetch(`/api/bff/consent/requests/${requestId}/decision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    return res.status
  }, created.requestId)
  expect(status).toBe(403)
  // The rejected POST decided nothing: the UI echo still approves.
  await reviewRequest(page, created, holder.thumbprint)
  await page.getByRole('button', { name: 'Approve and share' }).click()
  await expect(page.getByText('Verified — synthetic consent proof')).toBeVisible()
})

test('anonymous consent read fails closed without a token', async ({ page }) => {
  const setup = machineSetup()
  const other = nodeHolder()
  const credentialId = await issueCredential(setup, other.holderJwk, other.privateJwk)
  const created = await createRequest(setup, credentialId)
  await page.goto('/')
  await page.getByRole('button', { name: 'Holder consent' }).click()
  await page.getByLabel('Proof request id').fill(created.requestId)
  await page.getByRole('button', { name: 'Load request' }).click()
  await expect(page.getByText('Could not load: invalid or missing token')).toBeVisible()
})
