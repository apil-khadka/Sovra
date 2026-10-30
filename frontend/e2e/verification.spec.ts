// Real-browser verification evidence (SOV-011/SOV-041): the page
// imports the consent-step holder key, mints a fresh nonce, signs
// the binding proof with WebCrypto, and reads back the stored
// decision. A mismatched audience rejects.

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { MEMBER, loginAs, machineSetup } from './sovra'
import type { EcJwk } from './sovra'
import { browserHolder, decideViaBrowser, expectedProfile } from './journey'

test.use({ permissions: ['clipboard-read', 'clipboard-write'] })
test.skip(process.env.SOVRA_PROFILE === 'sdjwt-vc', 'Native verifier UI uses the synthetic binding; selected-profile coverage is in wallet.spec.ts.')

async function submitVerification(
  page: Page,
  requestId: string,
  audience: string,
  privateJwk: EcJwk,
  thumb: string,
): Promise<void> {
  await page.getByRole('link', { name: 'Verify presentation' }).click()
  await expect(page.getByRole('heading', { name: 'Verify presentation', exact: true })).toBeVisible()
  await page.getByLabel('Proof request id').fill(requestId)
  await page.getByLabel('Session audience').fill(audience)
  await page.getByRole('button', { name: 'New nonce' }).click()
  await page.getByLabel('Or import holder private JWK').fill(JSON.stringify(privateJwk))
  await page.getByRole('button', { name: 'Import key' }).click()
  await expect(page.getByText(`holder: ${thumb}`)).toBeVisible()
  await page.getByRole('button', { name: 'Submit verification' }).click()
}

test('browser-signed binding proof verifies and re-reads identically', async ({
  page,
  baseURL,
}) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  const approval = await decideViaBrowser(page, setup, 'approve')
  const submission = page.waitForRequest((req) =>
    req.url().endsWith('/api/bff/verification/presentations') && req.method() === 'POST')
  await submitVerification(page, approval.requestId, approval.audience, approval.privateJwk, approval.thumbprint)
  await expect(page.getByText('Accepted — synthetic evidence verified')).toBeVisible()
  const card = page.locator('.consent-card.state-verified')
  await expect(card.getByText(expectedProfile(), { exact: true })).toBeVisible()
  await expect(
    page.getByText('Stored decision re-read identically: a lost response replays, never rewrites.'),
  ).toBeVisible()
  // Retry the actual signed POST through the same browser session.
  // A decision GET alone does not prove submission idempotency.
  const sent = await submission
  const response = await sent.response()
  if (response === null) throw new Error('verification response missing')
  const first = await response.json() as Record<string, unknown>
  const replay = await page.evaluate(async (body: string) => {
    const cookie = document.cookie.split('; ').find((part) => part.startsWith('XSRF-TOKEN='))
    if (cookie === undefined) throw new Error('CSRF cookie missing')
    const res = await fetch('/api/bff/verification/presentations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': decodeURIComponent(cookie.slice('XSRF-TOKEN='.length)),
      },
      body,
    })
    return { status: res.status, decision: await res.json() as Record<string, unknown> }
  }, sent.postData() ?? '')
  expect(replay.status).toBe(200)
  expect(replay.decision).toEqual(first)
})

test('a mismatched audience rejects without accepting', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  const approval = await decideViaBrowser(page, setup, 'approve')
  await submitVerification(
    page,
    approval.requestId,
    'https://rp.example/wrong/callback',
    approval.privateJwk,
    approval.thumbprint,
  )
  await expect(page.getByText('Rejected — not accepted')).toBeVisible()
})

test('a tampered browser binding proof rejects without accepting', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  await loginAs(page, base, MEMBER)
  const approval = await decideViaBrowser(page, machineSetup(), 'approve')
  await page.route('**/api/bff/verification/presentations', async (route) => {
    const body = route.request().postDataJSON() as { bindingProof: string }
    const parts = body.bindingProof.split('.')
    // Change a significant signature byte, preserving JWT framing.
    parts[2] = (parts[2].startsWith('A') ? 'B' : 'A') + parts[2].slice(1)
    body.bindingProof = parts.join('.')
    await route.continue({ postData: JSON.stringify(body) })
  })
  await submitVerification(page, approval.requestId, approval.audience,
    approval.privateJwk, approval.thumbprint)
  await expect(page.getByText('Rejected — not accepted')).toBeVisible()
  await expect(page.getByText('BINDING_INVALID', { exact: true })).toBeVisible()
})

test('another browser holder cannot verify the approved credential', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  await loginAs(page, base, MEMBER)
  const approval = await decideViaBrowser(page, machineSetup(), 'approve')
  const other = await browserHolder(page)
  expect(other.thumbprint).not.toBe(approval.thumbprint)
  await submitVerification(page, approval.requestId, approval.audience,
    other.privateJwk, other.thumbprint)
  await expect(page.getByText('Rejected — not accepted')).toBeVisible()
  await expect(page.getByText('HOLDER_MISMATCH', { exact: true })).toBeVisible()
})
