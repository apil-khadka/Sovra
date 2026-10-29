// Real-browser verification evidence (SOV-011/SOV-041): the page
// imports the consent-step holder key, mints a fresh nonce, signs
// the binding proof with WebCrypto, and reads back the stored
// decision. A mismatched audience rejects.

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { MEMBER, loginAs, machineSetup } from './sovra'
import type { EcJwk } from './sovra'
import { decideViaBrowser, expectedProfile } from './journey'

test.use({ permissions: ['clipboard-read', 'clipboard-write'] })

async function submitVerification(
  page: Page,
  requestId: string,
  audience: string,
  privateJwk: EcJwk,
  thumb: string,
): Promise<void> {
  await page.getByRole('link', { name: 'Verify presentation' }).click()
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
  await submitVerification(page, approval.requestId, approval.audience, approval.privateJwk, approval.thumbprint)
  await expect(page.getByText('Accepted — synthetic evidence verified')).toBeVisible()
  const card = page.locator('.consent-card.state-verified')
  await expect(card.getByText(expectedProfile(), { exact: true })).toBeVisible()
  await expect(
    page.getByText('Stored decision re-read identically: a lost response replays, never rewrites.'),
  ).toBeVisible()
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
