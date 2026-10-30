import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { ISSUER_ID, MEMBER, VCT, api, createRequest, loginAs, machineSetup } from './sovra'

test.skip(process.env.SOVRA_PROFILE !== 'sdjwt-vc', 'Requires the SD-JWT backend profile.')

async function preparedWallet(page: Page, base: string, choice: 'approve' | 'deny' = 'approve'): Promise<string> {
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  const offer = await api(setup.base, setup.token, 'POST', '/api/vci/offers', { issuerId: ISSUER_ID, vct: VCT })
  expect(offer.status).toBe(200)
  const body = offer.json as { credential_offer: { grants: { 'pre-authorized_code': { 'pre-authorized_code': string } } } }
  await page.getByRole('link', { name: 'OpenID demo wallet', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'OpenID demo wallet', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Create wallet key' }).click()
  await page.getByLabel('Pre-authorized offer code').fill(body.credential_offer.grants['pre-authorized_code']['pre-authorized_code'])
  await page.getByRole('button', { name: 'Receive credential', exact: true }).click()
  await expect(page.getByText('Credential received', { exact: true })).toBeVisible()
  const credentialId = (await page.locator('.consent-field', { has: page.locator('dt', { hasText: 'Credential identifier' }) }).locator('dd').textContent())?.trim()
  if (!credentialId) throw new Error('credential identifier missing')
  const created = await createRequest(setup, credentialId)
  await page.getByLabel('Wallet consent request identifier').fill(created.requestId)
  await page.getByRole('button', { name: 'Review wallet consent', exact: true }).click()
  await expect(page.getByText('Wallet consent: PENDING', { exact: true })).toBeVisible()
  await expect(page.getByText('synthetic age check at checkout', { exact: true })).toBeVisible()
  if (choice === 'deny') {
    await page.getByRole('button', { name: 'Deny wallet consent', exact: true }).click()
    await expect(page.getByText('Wallet consent: DENIED', { exact: true })).toBeVisible()
    return created.requestId
  }
  await page.getByRole('button', { name: 'Approve wallet consent', exact: true }).click()
  await expect(page.getByText('Wallet consent: VERIFIED', { exact: true })).toBeVisible()
  const vp = await api(setup.base, setup.token, 'POST', '/api/vp/requests', { proofRequestId: created.requestId })
  expect(vp.status).toBe(200)
  const id = (vp.json as { session_id: string }).session_id
  await page.getByLabel('Presentation session identifier').fill(id)
  return id
}

test('browser wallet receives via VCI, approves consent, encrypts VP and replays identically', async ({ page, baseURL }) => {
  const id = await preparedWallet(page, baseURL ?? 'http://localhost:8080')
  await page.getByRole('button', { name: 'Review presentation request', exact: true }).click()
  await expect(page.getByText('Signed presentation request checked', { exact: true })).toBeVisible()
  const submitted = page.waitForRequest((req) => req.url().endsWith(`/api/vp/responses/${id}`) && req.method() === 'POST')
  await page.getByRole('button', { name: 'Share encrypted presentation', exact: true }).click()
  await expect(page.getByText('Wallet result: ACCEPTED', { exact: true })).toBeVisible()
  const request = await submitted
  const form = new URLSearchParams(request.postData() ?? '')
  expect(form.get('response')?.split('.')).toHaveLength(5)
  expect(form.has('vp_token')).toBe(false)
  await expect(page.getByText('Wallet result: ACCEPTED', { exact: true })).toBeVisible()
  await expect(page.getByText('sovra-g1-sdjwt-vc/0.2', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Retry same encrypted presentation', exact: true }).click()
  await expect(page.getByText('The same encrypted presentation returned the identical decision.')).toBeVisible()
  await page.screenshot({ path: 'test-results/wallet-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: 'test-results/wallet-mobile.png', fullPage: true })
  await page.getByRole('button', { name: 'Forget wallet', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Create wallet key', exact: true })).toBeVisible()
  await expect(page.getByText('Credential received', { exact: true })).toHaveCount(0)
})

test('browser wallet refuses a tampered signed presentation request before sharing', async ({ page, baseURL }) => {
  const id = await preparedWallet(page, baseURL ?? 'http://localhost:8080')
  await page.route(`**/api/vp/requests/${id}/object`, async (route) => {
    const response = await route.fetch()
    const parts = (await response.text()).split('.')
    parts[2] = (parts[2].startsWith('A') ? 'B' : 'A') + parts[2].slice(1)
    await route.fulfill({ response, body: parts.join('.') })
  })
  let shares = 0
  page.on('request', (req) => { if (req.url().includes(`/api/vp/responses/${id}`)) shares++ })
  await page.getByRole('button', { name: 'Review presentation request', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('refused or unavailable')
  await expect(page.getByRole('button', { name: 'Share encrypted presentation', exact: true })).toHaveCount(0)
  expect(shares).toBe(0)
})

test('wallet consent denial offers no presentation action', async ({ page, baseURL }) => {
  let shares = 0
  page.on('request', (req) => { if (req.url().includes('/api/vp/responses/')) shares++ })
  await preparedWallet(page, baseURL ?? 'http://localhost:8080', 'deny')
  await expect(page.getByLabel('Presentation session identifier')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Share encrypted presentation', exact: true })).toHaveCount(0)
  expect(shares).toBe(0)
})

test('corrupted encrypted response refuses and the original ciphertext retries safely', async ({ page, baseURL }) => {
  const id = await preparedWallet(page, baseURL ?? 'http://localhost:8080')
  await page.getByRole('button', { name: 'Review presentation request', exact: true }).click()
  await expect(page.getByText('Signed presentation request checked', { exact: true })).toBeVisible()
  const path = `**/api/vp/responses/${id}`
  await page.route(path, async (route) => {
    const form = new URLSearchParams(route.request().postData() ?? '')
    const parts = (form.get('response') ?? '').split('.')
    parts[3] = (parts[3].startsWith('A') ? 'B' : 'A') + parts[3].slice(1)
    form.set('response', parts.join('.'))
    await route.continue({ postData: form.toString() })
  })
  await page.getByRole('button', { name: 'Share encrypted presentation', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('refused or unavailable')
  await expect(page.getByText('Wallet result: ACCEPTED', { exact: true })).toHaveCount(0)
  await page.unroute(path)
  await page.getByRole('button', { name: 'Retry same encrypted presentation', exact: true }).click()
  await expect(page.getByText('Wallet result: ACCEPTED', { exact: true })).toBeVisible()
})

test('browser wallet receives via authorization code with a browser-owned PKCE verifier', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  const setup = machineSetup()
  await loginAs(page, base, MEMBER)
  await page.getByRole('link', { name: 'OpenID demo wallet', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'OpenID demo wallet', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Create wallet key' }).click()
  await page.getByRole('button', { name: 'New authorization request' }).click()
  const challenge = (await page.locator('.consent-field', { has: page.locator('dt', { hasText: 'PKCE challenge' }) }).locator('dd').textContent())?.trim()
  if (!challenge) throw new Error('PKCE challenge missing')
  // External actor: the holder agent authorizes the challenge out of
  // band. It never sees the verifier, which stays in wallet memory.
  const authorized = await api(setup.base, setup.token, 'POST', '/api/vci/authorize', { issuerId: ISSUER_ID, vct: VCT, codeChallenge: challenge })
  expect(authorized.status).toBe(200)
  const code = (authorized.json as { code: string }).code
  await page.getByLabel('Authorization code').fill(code)
  await page.getByRole('button', { name: 'Receive with authorization code', exact: true }).click()
  await expect(page.getByText('Credential received', { exact: true })).toBeVisible()
  // The consumed code is single-use: the wallet reports refusal, not a second credential.
  await page.getByRole('button', { name: 'Forget wallet', exact: true }).click()
  await page.getByRole('button', { name: 'Create wallet key' }).click()
  await page.getByRole('button', { name: 'New authorization request' }).click()
  await page.getByLabel('Authorization code').fill(code)
  await page.getByRole('button', { name: 'Receive with authorization code', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('single-use')
  await expect(page.getByText('Credential received', { exact: true })).toHaveCount(0)
})
