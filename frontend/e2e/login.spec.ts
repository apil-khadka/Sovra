// Real-browser BFF login evidence (SOV-006/SOV-041): actual DOM/JS
// login through Keycloak on the packaged origin, plus logout,
// downgrade, and rejection negatives.

import { expect, test } from '@playwright/test'
import { MEMBER, PRIVILEGED, loginAs, machineSetup, pageSessionStatus } from './sovra'

test('member login lands with a session and logs out through the provider', async ({
  page,
  baseURL,
}) => {
  const base = baseURL ?? 'http://localhost:8080'
  await page.goto('/')
  await page.getByRole('button', { name: 'Log in with Keycloak' }).click()
  await page.waitForURL(/sovra-keycloak/, { timeout: 20_000 })
  expect(page.url()).toContain('code_challenge_method=S256')
  await page.locator('#username').fill(MEMBER.username)
  await page.locator('#password').fill(MEMBER.password)
  await page.locator('#kc-login').click()
  await page.waitForURL((url) => url.href.startsWith(base), { timeout: 20_000 })
  await expect(page).toHaveURL(`${base}/`)
  const bar = page.locator('.auth-bar')
  await expect(bar).toContainText('demo-member')
  await expect(bar).toContainText('TENANT_MEMBER')
  await expect(bar).toContainText('RP_CLIENT')
  expect(await pageSessionStatus(page)).toBe(200)
  // Logout returns to the same origin with no session left.
  await page.getByRole('button', { name: 'Log out' }).click()
  await page.waitForURL(`${base}/`, { timeout: 20_000 })
  await expect(page.getByRole('button', { name: 'Log in with Keycloak' })).toBeVisible()
  expect(await pageSessionStatus(page)).toBe(401)
  // A fresh login shows the Keycloak form again: the provider SSO
  // session died too, instead of silently re-authenticating.
  await page.getByRole('button', { name: 'Log in with Keycloak' }).click()
  await page.waitForURL(/sovra-keycloak/, { timeout: 20_000 })
  await expect(page.locator('#username')).toBeVisible()
})

test('password-only privileged login withholds TRUST_ADMIN', async ({ page, baseURL }) => {
  const base = baseURL ?? 'http://localhost:8080'
  await loginAs(page, base, PRIVILEGED)
  const bar = page.locator('.auth-bar')
  await expect(bar).toContainText('TENANT_MEMBER')
  await expect(bar).not.toContainText('TRUST_ADMIN')
  await page.getByRole('button', { name: 'Log out' }).click()
  await page.waitForURL(`${base}/`, { timeout: 20_000 })
})

test('wrong password shows a Keycloak error and creates no session', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Log in with Keycloak' }).click()
  await page.waitForURL(/sovra-keycloak/, { timeout: 20_000 })
  await page.locator('#username').fill(MEMBER.username)
  await page.locator('#password').fill('wrong-password')
  await page.locator('#kc-login').click()
  await expect(page.locator('.kc-feedback-text')).toContainText('Invalid username or password')
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Log in with Keycloak' })).toBeVisible()
  expect(await pageSessionStatus(page)).toBe(401)
})

test('anonymous and machine-token BFF reads are rejected', async ({ page, request }) => {
  const setup = machineSetup()
  await page.goto('/')
  expect(await pageSessionStatus(page)).toBe(401)
  const res = await request.get(`${setup.base}/api/bff/me`, {
    headers: { Authorization: `Bearer ${setup.token}` },
  })
  expect(res.status()).toBe(401)
})
