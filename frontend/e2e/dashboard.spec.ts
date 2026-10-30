// Real-browser dashboard role gating (SOV-026/SEC-41): members
// and password-only privileged logins see the access notice on
// both desks instead of the queue. Positive trust-admin flows
// run in backend BFF tests with stepped-up sessions, since the
// browser suite cannot complete WebAuthn.

import { expect, test } from '@playwright/test'
import { MEMBER, PRIVILEGED, loginAs } from './sovra'

for (const desk of ['federation', 'secops'] as const) {
  test(`${desk} desk hides operational evidence from members`, async ({ page, baseURL }) => {
    const base = baseURL ?? 'http://localhost:8080'
    await loginAs(page, base, MEMBER)
    await page.goto(`/#/${desk}`)
    await expect(page.getByRole('heading', { name: desk === 'federation' ? 'Federation desk' : 'Security operations' })).toBeVisible()
    await expect(page.getByText('Trust admin session required')).toBeVisible()
    // No queue, snapshot, alert, or audit markup renders at all.
    await expect(page.getByRole('button', { name: 'Load queue' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Load evidence' })).toHaveCount(0)
  })

  test(`${desk} desk withholds the queue without step-up`, async ({ page, baseURL }) => {
    const base = baseURL ?? 'http://localhost:8080'
    await loginAs(page, base, PRIVILEGED)
    await page.goto(`/#/${desk}`)
    await expect(page.getByText('Trust admin session required')).toBeVisible()
  })
}

test('desks prompt anonymous visitors to log in', async ({ page }) => {
  await page.goto('/#/federation')
  await expect(page.getByText('Log in first')).toBeVisible()
  await page.goto('/#/secops')
  await expect(page.getByText('Log in first')).toBeVisible()
})
