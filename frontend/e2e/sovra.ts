// Shared real-browser E2E helpers (SOV-041). Server-side actors
// (issuer minting, RP request creation, machine setup) use Node fetch
// plus node:crypto; every holder proof — consent decision, binding
// proof — is produced by WebCrypto inside the page under test through
// the real React UI. Shapes mirror scripts/e2e-verification.py, which
// reads them from server code.

import { createECDH, createHash, createPrivateKey, randomBytes, sign } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import type { Page } from '@playwright/test'

export const ISSUER_ID = 'https://sovra.example/issuers/synth-1'
export const VCT = 'https://sovra.example/vct/adult-status/1'
export const RP_ID = 'https://rp.example/synth-shop'
export const AUDIENCE = 'https://rp.example/synth-shop/callback'
export const PURPOSE = 'synthetic age check at checkout'
export const POLICY_ID = 'sovra-synthetic-policy/age-check'
export const POLICY_VERSION = '1'
export const SECTION_ID = 'age_eligibility'
export const TOKEN_PREFIX = 'sovra_test_'

export const MEMBER = { username: 'demo-member', password: 'sovra-demo-member-01' }
export const PRIVILEGED = { username: 'demo-priv', password: 'sovra-demo-priv-02' }

export interface Credentials {
  username: string
  password: string
}

export interface MachineSetup {
  base: string
  tenantId: string
  token: string
}

export interface CreatedRequest {
  requestId: string
  planHash: string
  challenge: string
}

/**
 * P-256 JWK shared by the page export and node:crypto. Structural
 * (not DOM JsonWebKey), so it satisfies node's JWK input shape.
 */
export interface EcJwk {
  kty: string
  crv: string
  x: string
  y: string
  d?: string
  [key: string]: unknown
}

/** Global setup writes this; specs read it. Never committed (gitignored). */
export function machineFile(): string {
  return 'test-results/machine.json'
}

export function machineSetup(): MachineSetup {
  const setup = JSON.parse(readFileSync(machineFile(), 'utf-8')) as MachineSetup
  if (typeof setup.base !== 'string' || typeof setup.tenantId !== 'string' || typeof setup.token !== 'string') {
    throw new Error('browser setup file is malformed; rerun the suite so global setup rewrites it')
  }
  return setup
}

function b64uText(text: string): string {
  return Buffer.from(text, 'utf-8').toString('base64url')
}

/** RFC 7638 SHA-256 thumbprint over {"crv","kty","x","y"}. */
export function thumbprint(jwk: { x?: string; y?: string }): string {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  return createHash('sha256').update(canonical, 'utf-8').digest().toString('base64url')
}

/** Derive the public half of a P-256 private JWK (setup only). */
export function publicJwkFromPrivate(d: string): { x: string; y: string } {
  const ecdh = createECDH('prime256v1')
  ecdh.setPrivateKey(Buffer.from(d, 'base64url'))
  const pub = ecdh.getPublicKey()
  if (pub.length !== 65 || pub[0] !== 0x04) throw new Error('unexpected P-256 public key')
  return {
    x: pub.subarray(1, 33).toString('base64url'),
    y: pub.subarray(33, 65).toString('base64url'),
  }
}

/** Compact ES256 JWS (setup only; holder proofs sign in the page). */
export function signCompact(privateJwk: EcJwk, message: string): string {
  const key = createPrivateKey({ key: privateJwk, format: 'jwk' })
  const input = `${b64uText('{"alg":"ES256"}')}.${b64uText(message)}`
  const raw = derToRaw(sign('sha256', Buffer.from(input, 'ascii'), key))
  return `${input}.${raw.toString('base64url')}`
}

function derToRaw(der: Buffer): Buffer {
  // Minimal SEQUENCE { INTEGER r, INTEGER s } parser; P-256 halves
  // are at most 32 bytes plus a possible leading zero pad.
  let offset = 2
  const take = (): Buffer => {
    if (der[offset] !== 0x02) throw new Error('malformed ECDSA signature')
    const length = der[offset + 1] ?? 0
    const value = der.subarray(offset + 2, offset + 2 + length)
    offset += 2 + length
    const unpadded = value[0] === 0 ? value.subarray(1) : value
    if (unpadded.length > 32) throw new Error('oversized ECDSA half')
    return Buffer.concat([Buffer.alloc(32 - unpadded.length), unpadded])
  }
  return Buffer.concat([take(), take()])
}

async function api(
  base: string,
  token: string,
  method: string,
  path: string,
  body?: unknown,
  extra?: Record<string, string>,
): Promise<{ status: number; json: unknown }> {
  const res = await fetch(base + path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...extra,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  let json: unknown = null
  try {
    json = text === '' ? null : (JSON.parse(text) as unknown)
  } catch {
    json = null
  }
  return { status: res.status, json }
}

function planHash(planId: string): string {
  const canonical =
    [
      'sovra-plan/v1',
      planId,
      'age_over_18',
      ISSUER_ID,
      VCT,
      'adultOver18',
      `${POLICY_ID}#${SECTION_ID}`,
      POLICY_ID,
      POLICY_VERSION,
      'CANDIDATE_ONLY',
      '',
    ].join('\n')
  return createHash('sha256').update(canonical, 'utf-8').digest('hex')
}

function planWire(planId: string): Record<string, unknown> {
  return {
    plan_id: planId,
    requested_outcome: 'age_over_18',
    candidate_issuer_id: ISSUER_ID,
    credential_type: VCT,
    claim_paths: ['adultOver18'],
    evidence: [{ document_id: POLICY_ID, section_id: SECTION_ID }],
    policy_id: POLICY_ID,
    policy_version: POLICY_VERSION,
    recommendation: 'CANDIDATE_ONLY',
  }
}

/** Issuer-side mint for a browser-generated holder key (setup only). */
export async function issueCredential(
  setup: MachineSetup,
  holderJwk: Record<string, string>,
  privateJwk: EcJwk,
): Promise<string> {
  const idem = `e2e-b-${randomBytes(16).toString('hex')}`
  const thumb = thumbprint(holderJwk)
  const message = `sovra-issuance-proof/v1\n${idem}\n${VCT}\n${thumb}\nadultOver18=true`
  const expires = new Date(Date.now() + 2 * 3600_000).toISOString().replace('.000Z', 'Z')
  const { status, json } = await api(setup.base, setup.token, 'POST', '/api/issuance/credentials', {
    issuerId: ISSUER_ID,
    vct: VCT,
    holderJwk,
    holderProof: signCompact(privateJwk, message),
    claims: { adultOver18: true },
    expiresAt: expires,
  }, { 'Idempotency-Key': idem })
  if (status !== 201) throw new Error(`issue returned ${status}: ${JSON.stringify(json)}`)
  const credentialId = (json as { credentialId?: unknown }).credentialId
  if (typeof credentialId !== 'string' || credentialId === '') {
    throw new Error('issue response lacks credentialId')
  }
  return credentialId
}

/** RP-side proof-request creation (setup only). */
export async function createRequest(
  setup: MachineSetup,
  credentialId: string,
  audience: string = AUDIENCE,
): Promise<CreatedRequest> {
  const planId = `pln_e2e_b${randomBytes(6).toString('hex')}`
  const hash = planHash(planId)
  const challenge = randomBytes(24).toString('base64url')
  const expires = new Date(Date.now() + 3600_000).toISOString().replace('.000Z', 'Z')
  const { status, json } = await api(setup.base, setup.token, 'POST', '/api/consent/requests', {
    rpId: RP_ID,
    audience,
    purpose: PURPOSE,
    credentialId,
    claims: { adultOver18: true },
    plan: planWire(planId),
    policyId: POLICY_ID,
    policyVersion: POLICY_VERSION,
    planHash: hash,
    challenge,
    expiresAt: expires,
  })
  if (status !== 201) throw new Error(`consent create returned ${status}: ${JSON.stringify(json)}`)
  const requestId = (json as { requestId?: unknown }).requestId
  if (typeof requestId !== 'string' || requestId === '') {
    throw new Error('consent create response lacks requestId')
  }
  return { requestId, planHash: hash, challenge }
}

/** Drive the real Keycloak form; return once the app shows a session. */
export async function loginAs(page: Page, baseURL: string, creds: Credentials): Promise<void> {
  await page.goto('/')
  await page.getByRole('button', { name: 'Log in with Keycloak' }).click()
  await page.waitForURL(/sovra-keycloak/, { timeout: 20_000 })
  await page.locator('#username').fill(creds.username)
  await page.locator('#password').fill(creds.password)
  await page.locator('#kc-login').click()
  await page.waitForURL(`${baseURL}/`, { timeout: 20_000 })
  await page.getByRole('button', { name: 'Log out' }).waitFor({ timeout: 10_000 })
}

/** Session status from inside the page (real cookies, real origin). */
export function pageSessionStatus(page: Page): Promise<number> {
  return page.evaluate(() => fetch('/api/bff/me').then((res) => res.status))
}

function dockerDb(): { container: string; password: string } {
  return {
    container: process.env.SOVRA_E2E_DB_CONTAINER ?? 'sovra-db-1',
    password: process.env.SOVRA_DB_ADMIN_PASSWORD ?? 'sovra-dev-only',
  }
}

function psql(container: string, password: string, sql: string): string {
  const proc = spawnSync(
    'docker',
    ['exec', '-e', `PGPASSWORD=${password}`, container,
      'psql', '-U', 'sovra', '-d', 'sovra', '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql],
    { encoding: 'utf-8' },
  )
  if (proc.status !== 0) {
    const detail = `${proc.stderr ?? ''}${proc.stdout ?? ''}`.trim().slice(0, 300)
    throw new Error(`psql via ${container} failed: ${detail}`)
  }
  return (proc.stdout ?? '').trim()
}

/**
 * Mint one disposable machine account in sovra-demo for issuer/RP
 * setup calls, mirroring scripts/e2e-verification.py. Prints no
 * secret material.
 */
export function mintMachineAccount(): { tenantId: string; token: string } {
  const { container, password } = dockerDb()
  const tenantId = psql(container, password,
    "SELECT id FROM tenant WHERE slug = 'sovra-demo';").split('\n')[0]?.trim() ?? ''
  if (tenantId === '') throw new Error('sovra-demo tenant missing (is the compose stack up?)')
  const token = TOKEN_PREFIX + randomBytes(32).toString('base64url')
  const prefix = token.slice(TOKEN_PREFIX.length, TOKEN_PREFIX.length + 8)
  const digest = createHash('sha256').update(token, 'utf-8').digest('hex')
  psql(container, password,
    'INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) '
    + `VALUES ('${tenantId}', 'browser-e2e', '${prefix}', `
    + `decode('${digest}', 'hex'), '{ISSUER_OPS,RP_CLIENT,TENANT_MEMBER}');`)
  return { tenantId, token }
}

/** Fail fast unless the packaged origin and its DB pool are ready. */
export async function waitForStack(base: string): Promise<void> {
  const deadline = Date.now() + 180_000
  for (;;) {
    try {
      const res = await fetch(`${base}/api/health/ready`)
      if (res.status === 200 && (await res.text()).includes('"status":"READY"')) return
    } catch {
      // Stack still booting; retry until the deadline.
    }
    if (Date.now() > deadline) {
      throw new Error(`compose stack not READY at ${base} (run: docker compose up --build -d)`)
    }
    await new Promise((resolve) => setTimeout(resolve, 3000))
  }
}
