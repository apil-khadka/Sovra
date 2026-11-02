// Demo credential bootstrap (disposable synthetic data only).
//
// Creates one setup account (TENANT_MEMBER + ISSUER_OPS) directly in
// the demo database — the same SQL the Playwright global setup uses —
// then mints the two sandbox RP tokens through the real product
// endpoint. Tokens land in demo/.env.local (gitignored, mode 0600).
// Prints prefixes only, never token material.

import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = dirname(fileURLToPath(import.meta.url))
const SOVRA = process.env.SOVRA_BASE ?? 'http://localhost:8080'
const DB_CONTAINER = process.env.SOVRA_E2E_DB_CONTAINER ?? 'sovra-db-1'
const DB_PASSWORD = process.env.SOVRA_DB_ADMIN_PASSWORD ?? 'sovra-dev-only'

function psql(sql) {
  return execFileSync(
    'docker',
    ['exec', '-e', `PGPASSWORD=${DB_PASSWORD}`, DB_CONTAINER,
      'psql', '-U', 'sovra', '-d', 'sovra', '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql],
    { encoding: 'utf-8' },
  ).trim()
}

function mintAccount(tenantId, name, roles) {
  const token = `sovra_test_${randomBytes(32).toString('base64url')}`
  const prefix = token.slice('sovra_test_'.length, 'sovra_test_'.length + 8)
  const digest = createHash('sha256').update(token, 'utf-8').digest('hex')
  psql(
    'INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) '
    + `VALUES ('${tenantId}', '${name}', '${prefix}', `
    + `decode('${digest}', 'hex'), '{${roles}}');`,
  )
  return token
}

const tenantId = psql("SELECT id FROM tenant WHERE slug = 'sovra-demo';").split('\n')[0]?.trim() ?? ''
if (tenantId === '') throw new Error('sovra-demo tenant missing (is the compose stack up?)')

const setupToken = mintAccount(tenantId, `demo-setup-${Date.now()}`, 'TENANT_MEMBER,ISSUER_OPS')

async function sandbox(name) {
  const res = await fetch(`${SOVRA}/api/sandbox/accounts`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${setupToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
  if (res.status !== 201) throw new Error(`${name} bootstrap returned ${res.status}: ${await res.text()}`)
  return (await res.json()).token
}

const novabank = await sandbox('sandbox-novabank')
const cornercellar = await sandbox('sandbox-cornercellar')
const minimal = await sandbox('sandbox-minimal')

const path = join(ROOT, '.env.local')
writeFileSync(
  path,
  `SETUP_TOKEN=${setupToken}\nNOVABANK_RP_TOKEN=${novabank}\nCORNERCELLAR_RP_TOKEN=${cornercellar}\nMINIMAL_RP_TOKEN=${minimal}\n`,
)
chmodSync(path, 0o600)

for (const [label, token] of [['setup', setupToken], ['novabank', novabank], ['cornercellar', cornercellar], ['minimal', minimal]]) {
  console.log(`${label}: ${token.slice(0, 18)}… (saved to demo/.env.local)`)
}
