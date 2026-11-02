// Load-harness provisioning (PROD-016): disposable synthetic tenants
// with issuer + RP credentials for arrival-rate runs. Local smoke
// provisioning only — staging provisions through accreditation,
// never through this script.
//
// Prints prefixes only, never token material. Tokens land in
// load/.tokens.json (gitignored, mode 0600).

import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = dirname(fileURLToPath(import.meta.url))
const DB_CONTAINER = process.env.SOVRA_E2E_DB_CONTAINER ?? 'sovra-db-1'
const DB_PASSWORD = process.env.SOVRA_DB_ADMIN_PASSWORD ?? 'sovra-dev-only'

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const m = a.match(/^--([a-z-]+)(?:=(.*))?$/)
    return m ? [m[1], m[2] ?? 'true'] : [a, 'true']
  }),
)
const TENANTS = Math.max(1, parseInt(args.tenants ?? '3', 10))

function psql(sql) {
  return execFileSync(
    'docker',
    ['exec', '-e', `PGPASSWORD=${DB_PASSWORD}`, DB_CONTAINER,
      'psql', '-U', 'sovra', '-d', 'sovra', '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql],
    { encoding: 'utf-8' },
  ).trim()
}

function mintAccount(tenantId, name, roles) {
  // Scheme must match TokenHasher.PREFIX: the server rejects any
  // other bearer shape before lookup.
  const token = `sovra_test_${randomBytes(32).toString('base64url')}`
  const prefix = token.slice('sovra_test_'.length, 'sovra_test_'.length + 8)
  const digest = createHash('sha256').update(token, 'utf-8').digest('hex')
  psql(
    'INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) '
    + `VALUES ('${tenantId}', '${name}', '${prefix}', `
    + `decode('${digest}', 'hex'), '{${roles}}');`,
  )
  return { token, prefix }
}

const tenants = []
for (let i = 0; i < TENANTS; i++) {
  const slug = `load-t${i}`
  psql(
    `INSERT INTO tenant (slug, display_name) VALUES ('${slug}', 'load ${i}') `
    + 'ON CONFLICT (slug) DO NOTHING;',
  )
  const id = psql(`SELECT id FROM tenant WHERE slug = '${slug}';`).split('\n')[0].trim()
  if (id === '') throw new Error(`${slug} missing after upsert`)
  const stamp = Date.now()
  const issuer = mintAccount(id, `load-issuer-${i}-${stamp}`, 'ISSUER_OPS')
  const rp = mintAccount(id, `load-rp-${i}-${stamp}`, 'RP_CLIENT')
  tenants.push({ slug, id, issuerToken: issuer.token, rpToken: rp.token })
  console.log(`${slug}: issuer=${issuer.prefix} rp=${rp.prefix}`)
}

const path = join(ROOT, '.tokens.json')
writeFileSync(path, JSON.stringify({ provisionedAt: new Date().toISOString(), tenants }, null, 2))
chmodSync(path, 0o600)
console.log(`wrote ${path} (0600, gitignored)`)
