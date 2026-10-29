import { mkdirSync, writeFileSync } from 'node:fs'
import type { FullConfig } from '@playwright/test'
import { machineFile, mintMachineAccount, waitForStack } from './sovra'

// Fail fast without the compose stack, then mint one disposable
// machine account for issuer/RP setup calls. Prints no secrets.
async function globalSetup(config: FullConfig): Promise<void> {
  const base = config.projects[0]?.use?.baseURL ?? 'http://localhost:8080'
  await waitForStack(base)
  const setup = mintMachineAccount()
  const res = await fetch(`${base}/api/whoami`, {
    headers: { Authorization: `Bearer ${setup.token}` },
  })
  if (res.status !== 200) throw new Error(`minted machine account rejected (${res.status})`)
  const whoami = (await res.json()) as { tenantId?: unknown }
  if (whoami.tenantId !== setup.tenantId) throw new Error('minted account tenant mismatch')
  mkdirSync('test-results', { recursive: true })
  writeFileSync(machineFile(), JSON.stringify({ base, ...setup }))
  console.log(`browser setup: stack READY at ${base}; machine account minted`)
}

export default globalSetup
