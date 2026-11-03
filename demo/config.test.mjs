// Demo config tests: explicit modes and matched credential sources.
// Pure loader only — never touches the real demo/.env.local or real
// token files. All secrets here are fake placeholders.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { parseEnvFile, resolveDemoConfig } from './config.mjs'

const LEGACY_FILE = {
  SETUP_TOKEN: 'test-setup-token',
  NOVABANK_RP_TOKEN: 'test-novabank-token',
  CORNERCELLAR_RP_TOKEN: 'test-cornercellar-token',
}

const throwingReader = () => {
  throw new Error('token files must not be read without explicit dir')
}

describe('demo config modes', () => {
  it('legacy .env.local boots full single-node from root store', () => {
    const cfg = resolveDemoConfig({ env: {}, envFile: LEGACY_FILE, readToken: throwingReader })
    assert.equal(cfg.mode, 'full')
    assert.equal(cfg.sovraBase, 'http://localhost:8080')
    assert.equal(cfg.sovraSynth2, 'http://localhost:8080')
    assert.equal(cfg.dual, false)
    assert.equal(cfg.explicitTokensDir, false)
    assert.equal(cfg.nodeA.rpToken, 'test-novabank-token')
    assert.equal(cfg.nodeA.issuerToken, 'test-setup-token')
    assert.equal(cfg.nodeA.configured, true)
    assert.equal(cfg.nodeB.rpToken, cfg.nodeA.rpToken)
    assert.equal(cfg.legacy.configured, true)
  })

  it('fresh env-only dual mode boots interop-only without legacy file', () => {
    const cfg = resolveDemoConfig({
      env: {
        SOVRA_BASE: 'http://127.0.0.1:8280',
        SOVRA_BASE_SYNTH2: 'http://127.0.0.1:8281',
        SOVRA_A_RP_TOKEN: 'test-a-rp',
        SOVRA_A_ISSUER_TOKEN: 'test-a-issuer',
        SOVRA_B_RP_TOKEN: 'test-b-rp',
        SOVRA_B_ISSUER_TOKEN: 'test-b-issuer',
      },
      envFile: {},
      readToken: throwingReader,
    })
    assert.equal(cfg.mode, 'interop-only')
    assert.equal(cfg.dual, true)
    assert.equal(cfg.nodeA.rpToken, 'test-a-rp')
    assert.equal(cfg.nodeA.issuerToken, 'test-a-issuer')
    assert.equal(cfg.nodeB.rpToken, 'test-b-rp')
    assert.equal(cfg.nodeB.issuerToken, 'test-b-issuer')
    assert.equal(cfg.nodeB.unconfigured, false)
    assert.equal(cfg.legacy.configured, false)
  })

  it('explicit token dir supplies per-node credentials by basename only', () => {
    const seen = []
    const cfg = resolveDemoConfig({
      env: {
        SOVRA_BASE: 'http://127.0.0.1:8280',
        SOVRA_BASE_SYNTH2: 'http://127.0.0.1:8281',
        SOVRA_DEMO_TOKENS_DIR: '/tmp/fake-tokens',
      },
      envFile: {},
      readToken: (name) => {
        seen.push(name)
        return `fake-${name}`
      },
    })
    assert.equal(cfg.mode, 'interop-only')
    assert.equal(cfg.tokensDir, '/tmp/fake-tokens')
    assert.equal(cfg.nodeA.rpToken, 'fake-a-rp.token')
    assert.equal(cfg.nodeA.issuerToken, 'fake-a-issuer.token')
    assert.equal(cfg.nodeB.rpToken, 'fake-b-rp.token')
    assert.equal(cfg.nodeB.issuerToken, 'fake-b-issuer.token')
    assert.deepEqual([...new Set(seen)].sort(), [
      'a-issuer.token', 'a-rp.token', 'b-issuer.token', 'b-rp.token',
    ])
    assert.ok(!seen.some((n) => n.includes('setup') || n.includes('maker') || n.includes('checker')))
  })

  it('dual base with missing B credentials reports unconfigured, no A fallback', () => {
    const cfg = resolveDemoConfig({
      env: {
        SOVRA_BASE: 'http://127.0.0.1:8280',
        SOVRA_BASE_SYNTH2: 'http://127.0.0.1:8281',
        SOVRA_A_RP_TOKEN: 'test-a-rp',
        SOVRA_A_ISSUER_TOKEN: 'test-a-issuer',
      },
      envFile: {},
      readToken: () => '',
    })
    assert.equal(cfg.mode, 'interop-only')
    assert.equal(cfg.nodeB.unconfigured, true)
    assert.equal(cfg.nodeB.rpToken, '')
    assert.equal(cfg.nodeB.issuerToken, '')
    assert.notEqual(cfg.nodeB.rpToken, cfg.nodeA.rpToken)
  })

  it('ambient foreign files are ignored without explicit dir', () => {
    const cfg = resolveDemoConfig({ env: {}, envFile: LEGACY_FILE, readToken: throwingReader })
    assert.equal(cfg.nodeA.rpToken, 'test-novabank-token')
    assert.equal(cfg.nodeA.issuerToken, 'test-setup-token')
  })

  it('explicit base disables legacy routing even when legacy tokens exist', () => {
    const cfg = resolveDemoConfig({
      env: {
        SOVRA_BASE: 'http://127.0.0.1:8280',
        SOVRA_A_RP_TOKEN: 'test-a-rp',
        SOVRA_A_ISSUER_TOKEN: 'test-a-issuer',
      },
      envFile: LEGACY_FILE,
      readToken: () => '',
    })
    assert.equal(cfg.legacy.tokensPresent, true)
    assert.equal(cfg.legacy.configured, false)
    assert.equal(cfg.mode, 'interop-only')
    assert.equal(cfg.nodeA.rpToken, 'test-a-rp')
    assert.equal(cfg.nodeA.issuerToken, 'test-a-issuer')
  })

  it('empty config is unconfigured', () => {
    const cfg = resolveDemoConfig({ env: {}, envFile: {}, readToken: () => '' })
    assert.equal(cfg.mode, 'unconfigured')
    assert.equal(cfg.nodeA.configured, false)
    assert.equal(cfg.legacy.configured, false)
  })

  it('parses env files with the server shape', () => {
    const parsed = parseEnvFile(
      'SETUP_TOKEN=abc\nNOVABANK_RP_TOKEN=def \nSOVRA_BASE_SYNTH2=http://127.0.0.1:8281\n# comment\nBADLINE\n',
    )
    assert.deepEqual(parsed, {
      SETUP_TOKEN: 'abc',
      NOVABANK_RP_TOKEN: 'def',
      SOVRA_BASE_SYNTH2: 'http://127.0.0.1:8281',
    })
    assert.deepEqual(parseEnvFile(''), {})
  })
})
