// Demo server configuration (pure, no boot side effects).
//
// Explicit modes with matched credential sources: the server never
// auto-loads topology token files merely because they appear on disk,
// never falls back across stores (node B to node A, interop to legacy
// root tokens) when bases differ, and never misroutes legacy root
// credentials to a fresh store. Token files hold ONLY rp/issuer
// credentials; TRUST_ADMIN setup/maker/checker files are
// provisioning-only and are never read here (names only in this
// comment).

export const DEFAULT_SOVRA_BASE = 'http://localhost:8080'

const TOKEN_FILES = ['a-rp.token', 'a-issuer.token', 'b-rp.token', 'b-issuer.token']

export function parseEnvFile(text) {
  const out = {}
  if (typeof text !== 'string' || text === '') return out
  for (const line of text.split('\n')) {
    const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/)
    if (match !== null) out[match[1]] = match[2].trim()
  }
  return out
}

/**
 * Resolve demo configuration from explicit sources.
 *
 * @param {Record<string,string>} env process environment (or test double)
 * @param {Record<string,string>} envFile parsed demo/.env.local (or {} when absent)
 * @param {(name: string) => string} readToken reads one token file by
 *   basename (a-rp.token, a-issuer.token, b-rp.token, b-issuer.token);
 *   returns '' when missing. Only consulted when SOVRA_DEMO_TOKENS_DIR
 *   is explicitly set — there is no silent default directory.
 */
export function resolveDemoConfig({ env = {}, envFile = {}, readToken = null } = {}) {
  const opt = (key) => env[key] ?? envFile[key] ?? ''
  const explicitBase = (env.SOVRA_BASE ?? envFile.SOVRA_BASE ?? '') !== ''
  const explicitTokensDirValue = env.SOVRA_DEMO_TOKENS_DIR ?? envFile.SOVRA_DEMO_TOKENS_DIR ?? ''
  const explicitTokensDir = explicitTokensDirValue !== ''
  const tokensDir = explicitTokensDir ? explicitTokensDirValue : null

  const sovraBase = opt('SOVRA_BASE') || DEFAULT_SOVRA_BASE
  const sovraSynth2 = opt('SOVRA_BASE_SYNTH2') || sovraBase
  const dual = sovraSynth2 !== sovraBase

  const fileToken = (name) => {
    if (!explicitTokensDir || typeof readToken !== 'function') return ''
    if (!TOKEN_FILES.includes(name)) return ''
    try {
      const value = readToken(name)
      return typeof value === 'string' ? value.trim() : ''
    } catch {
      return ''
    }
  }

  const legacySetup = opt('SETUP_TOKEN')
  const legacyNova = opt('NOVABANK_RP_TOKEN')
  const legacyCorner = opt('CORNERCELLAR_RP_TOKEN')
  const legacyTokensPresent = Boolean(legacySetup && legacyNova && legacyCorner)
  // Legacy root credentials belong to the default root store. Once the
  // operator points SOVRA_BASE elsewhere the server runs interop-only
  // rather than silently misrouting old root tokens to the new store.
  const legacyAvailable = legacyTokensPresent && !explicitBase

  // Node A (central ledger). Legacy fallback applies ONLY in default
  // single-node mode with no explicit token dir: the documented legacy
  // .env.local setup where interop shares the root store.
  const allowLegacyFallback = !explicitBase && !explicitTokensDir
  const nodeARp = opt('SOVRA_A_RP_TOKEN')
    || fileToken('a-rp.token')
    || opt('INTEROP_RP_TOKEN')
    || (allowLegacyFallback ? legacyNova : '')
  const nodeAIssuer = opt('SOVRA_A_ISSUER_TOKEN')
    || fileToken('a-issuer.token')
    || (allowLegacyFallback ? legacySetup : '')
  const interopConfigured = Boolean(nodeARp && nodeAIssuer)

  // Node B: same store inherits A; a differing base requires its own
  // credentials — never a cross-store primary fallback.
  let nodeBRp = ''
  let nodeBIssuer = ''
  let synth2Unconfigured = false
  if (!dual) {
    nodeBRp = nodeARp
    nodeBIssuer = nodeAIssuer
  } else {
    nodeBRp = opt('SOVRA_B_RP_TOKEN') || fileToken('b-rp.token')
    nodeBIssuer = opt('SOVRA_B_ISSUER_TOKEN') || fileToken('b-issuer.token')
    synth2Unconfigured = !(nodeBRp && nodeBIssuer)
    if (synth2Unconfigured) {
      nodeBRp = ''
      nodeBIssuer = ''
    }
  }

  let mode = 'unconfigured'
  if (interopConfigured && legacyAvailable) mode = 'full'
  else if (interopConfigured) mode = 'interop-only'
  else if (legacyAvailable) mode = 'legacy-only'

  return {
    sovraBase,
    sovraSynth2,
    dual,
    explicitBase,
    explicitTokensDir,
    tokensDir,
    nodeA: { rpToken: nodeARp, issuerToken: nodeAIssuer, configured: interopConfigured },
    nodeB: {
      rpToken: nodeBRp, issuerToken: nodeBIssuer,
      configured: dual ? !synth2Unconfigured : interopConfigured,
      unconfigured: synth2Unconfigured,
    },
    legacy: {
      setupToken: legacySetup, novabankToken: legacyNova, cornercellarToken: legacyCorner,
      tokensPresent: legacyTokensPresent, configured: legacyAvailable,
    },
    mode,
  }
}
