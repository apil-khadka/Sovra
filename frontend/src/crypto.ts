// Browser holder crypto (synthetic demo only). All P-256 key
// handling and ES256 signing behind one narrow interface; the
// consent and verification clients build canonical messages on top.

export interface HolderKey {
  privateKey: CryptoKey
  jwk: JsonWebKey
  thumbprint: string
}

function base64Url(bytes: ArrayBuffer | Uint8Array): string {
  const raw = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (const byte of raw) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function base64UrlEncodeText(text: string): string {
  return base64Url(new TextEncoder().encode(text))
}

/** RFC 7638 SHA-256 JWK thumbprint over {"crv","kty","x","y"}. */
export async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return base64Url(digest)
}

/** Fresh P-256 holder key (synthetic demo; extractable for JWK export). */
export async function generateHolder(): Promise<HolderKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
  ])
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { privateKey: pair.privateKey, jwk, thumbprint: await thumbprint(jwk) }
}

/** Import a previously exported holder private key. */
export async function importHolder(privateJwk: JsonWebKey): Promise<HolderKey> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )
  const full = await crypto.subtle.exportKey('jwk', privateKey)
  const publicJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: full.x, y: full.y }
  return { privateKey, jwk: publicJwk, thumbprint: await thumbprint(publicJwk) }
}

/** Export the private half so the verifier demo can import the same key. */
export async function exportPrivateKey(holder: HolderKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', holder.privateKey)
}

/** ES256 JWS over an arbitrary canonical message (consent, presentation). */
export async function signMessage(holder: HolderKey, message: string): Promise<string> {
  const header = base64UrlEncodeText('{"alg":"ES256"}')
  const payload = base64UrlEncodeText(message)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    holder.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  // WebCrypto ECDSA yields raw r||s (IEEE P1363), already JWS-sized.
  const raw = new Uint8Array(signature)
  if (raw.length !== 64) throw new Error('unexpected signature size')
  return `${header}.${payload}.${base64Url(raw)}`
}

export function randomNonce(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(24)))
}
