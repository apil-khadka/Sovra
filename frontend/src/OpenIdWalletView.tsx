import { useState } from 'react'
import type { SessionInfo } from './auth'
import { generateHolder } from './crypto'
import type { HolderKey } from './crypto'
import { fetchReview, postDecision } from './consent'
import type { ConsentReview } from './consent'
import { encryptWalletPresentation, receiveCredential, reviewWalletRequest, sendWalletPresentation } from './openid-wallet'
import type { WalletCredential, WalletRequest } from './openid-wallet'
import type { VerificationDecision } from './verification'
import Field from './components/Field'
import StateCard from './components/StateCard'

/** Synthetic-only, in-memory holder journey. No persistence or recovery claims. */
export default function OpenIdWalletView({ session }: { session: SessionInfo | null }) {
  const [holder, setHolder] = useState<HolderKey | null>(null)
  const [code, setCode] = useState('')
  const [credential, setCredential] = useState<WalletCredential | null>(null)
  const [consentId, setConsentId] = useState('')
  const [consent, setConsent] = useState<ConsentReview | null>(null)
  const [sessionId, setSessionId] = useState('')
  const [request, setRequest] = useState<WalletRequest | null>(null)
  const [encrypted, setEncrypted] = useState('')
  const [decision, setDecision] = useState<VerificationDecision | null>(null)
  const [replayed, setReplayed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run(operation: () => Promise<void>, failure = 'This step was refused or unavailable. Check the identifiers, consent and selected profile before retrying.') {
    setBusy(true)
    setError('')
    try { await operation() } catch {
      setError(failure)
    } finally { setBusy(false) }
  }
  function reset() {
    setHolder(null); setCode(''); setCredential(null); setConsentId(''); setConsent(null)
    setSessionId(''); setRequest(null); setEncrypted(''); setDecision(null); setReplayed(false); setError('')
  }
  async function loadConsent() {
    const next = await fetchReview('', { kind: 'session' }, consentId.trim())
    if (next.credentialId !== credential?.id || next.holderThumbprint !== holder?.thumbprint) {
      throw new Error('Different credential or holder.')
    }
    setConsent(next)
    setRequest(null)
  }
  async function decide(choice: 'approve' | 'deny') {
    if (!holder || !consent) return
    setConsent(await postDecision('', { kind: 'session' }, holder, consent, choice))
  }
  async function share() {
    if (!holder || !credential || !request || !consent) return
    // Revalidate the signed request and current consent before every new share.
    const current = await fetchReview('', { kind: 'session' }, consent.requestId)
    if (current.credentialId !== credential.id || current.holderThumbprint !== holder.thumbprint) {
      throw new Error('Consent changed.')
    }
    const checked = await reviewWalletRequest(request.id, current)
    const jwe = await encryptWalletPresentation(holder, credential, checked)
    setEncrypted(jwe)
    setDecision(await sendWalletPresentation(checked.id, jwe))
  }
  async function replay() {
    if (!request || !encrypted) return
    const next = await sendWalletPresentation(request.id, encrypted)
    if (decision !== null && JSON.stringify(next) !== JSON.stringify(decision)) throw new Error('Replay differs.')
    setReplayed(decision !== null)
    setDecision(next)
  }

  return (
    <section className="consent" aria-label="OpenID demo wallet">
      <h1 className="view-title">OpenID demo wallet</h1>
      <p className="view-lede">For the SD-JWT synthetic demo: receive a credential, review consent, then share an encrypted presentation.</p>
      <p className="view-hint">This tab keeps your key and credential in memory only. Leaving this view or reloading loses them. Use synthetic data only.</p>
      {session === null && <p role="status">Log in with Keycloak before creating your wallet key.</p>}
      <div className="consent-form">
        <h2>1. Receive a credential</h2>
        {holder === null ? (
          <button disabled={busy || session === null} onClick={() => void run(async () => setHolder(await generateHolder()))}>Create wallet key</button>
        ) : <dl><Field label="Wallet holder" value={holder.thumbprint} mono /></dl>}
        {holder !== null && credential === null && (
          <>
            <label>Pre-authorized offer code
              <input type="password" value={code} autoComplete="off" spellCheck={false}
                onChange={(event) => setCode(event.target.value)} disabled={busy} />
            </label>
            <button className="primary" disabled={busy || code.trim() === ''} onClick={() => void run(async () => {
              setCredential(await receiveCredential(holder, code.trim())); setCode('')
            }, 'Credential receipt failed. Offer codes are single-use; request a fresh offer before trying again.')}>Receive credential</button>
          </>
        )}
        {credential !== null && <StateCard tone="verified" badge="Credential received">
          <dl><Field label="Credential identifier" value={credential.id} mono /><Field label="Holder" value={credential.holder} mono /></dl>
          <p>Issuer signature and holder binding checked. Final eligibility is checked by the verifier.</p>
        </StateCard>}

        {credential !== null && <>
          <h2>2. Review consent</h2>
          {session === null ? <p>Log in with Keycloak to review this credential's consent request.</p> : <>
            <label>Wallet consent request identifier
              <input value={consentId} onChange={(event) => { setConsentId(event.target.value); setConsent(null); setRequest(null); setDecision(null); setEncrypted(''); setReplayed(false) }}
                disabled={busy || encrypted !== ''} autoComplete="off" spellCheck={false} />
            </label>
            <button disabled={busy || consentId.trim() === '' || encrypted !== ''} onClick={() => void run(loadConsent)}>Review wallet consent</button>
            {consent !== null && <StateCard tone={consent.state === 'VERIFIED' ? 'verified' : consent.state === 'DENIED' ? 'denied' : 'review'} badge={`Wallet consent: ${consent.state}`}>
              <dl>
                <Field label="Relying party" value={consent.rpId} mono />
                <Field label="Audience" value={consent.audience} mono />
                <Field label="Purpose" value={consent.purpose} />
                <Field label="Exact claims" value={JSON.stringify(consent.claims)} mono />
                <Field label="Plan hash" value={consent.planHash} mono />
                <Field label="Challenge" value={consent.challenge} mono />
                <Field label="Expires" value={consent.expiresAt} mono />
                <Field label="Expected holder" value={consent.holderThumbprint} mono />
              </dl>
              {consent.state === 'PENDING' && <>
                <button className="primary" disabled={busy} onClick={() => void run(() => decide('approve'))}>Approve wallet consent</button>
                <button disabled={busy} onClick={() => void run(() => decide('deny'))}>Deny wallet consent</button>
              </>}
            </StateCard>}
          </>}
        </>}

        {consent?.state === 'VERIFIED' && <>
          <h2>3. Review and share</h2>
          <label>Presentation session identifier
            <input value={sessionId} onChange={(event) => { setSessionId(event.target.value); setRequest(null) }}
              disabled={busy || encrypted !== ''} autoComplete="off" spellCheck={false} />
          </label>
          <button disabled={busy || sessionId.trim() === '' || encrypted !== ''} onClick={() => void run(async () => {
            setRequest(await reviewWalletRequest(sessionId.trim(), consent))
          })}>Review presentation request</button>
          {request !== null && <StateCard tone="review" badge="Signed presentation request checked">
            <dl><Field label="Verifier audience" value={request.audience} mono />
              <Field label="Requested claim" value="adultOver18=true" mono />
              <Field label="Verifier nonce" value={request.nonce} mono /></dl>
            <p>Sharing sends the full synthetic credential and holder proof, encrypted for this verifier.</p>
            <button className="primary" disabled={busy || encrypted !== ''} onClick={() => void run(share)}>Share encrypted presentation</button>
          </StateCard>}
        </>}
        {decision !== null && <StateCard tone={decision.outcome === 'ACCEPTED' ? 'verified' : 'denied'} badge={`Wallet result: ${decision.outcome}`}>
          <dl><Field label="Decision identifier" value={decision.decisionId} mono />
            <Field label="Decision reason" value={decision.reasonCode} mono /><Field label="Decision profile" value={decision.profile} mono /></dl>
          {replayed && <p role="status">The same encrypted presentation returned the identical decision.</p>}
        </StateCard>}
        {encrypted !== '' && <button disabled={busy} onClick={() => void run(replay)}>Retry same encrypted presentation</button>}
        {busy && <p role="status">Working…</p>}
        {error !== '' && <p role="alert">{error}</p>}
        {holder !== null && <button disabled={busy} onClick={reset}>Forget wallet</button>}
      </div>
    </section>
  )
}
