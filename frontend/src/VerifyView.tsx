import { useState } from 'react'
import {
  generateHolder,
  importHolder,
  randomNonce,
} from './consent'
import type { HolderKey } from './consent'
import { VerifyApiError, fetchDecision, submitVerification } from './verification'
import type { VerificationDecision } from './verification'
import type { Caller, SessionInfo } from './auth'

// Minimal verifier flow (SOV-011). Three visibly distinct outcomes:
// accepted, rejected, unknown. Every server value renders as plain
// text; nothing here uses innerHTML or renders links.

type Stage =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'decided'; decision: VerificationDecision; replayed: boolean }
  | { kind: 'error'; message: string }

export default function VerifyView({ session }: { session: SessionInfo | null }) {
  const [base, setBase] = useState('')
  const [token, setToken] = useState('')
  const [useSession, setUseSession] = useState(true)
  const [requestId, setRequestId] = useState('')
  const [nonce, setNonce] = useState('')
  const [audience, setAudience] = useState('')
  const [holder, setHolder] = useState<HolderKey | null>(null)
  const [keyStatus, setKeyStatus] = useState('')
  const [importText, setImportText] = useState('')
  const [stage, setStage] = useState<Stage>({ kind: 'idle' })

  async function onGenerateKey() {
    setKeyStatus('Generating P-256 holder key…')
    try {
      setHolder(await generateHolder())
      setKeyStatus('')
    } catch {
      setKeyStatus('This browser refused to generate a key.')
    }
  }

  async function onImportKey() {
    setKeyStatus('Importing holder key…')
    try {
      const parsed = JSON.parse(importText) as JsonWebKey
      setHolder(await importHolder(parsed))
      setImportText('')
      setKeyStatus('')
    } catch {
      setKeyStatus('That text is not a usable private JWK.')
    }
  }

  function caller(): Caller {
    return session !== null && useSession ? { kind: 'session' } : { kind: 'token', token: token.trim() }
  }

  async function onSubmit() {
    if (holder === null) return
    setStage({ kind: 'submitting' })
    try {
      const first = await submitVerification(
        base.trim(),
        caller(),
        holder,
        requestId.trim(),
        nonce.trim(),
        audience.trim(),
      )
      // Response-loss shape: re-read the stored decision and confirm
      // the server returns the identical committed outcome.
      const reread = await fetchDecision(base.trim(), caller(), first.decisionId)
      setStage({
        kind: 'decided',
        decision: first,
        replayed:
          reread.decisionId === first.decisionId && reread.outcome === first.outcome,
      })
    } catch (err: unknown) {
      setStage({
        kind: 'error',
        message: err instanceof VerifyApiError ? err.message : 'unreachable',
      })
    }
  }

  const outcomeClass =
    stage.kind === 'decided'
      ? stage.decision.outcome === 'ACCEPTED'
        ? 'state-verified'
        : stage.decision.outcome === 'REJECTED'
          ? 'state-denied'
          : 'state-unavailable'
      : ''

  return (
    <section className="consent" aria-label="Verify presentation">
      <h2>Verify presentation (synthetic demo)</h2>

      {(stage.kind === 'idle' || stage.kind === 'error') && (
        <form
          className="consent-form"
          onSubmit={(event) => {
            event.preventDefault()
            void onSubmit()
          }}
        >
          <label>
            API base (blank for same origin)
            <input
              value={base}
              onChange={(event) => setBase(event.target.value)}
              autoComplete="off"
            />
          </label>
          {session !== null && (
            <label className="consent-session">
              <input
                type="checkbox"
                checked={useSession}
                onChange={(event) => setUseSession(event.target.checked)}
              />
              Act as {session.displayName} (browser session)
            </label>
          )}
          <label>
            RP bearer [REDACTED]
            <input
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              autoComplete="off"
              disabled={session !== null && useSession}
            />
          </label>
          <label>
            Proof request id
            <input
              value={requestId}
              onChange={(event) => setRequestId(event.target.value)}
              placeholder="approved request UUID"
              autoComplete="off"
            />
          </label>
          <label>
            Session audience
            <input
              value={audience}
              onChange={(event) => setAudience(event.target.value)}
              placeholder="must match the consented audience"
              autoComplete="off"
            />
          </label>
          <label>
            Fresh nonce
            <input
              value={nonce}
              onChange={(event) => setNonce(event.target.value)}
              placeholder="verifier-chosen, one decision per nonce"
              autoComplete="off"
            />
          </label>
          <div className="consent-keyrow">
            <button type="button" onClick={() => setNonce(randomNonce())}>
              New nonce
            </button>
            <button type="button" onClick={() => void onGenerateKey()}>
              Generate holder key
            </button>
            {holder !== null && (
              <code className="mono wrap">holder: {holder.thumbprint}</code>
            )}
            {keyStatus !== '' && <p>{keyStatus}</p>}
          </div>
          <label>
            Or import holder private JWK
            <input
              value={importText}
              onChange={(event) => setImportText(event.target.value)}
              placeholder='{"kty":"EC",…,"d":"…"}'
              autoComplete="off"
            />
          </label>
          <div className="consent-keyrow">
            <button type="button" onClick={() => void onImportKey()}>
              Import key
            </button>
          </div>
          <p>The binding key must be the credential holder key from the consent step.</p>
          <button type="submit" disabled={holder === null}>
            Submit verification
          </button>
          {stage.kind === 'error' && <p role="alert">Could not verify: {stage.message}</p>}
        </form>
      )}

      {stage.kind === 'submitting' && (
        <article className="consent-card state-review">
          <p className="consent-badge">Evaluating presentation…</p>
        </article>
      )}

      {stage.kind === 'decided' && (
        <article className={`consent-card ${outcomeClass}`}>
          <p className="consent-badge">
            {stage.decision.outcome === 'ACCEPTED' && 'Accepted — synthetic evidence verified'}
            {stage.decision.outcome === 'REJECTED' && 'Rejected — not accepted'}
            {stage.decision.outcome === 'UNKNOWN' && 'Unknown — dependency unavailable'}
          </p>
          <dl>
            <div className="consent-field">
              <dt>Outcome</dt>
              <dd className="mono">{stage.decision.outcome}</dd>
            </div>
            <div className="consent-field">
              <dt>Reason</dt>
              <dd className="mono">{stage.decision.reasonCode}</dd>
            </div>
            <div className="consent-field">
              <dt>Decision</dt>
              <dd className="mono">{stage.decision.decisionId}</dd>
            </div>
            <div className="consent-field">
              <dt>Profile</dt>
              <dd className="mono">{stage.decision.profile}</dd>
            </div>
            <div className="consent-field">
              <dt>Trust snapshot</dt>
              <dd className="mono">{String(stage.decision.trustSnapshot)}</dd>
            </div>
          </dl>
          {stage.decision.outcome === 'UNKNOWN' && (
            <p>Retry with a fresh nonce once the dependency recovers; this attempt is recorded.</p>
          )}
          {stage.replayed ? (
            <p>Stored decision re-read identically: a lost response replays, never rewrites.</p>
          ) : (
            <p role="alert">Re-read differed from the submission response.</p>
          )}
          <p>Synthetic G1 evidence only. A technical proof, never a legal or KYC determination.</p>
          <button type="button" onClick={() => setStage({ kind: 'idle' })}>
            New verification
          </button>
        </article>
      )}
    </section>
  )
}
