import { useState } from 'react'
import { ApiError } from './api'
import { EMPTY_CONNECTION, resolveCaller } from './auth'
import type { Connection, SessionInfo } from './auth'
import { generateHolder, importHolder, randomNonce } from './crypto'
import type { HolderKey } from './crypto'
import { fetchDecision, submitVerification } from './verification'
import type { VerificationDecision } from './verification'
import ConnectionFields from './components/ConnectionFields'
import Field from './components/Field'
import HolderKeyControls from './components/HolderKeyControls'
import StateCard from './components/StateCard'
import type { Tone } from './components/StateCard'

// Verifier flow (SOV-011). Three visibly distinct outcomes:
// accepted, rejected, unknown. Every server value renders as plain
// text; nothing here uses innerHTML or renders links.

type Stage =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'decided'; decision: VerificationDecision; replayed: boolean }
  | { kind: 'error'; message: string }

function toneFor(outcome: VerificationDecision['outcome']): Tone {
  if (outcome === 'ACCEPTED') return 'verified'
  if (outcome === 'REJECTED') return 'denied'
  return 'unavailable'
}

function badgeFor(outcome: VerificationDecision['outcome']): string {
  if (outcome === 'ACCEPTED') return 'Accepted — synthetic evidence verified'
  if (outcome === 'REJECTED') return 'Rejected — not accepted'
  return 'Unknown — dependency unavailable'
}

export default function VerifyView({ session }: { session: SessionInfo | null }) {
  const [connection, setConnection] = useState<Connection>(EMPTY_CONNECTION)
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

  async function onSubmit() {
    if (holder === null) return
    setStage({ kind: 'submitting' })
    try {
      const caller = resolveCaller(session, connection)
      const base = connection.base.trim()
      const first = await submitVerification(
        base,
        caller,
        holder,
        connection.requestId.trim(),
        nonce.trim(),
        audience.trim(),
      )
      // Response-loss shape: re-read the stored decision and confirm
      // the server returns the identical committed outcome.
      const reread = await fetchDecision(base, caller, first.decisionId)
      setStage({
        kind: 'decided',
        decision: first,
        replayed: reread.decisionId === first.decisionId && reread.outcome === first.outcome,
      })
    } catch (err: unknown) {
      setStage({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'unreachable',
      })
    }
  }

  return (
    <section className="consent" aria-label="Verify presentation">
      <h1 className="view-title">Verify presentation</h1>
      <p className="view-lede">Check a consent proof against trust, status, and a fresh nonce.</p>

      {(stage.kind === 'idle' || stage.kind === 'error') && (
        <form
          className="consent-form"
          onSubmit={(event) => {
            event.preventDefault()
            void onSubmit()
          }}
        >
          <ConnectionFields
            session={session}
            connection={connection}
            onChange={setConnection}
            tokenLabel="RP bearer [REDACTED]"
          />
          <label>
            Session audience
            <input
              name="audience"
              value={audience}
              onChange={(event) => setAudience(event.target.value)}
              placeholder="https://rp.example/callback…"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <div className="nonce-field">
            <label htmlFor="verify-nonce">Fresh nonce</label>
            <span className="consent-keyrow">
              <input
                id="verify-nonce"
                name="nonce"
                value={nonce}
                onChange={(event) => setNonce(event.target.value)}
                placeholder="New nonce fills this…"
                autoComplete="off"
                spellCheck={false}
              />
              <button type="button" onClick={() => setNonce(randomNonce())}>
                New nonce
              </button>
            </span>
          </div>
          <HolderKeyControls holder={holder} status={keyStatus} onGenerate={() => void onGenerateKey()}>
            <button type="button" onClick={() => void onImportKey()}>
              Import key
            </button>
          </HolderKeyControls>
          <label>
            Or import holder private JWK
            <input
              name="import-jwk"
              value={importText}
              onChange={(event) => setImportText(event.target.value)}
              placeholder='{"kty":"EC",…,"d":"…"}'
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <p className="view-hint">The binding key must be the credential holder key from consent.</p>
          <button type="submit" className="primary" disabled={holder === null}>
            Submit verification
          </button>
          {stage.kind === 'error' && <p role="alert">Could not verify: {stage.message}</p>}
        </form>
      )}

      {stage.kind === 'submitting' && (
        <StateCard tone="review" badge="Evaluating presentation…" />
      )}

      {stage.kind === 'decided' && (
        <StateCard tone={toneFor(stage.decision.outcome)} badge={badgeFor(stage.decision.outcome)}>
          <dl>
            <Field label="Outcome" value={stage.decision.outcome} mono />
            <Field label="Reason" value={stage.decision.reasonCode} mono />
            <Field label="Decision" value={stage.decision.decisionId} mono />
            <Field label="Profile" value={stage.decision.profile} mono />
          </dl>
          <details className="consent-details">
            <summary>Trust evidence</summary>
            <dl>
              <Field label="Trust snapshot" value={String(stage.decision.trustSnapshot)} mono />
            </dl>
          </details>
          {stage.decision.outcome === 'UNKNOWN' && (
            <p>Retry with a fresh nonce once the dependency recovers; this attempt is recorded.</p>
          )}
          {stage.replayed ? (
            <p>Stored decision re-read identically: a lost response replays, never rewrites.</p>
          ) : (
            <p role="alert">Re-read differed from the submission response.</p>
          )}
          <p>Synthetic evidence only. A technical proof, never a legal or KYC determination.</p>
          <button type="button" onClick={() => setStage({ kind: 'idle' })}>
            New verification
          </button>
        </StateCard>
      )}
    </section>
  )
}
