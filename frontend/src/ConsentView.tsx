import { useState } from 'react'
import { ApiError } from './api'
import { EMPTY_CONNECTION, resolveCaller } from './auth'
import type { Connection, SessionInfo } from './auth'
import { exportPrivateKey, generateHolder } from './crypto'
import type { HolderKey } from './crypto'
import { fetchPresentation, fetchReview, postDecision } from './consent'
import type { ConsentPresentation, ConsentReview } from './consent'
import ConnectionFields from './components/ConnectionFields'
import Field from './components/Field'
import HolderKeyControls from './components/HolderKeyControls'
import StateCard from './components/StateCard'
import StepIndicator from './components/StepIndicator'

// Holder consent flow (SOV-010). Five visibly distinct states:
// pending, review, denied, unavailable, verified. Every server value
// renders as plain text (React escapes by default); nothing here uses
// innerHTML or renders links, so hostile RP strings cannot execute.

type Stage =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'pending'; review: ConsentReview }
  | { kind: 'review'; review: ConsentReview }
  | { kind: 'deciding'; review: ConsentReview }
  | { kind: 'denied'; review: ConsentReview }
  | { kind: 'unavailable'; review: ConsentReview }
  | { kind: 'verified'; review: ConsentReview; presentation: ConsentPresentation }
  | { kind: 'error'; message: string }

export default function ConsentView({ session }: { session: SessionInfo | null }) {
  const [connection, setConnection] = useState<Connection>(EMPTY_CONNECTION)
  const [holder, setHolder] = useState<HolderKey | null>(null)
  const [keyStatus, setKeyStatus] = useState('')
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

  async function onCopyKey() {
    if (holder === null) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(await exportPrivateKey(holder)))
      setKeyStatus('Private JWK copied: paste it into the verify view.')
    } catch {
      setKeyStatus('This browser refused clipboard access.')
    }
  }

  async function onLoad() {
    setStage({ kind: 'loading' })
    try {
      const caller = resolveCaller(session, connection)
      const base = connection.base.trim()
      const review = await fetchReview(base, caller, connection.requestId.trim())
      if (review.state === 'PENDING') setStage({ kind: 'pending', review })
      else if (review.state === 'DENIED') setStage({ kind: 'denied', review })
      else if (review.state === 'UNAVAILABLE') setStage({ kind: 'unavailable', review })
      else {
        const presentation = await fetchPresentation(base, caller, review.requestId)
        setStage({ kind: 'verified', review, presentation })
      }
    } catch (err: unknown) {
      setStage({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'unreachable',
      })
    }
  }

  async function onDecide(decision: 'approve' | 'deny') {
    if (stage.kind !== 'review' || holder === null) return
    if (holder.thumbprint !== stage.review.holderThumbprint) return
    setStage({ kind: 'deciding', review: stage.review })
    try {
      const caller = resolveCaller(session, connection)
      const base = connection.base.trim()
      const review = await postDecision(base, caller, holder, stage.review, decision)
      if (review.state === 'VERIFIED') {
        const presentation = await fetchPresentation(base, caller, review.requestId)
        setStage({ kind: 'verified', review, presentation })
      } else if (review.state === 'DENIED') {
        setStage({ kind: 'denied', review })
      } else {
        setStage({ kind: 'unavailable', review })
      }
    } catch (err: unknown) {
      setStage({
        kind: 'error',
        message: err instanceof ApiError ? err.message : 'unreachable',
      })
    }
  }

  function onReset() {
    setStage({ kind: 'idle' })
  }

  const holderMatches =
    stage.kind === 'review' && holder !== null
      ? holder.thumbprint === stage.review.holderThumbprint
      : null

  return (
    <section className="consent" aria-label="Holder consent">
      <h1 className="view-title">Holder consent</h1>
      <p className="view-lede">Review the exact request, then approve or deny it with your key. Before starting: the proof request ID and the holder key for its credential.</p>
      <StepIndicator
        steps={['Load request', 'Review bound values', 'Decided']}
        current={
          stage.kind === 'pending' || stage.kind === 'review'
            ? 1
            : stage.kind === 'idle' || stage.kind === 'loading' || stage.kind === 'error'
              ? 0
              : 2
        }
        label="Consent progress"
      />

      {(stage.kind === 'idle' || stage.kind === 'loading' || stage.kind === 'error') && (
        <form
          className="consent-form"
          onSubmit={(event) => {
            event.preventDefault()
            void onLoad()
          }}
        >
          <ConnectionFields
            session={session}
            connection={connection}
            onChange={setConnection}
            tokenLabel="Bearer [REDACTED]"
          />
          <HolderKeyControls holder={holder} status={keyStatus} onGenerate={() => void onGenerateKey()}>
            {holder !== null && (
              <button type="button" onClick={() => void onCopyKey()}>
                Copy private JWK
              </button>
            )}
          </HolderKeyControls>
          <button type="submit" disabled={stage.kind === 'loading'}>
            {stage.kind === 'loading' ? 'Loading…' : 'Load request'}
          </button>
          {stage.kind === 'error' && <p role="alert">Could not load: {stage.message}</p>}
        </form>
      )}
      {(stage.kind === 'idle' || stage.kind === 'loading' || stage.kind === 'error') && (
        <div className="empty-slot">
          <p>
            <strong>No request loaded yet.</strong> You will need:
          </p>
          <ul>
            <li>The proof request ID from the relying party</li>
            <li>The holder key for that credential (generate it above)</li>
          </ul>
        </div>
      )}

      {stage.kind === 'pending' && (
        <StateCard tone="pending" focusOnMount
          badge="Pending — awaiting your decision">
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Purpose" value={stage.review.purpose} />
            <Field label="Expires" value={stage.review.expiresAt} mono />
          </dl>
          <p>Nothing is shared until you review the exact request and approve it.</p>
          <div className="consent-actions">
            <button
              type="button"
              onClick={() => setStage({ kind: 'review', review: stage.review })}
            >
              Review details
            </button>
            <button type="button" onClick={onReset}>
              Back
            </button>
          </div>
        </StateCard>
      )}

      {stage.kind === 'review' && (
        <StateCard tone="review" focusOnMount
          badge="Review — check every bound value">
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Audience" value={stage.review.audience} />
            <Field label="Purpose" value={stage.review.purpose} />
            <Field label="Exact claims" value={JSON.stringify(stage.review.claims)} mono />
            <Field label="Expires" value={stage.review.expiresAt} mono />
            <Field label="Expected holder" value={stage.review.holderThumbprint} mono />
          </dl>
          <details className="consent-details">
            <summary>Machine-bound values</summary>
            <dl>
              <Field label="Plan hash" value={stage.review.planHash} mono />
              <Field label="Challenge" value={stage.review.challenge} mono />
            </dl>
          </details>
          {holder === null && (
            <p role="alert">Generate your holder key first: only its signature can decide.</p>
          )}
          {holder !== null && holderMatches === false && (
            <p role="alert">
              Wrong holder: this key does not match the credential. Approval is disabled.
            </p>
          )}
          <div className="consent-actions">
            <button
              type="button"
              className="primary"
              disabled={holder === null || holderMatches === false}
              onClick={() => void onDecide('approve')}
            >
              Approve and share
            </button>
            <button
              type="button"
              disabled={holder === null || holderMatches === false}
              onClick={() => void onDecide('deny')}
            >
              Deny
            </button>
            <button type="button" onClick={onReset}>
              Cancel (shares nothing)
            </button>
          </div>
        </StateCard>
      )}

      {stage.kind === 'deciding' && (
        <StateCard tone="review" focusOnMount
          badge="Signing your decision…" />
      )}

      {stage.kind === 'denied' && (
        <StateCard tone="denied" focusOnMount
          badge="Denied — nothing was shared">
          <p className="outcome-sentence">Nothing was shared with {stage.review.rpId}.</p>
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Purpose" value={stage.review.purpose} />
          </dl>
          <p>No presentation exists for this request and none can be created from it.</p>
          <button type="button" onClick={onReset}>
            Done
          </button>
        </StateCard>
      )}

      {stage.kind === 'unavailable' && (
        <StateCard tone="unavailable" focusOnMount
          badge="Unavailable — no decision possible">
          <p>{stage.review.stateReason}</p>
          <p>An expired request, or one whose credential was revoked, cannot be approved.</p>
          <button type="button" onClick={onReset}>
            Done
          </button>
        </StateCard>
      )}

      {stage.kind === 'verified' && (
        <StateCard tone="verified" focusOnMount
          badge="Verified — synthetic consent proof">
          <p className="outcome-sentence">
            Shared with {stage.review.rpId}: one fact (adultOver18).
          </p>
          <p className="standing-line">Synthetic evidence only. A technical proof, never a legal or KYC determination.</p>
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Purpose" value={stage.review.purpose} />
            <Field label="Profile" value={stage.presentation.profile} mono />
          </dl>
          <details className="consent-details">
            <summary>Machine detail</summary>
            <dl>
              <Field
                label="Exact claims"
                value={JSON.stringify(stage.presentation.claims)}
                mono
              />
              <Field label="Presentation" value={stage.presentation.presentation} mono />
            </dl>
          </details>
          <button type="button" onClick={onReset}>
            Done
          </button>
        </StateCard>
      )}
    </section>
  )
}
