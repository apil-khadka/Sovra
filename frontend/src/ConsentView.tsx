import { useState } from 'react'
import {
  ConsentApiError,
  exportPrivateKey,
  fetchPresentation,
  fetchReview,
  generateHolder,
  postDecision,
} from './consent'
import type { ConsentPresentation, ConsentReview, HolderKey } from './consent'

// Minimal holder consent flow (SOV-010). Five visibly distinct states:
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

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="consent-field">
      <dt>{label}</dt>
      <dd className={mono === true ? 'mono' : undefined}>{value}</dd>
    </div>
  )
}

export default function ConsentView() {
  const [base, setBase] = useState('')
  const [token, setToken] = useState('')
  const [requestId, setRequestId] = useState('')
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

  async function onLoad() {
    setStage({ kind: 'loading' })
    try {
      const review = await fetchReview(base.trim(), token.trim(), requestId.trim())
      if (review.state === 'PENDING') setStage({ kind: 'pending', review })
      else if (review.state === 'DENIED') setStage({ kind: 'denied', review })
      else if (review.state === 'UNAVAILABLE') setStage({ kind: 'unavailable', review })
      else {
        const presentation = await fetchPresentation(base.trim(), token.trim(), review.requestId)
        setStage({ kind: 'verified', review, presentation })
      }
    } catch (err: unknown) {
      setStage({
        kind: 'error',
        message: err instanceof ConsentApiError ? err.message : 'unreachable',
      })
    }
  }

  async function onDecide(decision: 'approve' | 'deny') {
    if (stage.kind !== 'review' || holder === null) return
    if (holder.thumbprint !== stage.review.holderThumbprint) return
    setStage({ kind: 'deciding', review: stage.review })
    try {
      const review = await postDecision(base.trim(), token.trim(), holder, stage.review, decision)
      if (review.state === 'VERIFIED') {
        const presentation = await fetchPresentation(base.trim(), token.trim(), review.requestId)
        setStage({ kind: 'verified', review, presentation })
      } else if (review.state === 'DENIED') {
        setStage({ kind: 'denied', review })
      } else {
        setStage({ kind: 'unavailable', review })
      }
    } catch (err: unknown) {
      setStage({
        kind: 'error',
        message: err instanceof ConsentApiError ? err.message : 'unreachable',
      })
    }
  }

  function onReset() {
    setStage({ kind: 'idle' })
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

  const holderMatches =
    stage.kind === 'review' && holder !== null
      ? holder.thumbprint === stage.review.holderThumbprint
      : null

  return (
    <section className="consent" aria-label="Holder consent">
      <h2>Holder consent (synthetic demo)</h2>

      {(stage.kind === 'idle' || stage.kind === 'loading' || stage.kind === 'error') && (
        <form
          className="consent-form"
          onSubmit={(event) => {
            event.preventDefault()
            void onLoad()
          }}
        >
          <label>
            API base (blank for same origin)
            <input
              value={base}
              onChange={(event) => setBase(event.target.value)}
              placeholder=""
              autoComplete="off"
            />
          </label>
          <label>
            Bearer [REDACTED]
            <input
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              autoComplete="off"
            />
          </label>
          <label>
            Proof request id
            <input
              value={requestId}
              onChange={(event) => setRequestId(event.target.value)}
              placeholder="request UUID from the relying party"
              autoComplete="off"
            />
          </label>
          <div className="consent-keyrow">
            <button type="button" onClick={() => void onGenerateKey()}>
              Generate holder key
            </button>
            {holder !== null && (
              <code className="mono wrap">holder: {holder.thumbprint}</code>
            )}
            {holder !== null && (
              <button type="button" onClick={() => void onCopyKey()}>
                Copy private JWK
              </button>
            )}
            {keyStatus !== '' && <p>{keyStatus}</p>}
          </div>
          <button type="submit" disabled={stage.kind === 'loading'}>
            {stage.kind === 'loading' ? 'Loading…' : 'Load request'}
          </button>
          {stage.kind === 'error' && <p role="alert">Could not load: {stage.message}</p>}
        </form>
      )}

      {stage.kind === 'pending' && (
        <article className="consent-card state-pending">
          <p className="consent-badge">Pending — awaiting your decision</p>
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
        </article>
      )}

      {stage.kind === 'review' && (
        <article className="consent-card state-review">
          <p className="consent-badge">Review — check every bound value</p>
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Audience" value={stage.review.audience} />
            <Field label="Purpose" value={stage.review.purpose} />
            <Field label="Exact claims" value={JSON.stringify(stage.review.claims)} mono />
            <Field label="Plan hash" value={stage.review.planHash} mono />
            <Field label="Challenge" value={stage.review.challenge} mono />
            <Field label="Expires" value={stage.review.expiresAt} mono />
            <Field label="Expected holder" value={stage.review.holderThumbprint} mono />
          </dl>
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
        </article>
      )}

      {stage.kind === 'deciding' && (
        <article className="consent-card state-review">
          <p className="consent-badge">Signing your decision…</p>
        </article>
      )}

      {stage.kind === 'denied' && (
        <article className="consent-card state-denied">
          <p className="consent-badge">Denied — nothing was shared</p>
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Purpose" value={stage.review.purpose} />
          </dl>
          <p>No presentation exists for this request and none can be created from it.</p>
          <button type="button" onClick={onReset}>
            Done
          </button>
        </article>
      )}

      {stage.kind === 'unavailable' && (
        <article className="consent-card state-unavailable">
          <p className="consent-badge">Unavailable — no decision possible</p>
          <p>{stage.review.stateReason}</p>
          <p>An expired request, or one whose credential was revoked, cannot be approved.</p>
          <button type="button" onClick={onReset}>
            Done
          </button>
        </article>
      )}

      {stage.kind === 'verified' && (
        <article className="consent-card state-verified">
          <p className="consent-badge">Verified — synthetic consent proof</p>
          <dl>
            <Field label="Relying party" value={stage.review.rpId} />
            <Field label="Purpose" value={stage.review.purpose} />
            <Field label="Exact claims" value={JSON.stringify(stage.presentation.claims)} mono />
            <Field label="Profile" value={stage.presentation.profile} mono />
            <Field label="Presentation" value={stage.presentation.presentation} mono />
          </dl>
          <p>
            Synthetic G1 evidence only. A technical proof, never a legal or KYC determination.
          </p>
          <button type="button" onClick={onReset}>
            Done
          </button>
        </article>
      )}
    </section>
  )
}
