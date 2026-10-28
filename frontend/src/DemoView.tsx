import { useEffect, useState } from 'react'
import { fetchReadiness, fetchSnapshot } from './ops'
import type { ReadinessReport, TrustSnapshot } from './ops'

// Public synthetic demo walkthrough (SOV-035). Live data comes only from
// the two unauthenticated metadata endpoints (readiness, trust snapshot);
// the flow narrative below runs over synthetic fixtures only. This view
// accepts no input at all: there is no real-ID upload path anywhere in
// the app, and no production issuer connectivity behind it.

type SnapshotState =
  | { kind: 'loading' }
  | { kind: 'ready'; snapshot: TrustSnapshot | null }
  | { kind: 'error'; message: string }

const FIXTURE_STEPS: Array<{ title: string; body: string }> = [
  {
    title: '1. Synthetic issuance (fixture)',
    body: 'Issuer synth-1 mints an adultOver18 credential for a fixture P-256 holder key. ' +
      'Artifact profile sovra-g1-synthetic/0.2, labeled synthetic: true.',
  },
  {
    title: '2. Holder consent (fixture)',
    body: 'The holder reviews the exact RP, purpose, claims, and expiry, then signs an ' +
      'explicit approve/deny with the fixture holder key. Open "Holder consent" to run it.',
  },
  {
    title: '3. Verification (fixture)',
    body: 'The verifier checks signature, trust, status, freshness, and one-time challenge. ' +
      'Replay returns the stored decision byte-for-byte; tampering is rejected. ' +
      'Open "Verify presentation" to run it.',
  },
]

export function ReadinessPanel({ report }: { report: ReadinessReport }) {
  return (
    <article className="consent-card state-review">
      <p className="consent-badge">
        Flow readiness: {report.status === 'READY' ? 'READY' : 'NOT READY'}
      </p>
      <dl>
        {report.checks.map((check) => (
          <div className="consent-field" key={check.name}>
            <dt>{check.name}</dt>
            <dd className="mono">
              {check.status} · {check.code} · {check.durationMs}ms
            </dd>
          </div>
        ))}
      </dl>
      {report.status !== 'READY' && (
        <p role="alert">
          At least one flow dependency is down. Liveness may still report UP: that is the
          point of separating the two probes.
        </p>
      )}
    </article>
  )
}

export default function DemoView() {
  const [readiness, setReadiness] = useState<ReadinessReport | null>(null)
  const [readinessError, setReadinessError] = useState('')
  const [snapshot, setSnapshot] = useState<SnapshotState>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    fetchReadiness()
      .then((report) => {
        if (!controller.signal.aborted) setReadiness(report)
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) {
          setReadinessError(err instanceof Error ? err.message : 'unreachable')
        }
      })
    fetchSnapshot()
      .then((value) => {
        if (!controller.signal.aborted) setSnapshot({ kind: 'ready', snapshot: value })
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) {
          setSnapshot({
            kind: 'error',
            message: err instanceof Error ? err.message : 'unreachable',
          })
        }
      })
    return () => controller.abort()
  }, [])

  return (
    <section className="consent" aria-label="Synthetic demo">
      <h2>Public demo (synthetic fixtures only)</h2>
      <article className="consent-card state-pending">
        <p className="consent-badge">Synthetic only — no real identity data</p>
        <p>
          Every value on this page is either live sanitized metadata or a labeled synthetic
          fixture. This demo accepts no file uploads anywhere in the app, connects to no
          production issuer, and performs no legal or KYC determination.
        </p>
      </article>

      {readiness !== null && <ReadinessPanel report={readiness} />}
      {readinessError !== '' && <p role="alert">Readiness unreachable: {readinessError}</p>}

      {snapshot.kind === 'loading' && <p>Loading trust snapshot…</p>}
      {snapshot.kind === 'error' && (
        <p role="alert">Trust snapshot unreachable: {snapshot.message}</p>
      )}
      {snapshot.kind === 'ready' && snapshot.snapshot === null && (
        <p>No trust snapshot is activated yet; the flow cannot proceed until one is.</p>
      )}
      {snapshot.kind === 'ready' && snapshot.snapshot !== null && (
        <article className="consent-card state-verified">
          <p className="consent-badge">
            Active trust snapshot · version {snapshot.snapshot.version}
          </p>
          <dl>
            {snapshot.snapshot.issuers.map((issuer) => (
              <div className="consent-field" key={`${issuer.issuerId}:${issuer.keyId}`}>
                <dt>{issuer.displayName}</dt>
                <dd className="mono">
                  {issuer.scope} · {issuer.status} · key v{issuer.keyVersion}
                </dd>
              </div>
            ))}
          </dl>
        </article>
      )}

      {FIXTURE_STEPS.map((step) => (
        <article className="consent-card state-review" key={step.title}>
          <p className="consent-badge">{step.title}</p>
          <p>{step.body}</p>
        </article>
      ))}
    </section>
  )
}
