import Field from './components/Field'
import ReadinessPanel from './components/ReadinessPanel'
import StateCard from './components/StateCard'
import { useAsync } from './hooks/useAsync'
import { fetchReadiness, fetchSnapshot } from './ops'

// Public synthetic demo walkthrough (SOV-035). Live data comes only from
// the two unauthenticated metadata endpoints (readiness, trust snapshot);
// the flow narrative below runs over synthetic fixtures only. This view
// accepts no input at all: there is no real-ID upload path anywhere in
// the app, and no production issuer connectivity behind it.

const STEPS: Array<{ title: string; body: string; target: 'consent' | 'verify'; action: string }> = [
  {
    title: 'Synthetic issuance',
    body: 'Issuer synth-1 mints an adultOver18 credential for a fixture P-256 holder key.',
    target: 'consent',
    action: 'Open consent',
  },
  {
    title: 'Holder consent',
    body: 'The holder reviews RP, purpose, claims, and expiry, then signs approve or deny.',
    target: 'consent',
    action: 'Open consent',
  },
  {
    title: 'Verification',
    body: 'The verifier checks signature, trust, status, freshness, and a one-time challenge.',
    target: 'verify',
    action: 'Open verify',
  },
]

export default function DemoView() {
  const readiness = useAsync(fetchReadiness)
  const snapshot = useAsync(fetchSnapshot)

  return (
    <section className="consent" aria-label="Synthetic demo">
      <h1 className="view-title">Public demo</h1>
      <p className="view-lede">Synthetic fixtures only — no real identity data, no uploads.</p>

      <StateCard tone="pending" badge="What you are looking at">
        <p>
          Live sanitized metadata plus labeled synthetic fixtures. This demo connects to no
          production issuer and performs no legal or KYC determination.
        </p>
      </StateCard>

      {readiness.kind === 'ready' && <ReadinessPanel report={readiness.value} />}
      {readiness.kind === 'error' && <p role="alert">Readiness unreachable: {readiness.message}</p>}

      {snapshot.kind === 'loading' && <p>Loading trust snapshot…</p>}
      {snapshot.kind === 'error' && <p role="alert">Trust snapshot unreachable: {snapshot.message}</p>}
      {snapshot.kind === 'ready' && snapshot.value === null && (
        <p>No trust snapshot is activated yet; the flow cannot proceed until one is.</p>
      )}
      {snapshot.kind === 'ready' && snapshot.value !== null && (
        <StateCard tone="verified" badge={`Active trust snapshot · v${snapshot.value.version}`}>
          <dl>
            {snapshot.value.issuers.map((issuer) => (
              <Field
                key={`${issuer.issuerId}:${issuer.keyId}`}
                label={issuer.displayName}
                value={`${issuer.scope} · ${issuer.status} · key v${issuer.keyVersion}`}
                mono
              />
            ))}
          </dl>
        </StateCard>
      )}

      {STEPS.map((step) => (
        <StateCard key={step.title} tone="review" badge={step.title}>
          <p>{step.body}</p>
          <div className="consent-actions">
            <a className="button-link" href={`#/${step.target}`}>
              {step.action}
            </a>
          </div>
        </StateCard>
      ))}
    </section>
  )
}
