import { useAsync } from './hooks/useAsync'
import { fetchReadiness, fetchSnapshot } from './ops'

// The public walkthrough uses sanitized service metadata and synthetic
// fixtures only. It accepts no identity uploads and connects to no production
// issuer or legal/KYC decision process.

function formatDate(value: string): string {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp)) return value
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(timestamp)
}

export default function DemoView() {
  const readiness = useAsync(fetchReadiness)
  const snapshot = useAsync(fetchSnapshot)
  const interopDemoUrl = import.meta.env.VITE_SOVRA_INTEROP_DEMO_URL
    || (['localhost', '127.0.0.1', '::1'].includes(window.location.hostname)
      ? `${window.location.protocol}//${window.location.hostname}:5174/interoperability`
      : new URL('/interoperability', window.location.origin).toString())

  return (
    <section className="consent demo-view" aria-label="Synthetic demo">
      <header className="demo-intro">
        <div className="demo-intro-copy">
          <h1 className="view-title">Public demo</h1>
          <p className="view-lede">
            Explore consent and presentation verification with synthetic credentials.
            See which trust data and service checks support each step.
          </p>
          <div className="demo-intro-actions">
            <a className="demo-primary-link" href="#/consent">Start the consent walkthrough</a>
            <a className="demo-secondary-link" href="#/verify">Open presentation verifier</a>
          </div>
        </div>
        <aside className="demo-boundary" aria-label="Demo data boundary">
          <strong>Synthetic fixtures only</strong>
          <span>No identity uploads</span>
          <span>No production issuer or KYC decision</span>
        </aside>
      </header>

      <div className="demo-overview-grid">
        <section className="demo-panel" aria-labelledby="demo-readiness-title">
          <div className="demo-panel-heading">
            <div>
              <h2 id="demo-readiness-title">Flow readiness</h2>
              <p>Live checks for the dependencies used by the demo.</p>
            </div>
            {readiness.kind === 'ready' && (
              <span className={`demo-readiness-badge ${readiness.value.status === 'READY' ? 'is-ready' : 'has-issue'}`}>
                {readiness.value.status === 'READY' ? 'Ready' : 'Needs attention'}
              </span>
            )}
          </div>

          {readiness.kind === 'loading' && (
            <p className="demo-state-note" role="status">Checking flow dependencies…</p>
          )}
          {readiness.kind === 'error' && (
            <p className="demo-state-note is-error" role="alert">
              Readiness could not be loaded ({readiness.message}). Refresh this page to retry.
            </p>
          )}
          {readiness.kind === 'ready' && (() => {
            const report = readiness.value
            const upCount = report.checks.filter((check) => check.status === 'UP').length

            return (
              <>
                <p className="demo-panel-summary">
                  <strong>{upCount} of {report.checks.length} checks are UP.</strong>
                  <span>Readiness confirms configured dependencies responded; it does not guarantee every external integration.</span>
                </p>
                <ul className="demo-check-list">
                  {report.checks.map((check) => (
                    <li className="demo-check" key={check.name}>
                      <div className="demo-check-topline">
                        <strong>{check.name}</strong>
                        <span className={`demo-check-status is-${check.status.toLowerCase()}`}>
                          <span className="demo-status-mark" aria-hidden="true" />
                          {check.status}
                        </span>
                      </div>
                      <div className="demo-check-meta">
                        <code>{check.code}</code>
                        <span>{check.durationMs} ms</span>
                      </div>
                    </li>
                  ))}
                </ul>
                {report.status === 'NOT_READY' && (
                  <p className="demo-state-note is-error" role="alert">
                    One or more dependencies need attention. Review the checks above before starting a flow.
                  </p>
                )}
              </>
            )
          })()}
        </section>

        <section className="demo-panel" aria-labelledby="demo-trust-title">
          <div className="demo-panel-heading">
            <div>
              <h2 id="demo-trust-title">Active trust snapshot</h2>
              <p>Issuer keys and policies used to evaluate credentials.</p>
            </div>
          </div>

          {snapshot.kind === 'loading' && (
            <p className="demo-state-note" role="status">Loading trusted issuers…</p>
          )}
          {snapshot.kind === 'error' && (
            <p className="demo-state-note is-error" role="alert">
              Trust data could not be loaded ({snapshot.message}). Refresh this page to retry.
            </p>
          )}
          {snapshot.kind === 'ready' && snapshot.value === null && (
            <p className="demo-state-note">
              No trust snapshot is active yet. Verification needs an active issuer set before it can proceed.
            </p>
          )}
          {snapshot.kind === 'ready' && snapshot.value !== null && (
            <>
              <p className="demo-panel-summary demo-trust-summary">
                <strong>Version {snapshot.value.version}</strong>
                <span>{snapshot.value.issuers.length} trusted issuers</span>
                <span>{snapshot.value.policies.length} verification policies</span>
              </p>
              <ul className="demo-issuer-list">
                {snapshot.value.issuers.map((issuer) => (
                  <li className="demo-issuer" key={`${issuer.issuerId}:${issuer.keyId}`}>
                    <div className="demo-issuer-heading">
                      <strong>{issuer.displayName}</strong>
                      <span className="demo-issuer-state">{issuer.status}</span>
                    </div>
                    <p>{issuer.scope}</p>
                    <p className="demo-issuer-meta">
                      {issuer.credentialTypes.join(', ')} · key v{issuer.keyVersion} · valid through {formatDate(issuer.validThrough)}
                    </p>
                  </li>
                ))}
              </ul>
              {snapshot.value.policies.length > 0 ? (
                <details className="demo-disclosure">
                  <summary>View verification policies ({snapshot.value.policies.length})</summary>
                  <ul className="demo-policy-list">
                    {snapshot.value.policies.map((policy) => (
                      <li key={`${policy.rpId}:${policy.purpose}`}>
                        <strong>{policy.rpId}</strong>
                        <span>{policy.purpose}</span>
                        <span>{policy.allowedTypes.join(', ')} · maximum assurance {policy.maxAssurance}</span>
                      </li>
                    ))}
                  </ul>
                </details>
              ) : (
                <p className="demo-policy-empty">No verification policies are listed in this snapshot.</p>
              )}
            </>
          )}
        </section>
      </div>

      <section className="demo-paths" aria-labelledby="demo-paths-title">
        <div className="demo-section-heading">
          <h2 id="demo-paths-title">Explore the demo</h2>
          <p>Move from a holder decision to a verifier result, or open the supporting tools.</p>
        </div>
        <ul className="demo-link-list">
          <li>
            <a href="#/consent">
              <span className="demo-link-copy">
                <strong>Review a consent request</strong>
                <span>Inspect the relying party, purpose, requested claims, and expiry before approving or denying.</span>
              </span>
              <span className="demo-link-action">Open consent</span>
            </a>
          </li>
          <li>
            <a href="#/verify">
              <span className="demo-link-copy">
                <strong>Verify a presentation</strong>
                <span>Check the signature, issuer trust, credential status, freshness, and challenge.</span>
              </span>
              <span className="demo-link-action">Open verifier</span>
            </a>
          </li>
          <li>
            <a href="#/portal">
              <span className="demo-link-copy">
                <strong>Build an integration</strong>
                <span>Start with the minimal relying-party sample and its setup, request, decision, and verify steps.</span>
              </span>
              <span className="demo-link-action">Developer portal</span>
            </a>
          </li>
          <li>
            <a href={interopDemoUrl}>
              <span className="demo-link-copy">
                <strong>Test unfamiliar schemas</strong>
                <span>Explore known and unfamiliar credential types. This walkthrough requires the demo server.</span>
              </span>
              <span className="demo-link-action">Open interop demo</span>
            </a>
          </li>
        </ul>
      </section>
    </section>
  )
}
