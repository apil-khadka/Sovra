import { useState } from 'react'
import { ApiError } from './api'
import type { SessionInfo } from './auth'
import {
  fetchRpApps,
  fetchRpMetrics,
  fetchRpOutcomes,
  rotateRpCredential,
  revokeRpCredential,
} from './portal'
import type { RotatedApp, RpApp, RpMetrics, RpOutcome } from './portal'
import Field from './components/Field'
import StateCard from './components/StateCard'

// Relying-party dashboard (SOV-025). Tenant members manage
// authorized apps — rotate or revoke their credentials — and
// review verification outcomes and safe usage metrics. Only
// RP_CLIENT-bearing accounts appear; trust, issuer, auditor,
// and member credentials stay out of reach.

export default function RpDashboardView({ session }: { session: SessionInfo | null }) {
  const [apps, setApps] = useState<RpApp[] | undefined>(undefined)
  const [metrics, setMetrics] = useState<RpMetrics | undefined>(undefined)
  const [outcomes, setOutcomes] = useState<RpOutcome[] | undefined>(undefined)
  const [rotated, setRotated] = useState<RotatedApp | undefined>(undefined)
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)

  const member = session !== null && session.roles.includes('TENANT_MEMBER')

  async function refresh() {
    setLoading(true)
    setNotice('')
    try {
      const [freshApps, freshMetrics, freshOutcomes] = await Promise.all([
        fetchRpApps(),
        fetchRpMetrics(),
        fetchRpOutcomes(20),
      ])
      setApps(freshApps)
      setMetrics(freshMetrics)
      setOutcomes(freshOutcomes)
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setLoading(false)
    }
  }

  async function rotate(id: string) {
    setLoading(true)
    setNotice('')
    try {
      const fresh = await rotateRpCredential(id)
      setRotated(fresh)
      setApps(await fetchRpApps())
    } catch (err: unknown) {
      setRotated(undefined)
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setLoading(false)
    }
  }

  async function revoke(id: string) {
    setLoading(true)
    setNotice('')
    try {
      await revokeRpCredential(id)
      setRotated(undefined)
      setApps(await fetchRpApps())
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setLoading(false)
    }
  }

  if (!member) {
    return (
      <section className="consent" aria-label="Relying-party dashboard">
        <h1 className="view-title">Relying-party dashboard</h1>
        <StateCard tone="denied" badge="Tenant member session required">
          <p>
            {session === null
              ? 'Log in first — authorized apps and outcomes are visible to tenant members only.'
              : 'This session lacks the tenant member role, so the dashboard stays hidden.'}
          </p>
        </StateCard>
      </section>
    )
  }

  return (
    <section className="consent" aria-label="Relying-party dashboard">
      <h1 className="view-title">Relying-party dashboard</h1>
      <p>
        <button type="button" disabled={loading} onClick={() => void refresh()}>
          {loading ? 'Loading…' : 'Load dashboard'}
        </button>
      </p>
      {notice !== '' && <p role="alert">{notice}</p>}
      {apps === undefined && <p>Load the dashboard to begin.</p>}
      {metrics !== undefined && (
        <article className="consent-card" aria-label="Usage metrics">
          <p className="consent-badge">
            {metrics.total} decision{metrics.total === 1 ? '' : 's'}
          </p>
          <dl className="health-list">
            <Field label="Accepted" value={String(metrics.accepted)} />
            <Field label="Rejected" value={String(metrics.rejected)} />
            <Field label="Unknown" value={String(metrics.unknown)} />
          </dl>
        </article>
      )}
      {rotated !== undefined && (
        <StateCard tone="review" badge="New credential — copy the token now">
          <dl className="health-list">
            <Field label="App" value={rotated.name} mono />
            <Field label="Token" value={rotated.token} mono />
          </dl>
          <p>This token shows once and never reads back.</p>
        </StateCard>
      )}
      {apps !== undefined && (
        <>
          <h2>Authorized apps</h2>
          {apps.length === 0 && <p>No relying-party credentials yet.</p>}
          {apps.map((app) => (
            <article className="consent-card" key={app.id} aria-label="Authorized app">
              <p className="consent-badge">
                {app.name} — {app.revoked ? 'revoked' : 'active'}
              </p>
              <dl className="health-list">
                <Field label="Roles" value={app.roles.join(', ')} mono />
                <Field label="Expires" value={app.expiresAt ?? 'never'} mono />
              </dl>
              {!app.revoked && (
                <p>
                  <button type="button" disabled={loading} onClick={() => void rotate(app.id)}>
                    Rotate credential
                  </button>{' '}
                  <button type="button" disabled={loading} onClick={() => void revoke(app.id)}>
                    Revoke credential
                  </button>
                </p>
              )}
            </article>
          ))}
        </>
      )}
      {outcomes !== undefined && (
        <>
          <h2>Recent outcomes</h2>
          {outcomes.length === 0 && <p>No verification decisions yet.</p>}
          {outcomes.map((outcome) => (
            <article className="consent-card" key={outcome.decisionId} aria-label="Outcome">
              <p className="consent-badge">
                {outcome.outcome} — {outcome.reasonCode}
              </p>
              <dl className="health-list">
                <Field label="Decision" value={outcome.decisionId} mono />
                <Field label="Request" value={outcome.requestId} mono />
                <Field label="Relying party" value={outcome.rpId} />
                <Field label="Decided" value={outcome.decidedAt} mono />
              </dl>
            </article>
          ))}
        </>
      )}
    </section>
  )
}
