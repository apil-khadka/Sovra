import { useState } from 'react'
import { ApiError } from './api'
import type { SessionInfo } from './auth'
import { fetchAlerts, fetchAudit } from './federation'
import type { AuditEvent, OpsAlert } from './federation'
import { fetchReadiness } from './ops'
import type { ReadinessReport } from './ops'
import Field from './components/Field'
import ReadinessPanel from './components/ReadinessPanel'
import StateCard from './components/StateCard'

// Security operations desk (SOV-026). Trust admins read alerts,
// readiness, and the audit tail. Rows render as plain text; the
// desk cannot reach source data or keys.

export default function SecOpsView({ session }: { session: SessionInfo | null }) {
  const [alerts, setAlerts] = useState<OpsAlert[] | undefined>(undefined)
  const [events, setEvents] = useState<AuditEvent[] | undefined>(undefined)
  const [readiness, setReadiness] = useState<ReadinessReport | undefined>(undefined)
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)

  const admin = session !== null && session.roles.includes('TRUST_ADMIN')

  async function refresh() {
    setLoading(true)
    setNotice('')
    try {
      const [freshAlerts, freshEvents, freshReadiness] = await Promise.all([
        fetchAlerts(),
        fetchAudit(20),
        fetchReadiness(),
      ])
      setAlerts(freshAlerts)
      setEvents(freshEvents)
      setReadiness(freshReadiness)
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setLoading(false)
    }
  }

  if (!admin) {
    return (
      <section className="consent" aria-label="Security operations">
        <h1 className="view-title">Security operations</h1>
        <StateCard tone="denied" badge="Trust admin session required">
          <p>
            {session === null
              ? 'Log in first — alerts and audit evidence are visible to trust admins only.'
              : 'This session lacks the trust admin role, so operational evidence stays hidden.'}
          </p>
        </StateCard>
      </section>
    )
  }

  return (
    <section className="consent" aria-label="Security operations">
      <h1 className="view-title">Security operations</h1>
      <p>
        <button type="button" disabled={loading} onClick={() => void refresh()}>
          {loading ? 'Loading…' : 'Load evidence'}
        </button>
      </p>
      {notice !== '' && <p role="alert">{notice}</p>}
      {alerts === undefined && <p>Load evidence to begin.</p>}
      {alerts !== undefined && (
        <article className="consent-card" aria-label="Alerts">
          <p className="consent-badge">
            {alerts.length === 0 ? 'No active alerts' : `${alerts.length} active alert${alerts.length === 1 ? '' : 's'}`}
          </p>
          {alerts.length > 0 && (
            <dl className="health-list">
              {alerts.map((alert) => (
                <Field
                  key={`${alert.check}-${alert.code}`}
                  label={`${alert.alert} (${alert.severity})`}
                  value={`${alert.status} · ${alert.code} · since ${alert.firstObservedAt}`}
                />
              ))}
            </dl>
          )}
        </article>
      )}
      {readiness !== undefined && <ReadinessPanel report={readiness} />}
      {events !== undefined && (
        <>
          <h2>Audit tail</h2>
          {events.length === 0 && <p>No audit rows yet.</p>}
          {events.slice(0, 20).map((event) => (
            <article className="consent-card" key={event.id} aria-label="Audit row">
              <p className="consent-badge">
                {event.action} — {event.decision.toLowerCase()}
              </p>
              <dl className="health-list">
                <Field label="When" value={event.occurredAt} mono />
                <Field label="Actor" value={`${event.actorType} ${event.actorId}`} mono />
                <Field label="Resource" value={`${event.resourceType} ${event.resourceId}`} mono />
                {event.reasonCode !== '' && <Field label="Reason" value={event.reasonCode} mono />}
              </dl>
            </article>
          ))}
        </>
      )}
    </section>
  )
}
