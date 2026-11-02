import { useEffect, useState } from 'react'
import StateCard from './StateCard'
import type { ReadinessReport } from '../ops'

function dotClass(status: string): string {
  if (status === 'UP') return 'up'
  if (status === 'DEGRADED') return 'degraded'
  return 'down'
}

function ageLabel(checkedAt: number, now: number): string {
  const seconds = Math.max(0, Math.round((now - checkedAt) / 1000))
  if (seconds < 10) return 'checked just now'
  if (seconds < 60) return `checked ${seconds}s ago`
  return `checked ${Math.floor(seconds / 60)} min ago`
}

/** Flow-readiness checklist; shared by the status and demo views. */
export default function ReadinessPanel({ report }: { report: ReadinessReport }) {
  const ready = report.status === 'READY'
  const [checkedAt] = useState(() => Date.now())
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 10_000)
    return () => clearInterval(timer)
  }, [])

  const stale = now - checkedAt > 120_000

  return (
    <StateCard tone={ready ? 'verified' : 'review'} badge={`Flow readiness: ${report.status}`}>
      <p className="standing-line">
        Service is up; the flow also needs these seven checks. {ageLabel(checkedAt, now)}
        {stale ? ' — may be stale, reload the view.' : '.'}
      </p>
      <table className="readiness-table">
        <thead>
          <tr>
            <th scope="col">Check</th>
            <th scope="col">Status</th>
            <th scope="col">Code</th>
            <th scope="col">Latency</th>
          </tr>
        </thead>
        <tbody>
          {report.checks.map((check) => (
            <tr key={check.name}>
              <td>{check.name}</td>
              <td>
                <span className={`status-dot ${dotClass(check.status)}`} aria-hidden="true" />
                {check.status}
              </td>
              <td className="mono">{check.code}</td>
              <td className="mono">{check.durationMs}ms</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!ready && (
        <p role="alert">
          At least one flow dependency is down. Liveness may still report UP: that is the point of
          separating the two probes.
        </p>
      )}
    </StateCard>
  )
}
