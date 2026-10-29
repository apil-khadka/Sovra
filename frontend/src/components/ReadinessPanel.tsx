import Field from './Field'
import StateCard from './StateCard'
import type { ReadinessReport } from '../ops'

/** Flow-readiness checklist; shared by the status and demo views. */
export default function ReadinessPanel({ report }: { report: ReadinessReport }) {
  const ready = report.status === 'READY'
  return (
    <StateCard tone={ready ? 'verified' : 'review'} badge={`Flow readiness: ${report.status}`}>
      <dl>
        {report.checks.map((check) => (
          <Field
            key={check.name}
            label={check.name}
            value={`${check.status} · ${check.code} · ${check.durationMs}ms`}
            mono
          />
        ))}
      </dl>
      {!ready && (
        <p role="alert">
          At least one flow dependency is down. Liveness may still report UP: that is the point of
          separating the two probes.
        </p>
      )}
    </StateCard>
  )
}
