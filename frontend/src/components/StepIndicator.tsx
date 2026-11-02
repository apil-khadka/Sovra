/**
 * Three-step progress for the consent/verify ceremonies. Driven by
 * the view's existing stage union — no new state. Done steps show a
 * check, the current step is marked for assistive tech.
 */
export default function StepIndicator({
  steps,
  current,
  label,
}: {
  steps: string[]
  current: number
  label: string
}) {
  return (
    <ol className="steps" aria-label={label}>
      {steps.map((step, index) => (
        <li
          key={step}
          className={index < current ? 'step-done' : index === current ? 'step-now' : 'step-todo'}
          aria-current={index === current ? 'step' : undefined}
        >
          {index < current && (
            <span className="step-check" aria-hidden="true">
              ✓{' '}
            </span>
          )}
          {step}
        </li>
      ))}
    </ol>
  )
}
