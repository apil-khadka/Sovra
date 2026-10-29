/** One labeled value inside a card's <dl>; mono for machine values. */
export default function Field({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="consent-field">
      <dt>{label}</dt>
      <dd className={mono === true ? 'mono' : undefined} translate={mono === true ? 'no' : undefined}>
        {value}
      </dd>
    </div>
  )
}
