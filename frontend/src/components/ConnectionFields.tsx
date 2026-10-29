import type { Connection, SessionInfo } from '../auth'

/**
 * Who-is-calling fields shared by the consent and verify forms: an
 * optional API base, the session/token choice, and the request id.
 * The token row hides entirely while a session is in use, so the
 * form never shows two live credential paths at once.
 */
export default function ConnectionFields({
  session,
  connection,
  onChange,
  tokenLabel,
}: {
  session: SessionInfo | null
  connection: Connection
  onChange: (next: Connection) => void
  tokenLabel: string
}) {
  const sessionActive = session !== null && connection.useSession
  return (
    <>
      <label>
        API base (blank for same origin)
        <input
          name="api-base"
          value={connection.base}
          onChange={(event) => onChange({ ...connection, base: event.target.value })}
          placeholder="https://second-origin.example/…"
          autoComplete="off"
          spellCheck={false}
        />
      </label>
      {session !== null && (
        <label className="consent-session">
          <input
            type="checkbox"
            checked={connection.useSession}
            onChange={(event) => onChange({ ...connection, useSession: event.target.checked })}
          />
          Act as {session.displayName} (browser session)
        </label>
      )}
      {!sessionActive && (
        <label>
          {tokenLabel}
          <input
            name="bearer-token"
            type="password"
            value={connection.token}
            onChange={(event) => onChange({ ...connection, token: event.target.value })}
            placeholder="Paste a service-account token…"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
      )}
      <label>
        Proof request id
        <input
          name="request-id"
          value={connection.requestId}
          onChange={(event) => onChange({ ...connection, requestId: event.target.value })}
          placeholder="Request UUID, e.g. 3fa85f64–…"
          autoComplete="off"
          spellCheck={false}
        />
      </label>
    </>
  )
}
