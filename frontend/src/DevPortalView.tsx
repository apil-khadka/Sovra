import { useState } from 'react'
import { ApiError } from './api'
import type { SessionInfo } from './auth'
import { createSandbox, fetchDiscovery, fetchSandboxAccounts } from './portal'
import type { CreatedSandbox, PortalDiscovery, SandboxAccount } from './portal'
import Field from './components/Field'
import StateCard from './components/StateCard'

// Developer portal (SOV-022). Tenant members read capability
// discovery and onboard fixed-shape sandbox credentials —
// always RP_CLIENT, always expiring in 24 hours, demo
// profiles only. Tokens show once, then metadata only.

export default function DevPortalView({ session }: { session: SessionInfo | null }) {
  const [discovery, setDiscovery] = useState<PortalDiscovery | undefined>(undefined)
  const [accounts, setAccounts] = useState<SandboxAccount[] | undefined>(undefined)
  const [created, setCreated] = useState<CreatedSandbox | undefined>(undefined)
  const [name, setName] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)

  const member = session !== null && session.roles.includes('TENANT_MEMBER')

  async function refresh() {
    setLoading(true)
    setNotice('')
    try {
      const [freshDiscovery, freshAccounts] = await Promise.all([
        fetchDiscovery(),
        fetchSandboxAccounts(),
      ])
      setDiscovery(freshDiscovery)
      setAccounts(freshAccounts)
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setLoading(false)
    }
  }

  async function onboard() {
    setLoading(true)
    setNotice('')
    try {
      const fresh = await createSandbox(name.trim())
      setCreated(fresh)
      setName('')
      setAccounts(await fetchSandboxAccounts())
    } catch (err: unknown) {
      setCreated(undefined)
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setLoading(false)
    }
  }

  if (!member) {
    return (
      <section className="consent" aria-label="Developer portal">
        <h1 className="view-title">Developer portal</h1>
        <StateCard tone="denied" badge="Tenant member session required">
          <p>
            {session === null
              ? 'Log in first — sandbox onboarding is visible to tenant members only.'
              : 'This session lacks the tenant member role, so the portal stays hidden.'}
          </p>
        </StateCard>
      </section>
    )
  }

  return (
    <section className="consent" aria-label="Developer portal">
      <h1 className="view-title">Developer portal</h1>
      <p>
        <button type="button" disabled={loading} onClick={() => void refresh()}>
          {loading ? 'Loading…' : 'Load portal'}
        </button>
      </p>
      {notice !== '' && <p role="alert">{notice}</p>}
      {discovery === undefined && <p>Load the portal to begin.</p>}
      {discovery !== undefined && (
        <article className="consent-card" aria-label="Capability discovery">
          <p className="consent-badge">
            Contract {discovery.contractVersion} · {discovery.profile}
          </p>
          <dl className="health-list">
            <Field label="Service" value={`${discovery.service} ${discovery.version}`} mono />
            <Field label="Auth" value={discovery.auth.join(' · ')} />
            <Field label="Sandbox names" value={discovery.sandbox.namePattern} mono />
            <Field label="Sandbox roles" value={discovery.sandbox.roles.join(', ')} mono />
            <Field label="Sandbox lifetime" value={`${discovery.sandbox.ttlHours} hours`} />
            <Field label="Demo profiles" value={discovery.sandbox.demoProfiles.join(', ')} mono />
            <Field
              label="SDKs"
              value={`java ${discovery.sdks.java} · typescript ${discovery.sdks.typescript}`}
              mono
            />
            <Field label="Outcome reads" value={discovery.rp.outcomes} />
            <Field label="Credential desk" value={discovery.rp.credentials} />
          </dl>
        </article>
      )}
      {created !== undefined && (
        <StateCard tone="review" badge="New sandbox credential — copy the token now">
          <dl className="health-list">
            <Field label="Name" value={created.name} mono />
            <Field label="Token" value={created.token} mono />
            <Field label="Expires" value={created.expiresAt ?? 'never'} mono />
          </dl>
          <p>This token shows once and never reads back.</p>
        </StateCard>
      )}
      {accounts !== undefined && (
        <>
          <h2>Onboard a sandbox app</h2>
          <form
            onSubmit={(event) => {
              event.preventDefault()
              void onboard()
            }}
          >
            <p>
              <label>
                App name{' '}
                <input
                  type="text"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="sandbox-my-app"
                  autoComplete="off"
                />
              </label>
            </p>
            <p>
              <button type="submit" disabled={loading || name.trim() === ''}>
                Create sandbox credential
              </button>
            </p>
          </form>
          <h2>Sandbox credentials</h2>
          {accounts.length === 0 && <p>No sandbox credentials yet.</p>}
          {accounts.map((account) => (
            <article className="consent-card" key={account.id} aria-label="Sandbox credential">
              <p className="consent-badge">
                {account.name} — {account.revoked ? 'revoked' : 'active'}
              </p>
              <dl className="health-list">
                <Field label="Roles" value={account.roles.join(', ')} mono />
                <Field label="Expires" value={account.expiresAt ?? 'never'} mono />
                <Field label="Created" value={account.createdAt} mono />
              </dl>
            </article>
          ))}
        </>
      )}
    </section>
  )
}
