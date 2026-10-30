import { useEffect, useState } from 'react'
import ConsentView from './ConsentView'
import DemoView from './DemoView'
import FederationView from './FederationView'
import SecOpsView from './SecOpsView'
import VerifyView from './VerifyView'
import OpenIdWalletView from './OpenIdWalletView'
import ReadinessPanel from './components/ReadinessPanel'
import Field from './components/Field'
import { useAsync } from './hooks/useAsync'
import { fetchSession, login, logout } from './auth'
import { fetchHealth, fetchReadiness } from './ops'

type ViewName = 'status' | 'demo' | 'consent' | 'verify' | 'wallet' | 'federation' | 'secops'

const VIEW_TITLES: Record<ViewName, string> = {
  status: 'Sovra — Status',
  demo: 'Sovra — Public demo',
  consent: 'Sovra — Holder consent',
  verify: 'Sovra — Verify presentation',
  wallet: 'Sovra - OpenID demo wallet',
  federation: 'Sovra — Federation desk',
  secops: 'Sovra — Security operations',
}

const NAV: Array<{ view: ViewName; label: string }> = [
  { view: 'status', label: 'Status' },
  { view: 'demo', label: 'Demo' },
  { view: 'consent', label: 'Holder consent' },
  { view: 'verify', label: 'Verify presentation' },
  { view: 'wallet', label: 'OpenID demo wallet' },
  { view: 'federation', label: 'Federation desk' },
  { view: 'secops', label: 'Security operations' },
]

function viewFromHash(): ViewName {
  const match = window.location.hash.match(/^#\/(\w+)/)
  const found = NAV.find((item) => item.view === match?.[1])
  return found === undefined ? 'status' : found.view
}

/** Reads ?auth_error= once and scrubs it from the URL. */
function consumeAuthError(): string | null {
  const params = new URLSearchParams(window.location.search)
  const denied = params.get('auth_error')
  if (denied === null) return null
  params.delete('auth_error')
  const rest = params.toString()
  window.history.replaceState(null, '', window.location.pathname + (rest === '' ? '' : `?${rest}`))
  return denied
}

export default function App() {
  const [view, setView] = useState<ViewName>(viewFromHash)
  const [authError] = useState<string | null>(consumeAuthError)
  const [loggingOut, setLoggingOut] = useState(false)
  const health = useAsync(fetchHealth)
  const readiness = useAsync(fetchReadiness)
  const session = useAsync(fetchSession)

  useEffect(() => {
    document.title = VIEW_TITLES[view]
  }, [view])

  useEffect(() => {
    const onHashChange = () => setView(viewFromHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  async function onLogout() {
    setLoggingOut(true)
    try {
      await logout()
    } catch {
      setLoggingOut(false)
    }
  }

  const sessionInfo = session.kind === 'ready' ? session.value : null

  return (
    <>
      <a className="skip-link" href="#view">
        Skip to content
      </a>
      <header className="app-header">
        <p className="wordmark" translate="no">
          Sovra
        </p>
        <div className="auth-bar">
          {sessionInfo === null ? (
            <button type="button" onClick={login}>
              Log in with Keycloak
            </button>
          ) : (
            <>
              <span className="session-id" translate="no">
                {sessionInfo.displayName} · {sessionInfo.roles.join(', ')}
              </span>
              <button type="button" onClick={() => void onLogout()} disabled={loggingOut}>
                {loggingOut ? 'Logging out…' : 'Log out'}
              </button>
            </>
          )}
        </div>
      </header>
      <main id="view">
        {authError !== null && (
          <p role="alert">Login denied: {authError}. No session was created.</p>
        )}
        <nav className="app-nav" aria-label="Views">
          {NAV.map((item) => (
            <a
              key={item.view}
              href={`#/${item.view}`}
              aria-current={view === item.view ? 'page' : undefined}
            >
              {item.label}
            </a>
          ))}
        </nav>
        {view === 'status' && (
          <section className="consent" aria-label="Backend status">
            <h1 className="view-title">Status</h1>
            {health.kind === 'loading' && <p>Checking backend…</p>}
            {health.kind === 'ready' && (
              <>
                <dl className="health-list">
                  <Field label="Status" value={health.value.status} />
                  <Field label="Service" value={health.value.service} />
                  <Field label="Version" value={health.value.version} mono />
                </dl>
                {readiness.kind === 'ready' && <ReadinessPanel report={readiness.value} />}
                {readiness.kind === 'error' && (
                  <p role="alert">Readiness unreachable: {readiness.message}</p>
                )}
              </>
            )}
            {health.kind === 'error' && <p role="alert">Backend unreachable: {health.message}</p>}
          </section>
        )}
        {view === 'demo' && <DemoView />}
        {view === 'consent' && <ConsentView session={sessionInfo} />}
        {view === 'verify' && <VerifyView session={sessionInfo} />}
        {view === 'wallet' && <OpenIdWalletView session={sessionInfo} />}
        {view === 'federation' && <FederationView session={sessionInfo} />}
        {view === 'secops' && <SecOpsView session={sessionInfo} />}
      </main>
    </>
  )
}
