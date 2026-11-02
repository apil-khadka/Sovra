import { useEffect, useState } from 'react'
import ConsentView from './ConsentView'
import DemoView from './DemoView'
import FederationView from './FederationView'
import IssuerDeskView from './IssuerDeskView'
import HolderDeskView from './HolderDeskView'
import DevPortalView from './DevPortalView'
import RpDashboardView from './RpDashboardView'
import SecOpsView from './SecOpsView'
import VerifyView from './VerifyView'
import OpenIdWalletView from './OpenIdWalletView'
import ReadinessPanel from './components/ReadinessPanel'
import { useAsync } from './hooks/useAsync'
import { fetchSession, login, logout } from './auth'
import { fetchHealth, fetchReadiness } from './ops'

type ViewName = 'status' | 'demo' | 'consent' | 'verify' | 'wallet' | 'federation' | 'secops' | 'issuer' | 'holder' | 'portal' | 'rpdash'

const VIEW_TITLES: Record<ViewName, string> = {
  status: 'Sovra — Status',
  demo: 'Sovra — Public demo',
  consent: 'Sovra — Holder consent',
  verify: 'Sovra — Verify presentation',
  wallet: 'Sovra - OpenID demo wallet',
  federation: 'Sovra — Federation desk',
  secops: 'Sovra — Security operations',
  issuer: 'Sovra — Issuer desk',
  holder: 'Sovra — Holder dashboard',
  portal: 'Sovra — Developer portal',
  rpdash: 'Sovra — Relying-party dashboard',
}

const NAV: Array<{ view: ViewName; label: string }> = [
  { view: 'status', label: 'Status' },
  { view: 'demo', label: 'Demo' },
  { view: 'consent', label: 'Holder consent' },
  { view: 'verify', label: 'Verify presentation' },
  { view: 'wallet', label: 'OpenID demo wallet' },
  { view: 'federation', label: 'Federation desk' },
  { view: 'secops', label: 'Security operations' },
  { view: 'issuer', label: 'Issuer desk' },
  { view: 'holder', label: 'Holder dashboard' },
  { view: 'portal', label: 'Developer portal' },
  { view: 'rpdash', label: 'Relying-party dashboard' },
]

const NAV_GROUPS: Array<{ label: string | null; views: ViewName[] }> = [
  { label: null, views: ['status'] },
  { label: 'Try it', views: ['demo', 'consent', 'verify', 'wallet'] },
  { label: 'Operate', views: ['issuer', 'holder', 'federation', 'secops'] },
  { label: 'Build', views: ['portal', 'rpdash'] },
]

function navLabel(view: ViewName): string {
  return NAV.find((item) => item.view === view)?.label ?? view
}

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
  const [logoutFailed, setLogoutFailed] = useState(false)
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

  // View transitions move focus to the new heading so keyboard
  // and screen-reader users land on the content they chose.
  useEffect(() => {
    const heading = document.querySelector('main h1')
    if (heading instanceof HTMLElement) {
      heading.setAttribute('tabindex', '-1')
      heading.focus({ preventScroll: true })
    }
  }, [view])

  async function onLogout() {
    setLoggingOut(true)
    setLogoutFailed(false)
    try {
      await logout()
    } catch {
      setLoggingOut(false)
      setLogoutFailed(true)
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
      </header>
      <main id="view">
        <div className="app-shell">
          <aside className="app-rail">
            <nav className="app-nav-groups" aria-label="Views">
              {NAV_GROUPS.map((group) => (
                <div key={group.label ?? 'status'}>
                  {group.label !== null && (
                    <p className="nav-group-label" aria-hidden="true">
                      {group.label}
                    </p>
                  )}
                  <div
                    className="app-nav"
                    role="group"
                    aria-label={group.label ?? 'Status'}
                  >
                    {group.views.map((name) => (
                      <a
                        key={name}
                        href={`#/${name}`}
                        aria-current={view === name ? 'page' : undefined}
                      >
                        {navLabel(name)}
                      </a>
                    ))}
                  </div>
                </div>
              ))}
            </nav>
            <div className="auth-bar rail-session">
              {sessionInfo === null ? (
                <button type="button" onClick={login}>
                  Log in with Keycloak
                </button>
              ) : (
                <>
                  <span className="session-id" translate="no">
                    {sessionInfo.displayName}
                  </span>
                  <span className="role-chips">
                    {sessionInfo.roles.map((role) => (
                      <span key={role} className="role-chip" translate="no">
                        {role}
                      </span>
                    ))}
                  </span>
                  <button type="button" onClick={() => void onLogout()} disabled={loggingOut}>
                    {loggingOut ? 'Logging out…' : 'Log out'}
                  </button>
                  {logoutFailed && (
                    <span role="alert" className="auth-error">
                      Logout failed — try again.
                    </span>
                  )}
                </>
              )}
            </div>
          </aside>
          <div className="app-content">
            {authError !== null && (
              <p role="alert">Login denied: {authError}. No session was created.</p>
            )}
        {view === 'status' && (
          <section className="consent" aria-label="Backend status">
            <h1 className="view-title">Status</h1>
            {health.kind === 'loading' && <p role="status">Checking backend…</p>}
            {health.kind === 'ready' && (
              <>
                <div className="status-strip" role="status">
                  <strong>
                    {readiness.kind === 'ready' ? readiness.value.status : health.value.status}
                  </strong>
                  <span translate="no">
                    {health.value.service} {health.value.version}
                  </span>
                </div>
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
        {view === 'issuer' && <IssuerDeskView session={sessionInfo} />}
        {view === 'holder' && <HolderDeskView session={sessionInfo} />}
        {view === 'portal' && <DevPortalView session={sessionInfo} />}
        {view === 'rpdash' && <RpDashboardView session={sessionInfo} />}
          </div>
        </div>
      </main>
    </>
  )
}
