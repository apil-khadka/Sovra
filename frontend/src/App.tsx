import { useEffect, useState } from 'react'

interface Health {
  status: string
  service: string
  version: string
}

type State =
  | { kind: 'loading' }
  | { kind: 'ready'; health: Health }
  | { kind: 'error'; message: string }

export default function App() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/health', { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error(`backend responded ${res.status}`)
        const body = (await res.json()) as Health
        if (body.status !== 'UP') throw new Error('backend is not UP')
        setState({ kind: 'ready', health: body })
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === 'AbortError') return
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'unreachable',
        })
      })
    return () => controller.abort()
  }, [])

  return (
    <main>
      <h1>Sovra</h1>
      {state.kind === 'loading' && <p>Checking backend…</p>}
      {state.kind === 'ready' && (
        <dl>
          <dt>Status</dt>
          <dd>{state.health.status}</dd>
          <dt>Service</dt>
          <dd>{state.health.service}</dd>
          <dt>Version</dt>
          <dd>{state.health.version}</dd>
        </dl>
      )}
      {state.kind === 'error' && (
        <p role="alert">Backend unreachable: {state.message}</p>
      )}
    </main>
  )
}
