import { useEffect, useState } from 'react'

export type AsyncState<T> =
  | { kind: 'loading' }
  | { kind: 'ready'; value: T }
  | { kind: 'error'; message: string }

/**
 * Runs the task and tracks it; late results after unmount or a new
 * task are dropped. Callers pass stable tasks, so this runs once.
 */
export function useAsync<T>(task: () => Promise<T>): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ kind: 'loading' })
  useEffect(() => {
    let live = true
    task().then(
      (value) => {
        if (live) setState({ kind: 'ready', value })
      },
      (err: unknown) => {
        if (live) {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'unreachable',
          })
        }
      },
    )
    return () => {
      live = false
    }
  }, [task])
  return state
}
