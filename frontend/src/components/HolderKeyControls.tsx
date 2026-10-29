import type { ReactNode } from 'react'
import type { HolderKey } from '../crypto'

/**
 * Holder-key row: generate, the current thumbprint, view-specific
 * actions (copy/import), and a live status line. The status uses a
 * polite live region so key events announce without moving focus.
 */
export default function HolderKeyControls({
  holder,
  status,
  onGenerate,
  children,
}: {
  holder: HolderKey | null
  status: string
  onGenerate: () => void
  children?: ReactNode
}) {
  return (
    <div className="consent-keyrow">
      <button type="button" onClick={onGenerate}>
        Generate holder key
      </button>
      {holder !== null && (
        <code className="mono wrap" translate="no">
          holder: {holder.thumbprint}
        </code>
      )}
      {children}
      {status !== '' && (
        <p aria-live="polite" className="key-status">
          {status}
        </p>
      )}
    </div>
  )
}
