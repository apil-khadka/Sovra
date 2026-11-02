import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'

export type Tone = 'pending' | 'review' | 'denied' | 'unavailable' | 'verified'

/**
 * State card: a tone plus a badge line, then the view's content.
 * focusOnMount moves keyboard/screen-reader focus here when a
 * stage transition swaps the card in (Consent/Verify decisions).
 */
export default function StateCard({
  tone,
  badge,
  children,
  focusOnMount = false,
}: {
  tone: Tone
  badge: string
  children?: ReactNode
  focusOnMount?: boolean
}) {
  const ref = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (focusOnMount) ref.current?.focus()
  }, [focusOnMount])

  return (
    <article
      ref={ref}
      className={`consent-card state-${tone}`}
      tabIndex={focusOnMount ? -1 : undefined}
    >
      <p className="consent-badge">{badge}</p>
      {children}
    </article>
  )
}
