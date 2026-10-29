import type { ReactNode } from 'react'

export type Tone = 'pending' | 'review' | 'denied' | 'unavailable' | 'verified'

/** State card: a tone plus a badge line, then the view's content. */
export default function StateCard({
  tone,
  badge,
  children,
}: {
  tone: Tone
  badge: string
  children?: ReactNode
}) {
  return (
    <article className={`consent-card state-${tone}`}>
      <p className="consent-badge">{badge}</p>
      {children}
    </article>
  )
}
