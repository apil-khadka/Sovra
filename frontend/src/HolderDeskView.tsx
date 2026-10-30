import { useState } from 'react'
import { ApiError } from './api'
import type { SessionInfo } from './auth'
import { importHolder, signMessage } from './crypto'
import type { HolderKey } from './crypto'
import {
  fetchHolderCase,
  fetchHolderCases,
  fetchHolderChallenge,
  fetchHolderConsents,
  fetchHolderCredentials,
  fetchHolderRecovery,
  lockHolder,
  unlockHolder,
} from './holder'
import type {
  CaseDetail,
  Disclosure,
  HolderCase,
  HolderCredential,
  HolderUnlock,
  RecoveryStatus,
} from './holder'
import Field from './components/Field'
import StateCard from './components/StateCard'

// Holder dashboard (SOV-024). Members unlock with a holder-key
// proof, then read exactly that key's enrollment cases with
// corrections, disclosure history with verification outcomes,
// credentials, and recovery state. The private key lives in
// React memory only — locking, or leaving the view, drops it —
// the same posture as the demo wallet. Every value renders as
// plain text; other holders' rows are unreachable by design.

type Tab = 'cases' | 'consents' | 'credentials' | 'recovery'

function caseTone(state: HolderCase['state']): 'pending' | 'review' | 'verified' | 'denied' {
  if (state === 'PENDING') return 'pending'
  if (state === 'IN_REVIEW') return 'review'
  if (state === 'APPROVED') return 'verified'
  return 'denied'
}

function shortId(id: string): string {
  return id.length > 13 ? `${id.slice(0, 8)}…` : id
}

function failMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : 'unreachable'
}

export default function HolderDeskView({ session }: { session: SessionInfo | null }) {
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [tab, setTab] = useState<Tab>('cases')

  const [privateJwk, setPrivateJwk] = useState('')
  const [holder, setHolder] = useState<HolderKey | undefined>(undefined)
  const [unlocked, setUnlocked] = useState<HolderUnlock | undefined>(undefined)

  const [cases, setCases] = useState<HolderCase[] | undefined>(undefined)
  const [caseDetail, setCaseDetail] = useState<CaseDetail | undefined>(undefined)
  const [consents, setConsents] = useState<Disclosure[] | undefined>(undefined)
  const [credentials, setCredentials] = useState<HolderCredential[] | undefined>(undefined)
  const [recovery, setRecovery] = useState<RecoveryStatus | undefined>(undefined)

  const member = session !== null && session.roles.includes('TENANT_MEMBER')

  async function onUnlock() {
    let parsed: Record<string, unknown>
    try {
      parsed = JSON.parse(privateJwk) as Record<string, unknown>
    } catch {
      setNotice('That key is not valid JSON.')
      return
    }
    setBusy('unlock')
    setNotice('')
    try {
      const key = await importHolder(parsed as JsonWebKey)
      const asked = await fetchHolderChallenge()
      const proof = await signMessage(
        key,
        `holder-unlock/v1\n${asked.challenge}\n${key.thumbprint}`,
      )
      const bound = await unlockHolder(
        { kty: 'EC', crv: 'P-256', x: key.jwk.x, y: key.jwk.y },
        proof,
      )
      setHolder(key)
      setUnlocked(bound)
      setPrivateJwk('')
      setNotice(`Unlocked key ${bound.thumbprint.slice(0, 12)}… for fifteen minutes.`)
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function onLock() {
    setNotice('')
    try {
      await lockHolder()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setHolder(undefined)
      setUnlocked(undefined)
      setCases(undefined)
      setCaseDetail(undefined)
      setConsents(undefined)
      setCredentials(undefined)
      setRecovery(undefined)
    }
  }

  async function loadCases() {
    setNotice('')
    try {
      setCases(await fetchHolderCases())
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function openCase(enrollmentId: string) {
    setNotice('')
    try {
      setCaseDetail(await fetchHolderCase(enrollmentId))
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function loadConsents() {
    setNotice('')
    try {
      setConsents(await fetchHolderConsents())
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function loadCredentials() {
    setNotice('')
    try {
      setCredentials(await fetchHolderCredentials())
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function loadRecovery() {
    setNotice('')
    try {
      setRecovery(await fetchHolderRecovery())
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  if (!member) {
    return (
      <section className="consent" aria-label="Holder dashboard">
        <h1 className="view-title">Holder dashboard</h1>
        <StateCard tone="denied" badge="Member session required">
          <p>
            {session === null
              ? 'Log in first — your history unlocks with your holder key.'
              : 'This session lacks the member role, so holder history stays hidden.'}
          </p>
        </StateCard>
      </section>
    )
  }

  if (unlocked === undefined) {
    return (
      <section className="consent" aria-label="Holder dashboard">
        <h1 className="view-title">Holder dashboard</h1>
        <article className="consent-card" aria-label="Unlock holder history">
          <p className="consent-badge">Unlock with your holder key</p>
          <p>
            Paste the private half of your holder key. It signs one unlock proof, stays in this
            page's memory only, and locking drops it.
          </p>
          <label>
            Holder private key, JWK as JSON
            <textarea
              value={privateJwk}
              onChange={(e) => setPrivateJwk(e.target.value)}
              rows={3}
              placeholder='{"kty":"EC","crv":"P-256","x":"…","y":"…","d":"…"}'
            />
          </label>
          <p>
            <button
              type="button"
              className="primary"
              disabled={busy !== ''}
              onClick={() => void onUnlock()}
            >
              {busy === 'unlock' ? 'Unlocking…' : 'Unlock my history'}
            </button>
          </p>
          {notice !== '' && <p role="alert">{notice}</p>}
          {holder !== undefined && <p>Signed as key {holder.thumbprint.slice(0, 12)}…</p>}
        </article>
      </section>
    )
  }

  return (
    <section className="consent" aria-label="Holder dashboard">
      <h1 className="view-title">Holder dashboard</h1>
      <p>
        Unlocked key {unlocked.thumbprint.slice(0, 12)}… until{' '}
        {new Date(unlocked.expiresAt).toLocaleTimeString()}{' '}
        <button type="button" onClick={() => void onLock()}>
          Lock
        </button>
      </p>
      <nav className="app-nav" aria-label="History areas">
        {(['cases', 'consents', 'credentials', 'recovery'] as const).map((area) => (
          <button
            key={area}
            type="button"
            onClick={() => {
              setTab(area)
              setNotice('')
            }}
            aria-current={tab === area ? 'page' : undefined}
          >
            {area === 'cases'
              ? 'My cases'
              : area === 'consents'
                ? 'Disclosures'
                : area === 'credentials'
                  ? 'Credentials'
                  : 'Recovery'}
          </button>
        ))}
      </nav>
      {notice !== '' && <p role="alert">{notice}</p>}
      {tab === 'cases' && (
        <>
          <p>
            <button type="button" onClick={() => void loadCases()}>
              Load my cases
            </button>
          </p>
          {cases === undefined && <p>Load your cases to begin.</p>}
          {cases !== undefined && cases.length === 0 && <p>No cases for this key.</p>}
          {cases?.map((item) => (
            <StateCard
              key={item.enrollmentId}
              tone={caseTone(item.state)}
              badge={`Case ${shortId(item.enrollmentId)} — ${item.state.toLowerCase().replace('_', ' ')}`}
            >
              <dl className="health-list">
                <Field
                  label="Eligibility"
                  value={item.eligible ? 'eligible' : item.eligibilityReason.toLowerCase()}
                />
              </dl>
              <p>
                <button type="button" onClick={() => void openCase(item.enrollmentId)}>
                  Open case
                </button>
              </p>
            </StateCard>
          ))}
          {caseDetail !== undefined && (
            <article className="consent-card" aria-label="Enrollment case">
              <p className="consent-badge">Case {shortId(caseDetail.enrollmentId)}</p>
              <dl className="health-list">
                <Field label="Case id" value={caseDetail.enrollmentId} mono />
                <Field label="State" value={caseDetail.state} />
                <Field label="Bound revision" value={String(caseDetail.boundRevision)} />
                <Field
                  label="Eligibility"
                  value={caseDetail.eligible ? 'eligible' : caseDetail.eligibilityReason}
                />
                <Field
                  label="Approved revision"
                  value={
                    caseDetail.approvedRevision === null
                      ? 'none yet'
                      : String(caseDetail.approvedRevision)
                  }
                />
              </dl>
              {caseDetail.reviews.length > 0 && (
                <>
                  <h3>Reviews</h3>
                  <dl className="health-list">
                    {caseDetail.reviews.map((review, index) => (
                      <Field
                        key={`${review.revision}-${index}`}
                        label={`Rev ${review.revision} · ${review.reviewer}`}
                        value={`${review.decision.toLowerCase()} · proof ${review.bindingProofOk ? 'verified' : 'not shown'}`}
                      />
                    ))}
                  </dl>
                </>
              )}
              <h3>Corrections</h3>
              {caseDetail.revisions.map((revision) => (
                <article key={revision.revNo} className="consent-card" aria-label={`Revision ${revision.revNo}`}>
                  <p className="consent-badge">
                    Revision {revision.revNo} · confidence {revision.confidence} · by{' '}
                    {revision.createdBy}
                  </p>
                  <dl className="health-list">
                    {Object.entries(revision.normalized).map(([name, value]) => (
                      <Field key={name} label={name} value={value} />
                    ))}
                  </dl>
                </article>
              ))}
            </article>
          )}
        </>
      )}
      {tab === 'consents' && (
        <>
          <p>
            <button type="button" onClick={() => void loadConsents()}>
              Load disclosures
            </button>
          </p>
          {consents === undefined && <p>Load your disclosure history to begin.</p>}
          {consents !== undefined && consents.length === 0 && <p>No disclosures for this key.</p>}
          {consents?.map((item) => (
            <StateCard
              key={item.requestId}
              tone={
                item.state === 'APPROVED' || item.state === 'VERIFIED'
                  ? 'verified'
                  : item.state === 'DENIED'
                    ? 'denied'
                    : item.state === 'PENDING'
                      ? 'pending'
                      : 'review'
              }
              badge={`${item.state.toLowerCase()} — ${shortId(item.requestId)}`}
            >
              <dl className="health-list">
                <Field label="Relying party" value={item.rpId} mono />
                <Field label="Purpose" value={item.purpose} />
                <Field label="Claims" value={JSON.stringify(item.claims)} mono />
                <Field label="Expires" value={item.expiresAt} mono />
                <Field label="Verification" value={item.verificationOutcome ?? 'not presented'} />
              </dl>
            </StateCard>
          ))}
        </>
      )}
      {tab === 'credentials' && (
        <>
          <p>
            <button type="button" onClick={() => void loadCredentials()}>
              Load credentials
            </button>
          </p>
          {credentials === undefined && <p>Load your credentials to begin.</p>}
          {credentials !== undefined && credentials.length === 0 && <p>No credentials for this key.</p>}
          {credentials?.map((item) => (
            <StateCard
              key={item.credentialId}
              tone={item.status === 'VALID' ? 'verified' : 'denied'}
              badge={`Credential ${shortId(item.credentialId)} — ${item.status.toLowerCase()}`}
            >
              <dl className="health-list">
                <Field label="Issuer" value={item.issuerId} mono />
                <Field label="Type" value={item.vct} mono />
                <Field label="Expires" value={item.expiresAt} mono />
              </dl>
            </StateCard>
          ))}
        </>
      )}
      {tab === 'recovery' && (
        <>
          <p>
            <button type="button" onClick={() => void loadRecovery()}>
              Load recovery state
            </button>
          </p>
          {recovery === undefined && <p>Load your recovery state to begin.</p>}
          {recovery !== undefined && (
            <StateCard
              tone={recovery.status === 'ACTIVE' ? 'verified' : 'denied'}
              badge={`Key ${recovery.thumbprint.slice(0, 12)}… — ${recovery.status.toLowerCase()}`}
            >
              <dl className="health-list">
                <Field label="Registered key" value={recovery.keyId ?? 'not registered'} mono />
              </dl>
              {recovery.recoveries.length === 0 && <p>No loss reports for this key.</p>}
              {recovery.recoveries.length > 0 && (
                <dl className="health-list">
                  {recovery.recoveries.map((attempt) => (
                    <Field
                      key={attempt.recoveryId}
                      label={`${attempt.reason} · ${shortId(attempt.recoveryId)}`}
                      value={`${attempt.state.toLowerCase()}${attempt.newThumbprint === null ? '' : ` · new key ${attempt.newThumbprint.slice(0, 12)}…`}`}
                    />
                  ))}
                </dl>
              )}
            </StateCard>
          )}
        </>
      )}
    </section>
  )
}
