import { useState } from 'react'
import { ApiError } from './api'
import type { SessionInfo } from './auth'
import {
  activateSnapshot,
  approveProposal,
  fetchProposals,
  fetchSnapshot,
  proposeIssuers,
} from './federation'
import type { IssuerOnboarding, ProposalSummary } from './federation'
import type { TrustSnapshot } from './ops'
import Field from './components/Field'
import StateCard from './components/StateCard'

// Federation desk (SOV-026). Trust admins review the proposal
// queue, onboard issuers, and activate snapshots. Every value
// renders as plain text; the desk never sees source or key
// material. Non-admin sessions get a notice, not the queue.

function toneFor(state: ProposalSummary['state']): 'pending' | 'review' | 'verified' {
  if (state === 'PENDING') return 'pending'
  if (state === 'APPROVED') return 'review'
  return 'verified'
}

const EMPTY_ONBOARDING = {
  issuerId: '',
  displayName: '',
  scope: '',
  credentialTypes: '',
  keyId: '',
  publicKeyJwk: '',
  validThrough: '',
}

export default function FederationView({ session }: { session: SessionInfo | null }) {
  const [snapshot, setSnapshot] = useState<TrustSnapshot | null | undefined>(undefined)
  const [proposals, setProposals] = useState<ProposalSummary[] | undefined>(undefined)
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [form, setForm] = useState(EMPTY_ONBOARDING)
  const [formOpen, setFormOpen] = useState(false)

  const admin = session !== null && session.roles.includes('TRUST_ADMIN')

  async function refresh() {
    setNotice('')
    try {
      const [snap, queue] = await Promise.all([fetchSnapshot(), fetchProposals()])
      setSnapshot(snap)
      setProposals(queue)
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    }
  }

  async function onPropose() {
    let jwk: Record<string, unknown>
    try {
      jwk = JSON.parse(form.publicKeyJwk) as Record<string, unknown>
    } catch {
      setNotice('That JWK text is not valid JSON.')
      return
    }
    const onboarding: IssuerOnboarding = {
      issuerId: form.issuerId.trim(),
      displayName: form.displayName.trim(),
      scope: form.scope.trim(),
      credentialTypes: form.credentialTypes.split(',').map((t) => t.trim()).filter((t) => t !== ''),
      keyId: form.keyId.trim(),
      publicKeyJwk: jwk,
      validFrom: new Date().toISOString(),
      validThrough: form.validThrough.trim(),
      status: 'ACTIVE',
    }
    setBusy('propose')
    setNotice('')
    try {
      const result = await proposeIssuers([onboarding], 'federation desk onboarding')
      setForm(EMPTY_ONBOARDING)
      setFormOpen(false)
      setNotice(`Proposed version ${result.version}. A different admin must approve it.`)
      await refresh()
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setBusy('')
    }
  }

  async function onApprove(proposalId: string) {
    setBusy(proposalId)
    setNotice('')
    try {
      await approveProposal(proposalId)
      setNotice('Approved. Activate the version to put it live.')
      await refresh()
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setBusy('')
    }
  }

  async function onActivate(version: number) {
    setBusy(`activate-${version}`)
    setNotice('')
    try {
      await activateSnapshot(version)
      setNotice(`Version ${version} is now live.`)
      await refresh()
    } catch (err: unknown) {
      setNotice(err instanceof ApiError ? err.message : 'unreachable')
    } finally {
      setBusy('')
    }
  }

  if (!admin) {
    return (
      <section className="consent" aria-label="Federation desk">
        <h1 className="view-title">Federation desk</h1>
        <StateCard tone="denied" badge="Trust admin session required">
          <p>
            {session === null
              ? 'Log in first — the review queue is visible to trust admins only.'
              : 'This session lacks the trust admin role, so the queue stays hidden.'}
          </p>
        </StateCard>
      </section>
    )
  }

  return (
    <section className="consent" aria-label="Federation desk">
      <h1 className="view-title">Federation desk</h1>
      <p>
        <button type="button" onClick={() => void refresh()}>
          Load queue
        </button>{' '}
        <button type="button" onClick={() => setFormOpen((open) => !open)} aria-expanded={formOpen}>
          {formOpen ? 'Close onboarding' : 'Onboard issuer'}
        </button>
      </p>
      {notice !== '' && <p role={notice.startsWith('Proposed') || notice.startsWith('Approved') || notice.includes('now live') ? 'status' : 'alert'}>{notice}</p>}
      {formOpen && (
        <article className="consent-card" aria-label="Onboard issuer">
          <p className="consent-badge">New issuer proposal</p>
          <div className="consent-form">
            <label>
              Issuer id
              <input value={form.issuerId} onChange={(e) => setForm({ ...form, issuerId: e.target.value })} />
            </label>
            <label>
              Display name
              <input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
            </label>
            <label>
              Scope
              <input value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} />
            </label>
            <label>
              Credential types, comma separated
              <input value={form.credentialTypes} onChange={(e) => setForm({ ...form, credentialTypes: e.target.value })} />
            </label>
            <label>
              Key id
              <input value={form.keyId} onChange={(e) => setForm({ ...form, keyId: e.target.value })} />
            </label>
            <label>
              Public key JWK, as JSON
              <textarea
                value={form.publicKeyJwk}
                onChange={(e) => setForm({ ...form, publicKeyJwk: e.target.value })}
                rows={4}
              />
            </label>
            <label>
              Valid through, ISO date time
              <input value={form.validThrough} onChange={(e) => setForm({ ...form, validThrough: e.target.value })} placeholder="2030-01-01T00:00:00Z" />
            </label>
          </div>
          <p>
            <button type="button" className="primary" disabled={busy !== ''} onClick={() => void onPropose()}>
              {busy === 'propose' ? 'Proposing…' : 'Propose issuer'}
            </button>
          </p>
        </article>
      )}
      {snapshot === undefined && proposals === undefined && <p>Load the queue to begin.</p>}
      {snapshot !== undefined && (
        <article className="consent-card" aria-label="Active snapshot">
          <p className="consent-badge">
            {snapshot === null ? 'No active snapshot' : `Active snapshot, version ${snapshot.version}`}
          </p>
          {snapshot !== null && (
            <dl className="health-list">
              {snapshot.issuers.map((issuer) => (
                <Field
                  key={issuer.issuerId}
                  label={`${issuer.displayName} (${issuer.scope})`}
                  value={`${issuer.keyId} v${issuer.keyVersion} · ${issuer.status}`}
                  mono
                />
              ))}
            </dl>
          )}
        </article>
      )}
      {proposals !== undefined && (
        <>
          <h2>Review queue</h2>
          {proposals.length === 0 && <p>No proposals yet.</p>}
          {proposals.map((proposal) => (
            <StateCard
              key={proposal.proposalId}
              tone={toneFor(proposal.state)}
              badge={`Version ${proposal.version} — ${proposal.state.toLowerCase()}`}
            >
              <dl className="health-list">
                <Field label="Proposed by" value={proposal.proposedBy} />
                <Field label="Approved by" value={proposal.approvedBy ?? 'not yet'} />
                <Field label="Created" value={proposal.createdAt} mono />
              </dl>
              <p>
                {proposal.state === 'PENDING' && (
                  <button type="button" disabled={busy !== ''} onClick={() => void onApprove(proposal.proposalId)}>
                    {busy === proposal.proposalId ? 'Approving…' : 'Approve'}
                  </button>
                )}{' '}
                {proposal.state === 'APPROVED' && (
                  <button type="button" className="primary" disabled={busy !== ''} onClick={() => void onActivate(proposal.version)}>
                    {busy === `activate-${proposal.version}` ? 'Activating…' : 'Activate'}
                  </button>
                )}
              </p>
            </StateCard>
          ))}
        </>
      )}
    </section>
  )
}
