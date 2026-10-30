import { useEffect, useState } from 'react'
import { ApiError } from './api'
import type { SessionInfo } from './auth'
import {
  approveExtraction,
  correctExtraction,
  createEnrollmentCase,
  decideEnrollment,
  fetchCredential,
  fetchCredentialStatus,
  fetchDeskAudit,
  fetchEnrollmentCase,
  fetchEnrollmentQueue,
  fetchExtractionQueue,
  fetchExtractionRecord,
  fetchReviewView,
  revokeCredential,
  submitEnrollment,
} from './issuer'
import type {
  CredentialDetail,
  CredentialStatus,
  DeskAuditEvent,
  EnrollmentDetail,
  EnrollmentPage,
  EnrollmentSummary,
  RecordDetail,
  RecordPage,
  ReviewViewResult,
} from './issuer'
import Field from './components/Field'
import StateCard from './components/StateCard'

// Issuer information-management desk (SOV-023). Operators review
// extraction and enrollment queues, correct and approve revisions,
// decide cases through maker/checker, check credential status,
// and view originals under purpose-bound grants. Every value
// renders as plain text; originals render only as PNG/JPEG
// images from a server-declared type. Non-operator sessions get
// a notice, not the queues.

type Tab = 'extraction' | 'enrollment' | 'credentials' | 'audit'

function enrollmentTone(state: EnrollmentSummary['state']): 'pending' | 'review' | 'verified' | 'denied' {
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

export default function IssuerDeskView({ session }: { session: SessionInfo | null }) {
  const [tab, setTab] = useState<Tab>('extraction')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')

  const [queueState, setQueueState] = useState('pending')
  const [records, setRecords] = useState<RecordPage | undefined>(undefined)
  const [record, setRecord] = useState<RecordDetail | undefined>(undefined)
  const [correctFields, setCorrectFields] = useState('')
  const [correctOpen, setCorrectOpen] = useState(false)
  const [approveRevision, setApproveRevision] = useState('')

  const [caseState, setCaseState] = useState('all')
  const [cases, setCases] = useState<EnrollmentPage | undefined>(undefined)
  const [caseDetail, setCaseDetail] = useState<EnrollmentDetail | undefined>(undefined)
  const [decideRevision, setDecideRevision] = useState('')
  const [bindingProof, setBindingProof] = useState('')
  const [intakeOpen, setIntakeOpen] = useState(false)
  const [intakeObject, setIntakeObject] = useState('')
  const [intakeRecord, setIntakeRecord] = useState('')
  const [intakeJwk, setIntakeJwk] = useState('')

  const [credentialId, setCredentialId] = useState('')
  const [credential, setCredential] = useState<CredentialDetail | undefined>(undefined)
  const [credentialStatus, setCredentialStatus] = useState<CredentialStatus | undefined>(undefined)
  const [revokeArmed, setRevokeArmed] = useState(false)

  const [events, setEvents] = useState<DeskAuditEvent[] | undefined>(undefined)

  const [review, setReview] = useState<ReviewViewResult | undefined>(undefined)
  const [reviewUrl, setReviewUrl] = useState<string | undefined>(undefined)

  const operator = session !== null && session.roles.includes('ISSUER_OPS')

  useEffect(() => {
    return () => {
      if (reviewUrl !== undefined) URL.revokeObjectURL(reviewUrl)
    }
  }, [reviewUrl])

  function closeReview() {
    if (reviewUrl !== undefined) URL.revokeObjectURL(reviewUrl)
    setReviewUrl(undefined)
    setReview(undefined)
  }

  async function loadExtraction() {
    try {
      setRecords(await fetchExtractionQueue(queueState))
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function openRecord(recordId: string) {
    closeReview()
    try {
      const detail = await fetchExtractionRecord(recordId)
      setRecord(detail)
      const latest = detail.revisions.length === 0 ? '' : String(detail.revisions[detail.revisions.length - 1]?.revNo ?? '')
      setApproveRevision(latest)
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function onCorrect() {
    if (record === undefined) return
    let fields: Record<string, string>
    try {
      fields = JSON.parse(correctFields) as Record<string, string>
    } catch {
      setNotice('Those fields are not valid JSON.')
      return
    }
    setBusy('correct')
    setNotice('')
    try {
      const result = await correctExtraction(record.recordId, fields, 0.9)
      setCorrectFields('')
      setCorrectOpen(false)
      setNotice(`Correction stored as revision ${result.revision}.`)
      await openRecord(record.recordId)
      await loadExtraction()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function onApproveExtraction() {
    if (record === undefined) return
    const revision = Number(approveRevision)
    if (!Number.isInteger(revision) || revision < 1) {
      setNotice('Pick the revision to approve.')
      return
    }
    setBusy('approve-extraction')
    setNotice('')
    try {
      const result = await approveExtraction(record.recordId, revision)
      setNotice(`Revision ${result.approvedRevision} is now the approved head.`)
      await openRecord(record.recordId)
      await loadExtraction()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function onReviewView() {
    if (record === undefined) return
    setBusy('review-view')
    setNotice('')
    closeReview()
    try {
      const result = await fetchReviewView(record.vaultObjectId, record.objectVersion)
      if (result.contentType !== 'image/png' && result.contentType !== 'image/jpeg') {
        setNotice('That original is not a reviewable image.')
        return
      }
      const bytes = Uint8Array.from(atob(result.contentBase64), (c) => c.charCodeAt(0))
      const url = URL.createObjectURL(new Blob([bytes.buffer as ArrayBuffer], { type: result.contentType }))
      setReview(result)
      setReviewUrl(url)
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function loadEnrollments() {
    try {
      setCases(await fetchEnrollmentQueue(caseState))
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function openCase(enrollmentId: string) {
    try {
      const detail = await fetchEnrollmentCase(enrollmentId)
      setCaseDetail(detail)
      setDecideRevision(String(detail.boundRevision))
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  async function onIntake() {
    let jwk: Record<string, unknown>
    try {
      jwk = JSON.parse(intakeJwk) as Record<string, unknown>
    } catch {
      setNotice('That holder key is not valid JSON.')
      return
    }
    setBusy('intake')
    setNotice('')
    try {
      const result = await createEnrollmentCase(
        intakeObject.trim(),
        intakeRecord.trim(),
        jwk,
      )
      setIntakeObject('')
      setIntakeRecord('')
      setIntakeJwk('')
      setIntakeOpen(false)
      setNotice(`Case opened: ${result.enrollmentId}. Submit it for review from the queue.`)
      await loadEnrollments()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function onSubmit() {
    if (caseDetail === undefined) return
    setBusy('submit')
    setNotice('')
    try {
      await submitEnrollment(caseDetail.enrollmentId)
      setNotice('Submitted. A different operator must decide it.')
      await openCase(caseDetail.enrollmentId)
      await loadEnrollments()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function onDecide(decision: 'approve' | 'reject') {
    if (caseDetail === undefined) return
    const revision = Number(decideRevision)
    if (!Number.isInteger(revision) || revision < 1) {
      setNotice('Pick the revision under review.')
      return
    }
    if (decision === 'approve' && bindingProof.trim() === '') {
      setNotice('Approvals need the holder binding proof.')
      return
    }
    setBusy(`decide-${decision}`)
    setNotice('')
    try {
      await decideEnrollment(
        caseDetail.enrollmentId,
        revision,
        decision,
        decision === 'approve' ? bindingProof.trim() : undefined,
      )
      setBindingProof('')
      setNotice(decision === 'approve' ? 'Case approved.' : 'Case rejected.')
      await openCase(caseDetail.enrollmentId)
      await loadEnrollments()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function onLookupCredential() {
    const id = credentialId.trim()
    if (id === '') return
    setNotice('')
    setRevokeArmed(false)
    try {
      const [detail, status] = await Promise.all([fetchCredential(id), fetchCredentialStatus(id)])
      setCredential(detail)
      setCredentialStatus(status)
    } catch (err: unknown) {
      setCredential(undefined)
      setCredentialStatus(undefined)
      setNotice(failMessage(err))
    }
  }

  async function onRevoke() {
    if (credential === undefined) return
    setBusy('revoke')
    setNotice('')
    try {
      await revokeCredential(credential.credentialId)
      setRevokeArmed(false)
      setNotice('Credential revoked. That cannot be undone.')
      await onLookupCredential()
    } catch (err: unknown) {
      setNotice(failMessage(err))
    } finally {
      setBusy('')
    }
  }

  async function loadAudit() {
    setNotice('')
    try {
      setEvents(await fetchDeskAudit(50))
    } catch (err: unknown) {
      setNotice(failMessage(err))
    }
  }

  if (!operator) {
    return (
      <section className="consent" aria-label="Issuer desk">
        <h1 className="view-title">Issuer desk</h1>
        <StateCard tone="denied" badge="Issuer operator session required">
          <p>
            {session === null
              ? 'Log in first — the review queues are visible to issuer operators only.'
              : 'This session lacks the issuer operator role, so the queues stay hidden.'}
          </p>
        </StateCard>
      </section>
    )
  }

  return (
    <section className="consent" aria-label="Issuer desk">
      <h1 className="view-title">Issuer desk</h1>
      <nav className="app-nav" aria-label="Desk areas">
        {(['extraction', 'enrollment', 'credentials', 'audit'] as const).map((area) => (
          <button
            key={area}
            type="button"
            onClick={() => {
              setTab(area)
              setNotice('')
            }}
            aria-current={tab === area ? 'page' : undefined}
          >
            {area === 'extraction'
              ? 'Extraction'
              : area === 'enrollment'
                ? 'Enrollments'
                : area === 'credentials'
                  ? 'Credentials'
                  : 'Audit'}
          </button>
        ))}
      </nav>
      {notice !== '' && <p role="alert">{notice}</p>}
      {tab === 'extraction' && (
        <>
          <p>
            <label>
              Queue{' '}
              <select value={queueState} onChange={(e) => setQueueState(e.target.value)}>
                <option value="pending">Pending approval</option>
                <option value="stale">Stale approvals</option>
                <option value="approved">Approved</option>
                <option value="all">All</option>
              </select>
            </label>{' '}
            <button type="button" onClick={() => void loadExtraction()}>
              Load extraction queue
            </button>
          </p>
          {records === undefined && <p>Load the queue to begin.</p>}
          {records !== undefined && records.items.length === 0 && <p>No records in this queue.</p>}
          {records?.items.map((item) => (
            <StateCard
              key={item.recordId}
              tone={item.approvedRevision === null ? 'pending' : 'verified'}
              badge={`Record ${shortId(item.recordId)} — ${item.approvedRevision === null ? 'pending' : `approved rev ${item.approvedRevision}`}`}
            >
              <dl className="health-list">
                <Field label="Engine" value={`${item.engineId} · ${item.schemaId}`} mono />
                <Field label="Latest revision" value={String(item.latestRevision)} />
                <Field label="Created by" value={item.createdBy} />
              </dl>
              <p>
                <button type="button" onClick={() => void openRecord(item.recordId)}>
                  Open record
                </button>
              </p>
            </StateCard>
          ))}
          {record !== undefined && (
            <article className="consent-card" aria-label="Extraction record">
              <p className="consent-badge">Record {shortId(record.recordId)}</p>
              <dl className="health-list">
                <Field label="Record id" value={record.recordId} mono />
                <Field label="Source digest" value={record.sourceDigestHex} mono />
                <Field label="Profile" value={`${record.normalizerId} · ${record.canonId}`} mono />
                <Field
                  label="Approved revision"
                  value={record.approvedRevision === null ? 'none yet' : String(record.approvedRevision)}
                />
              </dl>
              {record.revisions.map((revision) => (
                <article key={revision.revNo} className="consent-card" aria-label={`Revision ${revision.revNo}`}>
                  <p className="consent-badge">
                    Revision {revision.revNo}
                    {revision.supersedes !== null ? ` · supersedes ${revision.supersedes}` : ''}
                    {' '}· confidence {revision.confidence} · by {revision.createdBy}
                  </p>
                  <h3>Observed fields</h3>
                  <dl className="health-list">
                    {Object.entries(revision.observed).map(([name, value]) => (
                      <Field key={name} label={name} value={value} />
                    ))}
                  </dl>
                  <h3>Normalized fields</h3>
                  <dl className="health-list">
                    {Object.entries(revision.normalized).map(([name, value]) => (
                      <Field key={name} label={name} value={value} />
                    ))}
                  </dl>
                </article>
              ))}
              <p>
                <label>
                  Approve revision{' '}
                  <input
                    value={approveRevision}
                    onChange={(e) => setApproveRevision(e.target.value)}
                    inputMode="numeric"
                  />
                </label>{' '}
                <button
                  type="button"
                  className="primary"
                  disabled={busy !== ''}
                  onClick={() => void onApproveExtraction()}
                >
                  {busy === 'approve-extraction' ? 'Approving…' : 'Approve revision'}
                </button>
              </p>
              <p>
                <button type="button" onClick={() => setCorrectOpen((open) => !open)} aria-expanded={correctOpen}>
                  {correctOpen ? 'Close correction' : 'Correct fields'}
                </button>{' '}
                <button type="button" disabled={busy !== ''} onClick={() => void onReviewView()}>
                  {busy === 'review-view' ? 'Loading original…' : 'View original'}
                </button>
              </p>
              {correctOpen && (
                <article className="consent-card" aria-label="Correct fields">
                  <p className="consent-badge">New correction revision</p>
                  <label>
                    Fields, as JSON
                    <textarea
                      value={correctFields}
                      onChange={(e) => setCorrectFields(e.target.value)}
                      rows={4}
                      placeholder='{"name": "Ana Fixed"}'
                    />
                  </label>
                  <p>
                    <button
                      type="button"
                      className="primary"
                      disabled={busy !== ''}
                      onClick={() => void onCorrect()}
                    >
                      {busy === 'correct' ? 'Storing…' : 'Store correction'}
                    </button>
                  </p>
                </article>
              )}
              {review !== undefined && reviewUrl !== undefined && (
                <article className="consent-card" aria-label="Original under review">
                  <p className="consent-badge">
                    Original · {review.contentType} · sha {review.sha256Hex.slice(0, 16)}…
                  </p>
                  <p>
                    <img src={reviewUrl} alt="Source original under review" style={{ maxWidth: '100%' }} />
                  </p>
                  <p>
                    <button type="button" onClick={closeReview}>
                      Close original
                    </button>
                  </p>
                </article>
              )}
            </article>
          )}
        </>
      )}
      {tab === 'enrollment' && (
        <>
          <p>
            <label>
              Queue{' '}
              <select value={caseState} onChange={(e) => setCaseState(e.target.value)}>
                <option value="all">All</option>
                <option value="pending">Pending</option>
                <option value="in_review">In review</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
              </select>
            </label>{' '}
            <button type="button" onClick={() => void loadEnrollments()}>
              Load enrollment queue
            </button>{' '}
            <button type="button" onClick={() => setIntakeOpen((open) => !open)} aria-expanded={intakeOpen}>
              {intakeOpen ? 'Close intake' : 'New case'}
            </button>
          </p>
          {intakeOpen && (
            <article className="consent-card" aria-label="Open enrollment case">
              <p className="consent-badge">New case from an approved extraction</p>
              <label>
                Vault object id
                <input
                  value={intakeObject}
                  onChange={(e) => setIntakeObject(e.target.value)}
                  placeholder="source object UUID"
                />
              </label>
              <label>
                Extraction record id
                <input
                  value={intakeRecord}
                  onChange={(e) => setIntakeRecord(e.target.value)}
                  placeholder="approved record UUID"
                />
              </label>
              <label>
                Holder key, public JWK as JSON
                <textarea
                  value={intakeJwk}
                  onChange={(e) => setIntakeJwk(e.target.value)}
                  rows={3}
                  placeholder='{"kty":"EC","crv":"P-256","x":"…","y":"…"}'
                />
              </label>
              <p>
                <button
                  type="button"
                  className="primary"
                  disabled={busy !== ''}
                  onClick={() => void onIntake()}
                >
                  {busy === 'intake' ? 'Opening…' : 'Open case'}
                </button>
              </p>
            </article>
          )}
          {cases === undefined && <p>Load the queue to begin.</p>}
          {cases !== undefined && cases.items.length === 0 && <p>No cases in this queue.</p>}
          {cases?.items.map((item) => (
            <StateCard
              key={item.enrollmentId}
              tone={enrollmentTone(item.state)}
              badge={`Case ${shortId(item.enrollmentId)} — ${item.state.toLowerCase().replace('_', ' ')}`}
            >
              <dl className="health-list">
                <Field label="Created by" value={item.createdBy} />
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
                <Field label="Created by" value={caseDetail.createdBy} />
                <Field label="Decided by" value={caseDetail.decidedBy ?? 'not yet'} />
                <Field
                  label="Eligibility"
                  value={caseDetail.eligible ? 'eligible' : caseDetail.eligibilityReason}
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
              {caseDetail.state === 'PENDING' && (
                <p>
                  <button
                    type="button"
                    className="primary"
                    disabled={busy !== ''}
                    onClick={() => void onSubmit()}
                  >
                    {busy === 'submit' ? 'Submitting…' : 'Submit for review'}
                  </button>
                </p>
              )}
              {caseDetail.state === 'IN_REVIEW' && (
                <>
                  <p>
                    <label>
                      Revision under review{' '}
                      <input
                        value={decideRevision}
                        onChange={(e) => setDecideRevision(e.target.value)}
                        inputMode="numeric"
                      />
                    </label>
                  </p>
                  <p>
                    <label>
                      Holder binding proof, for approvals
                      <textarea
                        value={bindingProof}
                        onChange={(e) => setBindingProof(e.target.value)}
                        rows={3}
                        placeholder="Paste the holder-signed enrollment-binding proof"
                      />
                    </label>
                  </p>
                  <p>
                    <button
                      type="button"
                      className="primary"
                      disabled={busy !== ''}
                      onClick={() => void onDecide('approve')}
                    >
                      {busy === 'decide-approve' ? 'Approving…' : 'Approve case'}
                    </button>{' '}
                    <button
                      type="button"
                      disabled={busy !== ''}
                      onClick={() => void onDecide('reject')}
                    >
                      {busy === 'decide-reject' ? 'Rejecting…' : 'Reject'}
                    </button>
                  </p>
                </>
              )}
            </article>
          )}
        </>
      )}
      {tab === 'credentials' && (
        <>
          <p>
            <label>
              Credential id{' '}
              <input
                value={credentialId}
                onChange={(e) => setCredentialId(e.target.value)}
                placeholder="credential UUID"
              />
            </label>{' '}
            <button type="button" onClick={() => void onLookupCredential()}>
              Look up
            </button>
          </p>
          {credential !== undefined && credentialStatus !== undefined && (
            <article className="consent-card" aria-label="Credential">
              <p className="consent-badge">Credential {shortId(credential.credentialId)}</p>
              <dl className="health-list">
                <Field label="Issuer" value={credential.issuerId} mono />
                <Field label="Type" value={credential.vct} mono />
                <Field label="Status" value={credentialStatus.status} />
                <Field label="Expires" value={credential.expiresAt} mono />
              </dl>
              <p>
                {revokeArmed ? (
                  <>
                    <button
                      type="button"
                      disabled={busy !== ''}
                      onClick={() => void onRevoke()}
                    >
                      {busy === 'revoke' ? 'Revoking…' : 'Confirm revoke'}
                    </button>{' '}
                    <button type="button" onClick={() => setRevokeArmed(false)}>
                      Keep credential
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    disabled={credentialStatus.status !== 'VALID'}
                    onClick={() => setRevokeArmed(true)}
                  >
                    Revoke…
                  </button>
                )}
              </p>
            </article>
          )}
        </>
      )}
      {tab === 'audit' && (
        <>
          <p>
            <button type="button" onClick={() => void loadAudit()}>
              Load audit tail
            </button>
          </p>
          {events === undefined && <p>Load the tail to begin.</p>}
          {events !== undefined && events.length === 0 && <p>No casework yet.</p>}
          {events?.map((event) => (
            <StateCard
              key={event.id}
              tone={event.decision === 'ALLOW' ? 'verified' : 'denied'}
              badge={`${event.action.toLowerCase().replace(/_/g, ' ')} — ${event.decision.toLowerCase()}`}
            >
              <dl className="health-list">
                <Field label="Actor" value={`${event.actorType} ${event.actorId}`} mono />
                <Field label="Resource" value={`${event.resourceType} ${shortId(event.resourceId)}`} mono />
                <Field label="At" value={event.occurredAt} mono />
              </dl>
            </StateCard>
          ))}
        </>
      )}
    </section>
  )
}
