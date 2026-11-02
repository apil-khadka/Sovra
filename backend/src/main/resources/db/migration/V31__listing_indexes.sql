-- PROD-008: composite indexes for tenant-scoped recent feeds.
-- Every query below was captured with EXPLAIN ANALYZE before this
-- migration; the pre-migration plans seq-scanned or sorted (see
-- docs/engineering/query-profiles.md). Each index matches one feed's
-- WHERE equality prefix plus its ORDER BY, so the list pages are
-- index-ordered with no sort and no full-table scan.
--
-- Sort order in the index (DESC) matches the ORDER BY exactly; the
-- id tiebreaker keeps keyset pagination stable when timestamps tie.

-- RP outcome feed: WHERE tenant_id [= decided_by] ORDER BY decided_at DESC, id DESC
CREATE INDEX IF NOT EXISTS verification_decision_tenant_recent_idx
  ON verification_decision (tenant_id, decided_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS verification_decision_tenant_agent_recent_idx
  ON verification_decision (tenant_id, decided_by, decided_at DESC, id DESC);

-- Holder disclosure feed: WHERE tenant_id AND holder_thumbprint
-- ORDER BY created_at DESC, id DESC
CREATE INDEX IF NOT EXISTS proof_request_holder_recent_idx
  ON proof_request (tenant_id, holder_thumbprint, created_at DESC, id DESC);

-- Holder credential feed: WHERE tenant_id AND holder_thumbprint
-- ORDER BY issued_at DESC, id DESC
CREATE INDEX IF NOT EXISTS credential_artifact_holder_recent_idx
  ON credential_artifact (tenant_id, holder_thumbprint, issued_at DESC, id DESC);

-- Quarantine ops feed: WHERE tenant_id [AND status] ORDER BY created_at DESC, id DESC
CREATE INDEX IF NOT EXISTS quarantine_admission_tenant_recent_idx
  ON quarantine_admission (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS quarantine_admission_tenant_status_recent_idx
  ON quarantine_admission (tenant_id, status, created_at DESC, id DESC);

-- Audit feed: WHERE tenant_id ORDER BY occurred_at DESC, id DESC.
-- Supersedes the ASC prefix index for this feed; the old index stays
-- because range scans over (tenant_id, occurred_at) still use it.
CREATE INDEX IF NOT EXISTS audit_event_tenant_recent_idx
  ON audit_event (tenant_id, occurred_at DESC, id DESC);

-- Enrollment queue: WHERE tenant_id [AND state] + keyset on (created_at, id)
-- ORDER BY created_at DESC, id DESC
CREATE INDEX IF NOT EXISTS enrollment_tenant_recent_idx
  ON enrollment (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS enrollment_tenant_state_recent_idx
  ON enrollment (tenant_id, state, created_at DESC, id DESC);
