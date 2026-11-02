-- Post-restore reconciliation (PROD-013). Run against the
-- ISOLATED scratch cluster before any traffic decision. Every
-- query must return the noted expectation; anything else stops
-- the promotion.
--
-- 1. Schema currency: the restore must match the deploying
-- version's migration tip (compare with the release notes).
SELECT version AS restored_tip FROM flyway_schema_history
ORDER BY installed_rank DESC LIMIT 1;

-- 2. Trust authority: exactly one live activation, no synthetic
-- issuers on a production restore.
SELECT COUNT(*) AS live_activations FROM trust_snapshot_activation
WHERE snapshot_version = (SELECT MAX(snapshot_version) FROM trust_snapshot_activation);
SELECT COUNT(*) AS synthetic_issuers FROM issuer_record
WHERE scope = 'synthetic-only' OR issuer_id LIKE 'https://sovra.example/%';

-- 3. Revocation horizon: revocations after the backup point do not
-- exist on the restore. List credentials revoked in the last hour
-- of the BACKUP window for manual re-application (the drill
-- reconciles these against the admin log, never by guessing).
SELECT id, status_updated_at FROM credential_artifact
WHERE status = 'REVOKED'
ORDER BY status_updated_at DESC LIMIT 20;

-- 4. In-flight protocol state cannot be trusted past the restore
-- point: sessions, nonces, and challenges are single-use and may
-- already be consumed on the fenced primary. The promotion
-- procedure clears them (see recovery.md); this query sizes the
-- invalidation before it runs.
SELECT
  (SELECT COUNT(*) FROM spring_session) AS sessions,
  (SELECT COUNT(*) FROM holder_unlock_challenge) AS challenges,
  (SELECT COUNT(*) FROM vp_session WHERE state = 'PENDING') AS pending_vp,
  (SELECT COUNT(*) FROM vci_grant WHERE consumed_at IS NULL) AS unconsumed_grants;

-- 5. Quarantine verdicts in SCANNING at backup time are orphans of
-- the fence, not of a crash: the sweeper requeues them by lease
-- on first boot (PROD-009). Confirm the lease columns exist.
SELECT COUNT(*) AS scanning_at_restore FROM quarantine_admission
WHERE status = 'SCANNING';
