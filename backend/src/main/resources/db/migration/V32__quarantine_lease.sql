-- PROD-009: bounded parallel quarantine workers.
--
-- The claim used to be single-threaded with no lease: a worker that
-- crashed between claim and verdict left its row SCANNING forever,
-- and parallel claimants blocked on each other's row locks. The
-- claim now records who holds a row and when, so a sweeper can
-- requeue leases that outlive their worker, and claimants skip rows
-- locked by a peer instead of blocking (advisory xact lock in the
-- claim subselect; SELECT FOR UPDATE stays unavailable because the
-- worker role deliberately has no table-level UPDATE grant).
--
-- claimed_at NULL means never claimed (or requeued); a SCANNING row
-- whose claimed_at is older than the sweep lease is presumed
-- orphaned and returns to QUARANTINED.

ALTER TABLE quarantine_admission
  ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS claimed_by TEXT NOT NULL DEFAULT '';

-- In-flight rows at migration time get a fresh lease instead of an
-- instant requeue on the first sweep.
UPDATE quarantine_admission
  SET claimed_at = now()
  WHERE status = 'SCANNING' AND claimed_at IS NULL;

-- The worker writes its own lease; the app role never touches these
-- columns (it admits rows, it does not scan them).
GRANT UPDATE (claimed_at, claimed_by) ON quarantine_admission TO sovra_quarantine;

-- Requeue widens WITH CHECK by exactly one transition:
-- SCANNING -> QUARANTINED. USING still confines the worker to
-- unscanned rows, so CLEAN / REJECTED / PROMOTED rows stay
-- untouchable (see QuarantineWorkerContainmentTests).
DROP POLICY IF EXISTS quarantine_worker_verdict ON quarantine_admission;
CREATE POLICY quarantine_worker_verdict ON quarantine_admission
  FOR UPDATE TO sovra_quarantine
  USING (status IN ('QUARANTINED', 'SCANNING'))
  WITH CHECK (status IN ('QUARANTINED', 'SCANNING', 'CLEAN', 'REJECTED'));

-- Claim order: oldest QUARANTINED row first.
CREATE INDEX IF NOT EXISTS quarantine_claim_idx
  ON quarantine_admission (created_at, id)
  WHERE status = 'QUARANTINED';

-- Sweep: SCANNING rows older than the lease.
CREATE INDEX IF NOT EXISTS quarantine_sweep_idx
  ON quarantine_admission (claimed_at)
  WHERE status = 'SCANNING';
