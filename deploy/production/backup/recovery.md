# Backup and recovery (PROD-013)

## Mechanism

- Nightly compressed base per cluster (`backup` service,
  `backup-base.sh`) plus continuous WAL archiving
  (`archive_command` on both primaries, 8-day retention).
  RPO: seconds (WAL granularity). RTO: base extract + WAL
  replay + reconcile, measured per drill (see evidence below).
- The `sovra_backup` role streams backups only (REPLICATION +
  CONNECT, no table privileges): restore credentials are
  separated from app identities by construction.
- Backups rest on platform-encrypted volumes with owner-only
  access; KMS-envelope encryption stages with the G2 provider
  pick (PROD-005). Manifests (sha256) ship with every base;
  restores verify before extract.

## Recovery procedure

1. **Fence**: `./fence-writers.sh --yes` against the stale
   primary (revokes CONNECT, terminates serving backends,
   verifies silence). A fenced primary never rejoins as a
   writer — it is rebuilt or decommissioned, never un-fenced.
2. **Restore**: `./restore.sh <app|keycloak> <target-time> <name>`
   into isolated scratch volumes. Verify the manifest (the
   script does), start the scratch cluster, replay to target.
3. **Reconcile**: run `reconcile.sql` on scratch. All five
   checks must meet their expectations. Then invalidate
   single-use state from before the restore point (sessions,
   challenges, pending VP/VCI rows past their horizon):
   ```sql
   TRUNCATE spring_session, spring_session_attributes,
     holder_unlock_challenge;
   DELETE FROM vp_session WHERE state = 'PENDING';
   DELETE FROM vci_grant WHERE consumed_at IS NULL
     AND expires_at < now();
   ```
   Forced re-login is the correct post-restore posture: a
   restored session may predate a revocation.
4. **Re-apply**: revocations and approvals issued between the
   backup point and the fence (from the admin log +
   `credential_artifact.status_updated_at` ordering) are
   re-applied by hand and re-audited. Uncertain authority is
   invalidated, never resurrected: when in doubt the credential
   is revoked and re-issued.
5. **Promote**: point the app at the reconciled cluster (update
   `SOVRA_DB_URL`, rolling restart), watch `/ready` on both
   replicas, run one login and one machine call per replica.
6. **No duplicate acceptance**: replay safety survives restore
   because nonces/decisions are rows, not memory — but a restore
   to BEFORE a decision erases its row, and a retried request
   would decide again. The fence window (no writers between
   fence and restore point) is what closes this hole: restores
   always target at-or-after the fence timestamp. The drill
   proves it (exercise 3).

## Drill schedule and exercises

Quarterly, on isolated scratch (never the primary). Evidence
lands in `docs/engineering/recovery-drill-<date>.md`:

1. Base + PITR to a chosen timestamp; record RPO/RTO.
2. Stale backup: restore a 7-day-old base, replay WAL, confirm
   currency via the migration tip + reconcile.
3. Fence-window proof: fence a scratch primary mid-write,
   restore at the fence timestamp, confirm no lost decision row
   and no duplicate acceptance on retry.
4. Split-brain refusal: attempt to write to the fenced primary
   as `sovra_app`; confirm CONNECT denied.
5. DB/key mismatch: restore app data against a scratch KMS
   without the KEK; confirm seal failures (loud, no plaintext).
6. Revocation-after-backup: revoke on scratch, restore
   pre-revocation, confirm the reconcile flags it and the
   re-application procedure clears it.
7. Deleted-object restore: delete a vault object, restore
   pre-delete, confirm the object returns WITH its version
   history and the delete audit row survives (audit restores
   from the same point — the delete is re-applied, not lost).
8. Interrupted issuance/verification: kill the app mid-decide on
   scratch, restore, confirm the atomic predicates (one winner,
   idempotent replay) still hold.

## What recovery cannot do

Restored backups do not recall disclosed plaintext: bytes the
holder or an RP already received stay received. Recovery
restores authority state, not confidentiality. The runbook
never claims otherwise.
