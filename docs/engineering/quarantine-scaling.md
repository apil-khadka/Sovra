# Quarantine worker scaling (PROD-009)

## Knobs

| Env | Default | Meaning |
|---|---|---|
| `SOVRA_WORKER_CONCURRENCY` | 4 (clamp 1..16) | Scan threads; each holds one DB connection. Pool is sized concurrency + 1 for the sweeper. |
| `SOVRA_WORKER_LEASE_MS` | 300000 | A SCANNING row older than this is presumed orphaned and requeues. Must exceed the slowest scan (envelope open + sniff), which is milliseconds at the 5 MB cap. |
| `SOVRA_WORKER_SWEEP_MS` | 60000 | Sweep interval; a startup sweep runs before the first poll. |
| `SOVRA_WORKER_ID` | hostname-pid | Stamp recorded in `claimed_by`. |

## Exactly-once argument

- The claim is one statement: the advisory xact lock in the
  subselect makes racing workers skip each other's candidates
  without blocking, and the outer `status = 'QUARANTINED'`
  predicate arbitrates the race — losers match nothing and retry.
  The lock releases at commit/rollback, so a crashed worker never
  wedges a row at the lock level.
- A crash between claim and verdict leaves SCANNING + `claimed_at`;
  the sweep requeues it after the lease. A row is therefore scanned
  at-least-once across crashes and exactly-once across live
  racers; the scan itself is a pure function of sealed bytes, so a
  re-scan after a crash reproduces the same verdict.
- `QuarantineWorkerParallelTests` proves 4 threads × 20 admissions
  yield exactly 20 scans, and that stale/fresh leases requeue/hold
  correctly. `QuarantineWorkerContainmentTests` proves the verdict
  policy widens by exactly one transition (SCANNING → QUARANTINED).

## Least privilege preserved

`SELECT FOR UPDATE` stays unavailable (no table-level UPDATE
grant); the worker gains only `UPDATE (claimed_at, claimed_by)` on
admission rows plus the requeue transition. CLEAN / REJECTED /
PROMOTED rows remain untouchable.
