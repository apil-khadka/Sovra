# Storage growth (PROD-010)

Measured 2026-11-02 against the synthetic compose stack
(PostgreSQL 17.7, `sovra-demo` tenant). Small numbers — the value
is the per-row rates, which scale linearly until the archive
decision below.

## Snapshot

- Database total: 15 MB.
- Largest tables: `audit_event` 2.5 MB (heap 1.6 MB, indexes
  872 kB), `credential_artifact` 664 kB, `proof_request` 624 kB,
  `issuance_idempotency` 608 kB, `verification_decision` 448 kB
  (indexes 232 kB — the heaviest-indexed table per byte, from the
  V31 feed indexes plus the replay uniqueness constraint).
- Compressed logical backup (`pg_dump -Fc`): ~1 MB in 0.3 s.
- WAL: ~441 bytes per audit row (~441 kB per 1,000 inserts).

## Growth model

- Audit dominates by design (every decision writes evidence).
  At 1M decisions/day the audit heap grows ~1.6 GB/day before
  compression — see the archive decision.
- Decisions, proofs, and credentials grow with issuance volume;
  idempotency mappings are bounded by the 24-hour window plus the
  nightly purge; grants/sessions/challenges/buckets are bounded by
  TTL plus purges.
- Vault BYTEA dominates per-row bytes (16 MB cap per object);
  tenant object quotas bound the total (count × cap).

## Decisions from these results

1. No partitioning day one: single-table sizes stay operable
   through the staging load verdict (PROD-016 re-measures at
   realistic volume).
2. Audit archival at 90 days (compressed, checksummed, restorable)
   once production volume is known; audit is append-only and
   never deleted, only moved to cheaper storage with the same
   grants. The archival job is staged work after the first
   production quarter, not day one.
3. No object-storage offload day one: vault BYTEA stays in
   PostgreSQL for transactional consistency (bytes + grants +
   audit commit together). Revisit if vault exceeds 100 GB or
   backup windows miss RTO.
4. Backup: nightly base + continuous WAL (see the
   [recovery runbook](../../deploy/production/backup/recovery.md)).
   At synthetic scale the base takes 0.3 s; the drill procedure
   re-measures RPO/RTO quarterly.
