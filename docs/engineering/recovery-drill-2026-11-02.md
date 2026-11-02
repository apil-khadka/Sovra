# Recovery drill evidence — 2026-11-02 (PROD-013)

Base-only drill against the synthetic demo stack (the demo has no
WAL archive; production adds PITR replay on top of this flow).
All commands ran as documented in
`deploy/production/backup/recovery.md`, adapted paths only.

## Timeline (measured)

| Step | Result |
|---|---|
| Backup role retrofit on a live cluster | `CREATE ROLE sovra_backup ... REPLICATION` OK |
| Separation proof (`sovra_backup` reading `audit_event`) | denied (fails at `app_tenant`) |
| `pg_basebackup -Ft -z -X stream` (15 MB DB) | 0.7 s, 6.0 MB output (`base.tar.gz` + `pg_wal.tar.gz` + manifest) |
| Extract to scratch volume | 2.0 s |
| Scratch cluster boot to serving | ~8 s |
| Row parity (audit 4785 / decisions 210 / trust snapshots 17) | identical live vs scratch |
| `reconcile.sql` | tip 33, 1 activation, 0 revocations to re-apply, 0 scanning orphans (16 synthetic issuers expected on demo; must be 0 on production) |
| Migration job (`MigrateMain`) against the restore | validates + applies pending V34, 0 errors |

RPO for this drill: backup age (base-only; WAL replay would cut
it to seconds). RTO at synthetic scale: ~11 s mechanical plus
reconcile reading time. Both re-measure at staging volume
(PROD-016).

## Cleanup

Scratch container, volume, host/container tarballs, and the drill
backup role removed; `docker volume ls` shows no drill residue.
The demo database is untouched (row counts verified after).
