# Retention (PROD-010)

## Classes

| Class | Tables | Horizon | Mechanism |
|---|---|---|---|
| Evidence (never deleted) | `audit_event`, `verification_decision`, `proof_request`, `credential_artifact`, trust history, `issuer_key_revocation` | forever (archive, not delete) | No purge path exists; least-privilege denies DELETE/UPDATE. |
| Replay safety (never deleted) | `vp_session` nonce uniqueness, decision `(tenant, request, nonce)` uniqueness | forever while the row lives; rows reap only past the grace window | Uniqueness constraints; replays reconcile against stored rows. |
| Idempotency window | `issuance_idempotency` | `expires_at` (24 h) | Lazy reclaim on access + nightly purge. Post-window, the same key starts a new issuance attempt. |
| Grants | `vault_grant` | `expires_at` (60 s–24 h TTL) | Nightly purge at expiry. Re-issue is cheap; expired rows are useless. |
| Protocol state | `vci_grant`, `vci_token`, `vp_session` | expiry + 24 h forensic grace | Nightly purge past grace, children before parents. |
| Sessions | `SPRING_SESSION*` | 30 min idle | Spring Session built-in cleanup. |
| Challenges | `holder_unlock_challenge` | 5 min | 5-minute bounded reap. |
| Rate buckets | `rate_limit_bucket` | 1 h idle | Nightly bounded reap. |
| Vault bytes | `vault_object(_version)` | tenant quota, then explicit delete | Owner-initiated delete only (see below). |

## Rules

- Purges are bounded (≤1,000 rows per table per run, expiry
  order) and idempotent: every replica may run them, backlogs
  drain over successive runs, and no purge takes a long lock.
- Maintenance-role separation: the app role holds no DELETE on
  purged tables. Each purge is a SECURITY DEFINER function the
  app may only EXECUTE (`V34__transient_purge.sql`,
  `TransientPurge`, `TransientPurgeTests`).
- Vault delete is explicit and audited, never TTL-driven:
  sealed bytes outlive their usefulness only when an owner says
  so. Tombstones: delete marks the version `DELETED`; bytes are
  overwritten on the retention schedule, not resurrected.
- Legal hold: a `legal_hold` flag per tenant suspends vault
  delete/purge and audit archival for that tenant; purges of
  protocol state continue (they carry no content). Set and
  released through `PUT /api/tenants/{id}/legal-hold`
  (TRUST_ADMIN, audited); the vault service refuses held
  destruction with `legal_hold` (409), and the purge function
  backstops direct `EXECUTE`. Hold classes still need counsel
  sign-off before first production use.
- Audit archival: evidence past 90 days moves to
  `audit_event_archive` in one bounded batch (1,000 rows) per
  night (`archive_audit_events`, `SECURITY DEFINER`, skip-locked
  so replicas never move a row twice). Held tenants' rows stay
  hot until release; platform rows archive by age. Reads union
  both tables (`AuditEventRepository`, telemetry reason counts),
  so archival is a storage optimization, never a visibility
  change.

## Quotas (proposed, pending approval)

- `sovra.quotas.vault-objects-per-tenant`: 100,000 objects
  (~1.6 TB worst case at the 16 MB cap; typical content is
  kilobytes). Enforced count-then-act at store time, approximate
  under concurrency; refusal is non-retryable `quota_exceeded`.
- Ingestion rate: per-tenant admission buckets (PROD-006) bound
  writes per second; byte rate derives from rate × object cap.
- Increase procedure: approve, set the value, rolling restart —
  no migration, no backfill.
