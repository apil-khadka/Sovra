# Query profiles (PROD-008)

Captured 2026-11-02 against the synthetic compose stack
(PostgreSQL 16, `sovra-demo` tenant pinned via `SET app.tenant`).
`EXPLAIN (ANALYZE, COSTS OFF)`. Plans marked BEFORE were captured
before migration V31; AFTER plans after.

## Hot reads: already indexed (no change)

| Query | Plan |
|---|---|
| `service_account` by `token_prefix` (per machine request) | `Index Scan using service_account_prefix_idx`, 1.0 ms |
| `human_membership` by id / `(issuer, subject)` (per BFF request) | PK / unique `(issuer, subject)` (seq scan only on the 10-row synthetic table; PK path exists) |
| Trust activation `MAX(snapshot_version)` (per snapshot read, cached) | `Index Only Scan Backward` on pkey, 0.02 ms |
| `issuer_record` / `rp_policy` by `snapshot_version` (per snapshot load, cached) | `Index Only Scan` / `Bitmap Index Scan` on unique keys, 0.34 / 0.01 ms |
| `vp_session` by `(tenant_id, nonce)` (replay check) | `Index Scan using vp_session_tenant_id_nonce_key`, 0.05 ms |
| Consent decide `UPDATE proof_request ... WHERE id AND state='PENDING'` | `Index Scan using proof_request_pkey` + filter, 0.05 ms |

## Fixed by V31

### RP outcome feed (BEFORE: seq scan + sort)

`RpOutcomeService.outcomes`: `WHERE tenant_id = ? ORDER BY decided_at DESC, id DESC LIMIT 20`:

```text
Limit (actual time=0.121..0.123 rows=20 loops=1)
  ->  Sort (actual time=0.121..0.121 rows=20 loops=1)
        Sort Key: decided_at DESC
        Sort Method: top-N heapsort  Memory: 27kB
        ->  Seq Scan on verification_decision (actual time=0.007..0.100 rows=210 loops=1)
              Filter: (tenant_id = 'e840b884-...')
```

AFTER: `Index Only Scan using verification_decision_tenant_recent_idx`,
0.073 ms, no sort node. Scoped variant (`AND decided_by = ?`) uses
`verification_decision_tenant_agent_recent_idx` (proven in
`QueryPlanTests` with selective fixtures).

### Audit feed (BEFORE: incremental sort)

`AuditEventRepository` recent: `WHERE tenant_id = ? ORDER BY occurred_at DESC,
id DESC LIMIT 50` used `audit_event_tenant_time_idx` (ASC prefix) plus an
in-memory incremental sort (0.096 ms at synthetic scale; the sort grows
with tenant history).

AFTER: `Index Only Scan using audit_event_tenant_recent_idx`,
0.070 ms, no sort node.

### Other feeds covered by V31 (same shape, verified in tests)

- Holder disclosures: `proof_request_holder_recent_idx`
  `(tenant_id, holder_thumbprint, created_at DESC, id DESC)`.
- Holder credentials: `credential_artifact_holder_recent_idx`
  `(tenant_id, holder_thumbprint, issued_at DESC, id DESC)`.
- Quarantine ops feed: `quarantine_admission_tenant_recent_idx` and
  `quarantine_admission_tenant_status_recent_idx`.
- Enrollment queue (already keyset-paginated): `enrollment_tenant_recent_idx`
  and `enrollment_tenant_state_recent_idx`.

## Regression net

`dev.sovra.db.QueryPlanTests` seeds 3,000 rows per feed table, runs
`ANALYZE`, and asserts each real feed SQL plans its index with no
sequential scan. The enrollment queue indexes (expensive parents to
seed) are guarded by `pg_indexes` presence. `TrustCacheTests`
additionally covers single-entry version-checked caching and
single-flight concurrent refresh.
