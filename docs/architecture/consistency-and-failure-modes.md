# Consistency contracts, reliability and failure modes

## Invariants

- An issuer's signed credential identifier, claim hash and key version are immutable once issued. Key ownership and revocation state are maintained in the issuer domain.
- Credential `REVOKED` is terminal in this demo. A fresh replacement requires a new identifier and a new signed artifact.
- Verification nonce may be consumed **at most once** and is scoped to a relying party, plan hash and expiry. Consume atomically at verification decision boundary; concurrent submissions must not both pass.
- A key rotation must not silently transform a formerly untrusted issuer into trusted. Trust metadata version and issuer accreditation scope are captured in the verification record.
- An AI plan must never create or modify an approved policy. Approved policy revisions require separate authorized action and audit record.

## Failure case → observable behavior

| Failure | Correct result in demo | Evidence |
| --- | --- | --- |
| Model timeout | Dynamic planning unavailable, not authorized | timeout injection and manually reviewed result |
| Country issuer offline after issuance | Verification may work only if trust/status checks meet freshness policy | isolated country-node test |
| Trust registry unavailable | Do not accept newly discovered/unknown issuer | dependency outage test |
| Status endpoint timeout | Return unknown/retry/manual review under configured risk profile | 503 injection |
| Two proofs reuse same nonce concurrently | Exactly one may succeed | concurrency test with atomic index/update |
| Revocation races a presentation | Defined order and snapshot/timestamp; no unbounded stale-status acceptance | interleaving test |
| Model fabricates claim equivalence | Plan rejected before wallet receives request | negative fixture |
| Tool returns injection payload | No new capability/privilege granted | prompt injection test |
| Country A admin tries to read Country B DB | Access denied | isolation configuration test |

## Business recovery contract

The [SRS invariants](../requirements/software-requirements-specification.md) extend the prototype rules to real-data and customer releases.
Unknown authority remains unverified even when continuing service would improve availability.
Restoring a database successfully is insufficient to reopen verification.

| Failure or transition | Required behavior | Evidence cases |
| --- | --- | --- |
| Older backup restores an unused copy of a consumed challenge | Fence previous writers; reconcile authoritative consumption or invalidate the ambiguous session generation before acceptance | SEC-08 through SEC-10, MC-03, AC-15 |
| Rollback restores stale trust, approval or revocation | Preserve current denies/epochs or close affected operation; never restore authority merely to regain availability | MC-03, MC-10, AC-15, AC-17 |
| Key disabled while cached DEKs/grants or restored key copies exist | Apply current deny policy and measured cache/job/copy containment; do not assert immediate universal erasure | SEC-35, SEC-44, MC-01, MC-04, AC-16 |
| Provider management plane fails while signing/unwrap still works | Follow declared data-plane authority/cache policy and emergency-control limits; forbid unapproved fallback | MC-04, MC-10 |
| Local OCR/storage/key service fails | Deny affected work rather than routing source data, derivatives or keys outside approved issuer locations | SEC-40, MC-05, AC-12 |
| HTTP health succeeds while freshness, replay storage or audit fails | Mark affected flow unready and alert with sanitized reasons; dependency failure cannot create acceptance | MC-08, AC-17 |
| Blue/green traffic or obsolete process continues writing | Enforce writer fencing, compatible schema/state transitions and one-time consumption across every serving path | MC-03, MC-10, AC-15, AC-17 |

Approve numeric per-store RPO/RTO, freshness, cache and containment bounds before making recovery commitments.
Exercise these contracts in isolated representative staging with synthetic load, actual provider/IAM behavior and independent assertions.
See [SOV-029 through SOV-034](../engineering/implementation-backlog.md) for operational implementation and release evidence.

## G1 implemented durability rules (SOV-007/SOV-009)

- Issuance commits atomically: credential row, idempotency record, and
  audit row share one transaction. If the audit row cannot commit, the
  request fails and no credential or retry state exists. Proven by an
  outage-injection test that revokes audit INSERT mid-run.
- Idempotent retries with the same key and request replay the original
  response byte-for-byte for 24 hours; the same key with a different
  request is a 422 conflict, never a silent second issuance. After
  retention lapses the key may mint a new credential; the old credential
  row lives on.
- A lost idempotency race reconciles against durable state: the loser
  re-reads the winner's record instead of issuing twice.
- Tenant pins never cross borrows or transactions: pooled connections
  reset `app.tenant` on close, and transactional borrows reset when the
  transaction completes (commit or rollback). A missing pin fails loudly
  at the database guard instead of leaking rows.
- Credential `REVOKED` is terminal; revocation changes only status
  columns (column-level grant), and signatures stay verifiable so
  verifiers must check status rather than infer it.
- Audit authority tradeoff (recorded, G1): audit rows commit in the same
  transaction as the decision they evidence, which requires the same
  database role. Separation is enforced by immutable grants (no
  UPDATE/DELETE for the app role), a sole-writer service, and
  privacy-minimizing sanitization. A separate-authority async audit
  shipper is G2 work; it must preserve the no-decision-without-evidence
  rule, not weaken it.

## Operational strategy (hackathon)

Prefer Docker Compose and a small number of processes. PostgreSQL is adequate for durable issuer/status/session records and an atomic replay cache (unique constraint or transactional update). If simple in-memory records are used, label the volatility and avoid claiming production consistency. Provide `healthz` (process alive) and `readyz` (critical verification dependencies satisfied) as distinct probes if time allows. Sanitize traces and collect `status_unknown`, `signature_reject`, `guard_reject` counts.

Do not build multi-region failover, Kafka or complex eventual-consistency machinery without evidence they solve an actual problem in this short prototype. Production planning may require signed status snapshots, an outbox, governance versioning, HSM/KMS and region-specific backups.
