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

## Operational strategy (hackathon)

Prefer Docker Compose and a small number of processes. PostgreSQL is adequate for durable issuer/status/session records and an atomic replay cache (unique constraint or transactional update). If simple in-memory records are used, label the volatility and avoid claiming production consistency. Provide `healthz` (process alive) and `readyz` (critical verification dependencies satisfied) as distinct probes if time allows. Sanitize traces and collect `status_unknown`, `signature_reject`, `guard_reject` counts.

Do not build multi-region failover, Kafka or complex eventual-consistency machinery without evidence they solve an actual problem in this short prototype. Production planning may require signed status snapshots, an outbox, governance versioning, HSM/KMS and region-specific backups.
