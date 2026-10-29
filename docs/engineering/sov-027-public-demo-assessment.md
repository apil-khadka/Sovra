# SOV-027 public-demo boundary assessment (G1 synthetic)

Date: 2026-10-29. Verdict: **synthetic-only admission implemented**
with the explicit operator-owned gaps below. SOV-027/028/030 stay
open until hosting, HTTPS origin, and charge-prevention controls are
evidenced against a provisioned deployment.

## What was built

Demo-mode blocking of arbitrary uploads through the vault and
quarantine APIs (`dev.sovra.config.DemoProperties`,
`ReasonCode.DEMO_SYNTHETIC_ONLY`):

- Config flag: `sovra.demo.synthetic-only`
  (`SOVRA_DEMO_SYNTHETIC_ONLY`, default `false`). Local
  development keeps the default so synthetic API tests can seal
  bytes; the public-demo profile arms it.
- Wired enforcement on every externally reachable ingestion path:
  `POST /api/vault/objects`, `POST
  /api/vault/objects/{id}/versions`, and `POST
  /api/quarantine/admissions` throw `403 demo_synthetic_only`
  when the flag is true — after the anonymous check, before any
  service lookup, so the block holds for authenticated privileged
  callers and unknown objects alike. No other controller calls
  `VaultService.store/storeVersion` or `QuarantineService.admit`,
  so no ingestion path bypasses the guard. Reads, grants,
  verdicts, and server-side promotion are unaffected: the demo
  serves server-seeded synthetic fixtures but accepts no visitor
  uploads.
- Negative tests: `DemoAdmissionTests` (6 tests) boots with the
  flag armed and proves vault store, vault version store, and
  quarantine admission reject valid-looking PNG bytes with 403
  `DEMO_SYNTHETIC_ONLY` for `ISSUER_OPS` callers, anonymous
  callers still get 401, and metadata/verdict reads stay on
  their normal 404 gate.
- Public-demo deployment profile: `compose.public-demo.yaml`
  layers over `compose.yaml` and forces
  `SOVRA_DEMO_SYNTHETIC_ONLY=true` plus a hard live-planner
  disarm (`SOVRA_AI_LIVE_ENABLED=false`, empty
  base-url/model/key) on both app instances, regardless of
  shell or `.env` state.
- Contract: `implemented-api.openapi.yaml` 0.8.0 documents the
  new 403 outcome on the three ingestion operations;
  `ApiCompatibilityTests` pins the bump.

## Launch-boundary position

Already in the tree and unchanged by this stage: service-account
creation is TRUST_ADMIN-gated (no unrestricted enrollment);
management exposure is health/info only with `show-details:
never`; request bounds (16 MiB vault, 8 MiB quarantine, grant
TTL, purpose counts) and audit hold on every path; the
production startup validator still refuses synthetic
configuration in production mode; `.env` stays gitignored with
empty credential placeholders in `.env.example`.

## Operator-owned before any public URL

No host has been selected or provisioned by this change. The
owner still must: approve an HTTPS origin with exact Keycloak
redirect/logout URIs; rotate every deployment credential off the
dev defaults; keep database, Keycloak administration, and worker
interfaces private; restrict demo accounts/roles and avoid
real-person identity fields; record capacity/expiry limits and a
rollback/stop procedure; and retest liveness, origin/cookies,
and image admission through the actual deployment
configuration. SBOM/provenance/secret scanning and
digest-pinned release inputs remain release-qualification work.
