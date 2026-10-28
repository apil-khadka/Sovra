# SOV-017 quarantine assessment (G1 synthetic)

Date: 2026-10-28. Verdict: **implemented for the synthetic scope**
with the explicit gaps below. SOV-017 stays open until its tracker
([issue](https://github.com/apil-khadka/Sovra/issues/22)) is reviewed
against this evidence.

## What was built

Encrypted quarantine with an isolated hostile-image worker
(`dev.sovra.quarantine`, `dev.sovra.worker`, V15):

- Admission desk: `POST /api/quarantine/admissions` (202) seals
  bytes as quarantine-marked vault objects (8 MiB cap, magic
  allowlist png/jpeg, claimed type stored as an untrusted label);
  `GET /api/quarantine/admissions/{id}` serves verdicts
  metadata-only; `POST .../promote` (201) re-seals CLEAN verdicts
  server-side under the caller's scan grant into fresh vault
  objects with real purposes. No endpoint serves quarantine bytes.
- Isolated worker: own JVM (`QuarantineWorkerMain`), own database
  role, no Spring, no HTTP, no credentials, heap-capped at 512m.
  One admission per transaction through the KMS-shaped KEK seam;
  compromise of this process cannot reach the signer, other
  tenants' bytes, or the network.
- Bounded scanner: hand-walked PNG chunk / JPEG marker parsers
  enforce header dimensions before any decode (16384 px edges,
  32 MP cap); trailing bytes after IEND/EOI reject polyglots;
  decoder attempts confirm renderability and dimension agreement.
  Every rejection names a machine-readable reason.
- Database containment: the worker role selects the cross-tenant
  queue, three vault seal column sets, and nothing else — no
  credentials, keys, grants, trust, audit, or tenants. A
  USING/WITH CHECK policy fences verdict writes to unscanned rows
  into scanned states, so even a compromised worker cannot flip
  REJECTED to CLEAN or touch PROMOTED rows.
- Promotion integrity: the content endpoint refuses
  quarantine-marked seals grant-or-no-grant (403 GRANT_INVALID);
  promotion claims PROMOTED in the row after the re-seal, so a
  retry or race conflicts and rolls its duplicate back while a
  bad grant leaves the admission CLEAN and retryable.

## Verification

- 26 new tests, 383/383 green (`./mvnw verify`): 10 scanner
  verdicts over hostile fixtures (spoof, polyglot, header bomb,
  truncation, corrupt scan data), 9 flow tests (admit/scan/
  promote/read, rejected-never-promotes, mismatch flagging,
  role gates, content-endpoint refusal), 7 worker-role
  containment tests as the role itself.
- `scripts/e2e-quarantine.py` PASS against compose: proves the
  worker container is alive, admits, awaits a live CLEAN verdict,
  promotes into grant-bound reads, rejects a polyglot, exercises
  the negative matrix, and re-proves role containment live.
- Contract 0.6.0 (`implemented-api.openapi.yaml`):
  `ApiCompatibilityTests` pins the three routes and their scopes.
- Regression: `e2e-vault.py`, `e2e-verification.py`, and
  `e2e-bff-login.py` all PASS on the same stack (the Dockerfile
  now ships an exploded classpath so one image boots either the
  API or the worker main).

## Explicit gaps

- Production KMS/HSM fail-closed until G2 (SOV-016): the worker
  refuses non-demo boot, so production quarantine awaits the
  provider pick with the vault.
- Scanner allowlist is png/jpeg only; no AV engine, no
  content-disarm, no human review queue (SR-23 wiring pending).
- Worker is a single compose replica with poll cadence; backlog
  metrics/alerts and multi-replica fencing beyond the atomic
  claim are SOV-027 platform work.
- Existing databases upgrading to V15 need the quarantine role
  login/password applied (fresh compose init handles it via
  `SOVRA_QUARANTINE_DB_PASSWORD`); the migration itself only
  creates the NOLOGIN role and fences.
- Independent review (SOV-037) still unscheduled; implementation
  tests do not substitute for it.
