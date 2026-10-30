# SDK release record (SOV-021)

## 0.14.0 — 2026-10-30

Targets API contract `0.14.0`. Adds the SOV-023 review queues:
`ExtractionClient.list` (`listExtractionRecords`) and
`EnrollmentClient.list` (`listEnrollments`) with posture/state
filters and keyset cursors. No breaking changes; every other
method is unchanged.

## 0.13.0 — 2026-10-30

Targets API contract `0.13.0`
(`docs/engineering/implemented-api.openapi.yaml`). Both SDKs pin
the contract in code (`SUPPORTED_CONTRACT`) and fail closed on
shape drift with a `decode_error` instead of partial objects.

| SDK | Location | Version | Runtime deps |
| --- | -------- | ------- | ------------ |
| Java | `sdk/java` (`dev.sovra:sovra-sdk:0.13.0`) | 0.13.0 | Jackson 3.0.3 only |
| TypeScript | `sdk/typescript` (`@sovra/sdk`) | 0.13.0 | none (Node 22+, `node:crypto` proofs in tests) |

Test-only deps: JUnit 6.0.3 + AssertJ 3.27.7 (Java);
TypeScript 5.7.2 + `@types/node` 22.10.2 (TS, locked in
`sdk/typescript/package-lock.json`).

### Provenance

- Scope frozen in `docs/architecture/decisions/SOV-021-sdk-scope.md`
  (OD-16): machine chain only, no BFF sessions, no
  OpenID4VCI/VP, no auto-retry on writes, reads retry 3x on 503,
  HTTPS except loopback.
- Java suite: 13 tests, all live-stack
  (`sdk/java/src/test/java/dev/sovra/sdk/`).
- TS suite: 13 tests, all live-stack
  (`sdk/typescript/src/test/`), mirroring the Java flows.
- CI: `sdk-live` job in `.github/workflows/app-checks.yml` runs
  both suites against a disposable compose stack on every push/PR.
- Trust tests are read-modify-write: they carry every authorized
  issuer and policy forward and dedupe their own test issuer id,
  so suite runs never evict the shared stack's issuers.

### Support

Both SDKs move in lockstep with the contract version. A contract
bump requires both `SUPPORTED_CONTRACT` constants, both suites,
and this record to move together. Independent third-party review
of the SDKs is unscheduled (same gate as SOV-037).
