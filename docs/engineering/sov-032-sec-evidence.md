# SEC evidence mapping (SOV-032, demo slice)

**Status:** demo evidence map, 2026-10-30. Backend 573 tests,
browser 34 passed / 4 skipped (synthetic), SDKs 13/13 each,
contract 0.16.0.

This maps each SEC case from the
[security validation plan](security-validation-plan.md) to
the evidence that exists today. Statuses are **covered**
(automated test asserts the required observation),
**partial** (some aspect tested, remainder named), or
**gap** (no evidence; production-gated). The full ASVS 5.0.0
Level 3 requirement-by-requirement mapping, property-based
generation, Jazzer/PIT adoption, and independent review all
remain; nothing here claims them.

## Mutation proof

One deliberate-check-removal experiment ran 2026-10-30 and
was reverted uncommitted: deleting the RP-app gate in
`RpCredentialService.scoped` made
`DeveloperPortalFlowTests#trustAndIssuerAccountsInvisibleToRpDesk`
fail while the sibling role-denial test still passed —
the gate's assertion is load-bearing, not decorative.

## Case map

| ID | Status | Evidence |
| --- | --- | --- |
| SEC-01 | covered | `AuthzMatrixTests`, `ApiKeyAuthTests`, per-endpoint 401/403 across flow tests; public surface (health, discovery, JWKS, VCI/VP metadata) carries approved metadata only. |
| SEC-02 | covered | RLS `tenant_isolation` plus tenant-first queries; cross-tenant refusal in `EnrollmentNegativeTests`, `IssuanceNegativeTests`, `AuditPaginationTests`, `BffHolderFlowTests`, `HumanMembershipTests` (`WRONG_TENANT`). |
| SEC-03 | covered | Authority checks live in services (`AuditedAuthorizer`), not controllers; BFF desks delegate to the same services, proven by every `Bff*FlowTests` class asserting identical denials. |
| SEC-04 | covered | `P256Tests`, `KeyBindingTests`, `VpFlowTests` (tampered JWE, wrong nonce/state, expired sessions), `VciFlowTests`, `IssuanceNegativeTests` proof validation. |
| SEC-05 | covered | `TrustFlowTests` / `TrustNegativeTests` (unknown kids, out-of-scope issuers); keys enter only through two-person trust activation — no attacker-directed key fetch exists. |
| SEC-06 | covered | `VerificationNegativeTests` (audience/holder substitution), consent binding proofs, VCI proof verifier constant-time `aud` compare, VP `kb+jwt` audience binding. |
| SEC-07 | covered | Clock-injected expiry boundaries: consent `expiresAt`, grant TTL 60..86400, VP 5-minute sessions, holder unlock 5/15-minute windows (`HolderUnlockServiceTests`). |
| SEC-08 | covered | Concurrent same-nonce verification converges on one decision via savepoint reconcile (`VerificationFlowTests`); VP replay returns stored bytes (`responseReplaysByteIdentically`). |
| SEC-09 | partial | Idempotent replay recovers the original decision bytes under the nonce contract. Actual process-restart-after-commit is not exercised: no test kills and restarts a verifier mid-flow. |
| SEC-10 | covered | Issuance idempotency: identical authorized retry returns the original credential, different bodies conflict without re-minting (`IssuanceFlowTests`, incl. concurrency). |
| SEC-11 | covered | `VerificationFreshnessTests`: stale, malformed, or unavailable status yields `UNKNOWN`/deny with exact versions — uncertainty never becomes verified evidence. |
| SEC-12 | covered | Decisions record snapshot/status versions; `concurrentRevokesConvergeOnOneVersionBump`, `currentDenialWinsOverWarmCachesWithExactVersions`; `TrustSealTests` seal the snapshot chain. |
| SEC-13 | covered | `ConsentNegativeTests` (refusal, post-approval change, expiry) plus the browser consent journey (`consent.spec.ts`) proving no proof delivery without approval. |
| SEC-14 | partial | `IssuerKeyLifecycleTests` covers rotation, retirement, compromise, and cross-issuer signing denial. Key-use authorization against real KMS/HSM is deferred to SOV-038; the software provider fails closed (`kms_unavailable`). |
| SEC-15 | covered | Adversarial planner fixtures (`PlanningEvaluationTests`, `PlanningModeTests`) plus the deterministic guard as final authority (`GuardServiceTests`, `PlanGuardTests`); model output never authorizes. |
| SEC-16 | covered | `PlanningToolBoundsTests`: hidden-tool dispatch, callback reauthorization, tenant/role validation, invented references, budgets, injection-shaped args treated as data. |
| SEC-17 | partial | Tool arguments are validated data, never destinations; the live provider calls only configured `SOVRA_AI_BASE_URL`. No instrumented-resolver, redirect, or DNS-rebinding test exists. |
| SEC-18 | covered | Malformed/oversized/invalid-enum model output rejected by bounded parse plus guard schema/semantic checks (`PlanningEvaluationTests`); Java conversion never establishes authorization. |
| SEC-19 | covered | `PlanningLiveFailureTests`: unreachable/throttled/truncated providers yield explicit unavailable/manual-review with no invented evidence; tool budgets bound the run. |
| SEC-20 | covered | `PlanningCanaryTests` (prompts, tool results, audit detail), `AuditCanaryTests` (sensitive keys dropped, truncation, hostile input), `OpsSanitizerTests`, telemetry excludes bodies and tokens. |
| SEC-21 | partial | Parameterized `JdbcTemplate` queries everywhere, bean validation on bodies, `ProblemJsonTests` shapes; no dedicated SQLi/polymorphic-deserialization fuzzer (Jazzer unevaluated). |
| SEC-22 | partial | Admission bounds hold: 8 MB quarantine / 16 MB vault caps, decoder/pixel limits, grant TTL windows, live-grant budget (64/version), tool budgets. No per-caller rate limiting exists in the demo. |
| SEC-23 | covered | `BffLoginTests` (S256 PKCE, fixation rotation, CSRF logout, session kill on revocation), `login.spec.ts` browser flow, machine/session chain separation. |
| SEC-24 | covered | Hostile-markup browser tests (issuer/holder desks render `<svg onload>` inert); every desk value renders as plain text. |
| SEC-25 | partial | Actuator exposes `health,info` only; `HealthEndpointTests`, sanitized error/problem bodies. No deployed-network reachability test from low-privilege networks. |
| SEC-26 | partial | `LeastPrivilegeTests` (column-scoped DB grants per role), `TenantDataSourceTests`, `QuarantineWorkerContainmentTests` (worker sees no audit/credentials/keys). Deployment IAM beyond compose was reviewed, not tested. |
| SEC-27 | partial | Retention purge destroys bytes with tombstones (`VaultFlowTests`), revocation and role removal kill live access (`BffLoginTests`). Backup/restore drills do not exist — no backup infrastructure in the demo. |
| SEC-28 | partial | `AuditDurabilityTests`: business writes and evidence commit atomically, failures roll back, denials record reasons. Tamper detection against an independent external anchor does not exist in the demo. |
| SEC-29 | covered | CI `supply-chain` job: `pnpm audit --audit-level=high`, OSV-Scanner v2.7.0 over both JS lockfiles and the CycloneDX Java SBOM (zero findings 2026-10-30); all actions SHA-pinned; app container runs as non-root `sovra`; `.env` secrets gitignored; SDKs scrub tokens. No SAST tool runs. |
| SEC-30 | partial | Cross-implementation parity through walt-id (`WaltIdVerificationParityTests`, `WaltIdSdJwtTests`, VCI/VP conformance tests). An independently implemented external wallet and independent review remain. |
| SEC-31 | covered | Stub-OP login tests (forced S256 PKCE, exact issuer/audience, tenant allowlist, group mapping, hardware-AMR gating) plus the real-Keycloak browser login journey in compose. |
| SEC-32 | gap | No TLS in the demo (HTTP loopback/compose network) and no reverse-proxy header tests. Production-gated on the approved ingress design. |
| SEC-33 | covered | `VaultNegativeTests` (ciphertext/tag/context/key substitution), `AadContextTests`; AEAD authentication fails before any plaintext output. |
| SEC-34 | partial | Fresh DEK + nonce per version proven distinct under 8 concurrent writers; KEK rotation tested. Crash-restore of in-flight workers is not exercised. |
| SEC-35 | covered | Grant binding denials (wrong principal/purpose/object, expired/revoked) in vault tests; KMS outage fails closed with no plaintext fallback; role separation in `LeastPrivilegeTests`. |
| SEC-36 | covered | `QuarantineScannerTests` hostile corpus (polyglot, malformed, bombs), allowlist png/jpeg by magic bytes, `QuarantineWorkerContainmentTests` (no signer/key/host access, no egress). |
| SEC-37 | covered | `EnrollmentNegativeTests`: obsolete or unreviewed provenance cannot authorize issuance; holder binding and exact-revision review required before signing. |
| SEC-38 | covered | `ExtractionCoreTests`: SHA-256 source/canonical/exact digests, normalizer-v1, canon-v1; digests are integrity references, never lookup keys; no public fingerprint oracle. |
| SEC-39 | covered | `EtagPreconditionTests` (stale preconditions fail), revision-bound approvals, obsolete-revision issuance refusal, concurrent correction tests. |
| SEC-40 | partial | Locality holds by construction (single Postgres, no replication/failover, no remote OCR, no export paths). No egress-capture test; failover is N/A (nothing to fail over to). |
| SEC-41 | covered | Per-desk role tests on both chains (BFF flow tests + `DeveloperPortalFlowTests` RP-subset 404s) and browser role gates for every desk; review-view is purpose-bound; no desk reaches source bytes or KMS. |
| SEC-42 | covered | SDK guarantees (origin/audience validation, no secret logging, no unsafe-write retry, ETag reads, `decode_error` fail-closed), `ApiCompatibilityTests` parity gate, quickstart suites, zero-dep TS bundle, session-only browser. |
| SEC-43 | covered | Opaque UUID `subjectRef` (unguessable, no PII-hash merging), member-only fixed-shape sandbox onboarding, self-verification confers no trust (`EnrollmentNegativeTests`). |
| SEC-44 | partial | Purge destroys bytes and key material with tombstones; KEK rotation tested. Key rewrap/retirement never runs and backup-restore drills do not exist; no universal-erasure claim is made. |

## Remaining for production

ASVS 5.0.0 Level 3 requirement-by-requirement mapping,
property-based suites, Jazzer/PIT adoption, the gaps above
(TLS/ingress, backup/restore, external anchors, rate
limiting, resolver tests, KMS/HSM, external wallet), and
independent review (SOV-034, SOV-037).
