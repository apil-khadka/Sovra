# Modularity and bug-class review (2026-10-29)

Six-area inspection (core platform, credential flows, data plane,
edge/AI/ops, client surface, whole-tree bug-class hunt) with every
cited body opened. Verdict: the codebase is genuinely modular —
package boundaries hold, crypto/authz/audit have real homes, and the
480-test suite pins behavior. Three items were fixed this turn; the
rest is ordered backlog below.

## Fixed this turn

1. **BFF/machine identity confusion (verified vulnerability).**
   `ApiKeyAuthFilter` is a `@Component`, so Boot auto-registered it
   with the servlet container at lowest precedence: it re-ran after
   the security chain on every path and a valid Bearer overwrote the
   session identity `BffSessionFilter` had established. Reproduced
   at runtime (`/api/bff/me` returned the machine's `TRUST_ADMIN`
   instead of the session's `TENANT_MEMBER`), bypassing
   per-request membership liveness and hardware-AMR gating. Fix: a
   `FilterRegistrationBean` with `setEnabled(false)` in
   `SecurityConfig` — the filter now runs only inside the machine
   chain. Regression test:
   `BffLoginTests#bearerNeverOverridesSessionOnBffPaths`.
2. **Duplicated P-256 crypto eliminated.** `IssuanceService` carried
   a line-for-line second implementation of holder-key parsing and
   ES256 verification (~90 lines), and curve params / coordinate
   encoding / thumbprints lived in three places. Now: `P256`
   (`dev.sovra.crypto`) is the single home for params, `fixed32`,
   base64url coordinates, and RFC 7638 thumbprints; `HolderProofs`
   owns parsing plus the one ECDSA transcode-and-verify tail; all
   other copies deleted (verified: one `secp256r1`, one transcode
   call, one thumbprint definition). Exception wording preserved
   exactly through translation seams. Pinned by `P256Tests` against
   independently computed vectors (SECG generator + Python
   recomputation). Full suite: 471/471 green.
3. **Stringly-typed roles eliminated.** The closed `Role` enum
   (`dev.sovra.authz`) now keys `REQUIRED_ROLES` (35 `EnumSet`
   entries), BFF `groupRoleMap`/`privilegedRoles`, principals,
   and repository rows; `Role.parseAll` is the single parse point
   and Spring enum binding fails boot on config typos (the
   fail-open hardware-AMR gate is unrepresentable). V18 adds
   `CHECK` allowlists on both `text[]` columns. A static
   exhaustiveness assertion over `Action.values()` (with an
   explicit audit-only declaration for `BFF_LOGIN`/`BFF_LOGOUT`,
   which never pass through authorization) forces every future
   action to be ruled or declared. The phantom `PLANNER` role is
   gone — converted probes now use known-but-insufficient roles.
   Pinned by `RoleTests` (parse + exhaustiveness),
   `BffConfigTests#unknownConfiguredRoleFailsBinding`, and
   `ServiceAccountLifecycleTests#databaseRejectsUnknownRoles`.
   Full suite: 480/480 green.

## Backlog (ranked by leverage/cost)

1. **Unify hand-rolled auth checks + denial audits.** ~89
   `authorize` sites each hand-roll caller/role/tenant/AMR checks
   and ~28 `deny` calls; several 400-paths skip denial audits
   (subject-key/controller binding gaps), and 4 services skip the
   membership check. One `AuthorizationService.check` entry +
   `DenyingScope` + controller `@ControllerAdvice` mapping would
   make silent-denial and check-skipping unrepresentable.
2. **Role enum + boot assertion.** Roles are strings in
   `REQUIRED_ROLES`, config maps, and `text[]` columns; typos fail
   open or closed unpredictably. Key the map by enum with an
   exhaustiveness assertion over `Action.values()`; fail boot on
   unknown config/DB roles.
3. **Status enums.** Lifecycle states (`QUARANTINED`, `VALID`,
   `ACTIVE`, …) are strings compared at ~15 sites; typos fail
   closed today but silently. Java enums + PG `CHECK` already
   partially covers this.
4. **Move VCI verification into `openid`.** `verifyVciProof` sits in
   `IssuanceService` although `OpenIdKeys`/`DcqlFilter` own the
   protocol; also fix `aud`/`nonce` to constant-time compare
   (currently `String.equals` on `aud`).
5. **Move the demo-ingestion gate into services.**
   `DemoAdmissionGuard` is controller-called; the service layer
   never enforces it, so the next endpoint is fail-open by
   default and BFF paths bypass it entirely.
6. **Structured signer AAD.** AAD is an exact-format string with
   ad-hoc asserts; an `AadContext` value type would make
   malformed bindings unconstructable.
7. **Frontend hardening queue:** split `api.ts` god module,
   re-enable `no-explicit-any`, fix the `typecheck` script (wired
   wrong), pin `jose`, move holder keygen off the main thread,
   add `download`/`rel=noopener` hardening.

## Explicit non-findings

- SQL is parameterized throughout (no injection class); `ORDER
  BY` interpolation in `AuditService` is allowlist-mapped.
- No `verify:false`, no `t:lower`-style downgrades, no secrets in
  logs, no frontend trust of server-enforced decisions.
- Vault/quarantine cryptographic layering and worker containment
  hold as previously assessed.

## Batch 3 (same day): audit remediation fixes

1. **Human-grant contract wired.** `MembershipRow.principal()`
   dropped the `(issuer, subject)` binding, so
   `TrustService.checkerSubject()` was a hardcoded `null` and no
   quorum could ever be person-verified. `ServiceAccountPrincipal`
   now carries the binding (machines: nulls, backward-compatible
   constructor); `ApprovalIdentity.of` derives maker/checker
   identity from it. Proven by
   `TrustFlowTests#humanQuorumIsPersonVerified` (two humans, two
   subjects, `approve` returns true).
2. **Membership tenant pinned fail-closed.** `upsert` silently kept
   the first tenant on cross-tenant re-login. Now: login-time
   pre-check plus a conditional `ON CONFLICT ... WHERE
   tenant_id` update; losers get `HumanTenantConflictException`,
   mapped to an audited `WRONG_TENANT` login denial. Pinned by
   `HumanMembershipTests`.
3. **Audit platform scope.** Global-resource actions (trust
   registry, issuer keys) were attributed to the actor's tenant,
   fragmenting the evidence chain across tenants. `V19` makes
   `tenant_id` nullable (NULL = platform row, visible to every
   tenant reader) and scoping follows `ResourceRef`, not the actor.
   The RLS guard leads with `app_tenant()` so missing-setting
   connections still fail loudly (short-circuit trap documented
   in the migration). Pinned by
   `AuditPaginationTests#platformRowsAreVisibleAcrossTenants`;
   contract bumped to 0.9.0.
4. **VP idempotent replay.** First attempt wrongly rejected
   completed-session resubmits; the suite's
   `responseReplaysByteIdentically` defines the true contract:
   COMPLETED sessions return the stored `response_body` verbatim
   (no re-decision, no new rows), immune to expiry. `V20` exposes
   `decision_id` through `resolve_vp_session`; the completion
   UPDATE stays PENDING-conditional for race safety.
5. **Approve quorum visible.** `POST .../approve` ignored the
   returned boolean; the response now carries `personVerified`.
6. **BFF contract documented.** All 12 session-chain operations
   added to the OpenAPI file (session cookie + XSRF scheme);
   served/documented parity holds both ways, enforced by
   `ApiCompatibilityTests` (now BFF-enabled) at contract 0.9.0.
   A redundant second parity test was written and removed in
   favor of the established gate.
7. **P1 merges.** `TenantContext.with/withResult` replace the two
   private copies in the wallet services;
   `IssuerKeys.usable` is the single issuer-usability predicate
   (`PlanningIssuers` deleted, both artifact verifiers repointed).
   Deliberately not merged: the six `text(JsonNode, String)`
   readers (one site already carries a divergent throwing
   contract, arguing for locality) and consent-local `scalar()`
   (single use).
8. **Conflict status unified.** Idempotency, service-account, and
   verification conflicts all return 409 (was mixed 422/409).

Full verification: backend 495/495, frontend build/lint/typecheck
clean, Playwright 11/11 on the rebuilt compose stack,
`check_repository.py` green.

## Batch 4 (same day): remaining backlog items

1. **VCI proof verifier moved (item 4).** `verifyVciProof` moved
   from `IssuanceService` to `openid.VciProofVerifier`, mirroring
   the `KeyBindingVerifier` shape (static, throws
   `HolderProofException`, caller maps with messages preserved).
   The issuance-side guarantee ("no caller reaches encoding
   without a valid proof") is intact — the call still happens
   inside validation. `aud` comparison is now constant-time
   (`nonce` already was). Covered by the existing 54
   VCI/issuance tests, all green unmodified.
2. **Structured signer AAD (item 6).** New `AadContext` value type:
   construction rejects framing-breakers (`;`, `=`, blanks) and
   parsing refuses duplicate keys instead of last-wins. This kills
   a real injection shape — issuer ids have no charset
   restriction, so a crafted id could previously inject a second
   `issuer=` field. Both encoders build through it; the signer's
   hand parser is deleted; refusal messages preserved. Pinned by
   new `AadContextTests` (5 tests).
3. **Key-status enum (item 3, first domain).** `KeyStatus`
   (`ACTIVE`/`REVOKED`) with `Role.from`-style fail-fast parsing;
   `KeyView.status` is now typed (JSON wire unchanged),
   `IssuerKeys.active` parses instead of string-comparing, and
   V21 adds the rest-side `CHECK`. Remaining status domains
   (credential, consent, VP session, quarantine) left as
   follow-up: their typos fail closed today, and each needs its
   own wire-compatible pass. Also repointed two missed inline
   issuer-usability checks to `IssuerKeys.usable`, completing the
   predicate unification (5 sites, 1 definition).
4. **Silent denials eliminated (item 1, defects).** New
   `AuditedAuthorizer.require` (audit package, edge-clean):
   authorize + mandatory denial record + correctly-mapped throw.
   Migrated all 9 silent sites (5 service-account operations, 4
   read-path `enforce()` calls) and deleted the now-unused
   `enforce()`, so the silent path cannot be reintroduced.
   `noRollbackFor = ForbiddenException` on the three
   transactional mutations, mirroring the trust-service
   precedent. Pinned by denial-evidence assertions in
   `ServiceAccountLifecycleTests` and `AuthzMatrixTests`.
   Not reproduced: "services skip the membership check" —
   `authorize()` centralizes liveness for both credential stores
   and no bypass exists; the gap was auditing, now closed.
   Follow-up (not done): migrating the other ~28 already-correct
   hand-rolled sites to the helper, and the full
   `DenyingScope`/`ControllerAdvice` rework.
5. **Frontend queue closed (item 7).** `no-explicit-any` enabled
   and green; `jose` is unused (WebCrypto direct, already
   off-main-thread); no external links/downloads to harden.

Full verification: backend 501/501, frontend build/lint/typecheck
clean, Playwright 11/11 on the rebuilt compose stack,
`check_repository.py` green. Changes uncommitted pending review.

## Batch 5 (same day): status enums + authz unification

1. **Status enums, all domains (item 3 complete).** Seven closed
   enums, each mirroring its rest-side `CHECK`, with `Role.from`-
   style fail-fast parsing: `VpSessionState`, `ConsentState`
   (stored lifecycle only; derived view states stay display
   strings), `QuarantineStatus`, `CredentialStatus`,
   `VaultObjectStatus`, `KekStatus`, `IssuerStatus`. Java
   comparisons are now `==`; SQL state literals became enum bind
   parameters (a typo'd literal can no longer silently match zero
   rows). `TrustedIssuer` is typed too; plan-context JSON maps
   through a strict `standing()` that throws `MalformedPlan`
   on unknown text (null stays null and refuses closed).
   No new migration was needed — every `CHECK` already existed
   except key status (V21, batch 4).
2. **Predicate unification finished.** Two more inline
   issuer-usability copies found during the enum pass (VCI offer
   trust check, signer registry check) now delegate to
   `IssuerKeys.usable`: 7 sites, 1 definition.
3. **Authz migration complete (item 1 complete).** All 24
   hand-rolled authorize+deny+throw sites now call
   `AuditedAuthorizer.require` (verified exact-shape before each
   rewrite; behavior identical — the added `WRONG_TENANT` mapping
   is unreachable at these sites). No `authz.authorize` call site
   outside the helper remains except the helper itself.
4. **No live issues found in passing.** `PlanParser.parseContext`
   (plan-supplied trust data) is test-fixture-only; production
   guards build context from snapshots.

Full verification: backend 501/501, Playwright 11/11 on the
rebuilt compose stack, `check_repository.py` green. Frontend
unchanged this batch (last green stands). Changes uncommitted
pending review alongside batch 4.

## 2026-10-30 verification and corrections

A fresh clean Java 25 build passed 496 tests before the new denial regression.
The historical 501-test totals above are not the current clean baseline.

The authorization helper migration did not by itself guarantee durable denial evidence.
An HTTP regression against issuer-key registration/revocation reproduced a 403 with no retained denial row because the enclosing transaction rolled back on `ForbiddenException`.
`AuditService.recordDenial` now owns a separate transaction, so a caller rollback cannot erase its refusal evidence.
Success audit records still join the business transaction and preserve atomicity.
`IssuerKeyLifecycleTests.forbiddenKeyMutationsRetainDenialEvidence` checks both denied operations, retained reason/action evidence and absence of a registered key.
This corrects the earlier claim that helper migration alone completed denial durability.

`AadContext` now validates every direct constructor call as well as the issuance factory.
Untrusted parsed fields use a separate internal `Parsed` value, preserving the signer's exact missing-field refusal behavior without exposing an encodable invalid context.
The regression covers direct construction with framing injection and missing required values.

The frontend standalone typecheck now uses `tsc -b` across all project references.
A temporary intentional application type error passed under the old command and failed under the corrected command; the probe was removed afterward.
The BFF disables saved API requests, fixing the reproduced post-login JSON landing.
Browser tests assert direct SPA landing and no longer navigate home to hide it.
The verification browser cases now include actual signed-POST replay, signature tampering and a different holder key.
See the [browser assessment](sov-041-browser-e2e.md) for scope and retained results.

Independent denial transactions also required tenant-pin cleanup across transaction suspension.
A two-connection pool regression reproduced a retained tenant setting after an inner `REQUIRES_NEW` transaction inherited the outer cleanup marker.
`TenantDataSource` now suspends and restores that marker with its transaction synchronization, so each transaction registers cleanup for its own connection.
`TenantDataSourceTests.suspendedTransactionsResetBothConnectionPins` checks both raw pooled connections after completion and confirms the resumed outer transaction still sees its intended tenant.

Final clean verification on 2026-10-30: backend `clean verify` passed 498/498 with zero failures/errors/skips; frontend typecheck/build/lint, repository validation and whitespace checks passed.
The expanded browser suite passed 13/13 before the final image rebuild.
A later run exposed a test helper view-transition race: filling before React switched views could target the old consent form and leave the verification request ID empty.
The helper now waits for the verification heading before filling shared fields; final-image results are recorded after retest.

After the view-transition correction, the final rebuilt-image browser run passed 13/13 and all four verification cases passed three repeated runs (12/12).
