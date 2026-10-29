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
