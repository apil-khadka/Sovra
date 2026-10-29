# Business API compatibility contracts (SOV-015)

**Baseline:** business SRS v0.6, 2026-10-28.
**Scope:** versioned control-plane, issuer-local, and verifier contracts;
approved origins, audiences, and per-operation scopes; RFC 9457 errors;
bounded pagination/filters; ETags/preconditions; jobs, cancellation, and
authenticated idempotent retry semantics.
**Authority:** the exact implemented contract is
[implemented-api.openapi.yaml](implemented-api.openapi.yaml) (currently
0.2.0). This document states the rules that contract follows; where they
conflict, the OpenAPI file plus the
[parity test](../../backend/src/test/java/dev/sovra/web/ApiCompatibilityTests.java)
win and this document must be corrected.

This API is a custom synthetic-demo control plane. It is not OpenID4VCI,
OpenID4VP, or SD-JWT VC conformance evidence, and no endpoint claims
protocol interoperability (SOV-036 owns profile qualification).

## 1. API families, origins, and audiences

| Family | Paths | Origin | Audience | Auth |
| --- | --- | --- | --- | --- |
| Control plane | `/api/trust/*`, `/api/audit/*`, `/api/guard/*`, `/api/plans/*`, `/api/whoami`, `/api/health` | configured control-plane host | control-plane service account | Service-account token, except `/api/health` and the two public federation reads below |
| Issuer-local | `/api/issuance/*` | issuer-local host | issuing tenant | `ISSUER_OPS` / `TENANT_MEMBER` (per operation) |
| Verifier | `/api/consent/*`, `/api/verification/*` | verifier host | consented RP audience | `RP_CLIENT` / `TENANT_MEMBER` (per operation) |

Public federation metadata (no authentication): `GET /api/health`,
`GET /api/trust/snapshots/current`, `GET /api/issuance/jwks.json`. Every
other operation requires an authenticated caller, and authority always
comes from the authenticated context — never from request fields or
forwarded headers (IF-02). Trusted routing rejects arbitrary redirects
and wrong audiences: consent binds the exact audience, and verification
refuses any submission whose audience differs from the consented one.

Browser origin (SOV-041): the packaged demo serves the React SPA
from the backend origin itself, so the SPA, BFF session cookies,
authorization callback, and logout share one origin with the API
(`http://localhost:8080` for compose `app-a`). No CORS
configuration exists because no cross-origin browser caller is
supported; session cookies are host-scoped with no `Domain`
attribute. BFF sessions are per-instance and not portable across
backend instances. See
`sov-041-same-origin-packaging.md` for the serving decision.

Per-operation authorizing roles are recorded in the OpenAPI
`x-sovra-scopes` extension and enforced by the central authorization
service; the matrix below summarizes them.

| Operation | Roles |
| --- | --- |
| health, currentSnapshot, issuerKeys | public |
| whoami | any authenticated account |
| listAuditEvents | `AUDIT_READER`, `TRUST_ADMIN` |
| proposeTrustChange, approveTrustChange, activateSnapshot | `TRUST_ADMIN` |
| registerIssuerKey, revokeIssuerKey | `TRUST_ADMIN` |
| issueCredential, revokeCredential | `ISSUER_OPS` |
| getCredential, credentialStatus | `TENANT_MEMBER`, `ISSUER_OPS` |
| createProofRequest, verifyPresentation | `RP_CLIENT` |
| reviewProofRequest, decideProofRequest, getConsentPresentation, getVerificationDecision, validatePlan, proposePlan, planStatus | `TENANT_MEMBER`, `RP_CLIENT` |

## 2. Versioning and evolution (NFR-09, IF-09)

- The OpenAPI `info.version` is the contract version. Any behavior
  change to a documented request, response, status, header, or error
  body requires a version bump in the same change.
- Additive changes (new paths, new optional parameters, new response
  headers such as `ETag`) are minor-compatible and need no migration.
- Breaking changes (removing/renaming members, changing statuses, or
  altering default error bodies) require a major version, a migration
  note in this document, and mixed-version consumer tests before the old
  shape is removed.
- Unknown JSON members are rejected (`fail-on-unknown-properties`), so
  producers can never silently widen a contract; SDK fixtures must agree
  with the OpenAPI schemas (SEC-42).

## 3. Errors (IF-07, IF-10)

Default error bodies are the frozen legacy contract and stay minimal by
design: 404s are always empty (never confirm or deny another tenant's
objects), 403s carry only `forbidden` plus the machine-readable reason
code, and no body leaks tokens, secrets, keys, or trust internals.

Clients that send `Accept: application/problem+json` receive RFC 9457
problem details instead: `type`/`title`/`status` plus the Sovra
extensions `code`, `correlationId`, and `retryable`. 404s stay empty in
both variants. New operations (SOV-013 planning and later) document
their failures against the `Problem` schema; legacy operations keep
their default bodies byte-identical while offering the same
negotiation. There is no separate legacy error format to migrate data
from — migration means adopting the `Accept` header, nothing else.

Caller behavior depends on codes, not prose: `retryable: false`
(invalid evidence, denial, replay, conflict) must never be retried as
approval, and `retryable: true` (dependency outages such as
`trust_unavailable` / `dependency_unavailable`) may be retried later
without implying any decision.

## 4. Pagination, filters, ETags, preconditions (IF-11)

- List operations define bounded limits. `GET /api/audit/events`
  accepts `limit` (1..100, default 50) over the stable
  `(occurred_at, id)` newest-first ordering.
- Keyset cursors are opaque strings. The audit cursor encodes the last
  row's `(occurred_at, id)` position; malformed cursors are a 400.
  Tenant filtering applies before the cursor, so a foreign cursor can
  only narrow the caller's own page, never widen it.
- No other list operation exists at G1; cursor pagination beyond audit
  events is reserved. When new lists arrive they must follow the same
  conventions: documented bound, stable ordering, opaque cursor,
  boundary-first filtering.
- Stable reads emit strong `ETag` content hashes: the consent review
  (tag covers the derived state, so expiry or a decision invalidates a
  cached review) and the verification decision (immutable, tag stable
  for the row's life). Exact `If-None-Match` matches return 304.
  `If-None-Match: *` never matches, and 404s carry no tag.
- Mutation preconditions beyond single-shot semantics are reserved.
  Today, duplicate-mutation safety comes from single-shot state
  machines: deciding twice is 409, revoking twice converges, and
  replays return the original bytes.

## 5. Jobs, cancellation, idempotent retry (IF-12)

No long-running work exists at G1: every operation completes
synchronously, so no job states, cancellation endpoints, or polling
contracts are defined. The reservation for them is:

- Long work will expose scoped job resources with explicit states;
  job admission or completion will never imply identity approval.
- Unsafe writes and jobs will require an authenticated idempotency key
  following the issuance convention: the `Idempotency-Key` header
  (`^[A-Za-z0-9_-]{1,128}$`), byte-identical replay for the same key
  and request, and 422 for the same key with a different request.
- Duplicate, reordered, or cancelled calls will never bypass state
  checks or rewrite a committed decision.

## 6. Validation and non-goals (SEC-21, SEC-29, SEC-42, SEC-43)

- Provider/consumer parity is enforced by test: every controller route
  must appear in the OpenAPI file at the pinned contract version, and
  no documented path may be stale.
- Malformed, ambiguous, oversized, and duplicate-key inputs are
  rejected before any business effect; parsers never establish
  authorization.
- SDKs and dashboards consume only these published operations with
  the documented origins, audiences, and scopes; direct database or
  key access and automatic cross-region fallback are prohibited.
- Error, pagination, precondition, and retry contract changes are
  covered by consumer fixtures; the frontend holds no server
  credentials and logs no secrets.
- Pending application/issuer identifiers confer no identity or trust
  authority; approval, uniqueness, holder binding, and scope checks
  remain enforced across enrollment and onboarding.

## 7. Open decisions

OD-16 (developer contract and SDK releases) stays open until the
customer developer-platform release: Java/TypeScript packaging and
version policy, application onboarding, sandbox/docs, the dashboard
role matrix, and callback contracts (if adopted) are all still to be
specified. This document plus the OpenAPI file are the G1 input to
that decision, not its closure.
