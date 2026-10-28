# Developer platform, APIs, SDKs, and dashboards

**Status:** business contract proposal, 2026-10-27.
This specifies the developer experience and dashboard scope; SDKs, developer portals, and the new APIs are not released or implemented here.
The [SRS](../requirements/software-requirements-specification.md) remains the requirements baseline.

## Standard mechanisms and Sovra resources

Use versioned HTTPS resource APIs described with [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.2.html), standard OAuth/OIDC mechanisms, and selected credential protocol adapters.
Custom business resources describe Sovra's enrollment, consent, document review, evidence planning, and trust workflows.
Do not customize cryptographic algorithms or relabel custom resource routes as OpenID4VCI/OpenID4VP.
The chosen proof profile remains a separate interoperability gate.

Separate approved origins and audiences for federation/developer control, issuer-local data, and RP verification.
An issuer-node API is addressed directly through approved issuer metadata, not through a shared source-data proxy.
A central developer dashboard must not fetch/aggregate subject documents or extracted personal fields.
SDK endpoint selection uses a trusted issuer configuration and validates origin/audience; a tenant supplied by a model or untrusted redirect does not select a data destination.

The [issuer-node OpenAPI draft](issuer-node-api.openapi.yaml) specifies a bounded initial document/enrollment contract.
The [existing orchestration API](api-contract.openapi.yaml) is an older custom demo draft and keeps its existing envelope until a versioned compatibility transition.
The drafts are not a complete production API or evidence that endpoint handlers exist.

## Shared API rules

| Concern | Required behavior |
| --- | --- |
| Authentication | Standard OAuth access-token validation for audience/issuer/scopes; dashboard login uses an approved user flow with PKCE and privileged MFA; credentials stay out of URLs/browser bundles |
| Authorization | Scopes are necessary but insufficient: principal, tenant, issuer, object, purpose, role, and current consent/approval also apply |
| Errors | New APIs use RFC 9457 application/problem+json with safe Sovra code, correlation_id, and retryable extensions; HTTP status agrees with the body |
| IDs | Opaque resource-specific IDs; no embedded identity numbers, raw document hashes, or globally correlating person IDs |
| Writes/retries | Authenticated caller/issuer/route-scoped idempotency keys bind body hashes and expiry; conflicting reuse fails; unsafe writes are not blindly retried |
| Concurrency | Version/ETag and If-Match on review/decision changes; stale changes return a conflict/precondition failure |
| Long work | Asynchronous job resource with explicit pending/running/succeeded/failed states and safe polling/backoff; transport acceptance is not identity approval |
| Lists | Bounded opaque cursor pagination with filters, stable ordering, object authorization, and no cross-tenant enumeration |
| Bounds | Documented request/content/decoder limits, timeouts, rate/concurrency quotas, and Retry-After where applicable |
| Confidentiality | Sensitive responses are non-cacheable; telemetry excludes bodies, bearer tokens, grants, and personal fields |
| Evolution | Published contract/SDK compatibility, deprecations, explicit schema versions, and contract-diff checks; no silent semantic changes |

[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) defines problem details and permits application extensions.
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) is the OAuth security reference; authentication-provider and sender-constraining choices remain part of the approved deployment design.
An API scope grants no authority to bypass local document decryption or identity enrollment checks.
After current authorization, an identical valid idempotency retry may recover its original receipt before evaluating a now-stale mutation precondition; that recovery must never execute the mutation again.

## Resource families and contract boundaries

| API surface | Proposed resources/actions | Data boundary |
| --- | --- | --- |
| Federation discovery | Issuers, capabilities, schema/profile references, public signing keys, trust epochs | Approved public metadata only |
| Organization/developer control | Organizations, apps/service principals, allowed origins/redirects, scopes, credential lifecycle, sandbox configuration | Organization configuration and sanitized usage, no person-level source records |
| Issuer node | Subjects, enrollments, documents/content, extraction jobs/revisions/reviews, access grants, issuance requests | Issuer-local images, fields, and approval records |
| RP verification | Intents/plans, guarded requests, sessions, consent, presentations, results | Purpose/consent-approved evidence only |
| Operations/security | Authorized audit evidence, policy/trust changes, key health, retention/recovery status | Restricted per issuer/tenant/role and location |

The node draft covers subject/enrollment creation and reads, image upload/read grants, extraction/revision/review, enrollment decisions, issuance-request admission, scoped deletion requests, and job status.
Production list/search, app administration, policy/trust, credential delivery/status, and callback contracts require their own reviewed schemas before exposure.
In particular, an issuance request is not yet the final credential issuance protocol.
Future callbacks must authenticate signed content and timestamp/event identity, enforce deduplication/replay windows, validate destinations, and minimize payloads; they are not silently part of this draft.

## Integration onboarding

1. An organization requests issuer or RP capabilities; identity/authority and an authorized administrator are reviewed before activation.
2. The integration administrator registers an application with an environment, approved origins/redirects, issuer/audience, and requested least-privilege scopes.
3. An authorized approval provisions its service/user authentication through the chosen identity provider and records scope/credential lifecycle ownership.
4. The developer receives versioned API references, SDK documentation, synthetic sandbox fixtures, and positive/negative quickstarts.
5. Contract tests verify endpoint/audience, consent, issuer trust, idempotent retries, error behavior, and egress before production activation.

Development and production credentials, data, keys, permissions, and endpoints remain separate.
Publishing a discovery entry or creating an app does not establish government accreditation or allow image decryption.
Credential rotation/revocation and administrator removal must be available and audited.

## SDK requirements

Provide maintained Java and TypeScript SDKs first, subject to packaging/licensing and compatibility review.
Use typed clients generated or checked against published OpenAPI, with reviewed authentication, retry, regional routing, error, and telemetry wrappers.
Generated code alone is not the supported developer experience or a security assurance.

| SDK capability | Required behavior |
| --- | --- |
| Typed resources | Clear issuer/node, enrollment/document, and RP-verification clients with typed states and errors |
| Configuration | Explicit environment, trusted origin/issuer/audience, deadlines, and supported API versions; no automatic cross-region fallback |
| Credentials | Provider-based token acquisition/refresh; no default logging, serialization, or browser exposure of server secrets |
| Browser boundary | Only approved short-lived user/session operations; server credentials and KMS operations are excluded |
| Retry behavior | Bounded backoff and safe Retry-After handling; writes require the declared idempotency contract and cannot create duplicate proof acceptance |
| Long work | Poll/cancel where supported, bounded timeouts, typed job outcome; a pending job never means verified identity |
| Uploads | Validate declared limits, target only approved local node, report safe progress, and avoid silent retries or arbitrary URL fetching |
| Diagnostics | Safe correlation IDs and opt-in sanitized diagnostics; no automatic personal fields, image bodies, document hashes, or tokens |
| Release quality | Signed/provenanced packages, version compatibility matrix, API-diff checks, license/dependency review, contract tests, examples, and upgrade guidance |

No SDK exposes decrypt-key access, skips consent, disables certificate validation, or treats an internal subject ID as an identity credential.
The portal must clearly distinguish released SDK versions from sample/pseudocode or planned capabilities.
A clean synthetic quickstart in each supported language is an acceptance gate.

## Role-specific dashboards

| Dashboard | Functions | Access limits |
| --- | --- | --- |
| Issuer workspace | Pending enrollments, controlled image review, extraction comparison/corrections, approval/rejection, scoped issuance, status/revocation, audit, keys/worker health | Source content stays on the issuer-approved origin; image access requires a separate purpose-bound grant; corrections create new review revisions |
| Holder workspace | Own enrollment status, document submission, permitted corrections/requests, credentials, incoming consent requests, disclosure history, recovery | No other holder's records; pending enrollment is visibly distinct from verified/issued status |
| RP/developer workspace | Organization/apps, scopes/credentials, integration guides/SDKs, sandbox, verification requests/results, rate/error metrics, permitted callbacks | No issuer source images, raw extraction values, KMS access, or generalized person search |
| Federation/security workspace | Approved issuer/scope/schema/trust changes, onboarding decisions, sanitized health, privileged access and audit | No central citizen index, no bulk source-document access, no implicit issuer key-use permission |

Dashboard roles use the same APIs and object/purpose authorization as SDKs.
Being an administrator, auditor, or support operator is not a blanket decryption entitlement.
Original-image viewers require safe rendering and approved caching/download behavior; they must not forward content to analytics or the planner.
Use accessible tables, explicit pending/review/approved/rejected states, and comparisons showing exactly which source/field revision is being approved.
High-impact approval separation, supported clients, numeric limits, and app/SDK release details remain explicit SRS decisions.

## Privilege removal and operational contracts

Application/admin removal, token expiry, decryption-grant expiry and active-job containment require declared measurable propagation bounds.
SDK retries and job polls must reauthorize current caller/resource scope and must not extend a known denied permission or expired grant.
Operator dashboards expose sanitized evidence and approved actions; access to a dashboard does not grant deployment, migration, signing or unwrap authority.
Privileged enrollment/recovery and high-impact approval flows require phishing-resistant authentication and bounded elevation.
Expose truthful degraded/unavailable states when freshness, replay storage, audit or provider authority is unsafe even if the API process is alive.
See the [implementation backlog](implementation-backlog.md) for API, SDK, dashboard and access-lifecycle acceptance criteria.

## Production contract completion

Before release, resolve SRS proof, authentication, locality, document crypto/retention, SDK packaging, and approval-policy decisions.
Validate the complete OpenAPI set, scope matrix, examples, generated clients, browser credential handling, and consumer/provider compatibility.
Run the expanded [security cases](security-validation-plan.md), including cross-issuer images, default-tool/dashboard privileges, unsafe SDK retries, and out-of-region routing.
