# Sovra Software Requirements Specification

**Version:** 0.5 - security implementation baseline draft.
**Date:** 2026-10-27.
**Status:** draft for product, engineering, security, and operations review.
**Scope:** federated identity-evidence interoperability platform, including a synthetic demonstration and production release requirements.

This specification expands the hackathon-only scope of version 0.2 and the business baseline of version 0.3.
Version 0.4 adds issuer-local encrypted documents, extraction/enrollment lifecycle, developer APIs/SDKs, and role-specific dashboards.
Version 0.5 makes the mission-critical research controls explicit requirements and links them to an implementation backlog and required security/recovery scenarios.
It describes required behavior, not implemented features or completed security assurance.
The repository contains a Java backend bootstrap and a React frontend bootstrap; the earlier TypeScript prototype was removed and only its JSON fixtures are preserved as migration evidence. The G1 vertical slice and security validation remain pending.

## Contents

1. [Purpose and conventions](#1-purpose-and-conventions)
2. [Product scope and release boundaries](#2-product-scope-and-release-boundaries)
3. [Actors and authority](#3-actors-and-authority)
4. [System context and constraints](#4-system-context-and-constraints)
5. [Principal use cases](#5-principal-use-cases)
6. [Functional requirements](#6-functional-requirements)
7. [Data requirements](#7-data-requirements)
8. [External interfaces](#8-external-interfaces)
9. [Security requirements](#9-security-requirements)
10. [States and consistency invariants](#10-states-and-consistency-invariants)
11. [User experience requirements](#11-user-experience-requirements)
12. [Non-functional requirements and target register](#12-non-functional-requirements-and-target-register)
13. [Verification and traceability](#13-verification-and-traceability)
14. [Release acceptance](#14-release-acceptance)
15. [Open decisions and dependencies](#15-open-decisions-and-dependencies)
16. [References and change control](#16-references-and-change-control)

## 1. Purpose and conventions

### 1.1 Purpose

Sovra enables a relying party to request narrowly scoped evidence from independently governed credential issuers, with explicit holder consent and deterministic verification.
An AI planner helps discover compatible issuer capabilities and interpret approved, supplied policy and schema documents.
The planner does not decide who is trusted, issue credentials, grant consent, or accept evidence.

This SRS gives product owners, implementers, integration partners, security reviewers, and operators a common basis for implementation and acceptance.
Confidentiality, correct authorization, evidence integrity, and recoverable operation take priority over throughput optimization.

### 1.2 Requirement conventions

**Shall** identifies a requirement of this draft.
Requirements become an approved release baseline only after review; no approval or security sign-off is asserted here.
Every implemented requirement needs an owner and linked acceptance evidence.

| Applicability | Meaning |
| --- | --- |
| Core | Required for the first complete synthetic vertical slice and retained for production |
| Production | Required before the corresponding feature processes real sensitive data or is offered to a customer |
| Future | Outside the initial release; requires a separate scope decision and acceptance evidence |

Core and Production obligations are cumulative for production.
They replace the earlier P0/P1/P2 labels, which described hackathon scheduling rather than security importance.
FR-01 through FR-15 retain their subject areas, with clarified scope and acceptance criteria.

### 1.3 Definitions

| Term | Meaning |
| --- | --- |
| Issuer | An authority configured to sign particular credential types and claims under an approved trust scope |
| Holder | The person or authorized agent controlling a credential and approving a presentation |
| Relying party (RP) | An organization requesting and evaluating evidence for an approved purpose |
| Tenant | An organizational access-control boundary; not automatically equivalent to a country or issuer |
| Issuer domain | An independently controlled authority, key, and source-data boundary |
| Credential | Issuer-signed claims under an explicitly identified proof profile |
| Presentation | Evidence supplied to a verification session with required holder, audience, and challenge binding |
| Trust metadata | Authorized issuer/key/scope/status information bound to a version or epoch |
| Policy | An approved, versioned set of evidence, assurance, purpose, and disclosure rules |
| Candidate plan | An untrusted mapping proposal from an RP intent to available evidence |
| Guard | Deterministic code validating a candidate against approved policy and trust inputs |
| Verification session | A bounded request binding RP, holder context, purpose, plan, challenge, and expiration |
| Verified evidence | Evidence passing configured technical checks; not a legal KYC/CDD verdict |
| Synthetic data | Fictional fixtures containing no real-person records or usable production credentials |
| Subject ID | Opaque issuer-local record reference, not proof of a person or a government-issued identifier |
| Enrollment | Policy-governed source-evidence validation, holder binding, review, and activation process |
| Document artifact | Immutable uploaded image or derived object with its own version, encryption envelope, and protected integrity reference |
| Extraction revision | Attributable candidate observations/normalized fields bound to an exact source and pipeline version |
| Document access grant | Short-lived principal/resource/version/purpose-bound authorization used with current authentication, not an encryption key |

## 2. Product scope and release boundaries

### 2.1 Objective and included capabilities

Identity systems differ in formats, schemas, trust anchors, assurance, and policy requirements.
Sovra shall help an RP discover a supported evidence path without requiring unnecessary source identity documents or a central citizen database.
Successful operation returns only authorized, consented, sufficiently fresh evidence; unsupported or uncertain requests remain unverified.

The initial scope includes issuer configuration, scoped issuance and revocation, public trust metadata, RP policy/intent management, advisory AI planning, deterministic validation, consent, challenge-bound presentation, verification, and minimized audit records.
Production adds authenticated tenant administration, governed trust/policy changes, managed signing keys, durable state, operational recovery, retention controls, and independently reviewed security evidence.
The business release also includes issuer-local image custody, extraction and evidence review, enrollment and information updates, documented APIs/SDKs, integration onboarding, and role-specific dashboards.

The first supported outcome is age_over_18, represented by a dedicated signed age-threshold attestation under an identified demonstration profile.
Adding outcomes requires explicit schema, policy, issuer-scope, consent, and negative-test coverage.

### 2.2 Synthetic demonstration

The demonstration shall use fictional issuer/RP identities and synthetic holder records only.
At least two independently configured issuer domains shall demonstrate separate authority and storage.
A previously unseen compatible schema and an incompatible schema shall be evaluated without adding a fixture-specific adapter after disclosure.
An eligible live Meta model shall be used for the hackathon planner workflow.
Submission logistics remain in the [hackathon guide](../hackathon/rules-and-deliverables.md), not in the business release criteria.

### 2.3 Exclusions and claim boundaries

The initial scope excludes biometric matching, acting as a government identity authority, sanctions screening, automatic legal KYC/AML approval, a global citizen index, blockchain, custom cryptographic protocols, and nationwide identity infrastructure.
Official accreditation, sovereign deployment, residency, unlinkability, and protocol conformance shall not be claimed without evidence for the exact deployment/profile.
Full OpenID4VCI/OpenID4VP interoperability and cryptographic selective disclosure depend on profile selection and testing.
Hiding fields in a complete signed token shall not be presented as selective disclosure.
Billing, subscription management, and native mobile-wallet applications require separate scope and requirements.

### 2.4 Production boundary

Real sensitive data shall not enter the system until applicable Production requirements, open-decision gates, and independent assessments are satisfied.
A working demo or successful framework build does not meet that boundary.
The production release remains a gated target.

## 3. Actors and authority

| Actor | Authorized responsibility | Authority limit |
| --- | --- | --- |
| Holder | Receive credentials, inspect requests, approve or refuse a specific presentation | Cannot sign as issuer or approve another holder's request |
| Issuer administrator | Manage permitted issuance, source records, status, and issuer key lifecycle | Cannot access another issuer's data or grant its own federation authority |
| RP operator | Submit intents and retrieve permitted results for the RP | Cannot read issuer source databases or bypass consent |
| Policy approver | Approve versioned purpose, claim, assurance, freshness, and disclosure rules | Model output is not an approved policy change |
| Federation administrator | Maintain approved issuer trust scopes and public metadata | Registry administration does not establish sovereign accreditation |
| Security administrator | Manage security configuration, privileged access, incidents, and key-compromise response | No blanket access to holder identity records |
| Platform operator | Deploy, monitor, back up, restore, and diagnose authorized infrastructure | Cannot bypass signing, consent, or tenant boundaries |
| Auditor | Read authorized decision evidence and configuration history | No private keys or unrestricted identity-record access |
| AI planner service | Read approved metadata through bounded tools and propose plans | Cannot sign, approve consent, modify policy/trust, or accept evidence |
| Issuer reviewer | Review exact source/extraction revisions and holder-binding evidence under approved assurance policy | OCR confidence and administrator status alone confer no identity authority |
| Integration developer | Configure authorized organization applications and use sandbox, contracts, SDKs, and permitted verification APIs | No default image, extracted PII, signing, or key-service access |
| Local extraction service | Process authorized documents within the issuer boundary using constrained workload identity | No shared-planner access, unapproved OCR egress, or signing authority |

Roles may be held by the same person in a synthetic demo.
Production privileges shall remain separately expressible, reviewable, and scoped even when personnel overlap.
No role assignment alone shall authorize cross-tenant or cross-issuer access.

## 4. System context and constraints

### 4.1 Components and technology

Sovra comprises issuer nodes, a holder-facing wallet/consent interface, an RP/verifier interface, federation metadata, a deterministic guard/verifier, and an advisory planner.
The [system architecture](../architecture/system-architecture.md) defines their relationships.
Components shall use explicit interfaces rather than directly accessing another issuer's source database.

The backend shall use Java 25 LTS with Spring Boot, Spring Security, Spring AI, Maven, PostgreSQL, and versioned SQL migrations.
The [Java/Spring baseline](../architecture/java-spring-baseline.md) records dated framework candidates, compatibility evidence, and dependency-selection conditions.
Patch versions, container digests, plugins, and the effective dependency graph shall be pinned and revalidated at implementation and release.
Spring AI shall remain behind a planner interface outside final authorization.
The browser client may use React/TypeScript through versioned API contracts.

Use a modular backend and a small number of deployables.
Authority, signing permissions, tenant access, and data boundaries shall remain explicit regardless of topology.
Separate containers on one host establish logical isolation only.
The [federated document lifecycle](../architecture/federated-document-lifecycle.md) defines the local vault, extraction, decryption, hash/provenance, and ID boundaries.
The [developer platform](../engineering/developer-platform.md) defines standard API mechanisms, custom resources, SDK scope, and dashboard responsibilities.

### 4.2 Assumptions and dependencies

Production issuers require separately established authority, scope, proofing assurance, and operational agreements.
RPs must supply approved policies; the model shall not invent authority from arbitrary retrieved prose.
The selected model endpoint requires a live contract test for authentication, model ID, structured outputs, tools, and failures.
The proof library must support the exact credential/presentation profile and runtime baseline.
Deployment, custody/recovery, retention, operational targets, and production privacy/legal assessment remain open decisions in Section 15.

## 5. Principal use cases

| Use case | Trigger and preconditions | Successful result | Exception behavior |
| --- | --- | --- | --- |
| UC-01 Onboard issuer | Authorized trust administrator reviews an issuer and requested scope | Approved version binds issuer, keys, credential/claim scope, assurance, endpoints, and provenance | Incomplete or unapproved onboarding grants no authority |
| UC-02 Issue credential | Authorized issuer has an approved source/holder context and permitted request | One scoped signed credential is issued and recorded durably | Retries do not duplicate issuance; unauthorized claims or unavailable signing fail safely |
| UC-03 Verify evidence | Authorized RP supplies an approved intent/policy | Guarded plan, consent, and fresh valid proof lead to one committed VERIFIED_EVIDENCE result | Invalid trust/proof/consent/status/binding/replay conditions never succeed |
| UC-04 Refuse consent | Holder inspects a pending request | Refusal or expiration occurs without presenting evidence | No background presentation or fallback export |
| UC-05 Revoke credential | Authorized issuer changes status | Durable revocation affects verification under the declared freshness policy | Stale or unavailable status is not implicit validity |
| UC-06 Change trust/policy/keys | Authorized approver submits a versioned change | Auditable approval and explicit transition rules | Rollback, substitution, and model changes cannot silently expand authority |
| UC-07 Handle failure | Model, registry, status, database, or signing dependency fails | Truthful unavailable, rejected, or manual-review result with safe retry guidance | No fabricated mapping, approval, or success before commit |
| UC-08 Inspect decision | Scoped RP operator/auditor requests a result | Permitted evidence identifies decision inputs, versions, and safe reasons | Cross-tenant lookup reveals neither records nor unauthorized existence information |
| UC-09 Recover service | Authorized operator restores state or contains compromise | Recovery preserves security invariants and approved recovery objectives | Lost replay history or compromised keys cannot silently permit acceptance |
| UC-10 Enroll from documents | Authorized issuer workflow or holder invitation creates a pending local subject/enrollment | Local encrypted upload, constrained extraction, reviewed evidence, and holder binding establish permitted issuance eligibility | Creating a subject ID, OCR text, or an uploaded file never automatically verifies identity |
| UC-11 Correct/add information | Authorized holder/operator submits new evidence or corrects candidate fields | New document/extraction/review versions preserve provenance and reassess affected claims | Stale approvals cannot authorize changed values; signed credentials are not overwritten |
| UC-12 View source image | Authorized local actor requests a specific image for an approved purpose | Short-lived grant and current permissions permit authenticated local decryption and delivery | Bad context/tag, expired grant, wrong actor, or denied KMS produces no plaintext |
| UC-13 Integrate an organization | Approved organization registers an application and scopes | Developer discovers contracts/SDKs, passes synthetic quickstart and negative tests, then requests production activation | App registration grants no issuer accreditation or document-decryption entitlement |
| UC-14 Manage through dashboard | Holder, issuer reviewer, RP developer, or federation operator signs in | Role/issuer-specific workspace exposes only permitted lifecycle and integration actions | Shared dashboard/support privilege cannot aggregate local source records or bypass APIs |

## 6. Functional requirements

### 6.1 Evidence workflow

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| FR-01 | Core | The system shall isolate issuer domains by configuration, source-data access, key identity, and signing permission | Two issuers cannot use each other's source database or signing identity |
| FR-02 | Core | An issuer shall issue only approved, purpose-scoped signed claims to an authorized holder context | Permitted synthetic issuance verifies; unauthorized claims/holders fail |
| FR-03 | Core | Federation metadata shall identify approved issuer keys, credential/claim scope, status, and trust version | Unknown, expired, suspended, or out-of-scope issuers fail |
| FR-04 | Core | RP requests shall validate purpose, outcome, RP identity, and approved policy/version before planning | Invalid/spoofed intent fails before a model call or disclosure |
| FR-05 | Core | The planner shall use bounded read-only discovery tools and return an untrusted candidate | Live model trace identifies actual model and versioned tool inputs; candidate cannot execute itself |
| FR-06 | Core | The guard shall independently reject unsupported, overbroad, untrusted, uncited, or policy-mismatched mappings | Invented issuer/claim/citation and excess-disclosure cases fail before presentation |
| FR-07 | Core | Holder approval shall bind exact RP, purpose, claims, plan, and expiration before presentation | Refusal, expiry, changed request, or missing consent prevents delivery |
| FR-08 | Core | Verification shall require valid signature, issuer/key scope, type/claims, holder, time, status, audience, consent, and challenge | Independently invalid conditions each prevent VERIFIED_EVIDENCE |
| FR-09 | Core | Audit/diagnostic output shall contain only minimized fields authorized for its purpose | Canary tests find no prohibited data in audit/telemetry paths |
| FR-10 | Core | The UI shall distinguish candidate, guard, consent, and final verification decisions using sanitized traces | Rejected/planned evidence never appears verified; no private model chain-of-thought |
| FR-11 | Core | Evaluation shall compare frozen compatible/incompatible unseen schemas against a static baseline without post-reveal fixture adapters | Fixture, prompt, configuration, and full result records reproduce the comparison |
| FR-12 | Core | Uncertainty or unavailable dependencies shall produce an explicit non-verified result | Outage/ambiguity cases yield rejection, manual review, or unavailable without fake success |
| FR-13 | Core | Authorized issuers shall revoke credentials and verification shall enforce the selected freshness/failure policy | Valid-then-revoked, stale, malformed, and missing-status cases follow policy |
| FR-14 | Production | Each integration shall declare and validate its immutable credential/presentation profile before conformance claims | Independent positive/negative interoperability evidence covers the exact profile |
| FR-15 | Future | Selective disclosure shall use a selected cryptographic profile and preserve its verification properties | Disclosure/tampering tests support the specific claim; field hiding is insufficient |

### 6.2 Administration and lifecycle

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| FR-16 | Production | Protected operations shall authenticate principals and authorize role, tenant, issuer/RP, and resource access | Anonymous, wrong-role, cross-tenant, and alternate-entry tests fail without business effects |
| FR-17 | Production | RP policies shall have approval provenance and immutable purpose/evidence/assurance/freshness versions | Unapproved edits are unusable; revision/approver history is traceable |
| FR-18 | Production | Trust changes shall require authorized approval and retain scope, effective version/time, and provenance | Unauthorized changes and stale rollback cannot expand acceptance |
| FR-19 | Core | Sessions shall bind approved plan/version/hash, RP/audience, holder context, nonce, purpose, and expiry | Changing any bound element fails |
| FR-20 | Core | Consent receipts shall bind the authenticated or proof-bound holder to the immutable request | Another holder/session or changed request invalidates the receipt |
| FR-21 | Core | Challenge consumption and terminal acceptance shall be durable and atomic across instances | Concurrent valid submissions create at most one fresh acceptance, preserved after restart |
| FR-22 | Core | Issuance shall support issuer-scoped idempotency with bound request hash and validity window | Identical authorized retry returns original; different content conflicts without minting |
| FR-23 | Production | Issuer key lifecycle shall support generation, publication, rotation, retirement, and compromise response | Rotation/retirement/compromise and actual key-access tests pass |
| FR-24 | Core | Result retrieval shall enforce caller/resource authorization and return safe outcomes and version references | Correct RP retrieves its result; unrelated principals cannot retrieve/enumerate it |
| FR-25 | Core | Responses shall distinguish technical verification from legal KYC/CDD determinations | Result/UI never implies legal approval from proof success |
| FR-26 | Production | Administrators shall access only permitted status, configuration, and lifecycle history | Role-specific workflows prevent unnecessary source-data access/export |
| FR-27 | Production | Security-sensitive changes and terminal decisions shall have durable protected audit evidence | Tamper/outage cases meet the declared fail-closed or durably pending contract |
| FR-28 | Production | Privileged user/service identity lifecycle shall support scoped enrollment, changes, removal, and recovery | Removed privileges and revoked/rotated credentials no longer authorize access |
| FR-29 | Core | Liveness, dependency readiness, and degraded operation shall be distinct observable conditions | Planner outage does not hide verifier health or imply evidence approval |
| FR-30 | Production | Backup, restore, and migration shall preserve issuer/verifier security invariants | Drills preserve declared recovery, consent, revocation, and replay guarantees |
| FR-31 | Production | Manual review shall preserve original non-verified outcomes and record follow-up separately | Reviewer cannot rewrite invalid proof/missing consent/untrusted issuer into verified evidence |
| FR-32 | Production | New outcomes/schemas/issuer integrations shall require approved scope and passing contract/security tests | Unapproved integrations remain unavailable; activation records approved versions |

### 6.3 Enrollment, documents, and developer experience

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| FR-33 | Production | Issuer-local enrollment shall accept new source information only through an authorized workflow or scoped holder invitation | Unauthorized enrollment/upload fails and pending records confer no attestation authority |
| FR-34 | Production | Subject, document, enrollment, credential, and session identifiers shall be distinct opaque references with local uniqueness and no PII-derived public identity key | Concurrent creation is unique; ID possession or a guessed/hashed identity value grants neither access nor verified status |
| FR-35 | Production | Source images and derivatives shall be stored in a private local vault using reviewed per-object-version envelope encryption | Storage/backup inspection finds ciphertext and protected metadata; tampered or cross-context objects fail authentication |
| FR-36 | Production | Extraction shall run inside the approved issuer processing boundary and retain source/version/digest, engine/schema/normalization version, confidence, and provenance | Reproducible fixtures distinguish original observations, normalized candidate values, and approved claims without planner egress |
| FR-37 | Production | Enrollment approval shall enforce the issuer's evidence-validation and holder-binding policy with attributable revision-specific review | Incorrect OCR, mismatched holder, missing evidence, and self-approval where prohibited cannot establish issuance eligibility |
| FR-38 | Production | New information and corrections shall create immutable revisions and require appropriate revalidation | Changed source/fields invalidate stale approval; history remains attributable and signed credentials are not edited |
| FR-39 | Production | Issuance shall derive only permitted claims from current approved source/enrollment versions and record their provenance | Caller-supplied unreviewed values or obsolete approval cannot authorize signing; refresh/revocation policy handles affected credentials |
| FR-40 | Production | Original-image viewing shall require current object/purpose authorization and a short-lived audited principal/resource/version-bound grant before unwrap | Wrong/expired/revoked grant or denied KMS/tag/context returns no plaintext; normal authentication remains required |
| FR-41 | Production | Issuer dashboard shall manage enrollment, controlled source review, extraction corrections, approvals, issuance/status, and scoped audit | UI actions use local APIs, enforce reviewer/key separation, and cannot access another issuer |
| FR-42 | Production | Holder dashboard shall expose only the holder's permitted enrollment, documents, correction requests, credentials, consent, disclosure history, and recovery | Other holders' records are inaccessible and pending/reviewed/issued states are distinct |
| FR-43 | Production | RP/developer dashboard shall manage authorized apps/scopes/credentials, integration docs/SDKs, sandbox, verification outcomes, and safe usage metrics | No issuer source images, raw extraction fields, generalized person search, or KMS access is exposed |
| FR-44 | Production | Federation/security dashboard shall manage scoped issuer onboarding, approved metadata/trust/schema changes, and sanitized operational evidence | Dashboard access alone cannot decrypt documents or grant sovereign accreditation |
| FR-45 | Production | Developer portal shall publish capability discovery, versioned OpenAPI, auth/scopes, safe errors, synthetic examples, quickstarts, limits, and supported SDK/API compatibility | An independent developer can find the correct approved issuer origin and complete a documented synthetic integration |
| FR-46 | Production | Initial supported Java and TypeScript SDKs shall provide typed contracts, safe token handling, bounded retries/jobs/uploads, origin validation, and sanitized diagnostics | Clean quickstarts and consumer/provider tests pass without server secrets in browser bundles or duplicate issuance/acceptance |
| FR-47 | Production | Organization/application onboarding shall separate sandbox/production, approve scopes/origins/audiences, and support credential rotation/revocation | Unapproved app/scopes cannot activate; revoked app/admin privileges stop new operations |
| FR-48 | Production | Document and derived-data retention/deletion shall track source/extraction dependencies, grants, backups, and key versions | Deletion/rotation/restore tests follow the declared lifecycle without falsely claiming recall of disclosed plaintext |

## 7. Data requirements

### 7.1 Logical data model

This table specifies ownership and minimum semantics, not a physical SQL schema.
Pseudonyms and correlation identifiers can still be sensitive and require access and retention controls.

| Record | Minimum semantics | Owning boundary |
| --- | --- | --- |
| Source holder record | Issuer-local source reference and eligibility inputs | Issuer domain only |
| Issuer trust record | Issuer identity, keys, type/claim scope, assurance, approved endpoints, status, epoch | Federation publishes approved public metadata |
| Credential issuance | Credential ID, holder binding, profile/type, claim digest, key version, validity, status, idempotency | Issuer domain; signed artifact delivered to holder |
| Policy revision | RP/purpose, allowed evidence, budget, assurance/freshness rules, sources, approval/version | Authorized policy/RP boundary |
| Candidate plan | Intent, source/schema/policy versions, claims, citations, unresolved issues, guard result | Minimized planner/guard boundary |
| Session | Authorized parties, plan, challenge, expiry, state, consumption/concurrency data | Verifier |
| Consent receipt | Holder/request, destination/purpose/claims, plan hash, validity, decision time | Authorized consent/verifier boundary |
| Verification result | Decision/reasons, consent/plan, trust/key/status versions, event time, correlation ID | Verifier and authorized RP access |
| Security audit | Scoped actor/action, object reference, safe reason, version/event time, integrity/provenance | Access-controlled audit boundary |
| Model invocation metadata | Provider/model/configuration/source versions, tool counts, timing, tokens/cost, safe outcomes | Minimized planner observability |
| Document envelope | Ciphertext, wrapped DEK, key/version reference, nonce/tag, artifact/version/purpose context, protected digest/provenance | Private issuer-local vault and authorized metadata store |
| Extraction/review provenance | Source artifact/version/digest, schema/normalizer/engine, observed/corrected values, confidence, validation/reviewer history | Authorized issuer-local processing/review store |
| Organization/application | Organization review, approved capabilities/origins/audiences/scopes, environment, credential references | Shared integration control plane without subject/document content |
| Original-image access grant | Current principal, issuer/object/version, purpose/action, validity and audit reference | Local authorization boundary; no key material |

### 7.2 Data controls

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| DR-01 | Core | Source records shall remain in their issuer domain without a federation-wide citizen index | Data-flow/storage inspection finds no centralized source-record store |
| DR-02 | Core | Holders/RPs shall receive only signed evidence permitted by policy and consent | Age-proof flow exposes no unrequested DOB/source document |
| DR-03 | Core | Sensitive identifiers, identity records, private keys, bearer tokens, and complete credentials/proofs shall not enter model inputs/tool results | Captured synthetic-canary invocations contain none |
| DR-04 | Production | Each sensitive record class shall have approved access, storage, retention, deletion, backup, and residency rules | Inventory covers primary/replica/cache/telemetry/model/backup destinations |
| DR-05 | Core | Credential content/identity and approved policy revisions shall be immutable | Rewriting fails or produces a separate credential/revision |
| DR-06 | Core | Tenant/issuer/RP and version bindings shall constrain persistence queries and authoritative decisions | Wrong-boundary IDs cannot select/mutate another boundary's records |
| DR-07 | Production | Deletion, retention jobs, and restores shall enforce the approved per-class lifecycle | Expiry/deletion/restore drills do not resurrect removed access or expired records contrary to policy |
| DR-08 | Core | Diagnostic identifiers and reason codes shall not encode raw personal data or secrets | Schema review and sensitive-canary tests pass |
| DR-09 | Production | Sensitive storage/backups shall be encrypted with separately controlled keys and tested recovery/rotation | Storage, IAM denial, and recovery evidence covers every destination |
| DR-10 | Production | Credential custody and holder recovery shall have an approved threat model and ownership/access design | Loss/theft/compromise/recovery/admin-access scenarios have reviewed controls/tests |
| DR-11 | Production | Originals, thumbnails/crops, extraction fields, digests, queues/temp files, and backups shall remain within approved issuer locations/operators | Complete storage/processing/telemetry inventory and egress tests cover every derivative and processor |
| DR-12 | Production | Every immutable object version shall have a fresh DEK, protected envelope context, and local wrapped-key reference without persisted plaintext DEKs | Concurrent/retry/restore inspection and key-role tests show no key/nonce reuse or plaintext key persistence |
| DR-13 | Production | Original-byte and derived-artifact digests shall identify exact versions and be protected with their provenance reference | Byte changes, crop/re-encoding, and replaced references are detected or recorded as new artifacts |
| DR-14 | Production | Structured extraction digests shall use an explicit schema, business normalizer, byte encoding, and reviewed canonicalization version | Equivalent supported representations reproduce a digest; changed semantics/version cannot inherit prior approval |
| DR-15 | Production | PII hashes and raw document digests shall not be public anonymized identifiers or cross-issuer lookup keys | Enumeration/correlation tests and discovery/API inspections show no exposed global fingerprint service |
| DR-16 | Production | Public/presentation subject references shall follow approved scope/privacy/profile rules without exposing internal source references by default | Cross-RP/issuer fixtures demonstrate declared correlation limits without unsupported unlinkability claims |
| DR-17 | Production | Backup/key-copy/cache inventories shall record authority, versions, retention, recovery scope, and security-state reconciliation dependencies | Restore/copy/cache tests cannot resurrect revoked authority, consumed challenges, deleted access, or unapproved data locations |

## 8. External interfaces

The [OpenAPI draft](../engineering/api-contract.openapi.yaml) is a custom synthetic orchestration interface.
It does not define all production authentication, administration, issuance, consent, or error contracts required here.
The separate [issuer-node API draft](../engineering/issuer-node-api.openapi.yaml) begins the local enrollment/document contract and remains unimplemented and incomplete for the whole product.
It is not evidence of OpenID protocol conformance.

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| IF-01 | Core | APIs shall use versioned, bounded, runtime-validated request/response/error contracts | Contract tests reject unknown/ambiguous inputs and verify safe machine-readable errors |
| IF-02 | Production | Principal/tenant authority shall come from authenticated context, not request fields or untrusted forwarded headers | Spoofed RP/tenant/issuer/proxy inputs cannot change authorization |
| IF-03 | Core | Discovery/schema/policy/key/status fetches shall use approved endpoints and validate responses | Forbidden URLs/redirects/addresses, invalid schemas, and stale metadata fail |
| IF-04 | Core | Model adapters shall implement the selected endpoint's actual authentication/tool/output/error/timeout contract | Live synthetic contract test records actual provider/model and outcomes |
| IF-05 | Production | Key-service interfaces shall enforce issuer-scoped signing and prevent application export of signing private keys | Cross-issuer signing/export attempts fail under actual service policy |
| IF-06 | Production | Data interfaces shall enforce least privilege and versioned migration compatibility | Application roles cannot perform unrelated administrative work or read another issuer store |
| IF-07 | Core | Results/errors shall distinguish invalid evidence, denial, replay, manual review, and transient failure with explicit retries | Caller behavior depends on codes, not prose; retries never imply approval |
| IF-08 | Production | Management/telemetry/backup/admin interfaces shall follow separate exposure and authorization rules | Public/ordinary-user network tests cannot reach prohibited data/actions |
| IF-09 | Production | Business APIs shall have versioned OpenAPI contracts and distinct approved control-plane, issuer-local, and verifier origins/audiences | Schema/operation/scope checks and trusted-routing tests reject arbitrary redirects, central source proxies, and wrong audiences |
| IF-10 | Production | New API errors shall use RFC 9457 problem details with safe Sovra code/correlation/retry extensions and a documented legacy migration | HTTP/media/status and typed SDK error fixtures agree without leaking internals |
| IF-11 | Production | List/search/review APIs shall define bounded authorized cursors, stable ordering, filters, ETags, and mutation preconditions | Pagination cannot enumerate another boundary and stale reviews fail without changes |
| IF-12 | Production | Long extraction/validation/issuance/deletion work shall expose scoped job states and declared idempotency/retry/cancellation semantics | Job admission/completion never implies identity approval and duplicate/reordered calls cannot bypass state checks |
| IF-13 | Production | SDKs and dashboards shall consume authorized published APIs and never gain direct database/key access or automatic cross-region fallback | Contract, browser-bundle, secret, scope, origin, and failure tests enforce the same boundaries for every client |

Initial operations are plan proposal, guard validation, session creation, consent response, presentation submission, and authorized result retrieval.
Issuance/status, trust/policy administration, and key lifecycle require separate authorized contracts before exposure.
Future webhooks/callbacks need their own authentication, replay/idempotency, destination-validation, and disclosure requirements.

## 9. Security requirements

The [threat model](../architecture/security-privacy-threat-model.md) and [security validation plan](../engineering/security-validation-plan.md) define detailed attacks and evidence methods.
The production assurance target is applicable OWASP ASVS 5.0.0 requirements through Level 3, assessed individually before production.
This draft does not assert certification, completed ASVS mapping, or absence of vulnerabilities.

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| SR-01 | Production | Protected routes/service entries shall enforce explicit principal, role, tenant, issuer/RP, and object authorization | Matrix covers anonymous, invalid, wrong-role/object, cross-tenant, and alternate-entry cases |
| SR-02 | Production | Privileged administration shall require strong MFA, scoped credentials, and reauthorization for designated high-impact actions | Enrollment/recovery, stolen-session, removal, and high-impact-action tests pass |
| SR-03 | Core | Crypto verification shall use reviewed libraries and profile-specific algorithm/type/key-source/issuer/audience/critical-header constraints | Tampered, unsigned, substituted, confused-type, and unauthorized-key cases fail |
| SR-04 | Core | Replay protection shall use an unpredictable session-bound challenge with durable atomic consumption | Multi-instance race/restart tests allow at most one fresh acceptance |
| SR-05 | Core | Consent, policy, trust scope, holder binding, and claim semantics shall be enforced independently of AI | Valid signatures/plausible output cannot bypass any required check |
| SR-06 | Core | Unknown/stale/malformed/unavailable trust/status shall not satisfy a required verification check | Fault/freshness-boundary cases remain explicitly unverified |
| SR-07 | Core | External text, metadata, model output, and tool arguments shall be untrusted bounded data | Injection, fabricated citations, malformed output, and privilege expansion fail safely |
| SR-08 | Core | Tool callbacks shall reauthorize trusted caller context and enforce per-request allowlists, validation, budgets, and minimized results/errors | Hidden/default-tool, wrong-tenant, repeated-call, and error-leak cases cannot gain authority/data |
| SR-09 | Core | Egress shall prevent unauthorized internal/metadata access, including redirects and resolved-address/DNS-rebinding paths | Instrumented tests observe no forbidden network request |
| SR-10 | Core | Parsing/persistence shall reject unsafe deserialization, ambiguous input, injection, and mass assignment | Fuzz/generated cases reject within limits without corruption or unsafe work |
| SR-11 | Production | Transport, cookies, sessions, CSRF/CORS, redirects, and proxy trust shall follow an explicit authentication/deployment design | Browser/TLS/ingress/session cases cover packaged production configuration |
| SR-12 | Core | Logs/metrics/traces/errors/crash reports/tool results/UI shall exclude prohibited sensitive content | Success/failure canaries cover complete configured telemetry/egress paths |
| SR-13 | Production | Signing/encryption/secrets shall use managed access controls, rotation, revocation, and tested compromise response | Actual IAM/key-service tests and incident exercises pass |
| SR-14 | Production | Dependencies shall have reviewed ownership, support, licenses, provenance, vulnerabilities, and critical-component replacement paths | Release inventory/SBOM, artifact/image scans, and review records exist |
| SR-15 | Production | Deployments shall limit process/database/cloud privilege, management exposure, ingress, and egress | Packaged deployment/infrastructure tests deny unapproved access/capabilities |
| SR-16 | Production | Security decisions/privileged changes shall have durable tamper-evident audit evidence with independently protected integrity | Deletion/modification/outage cases follow approved evidence policy |
| SR-17 | Production | Critical invariants shall have negative, generated/fuzz, concurrency, mutation, and independent-review evidence as applicable | Removing a critical check fails a relevant test; findings are retested |
| SR-18 | Production | Invalid acceptance, cross-tenant disclosure, sensitive leaks, consent/trust/replay bypass, and unresolved high/critical findings shall block release | Required release evidence is complete with no open blocking finding |
| SR-19 | Production | Images and sensitive derivatives shall use reviewed authenticated encryption with per-version keys and issuer/tenant/object/version/purpose context binding | Ciphertext/tag/AAD/key substitution fails before any plaintext output |
| SR-20 | Production | Encryption profiles shall enforce documented nonce uniqueness and authenticated handling under concurrency, retries, restarts, and re-encryption | Fault/retry tests and profile review exclude key/nonce reuse and unauthenticated output/truncation |
| SR-21 | Production | Every unwrap/read shall enforce current issuer/object/purpose/workload access and separated key lifecycle/use roles | Expired grants, wrong principal/issuer, revoked access, and unavailable KMS fail without key/plaintext fallback |
| SR-22 | Production | Image ingestion shall enforce allowlisted actual file types, size/pixel/decoder bounds, encrypted quarantine, and constrained local scanning | Spoofed/polyglot/oversized/malformed files and worker compromise fixtures cannot activate data or escape processing limits |
| SR-23 | Production | OCR/extraction shall be isolated from the advisory planner and require authoritative validation/review before claim issuance | Incorrect/confident OCR or document injection cannot sign unsupported claims or export PII |
| SR-24 | Production | Hashing/matching shall not be treated as encryption, anonymization, or proof of authenticity and shall use protected issuer/purpose-scoped mechanisms where justified | Guessable-field hashes and same-image fingerprints cannot become public lookup/identity authority |
| SR-25 | Production | Locality and least privilege shall hold across SDK/dashboard routing, OCR, replicas/backups, support access, analytics, and failover | Forbidden cross-boundary processing is denied even during outage, restore, or privileged UI use |
| SR-26 | Production | Privileged authentication, authenticator enrollment/recovery, and designated elevation shall be phishing resistant and time bounded with independent approval for high-impact changes | Weak recovery, stolen-session elevation, self-granted authority, and removed-role cases fail under approved bounds |
| SR-27 | Production | Ingestion, OCR, review, signing, decryption, deployment, migration, and audit shall use separately scoped identities with no implicit cross-issuer or arbitrary-signing capability | A compromised worker/API/deploy identity cannot sign arbitrary claims, unwrap unrelated data, run owner migrations, or grant itself those rights |
| SR-28 | Production | Recovery/failover shall fence obsolete writers and reconcile or invalidate ambiguous sessions/trust/revocation/approval state before reopening acceptance | Stale-backup, split-brain, key/data mismatch, and replay-after-restore cases create no unauthorized acceptance |
| SR-29 | Production | Key-copy and token/grant/DEK-cache behavior shall enforce explicit revocation/freshness bounds without fallback that bypasses current deny policy | Warm/cold caches and independently restored keys follow approved authority and containment rules during control/data-plane outages |
| SR-30 | Production | Hostile file processing shall use reviewed process/OS/runtime isolation and resource/egress limits outside any presumed Java Security Manager sandbox | Controlled worker compromise cannot access the signer, unrelated documents/keys, unrestricted network, or privileged host capabilities |
| SR-31 | Production | Production admission shall verify approved source, builder/provenance, artifact digest, configuration, and runtime identity rather than signature presence alone | Substituted artifact or provenance from an unapproved builder/source/configuration is rejected and audited |
| SR-32 | Production | Flow health/readiness and alerts shall reflect freshness, replay persistence, authorization/key availability, durable audit, and deny behavior rather than HTTP success alone | Stale authority or failed critical persistence closes affected readiness and alerts even while superficial probes remain green |
| SR-33 | Production | Administrative/root/host visibility and override powers shall have an explicit threat assessment and deployment-specific mitigations, including attested confidential processing when needed to meet the approved boundary | Independent review identifies remaining roots and exercises selected isolation/attestation/key-release controls without unsupported provider-confidentiality claims |

## 10. States and consistency invariants

### 10.1 State model

This is the target domain model; wire enums/persistence states shall be finalized in versioned contracts.
Plan decisions, presentation attempts, and session outcomes shall remain distinct.
Model recommendations shall never be verified-session states.

| Entity | States/transitions | Rule |
| --- | --- | --- |
| Candidate plan | CANDIDATE to GUARD_ACCEPTED, GUARD_REJECTED, or MANUAL_REVIEW | Guard acceptance permits consideration/session creation only |
| Consent | PENDING to APPROVED, DENIED, or EXPIRED | Applies only to its bound request; changed scope requires new consent |
| Session | AWAITING_CONSENT to READY, DENIED, EXPIRED, or CANCELLED; READY to VERIFIED, REJECTED, MANUAL_REVIEW, EXPIRED, or CANCELLED | Fresh acceptance requires valid bindings and durable challenge consumption |
| Verification outcome | VERIFIED_EVIDENCE, REJECTED, or MANUAL_REVIEW | Unavailable operation is separate and never interpreted as success |
| Credential | ACTIVE to REVOKED or EXPIRED | Revocation is terminal for that ID; replacement uses a new ID |
| Policy/trust revision | New approved versions supersede earlier versions under explicit effective/freshness rules | History is immutable; rollback cannot silently expand trust |
| Subject | PENDING_ENROLLMENT to ACTIVE after approved enrollment, then SUSPENDED/ARCHIVED under policy | Internal record ID is not identity proof; only approved scoped claims become issuable |
| Enrollment | EVIDENCE_PENDING to PROCESSING/REVIEW_REQUIRED, then APPROVED, REJECTED, or CANCELLED | Source, holder binding, policy, and exact review revision must satisfy approval |
| Document | AWAITING_UPLOAD to QUARANTINED, then ACCEPTED/REJECTED; eligible records may enter DELETION_PENDING/DELETED | Encrypted storage/scanning precedes extraction; deletion follows declared retention |
| Extraction revision | PENDING_REVIEW to APPROVED/REJECTED/SUPERSEDED | Corrections create a new unapproved revision; jobs and identity approval are distinct |

Malformed/unauthenticated submissions shall not mutate another party's session.
Authenticated invalid attempts shall be recorded and rate limited; their retry/terminalization policy is OD-06.
Terminal results shall be immutable.
Manual follow-up shall create a separately authorized record/request, never rewrite a failed proof as verified.
VERIFIED maps to the result decision VERIFIED_EVIDENCE; denial, expiry, cancellation, and rejection map to REJECTED with a safe reason, while MANUAL_REVIEW remains non-verified.
The unavailable-operation response does not itself establish a terminal session state; the declared retry policy governs that transition.

### 10.2 Invariants

| ID | Invariant | Verification |
| --- | --- | --- |
| INV-01 | A challenge shall authorize at most one fresh accepted decision across all instances | Concurrent submission, restart, and response-loss tests |
| INV-02 | Acceptance, consumption, and required durable audit reference shall commit consistently | Database/audit interruption at commit boundaries |
| INV-03 | Signed identity/content and approved policy versions shall not be rewritten in place | Mutation/replacement/history tests |
| INV-04 | Revocation shall not return to active under the same credential ID | Status-transition and restore tests |
| INV-05 | No AI/guard/admin/reviewer action shall replace required consent and proof checks | Bypass and altered-binding tests |
| INV-06 | Trust shall use authorized scope/version and declared status freshness, not signature validity alone | Scope/epoch/race/stale-cache tests |
| INV-07 | Dependency failure or uncertain transaction outcome shall not return a new verified decision | Fault and authorized result-recovery tests |
| INV-08 | Authorized idempotent retries shall not create additional issuance or fresh acceptance | Identical/conflicting request hash and concurrency tests |
| INV-09 | Record creation, upload, OCR, digest equality, and job success shall not establish identity/claim authority by themselves | Enrollment, review, holder-binding, and signing-bypass tests |
| INV-10 | Content/envelope/source-revision changes shall not inherit stale context, digests, or approval | AEAD substitution, ETag, provenance, and correction tests |
| INV-11 | Source images/PII/DEKs shall not become shared federation/planner data or cross a forbidden processing boundary on fallback | Locality, keys, SDK/dashboard routing, and egress tests |
| INV-12 | Recovery, backup restore, cache state, or concurrent obsolete writers shall not revive consumed sessions or terminally revoked authority | Fenced restore/split-brain and security-state reconciliation tests |
| INV-13 | New, rolled-back, recovered, and alternate ingress paths shall preserve the same issuer/purpose/consent/freshness/replay/locality constraints | Paired normal/failure/rollback/alternate-route adversarial tests |

A valid concurrency test with all dependencies available shall produce exactly one fresh acceptance.
When failure prevents commit, zero successes are valid; two successes are always a failure.
Authorized retrieval of an already committed result shall preserve the original decision identity and is not a new acceptance.
Cross-domain revocation and verification are not assumed to share a global transaction; OD-03 shall define the accepted snapshot/freshness window and record the actual status/trust version used.

## 11. User experience requirements

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| UX-01 | Core | Consent shall show verified RP identity, purpose, exact claims, expiry, and disclosure implications before approval | Visible content matches bound request and actual presented claims |
| UX-02 | Core | Approval/refusal shall be explicit, with no preselected approval or presentation from inactivity | Refusal/timeout/navigation-away cases produce no unauthorized presentation |
| UX-03 | Core | Candidate, pending, rejected, unavailable, manual-review, and verified states shall be distinct | Planning/transient error cannot appear as completed verification |
| UX-04 | Core | Untrusted content shall render safely and errors shall not expose sensitive data or enumeration | Hostile markup/link/identifier/error fixtures pass browser tests |
| UX-05 | Production | Consent/recovery shall support keyboard access, visible focus, readable labels, and assistive-technology assessment | Approved OD-12 accessibility/client target has browser/manual evidence |
| UX-06 | Production | Enrollment/review screens shall distinguish uploaded observations, corrected values, approved source revisions, internal IDs, and issued credentials | Reviewers/holders cannot mistake a pending record or OCR confidence for a verified identity |
| UX-07 | Production | Dashboard navigation and image viewers shall be role/issuer scoped with explicit purpose-bound access and safe local rendering | Support/admin/RP users cannot obtain raw source data merely through shared navigation or preview URLs |
| UX-08 | Production | Developer onboarding shall clearly expose the approved endpoint, environment, auth/scopes, supported API/SDK versions, sandbox, and errors | New developers complete synthetic quickstarts without undocumented privileges or copying live secrets |

## 12. Non-functional requirements and target register

### 12.1 Required properties

| ID | Applies | Requirement | Acceptance evidence |
| --- | --- | --- | --- |
| NFR-01 | Core | The finite approved adversarial corpus shall have zero invalid accepted proofs or unauthorized disclosures | Report corpus size, every outcome/failure, and environment |
| NFR-02 | Core | Verification/planning/database/status/key/tool timings shall be measured separately | Reproducible p50/p95/p99 and throughput/resource reports state dependency conditions |
| NFR-03 | Core | Model/tool work, input/output size, crypto work, retries, and concurrency shall have finite configured budgets | Boundary/overload tests fail safely without dropping security checks |
| NFR-04 | Production | Availability, latency, capacity, and recovery targets shall be approved/tested for actual workloads | OD-04/OD-05 values, windows, and test reports complete before release |
| NFR-05 | Production | Process/dependency failure, migration, and recovery shall preserve security invariants | Multi-instance/restart/backup/migration/restore tests pass |
| NFR-06 | Core | Domain decisions shall be testable independently of HTTP/framework/storage/model adapters | Policy/trust/consent tests use explicit clock and version inputs |
| NFR-07 | Core | A clean checkout shall reproduce the synthetic flow without private resources | Documented build/migration/fixture/E2E evidence passes in a clean environment |
| NFR-08 | Production | Releases shall identify source, dependencies, JDK build, configuration, and immutable artifact digest | Build/deployment records support rollback and attribution without secrets |
| NFR-09 | Production | API/schema evolution shall have compatibility, migration, and deprecation rules | Consumer/mixed-version/rollback tests cover supported transitions |
| NFR-10 | Core | AI evaluation shall freeze fixture answers, prompts/tools/model configuration/baseline and report all runs | Structural/semantic/citation/unseen-schema/false-accept/tool/latency/cost metrics include failures |
| NFR-11 | Production | Operators shall receive sanitized alerts and have tested incident/key-compromise runbooks | Alert/containment drills meet approved OD-05 objectives |
| NFR-12 | Production | Public security/privacy/residency/protocol claims shall be limited to supported deployment/profile evidence | Every release claim traces to approved evidence and scope |
| NFR-13 | Production | SDK releases shall provide reproducible consumer/provider contract tests, package provenance, compatible version guidance, and working Java/TypeScript quickstarts | Published package/version and clean-environment positive/negative integration evidence agree |
| NFR-14 | Production | Document/OCR pipelines and routing shall fail within configured budgets without unapproved data-location fallback | Outage/restore/load evidence confirms the same locality, integrity, and authority invariants |
| NFR-15 | Production | A representative isolated staging environment shall validate production security controls with synthetic load and controlled faults before live-data release | Packaged HTTP/PostgreSQL/key-provider tests cover the actual IAM/network/runtime/dependency design and bounded fault cleanup |
| NFR-16 | Production | Blue/green, rollback, migration, and incident operations shall preserve security state and declare separate control-plane/data-plane limitations | Traffic splits/rollback do not restore revoked keys/policies or duplicate nonce use; emergency-operation constraints are measured |
| NFR-17 | Production | MC-01 through MC-10 shall have independent assertions, measured detection/containment/recovery results, and retained sanitized release evidence | Missing/stale/failed MC evidence blocks the applicable production gate alongside SEC and ASVS evidence |

### 12.2 Target register

This SRS establishes no commercial SLA or unmeasured latency/availability claim.
Missing values below are production blockers, not permission to run without limits.
Development/test environments shall use documented finite conservative settings.

| Target | Required definition | State | Responsible role |
| --- | --- | --- | --- |
| Verification | End-to-end p95/p99, error rate, sustained/burst load, payload, cache state, hardware, and upstream conditions | Open - OD-04 | Engineering/operations |
| Planning | End-to-end deadline, model/tool budget, concurrency, rate/spend ceilings, failure behavior | Open - OD-04 | Engineering/product |
| Availability | Critical operations, evaluation window, dependency assumptions, degradation | Open - OD-04 | Product/operations |
| Recovery | Per-store RPO/RTO, backup age, key/replay/status recovery, restore verification, containment times | Open - OD-05 | Operations/security |
| Freshness | Per-assurance trust/status age, permitted clock skew, unknown/error handling | Open - OD-03 | Security/policy approver |
| Sessions/retries | Consent/session lifetime, nonce entropy, attempt limits, idempotency lifetime, retry classes | Open - OD-06 | Security/engineering |
| Data lifecycle | Per-class retention/deletion, backup expiry, audit exceptions, approved locations | Open - OD-07/OD-08 | Product/security/privacy reviewer |
| Privileged/key caches | Positive authorization age, token/grant/DEK lifetimes, known-deny propagation, active-job containment, and independent key-copy handling | Open - OD-18 | Security/identity/key owners |

## 13. Verification and traceability

### 13.1 Methods and evidence

Acceptance shall combine domain tests, real HTTP/PostgreSQL integration, browser consent/authentication, generated/fuzz input, concurrent interleavings, mutation tests, static/dependency/secret/image scans, failure/recovery tests, and independent assessment.
Mocked principals and in-memory replay tests alone shall not establish deployed authorization or durability.
Tools/versions shall pass Java/build compatibility, license, and maintenance review.
The [security plan](../engineering/security-validation-plan.md) defines required SEC-01 through SEC-44 and MC-01 through MC-10 production scenarios, whose implementation and execution remain pending.

Each requirement shall map to executable tests or reviewed manual evidence with commit/artifact/configuration references and an accountable reviewer.
Missing/skipped/stale/failed evidence shall remain an open gap.
The coverage map links groups to planned scenarios; it does not claim passing Java tests.

### 13.2 Security coverage map

| Requirement group | Planned cases | Additional evidence |
| --- | --- | --- |
| FR-01, FR-16, FR-24, FR-26, FR-28, DR-06, SR-01, SR-02 | SEC-01, SEC-02, SEC-03, SEC-26, SEC-31 | Role/resource matrix, MFA/recovery, and privileged lifecycle |
| FR-02, FR-08, FR-14, FR-15, SR-03 | SEC-04, SEC-05, SEC-06, SEC-07, SEC-30 | Exact profile and independent wallet fixtures |
| FR-19, FR-21, FR-22, INV-01, INV-02, INV-07, INV-08, SR-04 | SEC-08, SEC-09, SEC-10 | Durable state and atomic decision/recovery |
| FR-03, FR-13, FR-17, FR-18, DR-05, INV-03, INV-04, INV-06, SR-06 | SEC-11, SEC-12 | Policy/trust/freshness contract |
| FR-07, FR-20, FR-25, FR-31, INV-05, SR-05, UX-01, UX-02 | SEC-13 | Consent-to-presentation and review separation |
| FR-23, DR-09, DR-10, IF-05, SR-13 | SEC-14, SEC-26, SEC-27 | Signing/custody and compromise/recovery drills |
| FR-04, FR-05, FR-06, FR-11, FR-32, SR-07, SR-08, NFR-10 | SEC-15, SEC-16, SEC-18 | Frozen unseen/incompatible-schema evaluation |
| IF-03, SR-09 | SEC-17 | Resolver, redirects, actual egress |
| FR-12, FR-29, IF-04, IF-07, NFR-02, NFR-03 | SEC-19, SEC-22 | Live provider and finite failure budgets |
| FR-09, FR-10, DR-01, DR-02, DR-03, DR-08, SR-12 | SEC-20 | Full model/tool/telemetry/response canary capture |
| IF-01, IF-06, SR-10 | SEC-21 | Parser/resource and persistence cases |
| IF-02, SR-11, UX-03, UX-04 | SEC-23, SEC-24, SEC-32 | Browser/TLS/proxy/authentication |
| IF-08, SR-15 | SEC-25, SEC-26 | Management-network and least privilege |
| FR-30, DR-04, DR-07, NFR-04, NFR-05, NFR-11 | SEC-27 | Retention/migration and RPO/RTO/incident objectives |
| FR-27, SR-16 | SEC-28 | Independent audit integrity and outage policy |
| SR-14, SR-17, SR-18, NFR-01, NFR-06, NFR-07, NFR-08, NFR-09, NFR-12 | SEC-29 and full applicable suite | Provenance, mutation, clean deployment, independent assessment |
| UX-05 | Separate accessibility assessment | Approved target and assistive-technology evidence |
| FR-33, FR-34, FR-37, DR-16, INV-09, UX-06 | SEC-37, SEC-43 | Issuer enrollment authority, opaque local IDs, holder binding, and non-self-asserted approval |
| FR-35, FR-40, DR-12, SR-19, SR-20, SR-21 | SEC-33, SEC-34, SEC-35 | Envelope context/tag, nonce/retry safety, actual KMS duties, and principal/purpose grants |
| FR-36, DR-11, SR-22, SR-23 | SEC-36, SEC-37, SEC-40 | Bounded encrypted quarantine, isolated extraction, no planner PII, and reviewed provenance |
| FR-38, FR-39, DR-13, DR-14, DR-15, SR-24, INV-10 | SEC-38, SEC-39 | Protected digests, normalization/canonicalization, stale-source approvals, and no public hash identity lookup |
| FR-41, FR-42, FR-43, FR-44, UX-07 | SEC-35, SEC-41 | Local role/resource dashboards and original-image entitlement separation |
| FR-45, FR-46, FR-47, IF-09, IF-10, IF-11, IF-12, IF-13, UX-08, NFR-13 | SEC-29, SEC-42, SEC-43 | OpenAPI/SDK parity, app lifecycle, safe errors/pagination/preconditions/retries and sandbox onboarding |
| FR-48 | SEC-44 | Deletion, dependent artifacts, backup/KEK rotation, and no false plaintext-recall promise |
| SR-25, INV-11, NFR-14 | SEC-40, SEC-41, SEC-42, SEC-44 | Replica/worker/support/telemetry/SDK/restore locality and no unsafe failover |
| SR-26, SR-27, SR-29, DR-17 | MC-01, MC-04, MC-06, MC-09, MC-10 | Privileged recovery/elevation, actual workload/DB/key roles, copy/cache bounds and control/data-plane limits |
| SR-28, INV-12, INV-13, NFR-16 | MC-03, MC-05, MC-10 | Writer fencing, session-generation/revocation reconciliation, approved routing and rollback safety |
| SR-30, SR-33 | MC-02, MC-05, MC-06 | OS/runtime isolation and approved root/host/attestation boundary |
| SR-31 | MC-07 | Verified source/builder/artifact/configuration admission |
| SR-32, NFR-15, NFR-17 | MC-01, MC-02, MC-03, MC-04, MC-05, MC-06, MC-07, MC-08, MC-09, MC-10 | Representative synthetic-load testing, semantic readiness, alerts and independent recovery evidence |

The production assessment shall extend this map to individual applicable ASVS requirements.
Scanners and line coverage shall support rather than replace business-invariant tests and independent review.

## 14. Release acceptance

### 14.1 Core synthetic vertical slice

| ID | Scenario | Required result |
| --- | --- | --- |
| AC-01 | Trusted synthetic age credential, authorized RP/policy, live grounded plan, holder approval, fresh valid proof | One durable VERIFIED_EVIDENCE result after guard/consent; no unrequested DOB/source document to RP/model; legal KYC undetermined |
| AC-02 | Repeat with altered signature, wrong issuer/scope/holder/audience, expiry, and revocation | Each independently fails with safe reason and no accepted evidence |
| AC-03 | Submit one valid presentation concurrently across two instances, restart, and replay | Exactly one fresh acceptance with healthy dependencies; no new acceptance after restart |
| AC-04 | Refuse consent or change approved RP/purpose/claims/policy/plan | No presentation under original consent |
| AC-05 | Unseen compatible/incompatible schemas, invented citations, and injected metadata | Complete baseline comparison; unsafe/unsupported plans cannot execute |
| AC-06 | Fail model/registry/status/database/signing and lose responses at commit boundaries | Truthful non-verified or original-result recovery; no invented approval or duplicate issuance/acceptance |
| AC-07 | Inject sensitive synthetic canaries through success/rejection/tool/telemetry/errors | No prohibited data in model inputs, unauthorized responses, logs, traces, or metric labels |
| AC-08 | Build/start from clean public checkout using documented synthetic configuration | Core workflow/negative tests reproduce without private files or production secrets |

### 14.2 Extended product scenarios using synthetic data

These scenarios validate the additional Production features when implemented and before those features handle real sensitive data.
They do not turn the limited hackathon slice into a claim that every business feature is already delivered.

| ID | Scenario | Required result |
| --- | --- | --- |
| AC-09 | Swap ciphertext/tag/envelope context, repeat encryption retries, or attempt decryption as another principal/issuer | No unauthenticated plaintext or forbidden unwrap; nonce/key profile and grant bindings remain valid |
| AC-10 | Upload hostile/oversized images or extract plausible incorrect fields and attempt direct ID/credential activation | Quarantine/decoder controls hold; pending ID/OCR output confers no authority and required validation/review cannot be bypassed |
| AC-11 | Correct a field or replace an image after approval, then reuse an old review or issuance request | New source/extraction revision and digest are recorded; stale approval fails and prior signed credentials are never overwritten |
| AC-12 | Fail local OCR/storage/KMS while a shared portal, backup, or SDK could reach another region | No unapproved fallback/replication; no source PII/key/digest appears in federation or planner requests |
| AC-13 | Complete fresh Java/TypeScript sandbox quickstarts, then exercise wrong origins/scopes, typed errors, stale ETags, job polls, and idempotent retries | Documented clients obey the same API authorization and create no duplicate issuance/acceptance or server-secret browser exposure |
| AC-14 | Use holder/issuer/RP/federation/support dashboards and test record creation, image access, access removal, and deletion/restore | Each role sees only permitted local resources; new IDs remain pending; decryption/deletion follow the actual approved access/retention contract |
| AC-15 | Restore older database/security/key state while an obsolete writer and prior valid presentation exist | Writer fencing and state reconciliation/invalidation prevent replay, revoked-authority resurrection and duplicate decisions before readiness reopens |
| AC-16 | Remove privilege or disable/rotate keys with warm token/grant/DEK caches and an independent restored key copy | Current declared deny/expiry/containment policy holds across copies and serving instances; no silent authority extension |
| AC-17 | Substitute artifact/provenance, roll back during load, or keep HTTP healthy while authorization-critical dependencies fail | Admission rejects unapproved deployment; rollback preserves security state; affected flow readiness/alerts report unsafe dependencies |

The existing [demo scorecard](../demo/evaluation-and-acceptance.md) supplies T01-T15 demonstration cases.
Passing them does not waive this business SRS.

### 14.3 Production gate

Before real data or customer operation, the release shall have complete applicable Core/Production evidence, finalized profile/interface contracts, and approved values for relevant open targets.
It shall have an applicable ASVS assessment, independent architecture/code review and penetration test, retested findings, actual deployment/IAM/egress verification, custody/key evidence, and tested recovery/incident procedures.
Qualified responsible parties shall assess deployment-specific privacy, retention, residency, issuer authority, and RP obligations.
Security-critical failures and unresolved high/critical findings shall block release regardless of hackathon deadlines or demo success.
Independent assessment shall be separate from the implementation author's own generated tests.
MC-01 through MC-10, workload/root privilege assessment, replay-safe restoration, copy/cache revocation behavior, and artifact admission are explicit required release evidence.
The [implementation plan](../engineering/implementation-plan.md) and [task backlog](../engineering/implementation-backlog.md) order this work; closing a documentation or decision task does not close the corresponding implementation/security gate.

## 15. Open decisions and dependencies

Resolve these in public architecture/contracts or access-controlled deployment records as appropriate.
No private planning file is required to interpret requirements.
Roles identify responsibility, not named approvals or completed work.

| ID | Decision | Required resolution | Gate | Responsible role |
| --- | --- | --- | --- | --- |
| OD-01 | Proof profile/library | Exact format/version, holder binding, algorithms, issuance/presentation semantics, coverage, independent corpus | Before profile-dependent Java work or conformance claims | Architecture/security |
| OD-02 | Meta integration | Endpoint/model/version/adapter, live tool/output contract, provider retention, safe failure | Before live AI integration is declared complete | AI integration/security |
| OD-03 | Trust/status policy | Per-assurance max age/skew, unknown behavior, snapshot/epoch semantics, revocation/key races, status privacy | Before verification acceptance baseline approval | Security/policy approver |
| OD-04 | Service targets/budgets | Numeric latency/capacity/availability, windows/load/hardware/upstream conditions, deadlines, rates/retries/spend | Before commitments or production | Product/engineering/operations |
| OD-05 | Recovery/incidents | Per-store RPO/RTO, backup/key/replay recovery, escalation/containment, drill schedule | Before production | Operations/security |
| OD-06 | Session/idempotency policy | Lifetimes, nonce entropy, authenticated retry/terminalization, response-loss recovery, hashes, review follow-up | Before final session API/state implementation | Engineering/security |
| OD-07 | Data lifecycle | Classification/access/minimization/retention/deletion/backup/audit exceptions and processing terms | Before real collection | Product/security/privacy reviewer |
| OD-08 | Hosting/jurisdiction | Hosting/backup/telemetry/model regions, network separation, processor roles, residency evidence | Before real cross-boundary processing | Architecture/operations/privacy reviewer |
| OD-09 | Holder custody/recovery | Device/server key ownership/access, loss/theft/recovery, administrator limits | Before real credentials/holder keys stored | Product/security |
| OD-10 | Authentication/governance | Identity provider, service/RP authentication, MFA/recovery, privileged approvals, issuer authority, reviewer ownership | Before production administration | Security/product |
| OD-11 | Audit/commit policy | Protected integrity anchor, durability, access/retention, outage handling, decision/audit transaction relation | Before production audit guarantees | Security/engineering/operations |
| OD-12 | Accessibility/clients | Measurable target, supported browsers/assistive technology, consent/recovery assessment | Before customer-facing production | Product/frontend |
| OD-13 | Local document cryptography and processing | Approved vault/KMS locations/operators, envelope/AAD/nonce format, upload/decoder bounds, scanner/OCR pipeline, access-grant policy, derivative/backup/key lifecycle | Before real image ingestion/decryption | Architecture/security/operations |
| OD-14 | Enrollment/source-change assurance | Issuer evidence-validation and holder-binding method, reviewer/separation policy, correction rules, duplicate/merge handling, and refresh/revocation impact of source updates | Before real identity approval or evidence-derived signing | Issuer authority/security/product |
| OD-15 | Digest and matching profile | Exact byte/JSON canonicalization, field normalization/schema versions, protected provenance reference, local keyed-index need/key rotation, and permitted subject correlation | Before protected digests/matching are used as authoritative inputs | Security/data architecture |
| OD-16 | Developer contract and SDK releases | Complete API families/scopes/jobs/pagination/error compatibility, Java/TypeScript package/version policy, app onboarding, docs/sandbox, dashboard role matrix, callback contracts if adopted | Before customer developer-platform release | API/SDK/product/security |
| OD-17 | Root/workload and data-in-use boundary | Ultimate administrative overrides, host/cloud visibility, separation of workload/deploy/migration/key roles, sandbox strength, attestation/confidential-processing need and selected mitigations | Before deploying real sensitive processing | Security/architecture/issuer authority |
| OD-18 | Revocation/cache/copy authority | Explicit token/grant/DEK and positive-permission cache bounds, known-deny propagation, active-job containment, independent restored-key inventory and emergency control-plane limitations | Before real signing/decryption or privilege lifecycle operation | Security/identity/key/operations owners |

## 16. References and change control

### 16.1 Project references

| Reference | Role |
| --- | --- |
| [Product vision](../product/vision-and-scope.md) | Problem, federation premise, differentiator |
| [Architecture decisions](../architecture/architecture-decision-records.md) | Accepted direction and proposed gates |
| [Java/Spring baseline](../architecture/java-spring-baseline.md) | Runtime/framework direction and dated primary-source evidence |
| [Data/trust boundaries](../architecture/data-boundaries-and-trust.md) | Issuer, holder, federation, model, verifier boundaries |
| [Federated document lifecycle](../architecture/federated-document-lifecycle.md) | Local image encryption/decryption, extraction/provenance, enrollment and ID semantics |
| [Developer platform](../engineering/developer-platform.md), [issuer-node API](../engineering/issuer-node-api.openapi.yaml) | Custom resources, standard API mechanisms, SDK and dashboard contract proposals |
| [Consistency/failure modes](../architecture/consistency-and-failure-modes.md) | Replay, revocation, trust, outages |
| [Security validation](../engineering/security-validation-plan.md) | Required SEC-01 through SEC-44, MC-01 through MC-10 and release evidence; execution pending |
| [AI contract](../ai/agent-contract.md), [AI evaluation](../ai/evaluation-plan.md) | Tool boundaries, semantics, frozen evaluation |
| [OpenAPI draft](../engineering/api-contract.openapi.yaml) | Existing custom demo API, incomplete for business scope |
| [MVP specification](../engineering/mvp-specification.md), [demo scorecard](../demo/evaluation-and-acceptance.md) | Synthetic milestone and demonstration evidence |
| [Claims/limitations](../compliance/claims-and-limitations.md) | Supported assertions and deployment boundaries |
| [Mission-critical security research](../research/security-and-mission-critical-review.md) | Primary-source reasoning for the promoted security/recovery controls |
| [Implementation plan](../engineering/implementation-plan.md), [task backlog](../engineering/implementation-backlog.md) | Sequenced engineering tasks, dependencies, evidence and issue tracking |

### 16.2 Governance

This SRS governs product requirements; accepted ADRs constrain architecture and selected normative protocol profiles constrain their wire/cryptographic behavior.
Historical schedules and prototype behavior shall not silently narrow security requirements.
Conflicting requirements, ADRs, profiles, or contracts shall be explicitly resolved before affected implementation is accepted.
Changes to scope, claims, consent, proof profiles, data destinations, or security controls require impact assessment, updated test mappings, and independent security review where applicable.

| Version | Change |
| --- | --- |
| 0.2 | Earlier hackathon-only candidate |
| 0.3 | Business draft covering Java/Spring, production boundaries, functional/data/interface/security requirements, state invariants, acceptance evidence, and open-decision gates |
| 0.4 | Adds federated local image custody/crypto/extraction, enrollment and source revision rules, API/SDK integration, dashboards, and expanded security/acceptance coverage |
| 0.5 | Promotes research into privileged/workload isolation, recovery, cache/key-copy, artifact-admission and semantic-health requirements, required MC evidence, root/cache decisions, and dependency-ordered implementation tasks |
