# Implementation backlog

**Baseline:** business SRS v0.5, 2026-10-27.
**State:** planned work awaiting maintainer triage; no application/security gate is complete.

This backlog covers the Java/Spring business application, issuer-local images and extraction, identity lifecycle, integrations, SDKs, dashboards and required security evidence.
The [implementation plan](implementation-plan.md) defines release gates; the [SRS](../requirements/software-requirements-specification.md) remains the requirement authority.
The [task registry](implementation-tasks.json) contains the same stable IDs, dependencies, requirement/test references and tracker URLs in machine-readable form.

## How to use the tasks

Each task is initially `needs-triage` with a proposed priority and an accountable owner role, not an assigned person.
A maintainer confirms scope, names an owner and applies the repository's priority/status workflow.
Dependencies must meet their acceptance criteria before dependent integration is accepted; isolated design and synthetic scaffolding may proceed without asserting those dependencies are complete.
Component security tests ship with each implementation task; SOV-032 consolidates coverage and independent assertions rather than delaying testing until the end.
SOV-036 is conditional scope and is excluded from the initial narrow-attestation release unless its profile is selected.
If selected, it must pass before the SOV-034 release decision.

Task numbering is stable and is not execution order.
The graph includes forward references; follow dependencies and gates rather than ascending ID order.
No dates or effort estimates override security gates.
Do not attach secrets, identity data, raw credentials or private research to issues or evidence.

## Gate map

| Gate | Result | Principal task groups |
| --- | --- | --- |
| G0 | Approved proof, locality/root, identity/key and cache contracts | SOV-001, SOV-002, SOV-004 |
| G1 | Reproducible Java synthetic issuance/consent/verification with live bounded planning | SOV-003, SOV-005, SOV-007 through SOV-015, SOV-029, SOV-035 |
| G2 | Approved and tested sensitive-document, custody, deployment and recovery boundaries using synthetic data | SOV-006, SOV-016 through SOV-020, SOV-027, SOV-028, SOV-030, SOV-031 |
| G3 | Customer integration and dashboards plus complete SEC/MC/ASVS and independent release evidence | SOV-021 through SOV-026, SOV-032 through SOV-034 |
| Conditional | Tested expanded interoperable/selective-disclosure profile | SOV-036 |

G2 completion prepares the sensitive-data boundary but does not authorize real-data processing.
Real data and customer operation require the applicable G3 security/review evidence and named release approval under the SRS.
The synthetic milestone can pass G1 without shipping document custody or all business screens.

## Task index

| ID | Task | Gate | Proposed priority | Dependencies | Tracker |
| --- | --- | --- | --- | --- | --- |
| [SOV-001](#sov-001) | Freeze proof profile, issuer assurance, freshness and session semantics | G0 | p0 | None | [Issue](https://github.com/apil-khadka/Sovra/issues/5) |
| [SOV-002](#sov-002) | Approve issuer locality, lifecycle, custody and root trust boundaries | G0 | p0 | None | [Issue](https://github.com/apil-khadka/Sovra/issues/6) |
| [SOV-003](#sov-003) | Bootstrap Java 25 and Spring workspace with integration harness | G1 | p0 | None | [Issue](https://github.com/apil-khadka/Sovra/issues/7) |
| [SOV-004](#sov-004) | Select identity and key providers with revocation and cache contracts | G0 | p0 | SOV-001, SOV-002 | [Issue](https://github.com/apil-khadka/Sovra/issues/8) |
| [SOV-005](#sov-005) | Implement tenant, issuer, RP and object authorization | G1 | p0 | SOV-002, SOV-003, SOV-004 | [Issue](https://github.com/apil-khadka/Sovra/issues/9) |
| [SOV-006](#sov-006) | Implement privileged access and application credential lifecycle | G2 | p0 | SOV-004, SOV-005 | [Issue](https://github.com/apil-khadka/Sovra/issues/10) |
| [SOV-007](#sov-007) | Implement durable privacy-minimized audit and decision evidence | G1 | p0 | SOV-002, SOV-003, SOV-004, SOV-005 | [Issue](https://github.com/apil-khadka/Sovra/issues/11) |
| [SOV-008](#sov-008) | Implement versioned trust registry and approved RP policies | G1 | p0 | SOV-001, SOV-003, SOV-005, SOV-007 | [Issue](https://github.com/apil-khadka/Sovra/issues/12) |
| [SOV-009](#sov-009) | Implement issuer-scoped issuance and constrained signing | G1 | p0 | SOV-001, SOV-003, SOV-004, SOV-005, SOV-007, SOV-008 | [Issue](https://github.com/apil-khadka/Sovra/issues/13) |
| [SOV-010](#sov-010) | Implement consent-bound proof requests and minimal holder flow | G1 | p0 | SOV-001, SOV-003, SOV-005, SOV-007, SOV-008 | [Issue](https://github.com/apil-khadka/Sovra/issues/14) |
| [SOV-011](#sov-011) | Implement durable multi-instance verification and replay-safe acceptance | G1 | p0 | SOV-001, SOV-003, SOV-005, SOV-007, SOV-008, SOV-009, SOV-010 | [Issue](https://github.com/apil-khadka/Sovra/issues/15) |
| [SOV-012](#sov-012) | Implement freshness, revocation and key-compromise lifecycle | G1 | p0 | SOV-001, SOV-004, SOV-007, SOV-008, SOV-009, SOV-011 | [Issue](https://github.com/apil-khadka/Sovra/issues/16) |
| [SOV-013](#sov-013) | Integrate live Meta planning through bounded Spring AI tools | G1 | p1 | SOV-003, SOV-005, SOV-008, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/18) |
| [SOV-014](#sov-014) | Port deterministic plan guard and citation validation | G1 | p0 | SOV-001, SOV-003, SOV-008 | [Issue](https://github.com/apil-khadka/Sovra/issues/19) |
| [SOV-015](#sov-015) | Finalize business APIs and compatibility contracts | G1 | p1 | SOV-001, SOV-002, SOV-003, SOV-004 | [Issue](https://github.com/apil-khadka/Sovra/issues/17) |
| [SOV-016](#sov-016) | Implement encrypted local vault and purpose-bound document access | G2 | p0 | SOV-002, SOV-003, SOV-004, SOV-005, SOV-007, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/20) |
| [SOV-017](#sov-017) | Implement encrypted quarantine and isolated hostile-image admission | G2 | p0 | SOV-002, SOV-003, SOV-004, SOV-005, SOV-015, SOV-016, SOV-027 | [Issue](https://github.com/apil-khadka/Sovra/issues/22) |
| [SOV-018](#sov-018) | Implement local extraction, protected digests and provenance revisions | G2 | p1 | SOV-002, SOV-003, SOV-015, SOV-016, SOV-017 | [Issue](https://github.com/apil-khadka/Sovra/issues/23) |
| [SOV-019](#sov-019) | Implement enrollment review, corrections and claim eligibility | G2 | p0 | SOV-001, SOV-002, SOV-005, SOV-007, SOV-008, SOV-015, SOV-018, SOV-009 | [Issue](https://github.com/apil-khadka/Sovra/issues/24) |
| [SOV-020](#sov-020) | Implement holder credential custody and secure recovery | G2 | p0 | SOV-001, SOV-002, SOV-004, SOV-005, SOV-006, SOV-010, SOV-012, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/25) |
| [SOV-021](#sov-021) | Ship tested Java and TypeScript SDKs | G3 | p1 | SOV-003, SOV-005, SOV-015, SOV-016, SOV-019, SOV-011 | [Issue](https://github.com/apil-khadka/Sovra/issues/26) |
| [SOV-022](#sov-022) | Build developer portal, sandbox and integration onboarding | G3 | p1 | SOV-005, SOV-006, SOV-015, SOV-021 | [Issue](https://github.com/apil-khadka/Sovra/issues/27) |
| [SOV-023](#sov-023) | Build issuer information-management dashboard | G3 | p1 | SOV-005, SOV-006, SOV-007, SOV-012, SOV-015, SOV-016, SOV-019 | [Issue](https://github.com/apil-khadka/Sovra/issues/28) |
| [SOV-024](#sov-024) | Build holder enrollment, consent and credential dashboard | G3 | p1 | SOV-005, SOV-010, SOV-015, SOV-019, SOV-020 | [Issue](https://github.com/apil-khadka/Sovra/issues/29) |
| [SOV-025](#sov-025) | Build RP and organization integration dashboard | G3 | p1 | SOV-005, SOV-006, SOV-015, SOV-021, SOV-022 | [Issue](https://github.com/apil-khadka/Sovra/issues/30) |
| [SOV-026](#sov-026) | Build governed federation and security operations dashboard | G3 | p1 | SOV-005, SOV-006, SOV-007, SOV-008, SOV-015, SOV-029 | [Issue](https://github.com/apil-khadka/Sovra/issues/32) |
| [SOV-027](#sov-027) | Implement approved issuer-local deployment and isolation | G2 | p0 | SOV-002, SOV-003, SOV-004, SOV-005, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/21) |
| [SOV-028](#sov-028) | Implement supply-chain provenance and artifact admission | G2 | p0 | SOV-002, SOV-003, SOV-004, SOV-027 | [Issue](https://github.com/apil-khadka/Sovra/issues/33) |
| [SOV-029](#sov-029) | Implement semantic health, safe telemetry and security alerts | G1 | p0 | SOV-003, SOV-005, SOV-007, SOV-008, SOV-011, SOV-012 | [Issue](https://github.com/apil-khadka/Sovra/issues/31) |
| [SOV-030](#sov-030) | Approve and enforce service, resource and recovery budgets | G2 | p0 | SOV-002, SOV-003, SOV-004, SOV-015, SOV-027, SOV-029 | [Issue](https://github.com/apil-khadka/Sovra/issues/34) |
| [SOV-031](#sov-031) | Implement replay-safe recovery, key-copy containment and rollback | G2 | p0 | SOV-007, SOV-008, SOV-009, SOV-011, SOV-012, SOV-016, SOV-020, SOV-027, SOV-029, SOV-030 | [Issue](https://github.com/apil-khadka/Sovra/issues/35) |
| [SOV-032](#sov-032) | Complete SEC suite and ASVS applicability evidence | G3 | p0 | SOV-005, SOV-006, SOV-007, SOV-008, SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-016, SOV-017, SOV-018, SOV-019, SOV-020, SOV-021, SOV-022, SOV-023, SOV-024, SOV-025, SOV-026, SOV-027, SOV-028, SOV-029, SOV-030, SOV-031 | [Issue](https://github.com/apil-khadka/Sovra/issues/36) |
| [SOV-033](#sov-033) | Execute mission-critical attack, load, failover and rollback exercises | G3 | p0 | SOV-027, SOV-028, SOV-029, SOV-030, SOV-031, SOV-032 | [Issue](https://github.com/apil-khadka/Sovra/issues/37) |
| [SOV-034](#sov-034) | Obtain independent review and production release decision | G3 | p0 | SOV-032, SOV-033, SOV-035 | [Issue](https://github.com/apil-khadka/Sovra/issues/39) |
| [SOV-035](#sov-035) | Prove clean-checkout Java synthetic cross-issuer vertical slice | G1 | p0 | SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-029 | [Issue](https://github.com/apil-khadka/Sovra/issues/38) |
| [SOV-036](#sov-036) | Add interoperable selective disclosure under an approved profile | Conditional | p2 | SOV-001, SOV-009, SOV-012, SOV-020, SOV-032 | [Issue](https://github.com/apil-khadka/Sovra/issues/40) |

## Acceptance and evidence

Every implementation task requires tests of its public/user-facing paths, negative authorization and safe failure where relevant.
A design-only task closes a decision and does not establish implemented security.
Closure records the implementing commit/artifact, exact environment/configuration, reproducible commands and sanitized results; independent assessment remains separate from the author's own assertions.

### SOV-001

**Freeze proof profile, issuer assurance, freshness and session semantics**

Owner role: Architecture and security.
Gate: G0; proposed priority: p0; state: needs-triage.
Dependencies: None.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/5).
Requirements: FR-02, FR-08, FR-14, FR-17, FR-18, FR-21, FR-22, DR-05, DR-16, SR-03, SR-06, INV-03, INV-04, INV-06, INV-08.
Validation: SEC-04, SEC-05, SEC-06, SEC-07, SEC-10, SEC-11, SEC-12, SEC-30.
Open decisions to resolve or implement: OD-01, OD-03, OD-06, OD-14.

Acceptance criteria:

- Approve exact proof format, algorithms, holder binding, issuer/type/scope semantics and vetted library ownership/support.
- Specify trust/status freshness, clock skew, snapshot races, challenge lifetime, retry, idempotency and uncertain-commit recovery.
- Freeze independent valid and invalid fixtures; distinguish demo attestations from tested interoperable profiles.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-002

**Approve issuer locality, lifecycle, custody and root trust boundaries**

Owner role: Architecture, issuer authority and privacy.
Gate: G0; proposed priority: p0; state: needs-triage.
Dependencies: None.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/6).
Requirements: DR-01, DR-04, DR-09, DR-10, DR-11, DR-15, DR-16, SR-24, SR-25, SR-33, INV-11, NFR-12.
Validation: SEC-20, SEC-27, SEC-38, SEC-40, SEC-44, MC-05, MC-06.
Open decisions to resolve or implement: OD-07, OD-08, OD-09, OD-15, OD-17.

Acceptance criteria:

- Approve a data-flow inventory covering originals, derivatives, keys, TLS termination, OCR, telemetry, support, backups and failover.
- Record retention/deletion obligations, permitted disclosures and provider/operator/root visibility for each location.
- Decide whether attested confidential processing is required; document remaining administrative override powers and issuer approval.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-003

**Bootstrap Java 25 and Spring workspace with integration harness**

Owner role: Backend and build engineering.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: None.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/7).
Requirements: NFR-06, NFR-07, NFR-08, SR-14.
Validation: SEC-29.

Acceptance criteria:

- Resolve Java 25 LTS, Spring Boot/Security and Spring AI candidates from the baseline with BOMs and immutable build inputs.
- Provide a clean-checkout build, migrations, synthetic fixtures and packaged HTTP/PostgreSQL integration harness with two backend instances.
- Preserve existing TypeScript fixtures and prototype behavior until equivalent Java evidence passes; record dependency owners, licenses, support and SBOM.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-004

**Select identity and key providers with revocation and cache contracts**

Owner role: Security, identity and key operations.
Gate: G0; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-002.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/8).
Requirements: IF-05, SR-02, SR-13, SR-19, SR-20, SR-21, SR-26, SR-27, SR-29, DR-12, DR-17.
Validation: SEC-14, SEC-26, SEC-33, SEC-34, SEC-35, MC-01, MC-04, MC-06, MC-09, MC-10.
Open decisions to resolve or implement: OD-10, OD-13, OD-18.

Acceptance criteria:

- Approve provider, region/operator, key algorithms, envelope/AAD/nonce format and signing/unwrap interfaces.
- Specify MFA enrollment/recovery, JIT elevation, independent approvals and separate workload/deploy/migration/key/audit identities.
- Define measurable token, grant, DEK and positive-permission cache bounds, restored-key inventories and control/data-plane outage rules.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-005

**Implement tenant, issuer, RP and object authorization**

Owner role: Backend security.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/9).
Requirements: FR-01, FR-16, FR-24, DR-06, IF-02, IF-06, SR-01, SR-15, SR-27.
Validation: SEC-01, SEC-02, SEC-03, SEC-25, SEC-26, SEC-31, MC-01, MC-06.

Acceptance criteria:

- Enforce authenticated principal, tenant, issuer/RP, action and object authority at HTTP and service entry points.
- Run database access under non-owner, non-superuser roles without BYPASSRLS; separate migrations and test pooled tenant context.
- Deny cross-boundary reads, existence leaks, alternate-controller bypass and caller-supplied identity/proxy overrides in packaged tests.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-006

**Implement privileged access and application credential lifecycle**

Owner role: Identity and security.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-004, SOV-005.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/10).
Requirements: FR-26, FR-28, FR-47, SR-02, SR-26, SR-27, SR-29.
Validation: SEC-01, SEC-26, SEC-32, SEC-43, MC-01, MC-09.
SRS acceptance: AC-16.
Open decisions to resolve or implement: OD-10, OD-18.

Acceptance criteria:

- Implement phishing-resistant privileged enrollment, authentication, recovery and bounded elevation with independent high-impact approvals.
- Separate sandbox/production applications, approved scopes/origins/audiences, secret rotation and revocation.
- Exercise stolen sessions, removed roles, weak recovery and warm authorization caches within approved containment bounds.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-007

**Implement durable privacy-minimized audit and decision evidence**

Owner role: Backend and security operations.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/11).
Requirements: FR-27, DR-08, SR-12, SR-16, INV-02.
Validation: SEC-20, SEC-28, MC-06, MC-08.
Open decisions to resolve or implement: OD-07, OD-11.

Acceptance criteria:

- Define transaction/durability relations between decisions, nonce consumption and required audit references.
- Protect audit integrity under a separate authority and implement declared failure behavior when required evidence cannot commit.
- Test mutation/deletion, outages and sensitive canaries across successful and rejected operations without logging credentials, PII or tokens.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-008

**Implement versioned trust registry and approved RP policies**

Owner role: Trust and policy backend.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-003, SOV-005, SOV-007.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/12).
Requirements: FR-03, FR-13, FR-17, FR-18, FR-25, FR-32, DR-05, SR-05, SR-06, INV-03, INV-05, INV-06.
Validation: SEC-11, SEC-12, SEC-13.

Acceptance criteria:

- Implement scoped issuer/type/claim/purpose approval, immutable policy/trust revisions and effective epochs.
- Validate approved metadata endpoints, signed key bindings, freshness and separately authorized changes.
- Prove AI, ordinary admins and unapproved schemas cannot create policy authority or broaden trust.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-009

**Implement issuer-scoped issuance and constrained signing**

Owner role: Credential backend and key operations.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-003, SOV-004, SOV-005, SOV-007, SOV-008.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/13).
Requirements: FR-02, FR-23, DR-05, DR-09, IF-05, SR-03, SR-13, SR-27, INV-03, INV-08.
Validation: SEC-04, SEC-05, SEC-06, SEC-14, SEC-26, MC-06.

Acceptance criteria:

- Issue only permitted profile claims from authorized synthetic issuer inputs and current trust/type scope.
- Bind credential ID, holder, key version, validity and status; make authorized duplicate retries recover the same result.
- Constrain the signing boundary to approved issuance evidence; reject arbitrary payload, wrong-issuer signing, key export and self-granted key permissions.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-010

**Implement consent-bound proof requests and minimal holder flow**

Owner role: Verifier backend and holder frontend.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-003, SOV-005, SOV-007, SOV-008.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/14).
Requirements: FR-07, FR-20, FR-21, DR-02, SR-05, UX-01, UX-02, UX-03, UX-04, INV-05.
Validation: SEC-13, SEC-23, SEC-24, SEC-32.

Acceptance criteria:

- Bind request, RP/audience, purpose, exact claims, plan hash, challenge and expiry to explicit holder consent.
- Implement visibly distinct pending, denied, unavailable, review and verified states with safe rendering.
- Prove refusal, inactivity, scope edits, wrong holder and expired consent cannot produce an authorized presentation.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-011

**Implement durable multi-instance verification and replay-safe acceptance**

Owner role: Verifier backend.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-003, SOV-005, SOV-007, SOV-008, SOV-009, SOV-010.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/15).
Requirements: FR-08, FR-19, FR-21, FR-22, FR-31, SR-04, SR-05, SR-06, INV-01, INV-02, INV-05, INV-07, INV-08.
Validation: SEC-04, SEC-07, SEC-08, SEC-09, SEC-10, SEC-11, SEC-12, SEC-13.
SRS acceptance: AC-02, AC-03, AC-06.
Open decisions to resolve or implement: OD-06.

Acceptance criteria:

- Validate signature/profile, holder, audience, consent, policy, trust scope/status/freshness and session bindings before acceptance.
- Commit nonce consumption, immutable decision and required audit relation atomically across two instances.
- Exercise concurrency, process kill, commit ambiguity and response loss; only authorized retrieval may return an existing result and manual follow-up cannot rewrite invalid evidence.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-012

**Implement freshness, revocation and key-compromise lifecycle**

Owner role: Credential backend and security operations.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-004, SOV-007, SOV-008, SOV-009, SOV-011.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/16).
Requirements: FR-18, FR-23, FR-30, DR-05, DR-17, SR-06, SR-13, SR-29, INV-04, INV-06.
Validation: SEC-11, SEC-12, SEC-14, SEC-27, MC-04, MC-09, MC-10.

Acceptance criteria:

- Implement terminal credential revocation, key rotation/compromise, trust epochs and declared status snapshot freshness.
- Reject unknown/stale authority and current denied grants even when positive or DEK caches are warm.
- Exercise revocation races and dependency outages; record actual authority/key/status versions and containment times.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-013

**Integrate live Meta planning through bounded Spring AI tools**

Owner role: AI integration.
Gate: G1; proposed priority: p1; state: needs-triage.
Dependencies: SOV-003, SOV-005, SOV-008, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/18).
Requirements: FR-04, FR-05, FR-06, FR-11, FR-12, FR-29, DR-03, IF-04, IF-07, SR-07, SR-08, SR-09, NFR-03, NFR-10.
Validation: SEC-15, SEC-16, SEC-17, SEC-18, SEC-19, SEC-20, SEC-22.
SRS acceptance: AC-05, AC-06, AC-07.
Open decisions to resolve or implement: OD-02.

Acceptance criteria:

- Verify the actual Meta endpoint, model, adapter and live tool/structured-output/error contract using synthetic inputs.
- Reauthorize trusted context in every tool callback and constrain destinations, resolved addresses, redirects, schema, calls, tokens, deadlines and retries.
- Freeze prompt/model/tool versions and compare unseen/incompatible-schema outcomes against a deterministic baseline, including failures and sanitized latency/cost evidence.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-014

**Port deterministic plan guard and citation validation**

Owner role: Policy backend.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-003, SOV-008.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/19).
Requirements: FR-05, FR-06, FR-09, FR-10, FR-11, FR-25, FR-32, DR-02, DR-03, SR-05, SR-07, SR-08, NFR-06, NFR-10.
Validation: SEC-13, SEC-15, SEC-16, SEC-18, SEC-20.
SRS acceptance: AC-05.

Acceptance criteria:

- Validate claim semantics, issuer/type eligibility, approved RP policy, disclosure budget and real source-section citations independently of model output.
- Reject invented claims/issuers/citations, injection, excessive disclosure and incompatible schemas before a holder request is created.
- Keep domain decisions framework-independent with explicit version/clock inputs and frozen positive/negative fixtures.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-015

**Finalize business APIs and compatibility contracts**

Owner role: API architecture.
Gate: G1; proposed priority: p1; state: needs-triage.
Dependencies: SOV-001, SOV-002, SOV-003, SOV-004.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/17).
Requirements: IF-01, IF-02, IF-03, IF-07, IF-09, IF-10, IF-11, IF-12, NFR-09.
Validation: SEC-17, SEC-19, SEC-21, SEC-29, SEC-42, SEC-43.
Open decisions to resolve or implement: OD-16.

Acceptance criteria:

- Complete versioned control-plane, issuer-local and verifier contracts with approved origins, audiences and per-operation scopes.
- Specify RFC 9457 errors, bounded pagination/filters, ETags/preconditions, jobs, cancellation and authenticated idempotent retry semantics.
- Validate OpenAPI and provider/consumer compatibility, malformed/ambiguous inputs, destination routing and legacy error migration without claiming OpenID conformance.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-016

**Implement encrypted local vault and purpose-bound document access**

Owner role: Document backend and key operations.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005, SOV-007, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/20).
Requirements: FR-35, FR-40, DR-09, DR-12, DR-17, SR-19, SR-20, SR-21, SR-29, INV-10, INV-11.
Validation: SEC-33, SEC-34, SEC-35, SEC-44, MC-04, MC-09, MC-10.
SRS acceptance: AC-09, AC-12, AC-16.
Open decisions to resolve or implement: OD-13, OD-18.

Acceptance criteria:

- Use reviewed per-object-version envelope AEAD, fresh DEKs, protected context and approved local wrapping keys.
- Authorize current principal, issuer, object/version, purpose and workload before unwrap; release no plaintext before full authentication.
- Test ciphertext/tag/context/key substitution, nonce concurrency/retry safety, expired/revoked grants and KMS/cache outages with no plaintext fallback.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-017

**Implement encrypted quarantine and isolated hostile-image admission**

Owner role: Document processing and platform security.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005, SOV-015, SOV-016, SOV-027.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/22).
Requirements: SR-22, SR-23, SR-30, SR-33, NFR-03, NFR-14, INV-09, INV-11.
Validation: SEC-21, SEC-22, SEC-36, SEC-40, MC-02, MC-05, MC-06.
SRS acceptance: AC-10, AC-12.
Open decisions to resolve or implement: OD-13, OD-17.

Acceptance criteria:

- Admit allowlisted actual file types into encrypted local quarantine with byte/pixel/decoder/time/resource limits.
- Run scanning/decoding in separately scoped OS/process/runtime isolation without relying on Java Security Manager.
- Exercise malformed/polyglot/bomb fixtures and controlled worker compromise; deny signer/key/unrelated-document/host access and forbidden egress.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-018

**Implement local extraction, protected digests and provenance revisions**

Owner role: Document and data engineering.
Gate: G2; proposed priority: p1; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-015, SOV-016, SOV-017.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/23).
Requirements: FR-36, FR-38, DR-11, DR-13, DR-14, DR-15, SR-23, SR-24, INV-09, INV-10.
Validation: SEC-36, SEC-37, SEC-38, SEC-39, SEC-40.
SRS acceptance: AC-10, AC-11, AC-12.
Open decisions to resolve or implement: OD-15.

Acceptance criteria:

- Extract only in approved local processing and preserve source/version/digest, engine/schema/normalizer, confidence and observed versus corrected values.
- Protect exact-byte and canonical structured digests with provenance; never expose guessable PII hashes or global image fingerprints as identity authority.
- Create immutable unapproved revisions on corrections/re-encoding and prove stale digests/reviews cannot authorize claims or leak to the planner.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-019

**Implement enrollment review, corrections and claim eligibility**

Owner role: Issuer enrollment backend.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-002, SOV-005, SOV-007, SOV-008, SOV-015, SOV-018, SOV-009.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/24).
Requirements: FR-33, FR-34, FR-37, FR-38, FR-39, FR-31, DR-14, DR-16, UX-06, INV-09, INV-10.
Validation: SEC-37, SEC-39, SEC-43.
SRS acceptance: AC-10, AC-11.
Open decisions to resolve or implement: OD-14.

Acceptance criteria:

- Create distinct opaque issuer-local subject/document/enrollment/credential identifiers without granting identity status through ID creation.
- Enforce issuer evidence validation, holder binding, revision-specific review and required separation of duties.
- Reject self-approval, caller-supplied claims, stale source approvals and OCR-only authority; source changes follow explicit refresh/revocation policy.
- Integrate current approved enrollment/source revisions with the constrained signer and prove obsolete or unreviewed provenance cannot authorize production issuance.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-020

**Implement holder credential custody and secure recovery**

Owner role: Holder security.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-001, SOV-002, SOV-004, SOV-005, SOV-006, SOV-010, SOV-012, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/25).
Requirements: FR-14, FR-20, DR-10, DR-16, SR-02, SR-11, UX-05.
Validation: SEC-07, SEC-13, SEC-14, SEC-24, SEC-32, MC-01, MC-09.
SRS acceptance: AC-14, AC-16.
Open decisions to resolve or implement: OD-09, OD-12.

Acceptance criteria:

- Implement approved client/server key custody, presentation binding, loss/theft/recovery and administrator limitations.
- Ensure recovery invalidates affected authority under declared bounds without bypassing proof/consent or resurrecting revoked credentials.
- Assess supported browsers, keyboard/focus/labels and assistive technology against an approved accessibility target with actual recovery/consent flows.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-021

**Ship tested Java and TypeScript SDKs**

Owner role: SDK engineering.
Gate: G3; proposed priority: p1; state: needs-triage.
Dependencies: SOV-003, SOV-005, SOV-015, SOV-016, SOV-019, SOV-011.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/26).
Requirements: FR-46, IF-13, NFR-09, NFR-13.
Validation: SEC-29, SEC-42, SEC-43.
SRS acceptance: AC-13.
Open decisions to resolve or implement: OD-16.

Acceptance criteria:

- Provide typed supported contracts, safe authentication, strict origin/audience validation and sanitized typed errors.
- Bound upload/job/retry behavior and preserve idempotency, preconditions and cancellation without automatic cross-region fallback.
- Pass clean Java/TypeScript quickstarts, consumer/provider and negative security tests; publish version/support/provenance records without browser secrets.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-022

**Build developer portal, sandbox and integration onboarding**

Owner role: Developer experience.
Gate: G3; proposed priority: p1; state: needs-triage.
Dependencies: SOV-005, SOV-006, SOV-015, SOV-021.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/27).
Requirements: FR-45, FR-47, IF-11, UX-08, NFR-13.
Validation: SEC-42, SEC-43.
SRS acceptance: AC-13.
Open decisions to resolve or implement: OD-16.

Acceptance criteria:

- Publish capability discovery, correct approved origins, API/auth/scope/error/limit guidance and Java/TypeScript SDK compatibility.
- Provide synthetic sandbox, complete quickstarts and approved organization/application onboarding without undocumented privileges.
- Have an independent developer complete a scoped synthetic integration and rotate/revoke credentials without exposing live secrets.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-023

**Build issuer information-management dashboard**

Owner role: Issuer frontend.
Gate: G3; proposed priority: p1; state: needs-triage.
Dependencies: SOV-005, SOV-006, SOV-007, SOV-012, SOV-015, SOV-016, SOV-019.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/28).
Requirements: FR-41, UX-06, UX-07, IF-13.
Validation: SEC-23, SEC-24, SEC-35, SEC-37, SEC-39, SEC-41.
SRS acceptance: AC-11, AC-14.

Acceptance criteria:

- Expose local enrollment, source/extraction corrections, revision review, issuance/status and scoped audit through published APIs.
- Require explicit purpose-bound authorization for original-image viewing and distinguish observations, approvals and credentials.
- Exercise reviewer separation, stale ETags, hostile rendering and cross-issuer/ordinary-admin access in browser E2E tests.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-024

**Build holder enrollment, consent and credential dashboard**

Owner role: Holder frontend.
Gate: G3; proposed priority: p1; state: needs-triage.
Dependencies: SOV-005, SOV-010, SOV-015, SOV-019, SOV-020.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/29).
Requirements: FR-42, UX-01, UX-02, UX-03, UX-04, UX-05, UX-06, UX-07, IF-13.
Validation: SEC-13, SEC-23, SEC-24, SEC-32, SEC-41.
SRS acceptance: AC-04, AC-14.
Open decisions to resolve or implement: OD-12.

Acceptance criteria:

- Show only permitted holder enrollment, corrections, documents, credentials, disclosure history and recovery through authorized APIs.
- Render exact RP/purpose/claims/expiry before explicit approval and keep pending, denied, unavailable and verified states distinct.
- Pass cross-holder/hostile-content/expired-viewer tests plus approved accessibility and supported-client assessment.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-025

**Build RP and organization integration dashboard**

Owner role: RP frontend.
Gate: G3; proposed priority: p1; state: needs-triage.
Dependencies: SOV-005, SOV-006, SOV-015, SOV-021, SOV-022.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/30).
Requirements: FR-43, UX-07, UX-08, IF-13.
Validation: SEC-23, SEC-24, SEC-41, SEC-42, SEC-43.
SRS acceptance: AC-13, AC-14.

Acceptance criteria:

- Manage authorized apps, scopes, credentials, documentation, SDKs, verification outcomes and safe usage metrics.
- Enforce sandbox/production, role/object and audience boundaries through public APIs.
- Demonstrate no source-image/OCR/person-search/KMS entitlement and test rotation, revoked roles and cross-organization navigation.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-026

**Build governed federation and security operations dashboard**

Owner role: Federation frontend and security operations.
Gate: G3; proposed priority: p1; state: needs-triage.
Dependencies: SOV-005, SOV-006, SOV-007, SOV-008, SOV-015, SOV-029.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/32).
Requirements: FR-44, FR-26, UX-07, IF-13.
Validation: SEC-23, SEC-24, SEC-26, SEC-41, MC-01, MC-08.
SRS acceptance: AC-14.

Acceptance criteria:

- Manage approved issuer onboarding and versioned trust/schema metadata through scoped high-impact approval flows.
- Present sanitized health, authority versions, security alerts and audit evidence with no raw-source/key access.
- Test that dashboard administrators cannot self-accredit issuers, decrypt documents or bypass independent approvals.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-027

**Implement approved issuer-local deployment and isolation**

Owner role: Platform security and operations.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/21).
Requirements: DR-01, DR-04, DR-11, IF-08, SR-09, SR-11, SR-15, SR-25, SR-27, SR-30, SR-33, INV-11, INV-13, NFR-14.
Validation: SEC-17, SEC-23, SEC-25, SEC-26, SEC-31, SEC-40, SEC-41, MC-02, MC-05, MC-06.
SRS acceptance: AC-12, AC-14.
Open decisions to resolve or implement: OD-08, OD-17.

Acceptance criteria:

- Implement approved ingress/TLS termination, private data/key paths, issuer-local OCR/storage/backups and management-plane separation.
- Apply distinct workload/runtime/deployment/migration/audit identities, database privilege controls and explicit egress restrictions.
- Test alternate ingress, direct DB/key access, DNS/redirect SSRF, support paths and outage routing against the approved locality/root threat model.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-028

**Implement supply-chain provenance and artifact admission**

Owner role: Build and platform security.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-027.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/33).
Requirements: SR-14, SR-31, NFR-08, NFR-09.
Validation: SEC-29, MC-07.
SRS acceptance: AC-17.

Acceptance criteria:

- Produce source/dependency/JDK/configuration inventory, SBOM, scans and signed provenance bound to immutable artifacts.
- Admission must verify approved source, builder, digest, configuration and runtime identity.
- Reject a validly signed artifact from the wrong source/builder plus substituted images/configuration; prove supported migration/rollback compatibility.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-029

**Implement semantic health, safe telemetry and security alerts**

Owner role: Observability and security operations.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-003, SOV-005, SOV-007, SOV-008, SOV-011, SOV-012.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/31).
Requirements: FR-29, DR-08, SR-12, SR-32, NFR-02, NFR-11.
Validation: SEC-19, SEC-20, SEC-28, MC-08, MC-10.
SRS acceptance: AC-07, AC-17.

Acceptance criteria:

- Separate process liveness from flow readiness and test actual freshness, replay persistence, authorization/key and durable-audit dependencies.
- Close affected readiness and alert on unsafe stale authority/commit failure even when HTTP probes succeed.
- Report sanitized stage timings and reason metrics; success/failure canaries cover logs, traces, errors, metrics, model paths and crash handling.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-030

**Approve and enforce service, resource and recovery budgets**

Owner role: Product, performance and operations.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-015, SOV-027, SOV-029.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/34).
Requirements: NFR-02, NFR-03, NFR-04, NFR-11, NFR-14, NFR-15.
Validation: SEC-19, SEC-21, SEC-22, SEC-27, MC-02, MC-08, MC-09, MC-10.
Open decisions to resolve or implement: OD-04, OD-05, OD-13, OD-18.

Acceptance criteria:

- Approve numeric latency/capacity/availability/RPO/RTO and detection/containment targets with load, windows and dependency assumptions.
- Enforce body/file/parser/decoder/crypto/model/tool/concurrency/rate/deadline/retry budgets with safe overload behavior.
- Measure p50/p95/p99, throughput/resources and cache/control/data-plane bounds in isolated representative staging under synthetic load.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-031

**Implement replay-safe recovery, key-copy containment and rollback**

Owner role: Operations and security.
Gate: G2; proposed priority: p0; state: needs-triage.
Dependencies: SOV-007, SOV-008, SOV-009, SOV-011, SOV-012, SOV-016, SOV-020, SOV-027, SOV-029, SOV-030.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/35).
Requirements: FR-30, FR-48, DR-07, DR-09, DR-17, SR-13, SR-25, SR-28, SR-29, INV-04, INV-12, INV-13, NFR-05, NFR-11, NFR-16.
Validation: SEC-14, SEC-27, SEC-44, MC-03, MC-04, MC-05, MC-09, MC-10.
SRS acceptance: AC-14, AC-15, AC-16, AC-17.
Open decisions to resolve or implement: OD-05, OD-07, OD-18.

Acceptance criteria:

- Fence obsolete writers and reconcile or invalidate ambiguous replay, revocation, trust and approval state before restored acceptance.
- Inventory independent restored keys, backups, cached DEKs/grants and derivative/deletion dependencies; implement measured containment without claiming plaintext recall.
- Exercise stale restore, split brain, blue/green rollback, key/data mismatch and control/data-plane outages within approved locality and recovery bounds.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-032

**Complete SEC suite and ASVS applicability evidence**

Owner role: Security validation.
Gate: G3; proposed priority: p0; state: needs-triage.
Dependencies: SOV-005, SOV-006, SOV-007, SOV-008, SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-016, SOV-017, SOV-018, SOV-019, SOV-020, SOV-021, SOV-022, SOV-023, SOV-024, SOV-025, SOV-026, SOV-027, SOV-028, SOV-029, SOV-030, SOV-031.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/36).
Requirements: SR-10, SR-17, SR-18, NFR-01, NFR-06, NFR-15, NFR-17.
Validation: SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10, SEC-11, SEC-12, SEC-13, SEC-14, SEC-15, SEC-16, SEC-17, SEC-18, SEC-19, SEC-20, SEC-21, SEC-22, SEC-23, SEC-24, SEC-25, SEC-26, SEC-27, SEC-28, SEC-29, SEC-30, SEC-31, SEC-32, SEC-33, SEC-34, SEC-35, SEC-36, SEC-37, SEC-38, SEC-39, SEC-40, SEC-41, SEC-42, SEC-43, SEC-44.
SRS acceptance: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08, AC-09, AC-10, AC-11, AC-12, AC-13, AC-14, AC-15, AC-16, AC-17.

Acceptance criteria:

- Implement every applicable SEC-01 through SEC-44 case with independently asserted expected outcomes across packaged HTTP, database, provider and browser paths.
- Add generated/fuzz, concurrency, restart, mutation and fault tests where relevant; require removing a critical check to fail its assertion.
- Record individual ASVS 5.0.0 requirements through Level 3, applicability rationale, evidence and findings; missing evidence or unresolved high/critical findings blocks release.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-033

**Execute mission-critical attack, load, failover and rollback exercises**

Owner role: Security exercise and operations.
Gate: G3; proposed priority: p0; state: needs-triage.
Dependencies: SOV-027, SOV-028, SOV-029, SOV-030, SOV-031, SOV-032.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/37).
Requirements: SR-26, SR-27, SR-28, SR-29, SR-30, SR-31, SR-32, SR-33, INV-12, INV-13, NFR-15, NFR-16, NFR-17.
Validation: MC-01, MC-02, MC-03, MC-04, MC-05, MC-06, MC-07, MC-08, MC-09, MC-10.
SRS acceptance: AC-12, AC-15, AC-16, AC-17.
Open decisions to resolve or implement: OD-05, OD-17, OD-18.

Acceptance criteria:

- Execute MC-01 through MC-10 against isolated representative deployed staging under declared synthetic load and controlled faults.
- Retain independent assertions, normal/failure comparisons, actual authority/provider/cache observations and measured detection/containment/recovery results.
- Clean up faults, retest findings and block release for unsafe acceptance, disclosure, locality/replay bypass or missing/stale evidence.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-034

**Obtain independent review and production release decision**

Owner role: Independent security reviewer and release authority.
Gate: G3; proposed priority: p0; state: needs-triage.
Dependencies: SOV-032, SOV-033, SOV-035.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/39).
Requirements: SR-18, SR-33, NFR-04, NFR-12, NFR-17.
Validation: SEC-30, MC-01, MC-02, MC-03, MC-04, MC-05, MC-06, MC-07, MC-08, MC-09, MC-10.
SRS acceptance: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08, AC-09, AC-10, AC-11, AC-12, AC-13, AC-14, AC-15, AC-16, AC-17.
Open decisions to resolve or implement: OD-01, OD-04, OD-05, OD-07, OD-08, OD-09, OD-10, OD-11, OD-12, OD-13, OD-14, OD-15, OD-16, OD-17, OD-18.

Acceptance criteria:

- Obtain independent proof/profile, application, infrastructure, privacy/residency and privileged/root boundary review for the exact deployment/customer scope.
- Retest findings, close every applicable open decision and require complete SEC/MC/ASVS evidence with no unresolved high/critical finding.
- Have named accountable release/issuer authorities approve the real-data and production gates; publish only evidence-supported claims and limitations.
- If the expanded interoperable/selective-disclosure profile is selected, require SOV-036 to pass before approving that release.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-035

**Prove clean-checkout Java synthetic cross-issuer vertical slice**

Owner role: Backend integration and E2E.
Gate: G1; proposed priority: p0; state: needs-triage.
Dependencies: SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-029.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/38).
Requirements: FR-04, FR-09, FR-10, FR-11, FR-12, FR-19, FR-20, FR-21, FR-22, NFR-01, NFR-07, NFR-10.
Validation: SEC-04, SEC-08, SEC-09, SEC-11, SEC-12, SEC-13, SEC-15, SEC-16, SEC-18, SEC-19, SEC-20.
SRS acceptance: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08.
Open decisions to resolve or implement: OD-02.

Acceptance criteria:

- Reproduce the Java issuer-to-holder-to-verifier flow from a clean checkout using synthetic jurisdictions, scoped keys/data and a real Meta call.
- Prove SRS AC-01 through AC-08, including refusal, tampering, replay, stale/unknown authority, incompatible plans and no source-record/model PII exchange.
- Retain commands, immutable versions, complete positive/negative outcomes and sanitized evidence; this gate grants no real-data or production authorization.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-036

**Add interoperable selective disclosure under an approved profile**

Owner role: Credential interoperability.
Gate: Conditional; proposed priority: p2; state: needs-triage.
Dependencies: SOV-001, SOV-009, SOV-012, SOV-020, SOV-032.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/40).
Requirements: FR-14, FR-15, DR-02, DR-16, SR-03, NFR-12.
Validation: SEC-04, SEC-05, SEC-06, SEC-30.
Open decisions to resolve or implement: OD-01.
Condition: Requires separate approval of expanded proof-profile scope; excluded from initial narrow-attestation gate.

Acceptance criteria:

- Proceed only when a separately approved interoperable/selective-disclosure profile is selected beyond the initial narrow-attestation scope.
- Use independent wallet/issuer/verifier implementations and positive/negative protocol corpus for the exact profile versions.
- Prove undisclosed fields are cryptographically absent and holder/replay/status semantics remain valid before making conformance or unlinkability claims.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.
