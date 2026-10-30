# Implementation backlog

**Baseline:** business SRS v0.6, 2026-10-28.
**State:** 2026-10-29 source/evidence audit recorded; issue triage and full acceptance remain separate.

This backlog contains 41 tasks for the Java/Spring business application, issuer-local identity/documents, protocol qualification, SDKs, dashboards, deployed security and independent release evidence.
The [SRS](../requirements/software-requirements-specification.md) defines requirements and the [implementation plan](implementation-plan.md) defines delivery gates.
The [task registry](implementation-tasks.json) contains the same task IDs, dependencies, acceptance criteria and tracker URLs for tooling.
The [provider architecture assessment](../architecture/identity-key-provider-architecture.md) records the selected reference and ARCH-01 through ARCH-08.

## Development and release boundaries

Confirmed initial launch: public demo with synthetic identities/documents only and no new paid services, subscriptions or hardware.
Use self-hosted Keycloak and existing or verified no-charge resources; paid HSM/TEE qualification is deferred and real-ID ingestion remains disabled.
Before publication, verify external capacity and charge prevention, restricted demo actions, rotated secrets, private administration and bounded resource use.
Actual visitor/authentication metadata still requires minimization/protection, and fixtures never count as a live model call.

The selected reference is issuer-local Keycloak plus Google Cloud KMS Single-tenant HSM/Confidential Space where the complete issuer-approved location/capability intersection exists.
Synthetic SOV-006 and G1 development can proceed under SOV-001/002/004 contracts without a production account or completed external assessment.
SOV-037 independent assessment and SOV-039 actual issuer/location approval remain gates before real-data provisioning/processing.
SOV-027/028/038 provide isolated deployment, artifact admission and deployed attested key/input-path evidence; SOV-032/033/034 retain complete release assessment.
No architecture recommendation, source observation or historical test report closes a live-data/security gate.

SOV-036 is mandatory G1 qualification for the already selected full interoperable profile.
It no longer depends on final whole-product SEC coverage or holder-custody release, avoiding a circular prerequisite.
SOV-010/011 integrate the qualified profile and SOV-041 proves the packaged consent-to-verification flow across two instances.
An independent credential-signature probe is issuance evidence, not complete verification E2E evidence.

## Triage and closure

Stable numbering is not execution order; follow dependencies, including forward references.
An owner role is a responsibility, not an assigned person or an appointed external assessor.
Existing task status is retained for maintainer triage; source observations do not assert full acceptance.
Dependencies must meet the relevant criteria before dependent integration is accepted, while isolated synthetic design/scaffolding may proceed without claiming those dependencies passed.
Security tests ship with each component; SOV-032 consolidates and assesses evidence rather than deferring testing to the end.
Record exact commits/artifacts, effective configuration, reproducible commands, independently asserted positive/negative results and retested findings.
Do not attach identity data, credentials, secrets or private research to public issues/evidence.

## Gate map

| Gate | Principal scope |
| --- | --- |
| G0 | SOV-001/002/004 contracts; SOV-039 deployment/location qualification and SOV-037 independent design assessment remain unsatisfied live-data gates |
| G1 | Java authority/audit/trust/issuance, mandatory SOV-036 profile qualification, consent/verification/status, bounded AI/guard, SOV-040 authority hardening and SOV-041 packaged E2E |
| G2 | Privileged lifecycle, document/custody features, isolated deployment, budgets/recovery and SOV-038 attested HSM/input gateways, tested with synthetic data |
| G3 | SDK/portal/dashboards and applicable SEC/MC/ASVS evidence, independent assessment, finding retest and accountable production release |

G2 completion alone does not authorize real-data collection, signing, decryption or customer operation.
All selected-profile, authority, locality, consent and replay requirements remain applicable across rollback and recovery.

Read the [current continuation guide](continuation-guide.md) for the implementation inventory, exact next steps, no-credit verification and public-demo blockers.
Implementation progress below is source/evidence scope, not a maintainer status or completed security gate.
All 41 remote issues were observed open during this audit.

## Task index

| ID | Task | Phase | Progress | Dependencies | Tracker |
| --- | --- | --- | --- | --- | --- |
| [SOV-001](#sov-001) | Freeze proof profile, issuer assurance, freshness and session semantics | G0 | partial | None | [Issue](https://github.com/apil-khadka/Sovra/issues/5) |
| [SOV-002](#sov-002) | Approve issuer locality, lifecycle, custody and root trust boundaries | G0 | partial | None | [Issue](https://github.com/apil-khadka/Sovra/issues/6) |
| [SOV-003](#sov-003) | Bootstrap Java 25 and Spring workspace with integration harness | G1 | demo_implemented | None | [Issue](https://github.com/apil-khadka/Sovra/issues/7) |
| [SOV-004](#sov-004) | Select identity and key providers with revocation and cache contracts | G0 | partial | SOV-001, SOV-002 | [Issue](https://github.com/apil-khadka/Sovra/issues/8) |
| [SOV-005](#sov-005) | Implement tenant, issuer, RP and object authorization | G1 | partial | SOV-002, SOV-003, SOV-004 | [Issue](https://github.com/apil-khadka/Sovra/issues/9) |
| [SOV-006](#sov-006) | Implement privileged access and application credential lifecycle | G2 | partial | SOV-004, SOV-005 | [Issue](https://github.com/apil-khadka/Sovra/issues/10) |
| [SOV-007](#sov-007) | Implement durable privacy-minimized audit and decision evidence | G1 | partial | SOV-002, SOV-003, SOV-004, SOV-005 | [Issue](https://github.com/apil-khadka/Sovra/issues/11) |
| [SOV-008](#sov-008) | Implement versioned trust registry and approved RP policies | G1 | partial | SOV-001, SOV-003, SOV-005, SOV-007 | [Issue](https://github.com/apil-khadka/Sovra/issues/12) |
| [SOV-009](#sov-009) | Implement issuer-scoped issuance and constrained signing | G1 | partial | SOV-001, SOV-003, SOV-004, SOV-005, SOV-007, SOV-008 | [Issue](https://github.com/apil-khadka/Sovra/issues/13) |
| [SOV-010](#sov-010) | Implement consent-bound proof requests and minimal holder flow | G1 | partial | SOV-001, SOV-003, SOV-005, SOV-007, SOV-008, SOV-036 | [Issue](https://github.com/apil-khadka/Sovra/issues/14) |
| [SOV-011](#sov-011) | Implement durable multi-instance verification and replay-safe acceptance | G1 | partial | SOV-001, SOV-003, SOV-005, SOV-007, SOV-008, SOV-009, SOV-010, SOV-036 | [Issue](https://github.com/apil-khadka/Sovra/issues/15) |
| [SOV-012](#sov-012) | Implement freshness, revocation and key-compromise lifecycle | G1 | partial | SOV-001, SOV-004, SOV-007, SOV-008, SOV-009, SOV-011 | [Issue](https://github.com/apil-khadka/Sovra/issues/16) |
| [SOV-013](#sov-013) | Integrate live Meta planning through bounded Spring AI tools | G1 | partial | SOV-003, SOV-005, SOV-008, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/18) |
| [SOV-014](#sov-014) | Port deterministic plan guard and citation validation | G1 | demo_implemented | SOV-001, SOV-003, SOV-008 | [Issue](https://github.com/apil-khadka/Sovra/issues/19) |
| [SOV-015](#sov-015) | Finalize business APIs and compatibility contracts | G1 | partial | SOV-001, SOV-002, SOV-003, SOV-004 | [Issue](https://github.com/apil-khadka/Sovra/issues/17) |
| [SOV-016](#sov-016) | Implement encrypted local vault and purpose-bound document access | G2 | partial | SOV-002, SOV-003, SOV-004, SOV-005, SOV-007, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/20) |
| [SOV-017](#sov-017) | Implement encrypted quarantine and isolated hostile-image admission | G2 | partial | SOV-002, SOV-003, SOV-004, SOV-005, SOV-015, SOV-016, SOV-027 | [Issue](https://github.com/apil-khadka/Sovra/issues/22) |
| [SOV-018](#sov-018) | Implement local extraction, protected digests and provenance revisions | G2 | demo_implemented | SOV-002, SOV-003, SOV-015, SOV-016, SOV-017 | [Issue](https://github.com/apil-khadka/Sovra/issues/23) |
| [SOV-019](#sov-019) | Implement enrollment review, corrections and claim eligibility | G2 | demo_implemented | SOV-001, SOV-002, SOV-005, SOV-007, SOV-008, SOV-015, SOV-018, SOV-009 | [Issue](https://github.com/apil-khadka/Sovra/issues/24) |
| [SOV-020](#sov-020) | Implement holder credential custody and secure recovery | G2 | demo_implemented | SOV-001, SOV-002, SOV-004, SOV-005, SOV-006, SOV-010, SOV-012, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/25) |
| [SOV-021](#sov-021) | Ship tested Java and TypeScript SDKs | G3 | demo_implemented | SOV-003, SOV-005, SOV-015, SOV-016, SOV-019, SOV-011 | [Issue](https://github.com/apil-khadka/Sovra/issues/26) |
| [SOV-022](#sov-022) | Build developer portal, sandbox and integration onboarding | G3 | not_started | SOV-005, SOV-006, SOV-015, SOV-021 | [Issue](https://github.com/apil-khadka/Sovra/issues/27) |
| [SOV-023](#sov-023) | Build issuer information-management dashboard | G3 | demo_implemented | SOV-005, SOV-006, SOV-007, SOV-012, SOV-015, SOV-016, SOV-019 | [Issue](https://github.com/apil-khadka/Sovra/issues/28) |
| [SOV-024](#sov-024) | Build holder enrollment, consent and credential dashboard | G3 | demo_implemented | SOV-005, SOV-010, SOV-015, SOV-019, SOV-020 | [Issue](https://github.com/apil-khadka/Sovra/issues/29) |
| [SOV-025](#sov-025) | Build RP and organization integration dashboard | G3 | not_started | SOV-005, SOV-006, SOV-015, SOV-021, SOV-022 | [Issue](https://github.com/apil-khadka/Sovra/issues/30) |
| [SOV-026](#sov-026) | Build governed federation and security operations dashboard | G3 | demo_implemented | SOV-005, SOV-006, SOV-007, SOV-008, SOV-015, SOV-029 | [Issue](https://github.com/apil-khadka/Sovra/issues/32) |
| [SOV-027](#sov-027) | Implement approved issuer-local deployment and isolation | G2 | partial | SOV-002, SOV-003, SOV-004, SOV-005, SOV-015, SOV-037, SOV-039 | [Issue](https://github.com/apil-khadka/Sovra/issues/21) |
| [SOV-028](#sov-028) | Implement supply-chain provenance and artifact admission | G2 | partial | SOV-002, SOV-003, SOV-004, SOV-027 | [Issue](https://github.com/apil-khadka/Sovra/issues/33) |
| [SOV-029](#sov-029) | Implement semantic health, safe telemetry and security alerts | G1 | demo_implemented | SOV-003, SOV-005, SOV-007, SOV-008, SOV-011, SOV-012 | [Issue](https://github.com/apil-khadka/Sovra/issues/31) |
| [SOV-030](#sov-030) | Approve and enforce service, resource and recovery budgets | G2 | partial | SOV-002, SOV-003, SOV-004, SOV-015, SOV-027, SOV-029 | [Issue](https://github.com/apil-khadka/Sovra/issues/34) |
| [SOV-031](#sov-031) | Implement replay-safe recovery, key-copy containment and rollback | G2 | partial | SOV-007, SOV-008, SOV-009, SOV-011, SOV-012, SOV-016, SOV-020, SOV-027, SOV-029, SOV-030 | [Issue](https://github.com/apil-khadka/Sovra/issues/35) |
| [SOV-032](#sov-032) | Complete SEC suite and ASVS applicability evidence | G3 | partial | SOV-005, SOV-006, SOV-007, SOV-008, SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-016, SOV-017, SOV-018, SOV-019, SOV-020, SOV-021, SOV-022, SOV-023, SOV-024, SOV-025, SOV-026, SOV-027, SOV-028, SOV-029, SOV-030, SOV-031, SOV-036, SOV-038, SOV-040, SOV-041 | [Issue](https://github.com/apil-khadka/Sovra/issues/36) |
| [SOV-033](#sov-033) | Execute mission-critical attack, load, failover and rollback exercises | G3 | deferred_production | SOV-027, SOV-028, SOV-029, SOV-030, SOV-031, SOV-032 | [Issue](https://github.com/apil-khadka/Sovra/issues/37) |
| [SOV-034](#sov-034) | Obtain independent review and production release decision | G3 | deferred_production | SOV-032, SOV-033, SOV-035, SOV-036, SOV-037, SOV-038, SOV-039, SOV-040, SOV-041 | [Issue](https://github.com/apil-khadka/Sovra/issues/39) |
| [SOV-035](#sov-035) | Prove clean-checkout Java synthetic cross-issuer vertical slice | G1 | partial | SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-029, SOV-036, SOV-041 | [Issue](https://github.com/apil-khadka/Sovra/issues/38) |
| [SOV-036](#sov-036) | Qualify selected SD-JWT VC and OpenID libraries and profile adapters | G1 | partial | SOV-001, SOV-003, SOV-004, SOV-009, SOV-015 | [Issue](https://github.com/apil-khadka/Sovra/issues/40) |
| [SOV-037](#sov-037) | Obtain independent G0 architecture, privacy and custody assessment | G0 | deferred_production | SOV-001, SOV-002, SOV-004, SOV-039 | [Issue](https://github.com/apil-khadka/Sovra/issues/42) |
| [SOV-038](#sov-038) | Implement attested HSM authorization and confidential input gateways | G2 | deferred_production | SOV-004, SOV-006, SOV-016, SOV-027, SOV-028, SOV-040 | [Issue](https://github.com/apil-khadka/Sovra/issues/44) |
| [SOV-039](#sov-039) | Approve the first issuer jurisdiction and complete provider capability matrix | G0 | deferred_production | SOV-002, SOV-004 | [Issue](https://github.com/apil-khadka/Sovra/issues/41) |
| [SOV-040](#sov-040) | Harden issuer bindings, immutable approval identity and sealed trust snapshots | G1 | partial | SOV-004, SOV-005, SOV-008, SOV-009 | [Issue](https://github.com/apil-khadka/Sovra/issues/43) |
| [SOV-041](#sov-041) | Add packaged two-instance consent-to-verification end-to-end suite | G1 | partial | SOV-010, SOV-011, SOV-012, SOV-015, SOV-036 | [Issue](https://github.com/apil-khadka/Sovra/issues/45) |

## Acceptance and evidence

### SOV-001

**Freeze proof profile, issuer assurance, freshness and session semantics**

Owner role: Architecture and security.
Gate: G0; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: SOV-001 v0.4 records artifact-layer qualification; VCI/VP, kb+jwt, independent interoperability and strong digest pinning remain.
Dependencies: None.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/5).
Requirements: FR-02, FR-08, FR-14, FR-17, FR-18, FR-21, FR-22, DR-05, DR-16, SR-03, SR-06, INV-03, INV-04, INV-06, INV-08.
Validation: SEC-04, SEC-05, SEC-06, SEC-07, SEC-10, SEC-11, SEC-12, SEC-30.
Open decisions: OD-01, OD-03, OD-06, OD-14.
Evidence reference: `docs/architecture/decisions/SOV-001-proof-profile.md`.

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
Gate: G0; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Locality/custody reference recorded; actual issuer locations, legal retention and independent custody approval remain.
Dependencies: None.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/6).
Requirements: DR-01, DR-04, DR-09, DR-10, DR-11, DR-15, DR-16, SR-24, SR-25, SR-33, INV-11, NFR-12.
Validation: SEC-20, SEC-27, SEC-38, SEC-40, SEC-44, MC-05, MC-06.
Open decisions: OD-07, OD-08, OD-09, OD-15, OD-17.

Acceptance criteria:

- Approve a data-flow inventory covering originals, derivatives, keys, TLS termination, OCR, telemetry, support, backups and failover.
- Record retention/deletion obligations, permitted disclosures and provider/operator/root visibility for each location.
- Apply the mandatory attested sensitive-processing boundary and SOV-002 v0.2 non-exportable-key recovery clarification; document remaining root powers and obtain issuer/privacy approval before real-data use.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-003

**Bootstrap Java 25 and Spring workspace with integration harness**

Owner role: Backend and build engineering.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-29).
Remaining/evidence scope: Java/React build, real PostgreSQL harness, container and CI foundations exist; no production acceptance inferred.
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
Gate: G0; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Keycloak and deferred cloud reference chosen; synthetic continuation does not require a provider re-pick. Production qualification remains.
Dependencies: SOV-001, SOV-002.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/8).
Requirements: IF-05, SR-02, SR-13, SR-19, SR-20, SR-21, SR-26, SR-27, SR-29, DR-12, DR-17.
Validation: SEC-14, SEC-26, SEC-33, SEC-34, SEC-35, MC-01, MC-04, MC-06, MC-09, MC-10.
Open decisions: OD-10, OD-13, OD-18.

Acceptance criteria:

- Approve provider, region/operator, key algorithms, envelope/AAD/nonce format and signing/unwrap interfaces.
- Specify MFA enrollment/recovery, JIT elevation, independent approvals and separate workload/deploy/migration/key/audit identities.
- Define measurable token, grant, DEK and positive-permission cache bounds, restored-key inventories and control/data-plane outage rules.
- Use SOV-004 v0.3: issuer-local Keycloak and the Google Cloud Single-tenant HSM/Confidential Space reference; actual issuer regions remain subject to SOV-039 and independent assessment to SOV-037.
- Disable cross-request plaintext-DEK caching, distinguish local five-second stop freshness from cloud IAM/token propagation, and qualify attested key-use/input channels under SOV-038.
- Initial delivery is a public synthetic-data demo with no new paid services or hardware; the cloud HSM/TEE reference is deferred qualification and is not a demo provisioning dependency.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-005

**Implement tenant, issuer, RP and object authorization**

Owner role: Backend security.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Role/resource authorization and tenant guards exist; deployment-specific issuer/legal authority and production assessment remain.
Dependencies: SOV-002, SOV-003, SOV-004.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/9).
Requirements: FR-01, FR-16, FR-24, DR-06, IF-02, IF-06, SR-01, SR-15, SR-27, SR-34, SR-35.
Validation: SEC-01, SEC-02, SEC-03, SEC-25, SEC-26, SEC-31, MC-01, MC-06.

Acceptance criteria:

- Enforce authenticated principal, tenant, issuer/RP, action and object authority at HTTP and service entry points.
- Run database access under non-owner, non-superuser roles without BYPASSRLS; separate migrations and test pooled tenant context.
- Deny cross-boundary reads, existence leaks, alternate-controller bypass and caller-supplied identity/proxy overrides in packaged tests.
- Revalidate current roles and entitlement/elevation epochs after authentication and before privileged operations; exercise removal during warm caches and queued work rather than checking credential liveness alone.
- Bind tenant and legal issuer separately; a session GUC is request isolation rather than a defense against a database role able to issue arbitrary SQL.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-006

**Implement privileged access and application credential lifecycle**

Owner role: Identity and security.
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Keycloak OIDC/BFF and service-account lifecycle exist; browser-origin packaging, hardware/recovery/elevation and full privileged acceptance remain.
Dependencies: SOV-004, SOV-005.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/10).
Requirements: FR-26, FR-28, FR-47, SR-02, SR-26, SR-27, SR-29, SR-34, SR-35.
Validation: SEC-01, SEC-26, SEC-32, SEC-43, MC-01, MC-09.
SRS acceptance: AC-16.
Open decisions: OD-10, OD-18.
Evidence reference: `backend/src/main/java/dev/sovra/bff`.
Evidence reference: `scripts/e2e-bff-login.py`.

Acceptance criteria:

- Implement phishing-resistant privileged enrollment, authentication, recovery and bounded elevation with independent high-impact approvals.
- Separate sandbox/production applications, approved scopes/origins/audiences, secret rotation and revocation.
- Exercise stolen sessions, removed roles, weak recovery and warm authorization caches within approved containment bounds.
- Implement issuer-local Keycloak OIDC authorization code with S256 PKCE through a Spring BFF, server-held tokens, protected cookies/CSRF and an allowlisted issuer/audience/redirect registry; keep machine authentication separate.
- Enforce verified hardware-bound privileged authentication context, controlled enrollment/recovery without weak-factor fallback, stable (iss, sub) membership and independently approved action-bound elevation.
- Local synthetic Keycloak development may proceed under SOV-004 v0.3; production identity tenant, cloud credentials and independent release approvals are not prerequisites for writing that synthetic implementation and are not claimed completed.
- Pin a maintained Keycloak server/container and its supported runtime; enforce reviewed attestation trust/AAGUID and user-verification policy at privileged enrollment, reject weaker legacy credentials/fallback, and test configuration drift and recovery.
- For the public synthetic demo, use self-hosted Keycloak on existing or verified no-charge resources with restricted demo accounts; do not require paid hosted identity, SMS, email or new security-key purchases, and do not claim unavailable hardware assurance passed.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-007

**Implement durable privacy-minimized audit and decision evidence**

Owner role: Backend and security operations.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Transactional audit and integrity/denial tests exist for demo; independent production integrity authority and lifecycle evidence remain.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/11).
Requirements: FR-27, DR-08, SR-12, SR-16, INV-02.
Validation: SEC-20, SEC-28, MC-06, MC-08.
Open decisions: OD-07, OD-11.

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
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Versioned/sealed trust and policy workflows exist; person-verified human quorum and actual accreditation remain.
Dependencies: SOV-001, SOV-003, SOV-005, SOV-007.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/12).
Requirements: FR-03, FR-13, FR-17, FR-18, FR-25, FR-32, DR-05, SR-05, SR-06, INV-03, INV-05, INV-06, SR-35.
Validation: SEC-11, SEC-12, SEC-13.

Acceptance criteria:

- Implement scoped issuer/type/claim/purpose approval, immutable policy/trust revisions and effective epochs.
- Validate approved metadata endpoints, signed key bindings, freshness and separately authorized changes.
- Prove AI, ordinary admins and unapproved schemas cannot create policy authority or broaden trust.
- SOV-040 must seal activated snapshot membership and bind independently authenticated immutable approvers; inequality of supplied names is not independent approval against a compromised runtime/database writer.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-009

**Implement issuer-scoped issuance and constrained signing**

Owner role: Credential backend and key operations.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Constrained synthetic and SD-JWT artifact issuance exists; VCI flows, approved enrollment provenance and real KMS remain.
Dependencies: SOV-001, SOV-003, SOV-004, SOV-005, SOV-007, SOV-008.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/13).
Requirements: FR-02, FR-23, DR-05, DR-09, IF-05, SR-03, SR-13, SR-27, INV-03, INV-08, SR-35.
Validation: SEC-04, SEC-05, SEC-06, SEC-14, SEC-26, MC-06.

Acceptance criteria:

- Issue only permitted profile claims from authorized synthetic issuer inputs and current trust/type scope.
- Bind credential ID, holder, key version, validity and status; make authorized duplicate retries recover the same result.
- Constrain the signing boundary to approved issuance evidence; reject arbitrary payload, wrong-issuer signing, key export and self-granted key permissions.
- Keep synthetic issuance explicitly labelled; the production boundary validates typed issuer/source/approval authority before invoking the byte-signing adapter and rejects synthetic genesis/key/configuration on every production path.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-010

**Implement consent-bound proof requests and minimal holder flow**

Owner role: Verifier backend and holder frontend.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Consent APIs, BFF holder paths and React consent view exist; packaged browser and external wallet/profile evidence remain.
Dependencies: SOV-001, SOV-003, SOV-005, SOV-007, SOV-008, SOV-036.
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
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Durable verification, atomic replay and HTTP race/restart evidence exist; complete selected protocol/browser acceptance remains.
Dependencies: SOV-001, SOV-003, SOV-005, SOV-007, SOV-008, SOV-009, SOV-010, SOV-036.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/15).
Requirements: FR-08, FR-19, FR-21, FR-22, FR-31, SR-04, SR-05, SR-06, INV-01, INV-02, INV-05, INV-07, INV-08.
Validation: SEC-04, SEC-07, SEC-08, SEC-09, SEC-10, SEC-11, SEC-12, SEC-13.
SRS acceptance: AC-02, AC-03, AC-06.
Open decisions: OD-06.

Acceptance criteria:

- Validate signature/profile, holder, audience, consent, policy, trust scope/status/freshness and session bindings before acceptance.
- Commit nonce consumption, immutable decision and required audit relation atomically across two instances.
- Exercise concurrency, process kill, commit ambiguity and response loss; only authorized retrieval may return an existing result and manual follow-up cannot rewrite invalid evidence.
- Accept the selected SD-JWT VC/OpenID4VP profile only after SOV-036 qualification; a custom synthetic JWS or independent issuer-signature check does not satisfy the interoperable verification gate.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-012

**Implement freshness, revocation and key-compromise lifecycle**

Owner role: Credential backend and security operations.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Synthetic revocation/freshness and filtered serving JWKS exist; production status privacy, lifecycle and compromise drills remain.
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
Gate: G1; proposed priority: p1; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Fixture/live adapters and a dated successful Baseten smoke exist; latest changes are uncommitted. Hard no-charge limit, retention and full live evaluation remain.
Dependencies: SOV-003, SOV-005, SOV-008, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/18).
Requirements: FR-04, FR-05, FR-06, FR-11, FR-12, FR-29, DR-03, IF-04, IF-07, SR-07, SR-08, SR-09, NFR-03, NFR-10.
Validation: SEC-15, SEC-16, SEC-17, SEC-18, SEC-19, SEC-20, SEC-22.
SRS acceptance: AC-05, AC-06, AC-07.
Open decisions: OD-02.
Evidence reference: `docs/ai/live-integration.md`.
Evidence reference: `scripts/smoke-live-planning.py`.

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
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-29).
Remaining/evidence scope: Deterministic guard, policy/citation validation and planner baseline/evaluation code exist; retain exact corpus evidence at release.
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
Gate: G1; proposed priority: p1; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Implemented API 0.16.0 with served/documented parity gate covers machine and BFF routes; remaining product APIs, compatibility and profile contracts remain.
Dependencies: SOV-001, SOV-002, SOV-003, SOV-004.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/17).
Requirements: IF-01, IF-02, IF-03, IF-07, IF-09, IF-10, IF-11, IF-12, NFR-09.
Validation: SEC-17, SEC-19, SEC-21, SEC-29, SEC-42, SEC-43.
Open decisions: OD-16.

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
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Software-key vault/grants, purpose-bound BFF review-view and two-phase retention purge (V28 SECURITY DEFINER zeroing, tombstones) with HTTP evidence exist; KMS/attestation, key retirement/rewrap and independent review remain.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005, SOV-007, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/20).
Requirements: FR-35, FR-40, DR-09, DR-12, DR-17, SR-19, SR-20, SR-21, SR-29, INV-10, INV-11.
Validation: SEC-33, SEC-34, SEC-35, SEC-44, MC-04, MC-09, MC-10.
SRS acceptance: AC-09, AC-12, AC-16.
Open decisions: OD-13, OD-18.
Evidence reference: `docs/engineering/sov-016-vault-assessment.md`.

Acceptance criteria:

- Use reviewed per-object-version envelope AEAD, fresh DEKs, protected context and approved local wrapping keys.
- Authorize current principal, issuer, object/version, purpose and workload before unwrap; release no plaintext before full authentication.
- Test ciphertext/tag/context/key substitution, nonce concurrency/retry safety, expired/revoked grants and KMS/cache outages with no plaintext fallback.
- Use zero cross-request plaintext-DEK cache entries, current purpose/object/version grants and the attested vault gateway; require SOV-038 deployed input/key-use denial evidence before real-data release.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-017

**Implement encrypted quarantine and isolated hostile-image admission**

Owner role: Document processing and platform security.
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Isolated PNG/JPEG quarantine worker, admission queue and verdict metrics with HTTP evidence exist; deeper scanning/review, production custody and independent review remain.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005, SOV-015, SOV-016, SOV-027.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/22).
Requirements: SR-22, SR-23, SR-30, SR-33, NFR-03, NFR-14, INV-09, INV-11.
Validation: SEC-21, SEC-22, SEC-36, SEC-40, MC-02, MC-05, MC-06.
SRS acceptance: AC-10, AC-12.
Open decisions: OD-13, OD-17.
Evidence reference: `docs/engineering/sov-017-quarantine-assessment.md`.

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
Gate: G2; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Fixture engine, normalizer-v1, per-field canonical/exact digests, append-only revisions, head-only approvals and 4 extraction endpoints exist with 16 tests; OD-15 frozen as mip-digest-v1. Production engine/schema registry, live OCR gates, live-only profile and independent review remain.
Dependencies: SOV-002, SOV-003, SOV-015, SOV-016, SOV-017.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/23).
Requirements: FR-36, FR-38, DR-11, DR-13, DR-14, DR-15, SR-23, SR-24, INV-09, INV-10.
Validation: SEC-36, SEC-37, SEC-38, SEC-39, SEC-40.
SRS acceptance: AC-10, AC-11, AC-12.
Open decisions: OD-15.

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
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Enrollment cases with opaque subject refs, maker/checker decisions, holder binding proofs, revision-bound approvals, stale-source re-review and an issuance gate exist with 14 tests. Production evidence policy, legal authority and independent review remain.
Dependencies: SOV-001, SOV-002, SOV-005, SOV-007, SOV-008, SOV-015, SOV-018, SOV-009.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/24).
Requirements: FR-33, FR-34, FR-37, FR-38, FR-39, FR-31, DR-14, DR-16, UX-06, INV-09, INV-10.
Validation: SEC-37, SEC-39, SEC-43.
SRS acceptance: AC-10, AC-11.
Open decisions: OD-14.

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
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Holder key registry with approval-time activation, loss/theft/compromise reports that revoke at once, TRUST_ADMIN recovery with fresh-key proofs and eligibility re-proof, and issuance bound to the ACTIVE key exist with 12 tests; OD-09 frozen and DR-10 demo threat model recorded. Device custody, encrypted backup, MFA/reauth, holder recovery UX and independent review remain.
Dependencies: SOV-001, SOV-002, SOV-004, SOV-005, SOV-006, SOV-010, SOV-012, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/25).
Requirements: FR-14, FR-20, DR-10, DR-16, SR-02, SR-11, UX-05.
Validation: SEC-07, SEC-13, SEC-14, SEC-24, SEC-32, MC-01, MC-09.
SRS acceptance: AC-14, AC-16.
Open decisions: OD-09, OD-12.

Acceptance criteria:

- Implement approved client/server key custody, presentation binding, loss/theft/recovery and administrator limitations.
- Ensure recovery invalidates affected authority under declared bounds without bypassing proof/consent or resurrecting revoked credentials.
- Assess supported browsers, keyboard/focus/labels and assistive technology against an approved accessibility target with actual recovery/consent flows.
- Keep non-exportable device keys out of server backups; recover permitted encrypted credential state through re-proof, new keys and profile-compliant reissuance/rebinding with old authority revoked, subject to the SOV-002 v0.2 custody approval.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-021

**Ship tested Java and TypeScript SDKs**

Owner role: SDK engineering.
Gate: G3; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Java (sdk/java) and TypeScript (sdk/typescript) SDKs at contract 0.16.0 with 13 live-stack tests each, sdk-live CI job, READMEs and sdk/RELEASE.md; independent review remains.
Dependencies: SOV-003, SOV-005, SOV-015, SOV-016, SOV-019, SOV-011.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/26).
Requirements: FR-46, IF-13, NFR-09, NFR-13.
Validation: SEC-29, SEC-42, SEC-43.
SRS acceptance: AC-13.
Open decisions: OD-16.

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
Gate: G3; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Developer portal over fixed-shape sandbox onboarding (RP_CLIENT-only, 24h, demo profiles only) plus public capability discovery, 9 machine-chain + 2 BFF session tests, contract 0.16.0; production accreditation and independent review remain.
Dependencies: SOV-005, SOV-006, SOV-015, SOV-021.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/27).
Requirements: FR-45, FR-47, IF-11, UX-08, NFR-13.
Validation: SEC-42, SEC-43.
SRS acceptance: AC-13.
Open decisions: OD-16.

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
Gate: G3; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Issuer desk over machine review queues plus 14 session BFF endpoints (correction/approval, intake/submit/decide, credential status/revoke, purpose-bound original viewing, scoped audit); 3 queue, 5 BFF flow and 6 browser tests. Production accreditation and independent review remain.
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
Gate: G3; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Holder dashboard over challenge-proof unlock (cases with corrections, disclosure history with outcomes, credentials, recovery), 6 unlock unit + 4 BFF flow + 5 browser tests; dedicated accessibility audit and independent review remain.
Dependencies: SOV-005, SOV-010, SOV-015, SOV-019, SOV-020.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/29).
Requirements: FR-42, UX-01, UX-02, UX-03, UX-04, UX-05, UX-06, UX-07, IF-13.
Validation: SEC-13, SEC-23, SEC-24, SEC-32, SEC-41.
SRS acceptance: AC-04, AC-14.
Open decisions: OD-12.

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
Gate: G3; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: RP dashboard over RP-subset credential desk (member-only rotate/revoke), audience-scoped outcomes and metrics, portal + dashboard React views, 4 browser tests (onboarding, rotate/revoke drill, seeded outcomes, role gates); dedicated accessibility audit and independent review remain.
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
Gate: G3; proposed priority: p1; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-30).
Remaining/evidence scope: Federation desk (proposal queue, onboarding, approve/activate) and security-operations desk (alerts, readiness, audit tail) exist over 7 session-only BFF endpoints plus a machine proposal queue, with 4 backend BFF tests and 5 browser role-gating tests; maker/checker and admin-only rules enforced server-side. Production accreditation authority, metadata lifecycle and independent review remain.
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
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Local Compose includes migrations and worker isolation; same-origin public profile, TLS, private admin, runtime privilege and actual host qualification remain.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-005, SOV-015, SOV-037, SOV-039.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/21).
Requirements: DR-01, DR-04, DR-11, IF-08, SR-09, SR-11, SR-15, SR-25, SR-27, SR-30, SR-33, INV-11, INV-13, NFR-14.
Validation: SEC-17, SEC-23, SEC-25, SEC-26, SEC-31, SEC-40, SEC-41, MC-02, MC-05, MC-06.
SRS acceptance: AC-12, AC-14.
Open decisions: OD-08, OD-17.

Acceptance criteria:

- Implement approved ingress/TLS termination, private data/key paths, issuer-local OCR/storage/backups and management-plane separation.
- Apply distinct workload/runtime/deployment/migration/audit identities, database privilege controls and explicit egress restrictions.
- Test alternate ingress, direct DB/key access, DNS/redirect SSRF, support paths and outage routing against the approved locality/root threat model.
- Serving containers receive no migration-owner credentials or schema-administration capability; a separately approved migration job owns schema changes.
- Keep issuer identity metadata, TLS/input processing, confidential runtime, storage, HSM, backup and support paths within the approved capability matrix; expose no ordinary-host plaintext ingress bypass.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-028

**Implement supply-chain provenance and artifact admission**

Owner role: Build and platform security.
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Pinned builds, CycloneDX SBOM and CI supply-chain job (pnpm audit high+, OSV-Scanner v2.7.0, zero findings 2026-10-30) exist; signed provenance, deployment admission enforcement and independent review remain.
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
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: demo_implemented (reviewed 2026-10-29).
Remaining/evidence scope: Semantic readiness, safe telemetry/alerts and outage checks exist; retain deployment-specific evidence and approved operational objectives.
Dependencies: SOV-003, SOV-005, SOV-007, SOV-008, SOV-011, SOV-012.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/31).
Requirements: FR-29, DR-08, SR-12, SR-32, NFR-02, NFR-11.
Validation: SEC-19, SEC-20, SEC-28, MC-08, MC-10.
SRS acceptance: AC-07, AC-17.
Evidence reference: `docs/engineering/semantic-health.md`.

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
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Finite request/tool/token/worker budgets and aggregate live-grant budget (64/version, 409 recovery) with HTTP evidence exist; measured staging capacity, approved recovery/service targets and independent review remain.
Dependencies: SOV-002, SOV-003, SOV-004, SOV-015, SOV-027, SOV-029.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/34).
Requirements: NFR-02, NFR-03, NFR-04, NFR-11, NFR-14, NFR-15.
Validation: SEC-19, SEC-21, SEC-22, SEC-27, MC-02, MC-08, MC-09, MC-10.
Open decisions: OD-04, OD-05, OD-13, OD-18.

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
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: HTTP instance/database-restart replay evidence exists; stale-backup fencing, independent key copies, deletion and full rollback/restore drills remain.
Dependencies: SOV-007, SOV-008, SOV-009, SOV-011, SOV-012, SOV-016, SOV-020, SOV-027, SOV-029, SOV-030.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/35).
Requirements: FR-30, FR-48, DR-07, DR-09, DR-17, SR-13, SR-25, SR-28, SR-29, INV-04, INV-12, INV-13, NFR-05, NFR-11, NFR-16.
Validation: SEC-14, SEC-27, SEC-44, MC-03, MC-04, MC-05, MC-09, MC-10.
SRS acceptance: AC-14, AC-15, AC-16, AC-17.
Open decisions: OD-05, OD-07, OD-18.

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
Gate: G3; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: SEC-01..44 demo evidence map (30 covered, 13 partial, 1 gap) plus an executed mutation proof exist; full ASVS L3 mapping, property/fuzz/mutation suites and independent review remain.
Dependencies: SOV-005, SOV-006, SOV-007, SOV-008, SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-016, SOV-017, SOV-018, SOV-019, SOV-020, SOV-021, SOV-022, SOV-023, SOV-024, SOV-025, SOV-026, SOV-027, SOV-028, SOV-029, SOV-030, SOV-031, SOV-036, SOV-038, SOV-040, SOV-041.
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
Gate: G3; proposed priority: p0; triage: needs-triage.
Progress: deferred_production (reviewed 2026-10-30).
Remaining/evidence scope: Representative deployed MC attack/load/failover exercises have not been established; not a paid-infrastructure blocker for local synthetic work.
Dependencies: SOV-027, SOV-028, SOV-029, SOV-030, SOV-031, SOV-032.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/37).
Requirements: SR-26, SR-27, SR-28, SR-29, SR-30, SR-31, SR-32, SR-33, INV-12, INV-13, NFR-15, NFR-16, NFR-17.
Validation: MC-01, MC-02, MC-03, MC-04, MC-05, MC-06, MC-07, MC-08, MC-09, MC-10.
SRS acceptance: AC-12, AC-15, AC-16, AC-17.
Open decisions: OD-05, OD-17, OD-18.

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
Gate: G3; proposed priority: p0; triage: needs-triage.
Progress: deferred_production (reviewed 2026-10-30).
Remaining/evidence scope: Independent production release approval is not complete; do not infer it from passing demo tests.
Dependencies: SOV-032, SOV-033, SOV-035, SOV-036, SOV-037, SOV-038, SOV-039, SOV-040, SOV-041.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/39).
Requirements: SR-18, SR-33, NFR-04, NFR-12, NFR-17.
Validation: SEC-30, MC-01, MC-02, MC-03, MC-04, MC-05, MC-06, MC-07, MC-08, MC-09, MC-10.
SRS acceptance: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08, AC-09, AC-10, AC-11, AC-12, AC-13, AC-14, AC-15, AC-16, AC-17.
Open decisions: OD-01, OD-04, OD-05, OD-07, OD-08, OD-09, OD-10, OD-11, OD-12, OD-13, OD-14, OD-15, OD-16, OD-17, OD-18.

Acceptance criteria:

- Obtain independent proof/profile, application, infrastructure, privacy/residency and privileged/root boundary review for the exact deployment/customer scope.
- Retest findings, close every applicable open decision and require complete SEC/MC/ASVS evidence with no unresolved high/critical finding.
- Have named accountable release/issuer authorities approve the real-data and production gates; publish only evidence-supported claims and limitations.
- Require mandatory SOV-036 profile qualification, SOV-037 independent design assessment, SOV-039 jurisdiction approval and SOV-038/040/041 implementation evidence before approving real-data release.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-035

**Prove clean-checkout Java synthetic cross-issuer vertical slice**

Owner role: Backend integration and E2E.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Demo UI, prior clean-checkout proof and live smoke exist; reproducible packaged browser journey, protocol qualification and zero-charge public release evidence remain.
Dependencies: SOV-009, SOV-010, SOV-011, SOV-012, SOV-013, SOV-014, SOV-015, SOV-029, SOV-036, SOV-041.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/38).
Requirements: FR-04, FR-09, FR-10, FR-11, FR-12, FR-19, FR-20, FR-21, FR-22, NFR-01, NFR-07, NFR-10.
Validation: SEC-04, SEC-08, SEC-09, SEC-11, SEC-12, SEC-13, SEC-15, SEC-16, SEC-18, SEC-19, SEC-20.
SRS acceptance: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08.
Open decisions: OD-02.
Evidence reference: `docs/engineering/first-vertical-slice.md`.

Acceptance criteria:

- Reproduce the Java issuer-to-holder-to-verifier flow from a clean checkout using synthetic jurisdictions, scoped keys/data and a real Meta call.
- Prove SRS AC-01 through AC-08, including refusal, tampering, replay, stale/unknown authority, incompatible plans and no source-record/model PII exchange.
- Retain commands, immutable versions, complete positive/negative outcomes and sanitized evidence; this gate grants no real-data or production authorization.
- Publish only bundled or pre-approved synthetic identity/document fixtures; reject real-ID uploads and disable production issuer connectivity and credential authority while minimizing actual visitor/authentication metadata.
- Before public exposure, verify zero-new-payment hosting/external-service capacity and charge prevention, rotate deployment secrets, keep administration private and prove bounded demo actions/resource use; local Compose defaults are not publication approval.
- Use a live model only within verified no-charge capacity; label unavailable or fixture-driven planning truthfully and do not count fixture mode as completed live-Meta acceptance.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-036

**Qualify selected SD-JWT VC and OpenID libraries and profile adapters**

Owner role: Credential interoperability.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: SD-JWT artifact adapters, kb+jwt binding, VCI/VP/DCQL/encrypted-response flows, and the independent-wallet adversarial corpus exist with both-profile HTTP evidence; external conformance suites, walt-id session-handler adoption, strong digest pinning, and SOV-037 review remain. Keep issue 40 open.
Dependencies: SOV-001, SOV-003, SOV-004, SOV-009, SOV-015.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/40).
Requirements: FR-14, FR-15, DR-02, DR-16, SR-03, NFR-12.
Validation: SEC-04, SEC-05, SEC-06, SEC-30.
Open decisions: OD-01.
Evidence reference: `docs/architecture/decisions/SOV-001-proof-profile.md`.
Evidence reference: `docs/engineering/sov-036-protocol-assessment.md`.

Acceptance criteria:

- Qualify the mandatory full profile selected in SOV-001: pin exact supported issuer/verifier/format modules, trusted artifact origin and strong provenance/digests, license/support/dependency review and Java 25 packaged compatibility.
- Use independent wallet/issuer/verifier fixtures and applicable conformance/adversarial harnesses for exact SD-JWT VC/OpenID4VCI/OpenID4VP versions, disclosure integrity, holder binding, audience/nonce, encryption and malformed cases.
- Implement profile adapters behind the existing seams without claiming synthetic JWT interoperability; fixtures may use labelled synthetic state services, while full Sovra consent/replay/status integration is accepted under SOV-010/011/012 and SOV-041.
- Run before profile-dependent integration acceptance; do not depend on the final whole-product SEC suite or holder-custody release, which would make the gate circular.

Required closure evidence:

- Reviewed design or implemented artifact for the assigned scope.
- Reproducible positive and negative validation, actual configuration/version references and sanitized results.
- Independent review of security-critical behavior and retest of findings where applicable.

### SOV-037

**Obtain independent G0 architecture, privacy and custody assessment**

Owner role: Independent security/privacy assessor and issuer authority.
Gate: G0; proposed priority: p0; triage: needs-triage.
Progress: deferred_production (reviewed 2026-10-30).
Remaining/evidence scope: No named independent assessor/date or accepted independent design/privacy report is recorded.
Dependencies: SOV-001, SOV-002, SOV-004, SOV-039.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/42).
Requirements: SR-18, SR-26, SR-27, SR-33, SR-34, SR-35, DR-10, NFR-12.
Validation: SEC-26, SEC-30, SEC-32, MC-01, MC-05, MC-06.
Open decisions: OD-07, OD-08, OD-09, OD-10, OD-13, OD-17, OD-18.

Acceptance criteria:

- Have a named qualified independent assessor review the exact G0 revisions, current code findings ARCH-01 through ARCH-08, operator/root powers, actual jurisdiction matrix and proposed custody changes.
- Record issuer/privacy decisions, findings, remediation owners and retest conditions without treating this engineering research or an implementation author review as independent approval.
- Block real-data provisioning/processing until the applicable design review passes; synthetic contract-driven development may continue and final deployed/release assessment remains SOV-034.

Required closure evidence:

- Versioned reviewed decision or implementing commit/artifact for the exact scope.
- Reproducible positive/negative evidence, effective configuration and sanitized results.
- Independent assessment and retested findings where required; no fabricated approval.

### SOV-038

**Implement attested HSM authorization and confidential input gateways**

Owner role: Confidential platform, key and security engineering.
Gate: G2; proposed priority: p0; triage: needs-triage.
Progress: deferred_production (reviewed 2026-10-30).
Remaining/evidence scope: KMS sign/unwrap paths remain fail-closed placeholders; no deployed attestation/key/input-channel qualification established.
Dependencies: SOV-004, SOV-006, SOV-016, SOV-027, SOV-028, SOV-040.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/44).
Requirements: IF-05, SR-13, SR-19, SR-21, SR-25, SR-27, SR-29, SR-33, SR-35, INV-11, INV-13.
Validation: SEC-14, SEC-26, SEC-33, SEC-35, SEC-40, MC-02, MC-04, MC-05, MC-06, MC-07, MC-10.
SRS acceptance: AC-09, AC-12, AC-16, AC-17.
Open decisions: OD-08, OD-13, OD-17, OD-18.

Acceptance criteria:

- Implement the reviewed reference or an explicitly qualified regional profile with per-issuer non-exportable P-256 HSM signing keys, distinct wrapping keys, immutable key versions and verified provider response/protection/integrity/JOSE encoding.
- Bind key-use credentials to exact approved production attestation/image/workload/location claims; deny wrong/debug/revoked image, host metadata credentials, impersonation, deployment identity and direct generic signing/unwrap bypasses.
- Validate typed current issuance/source/approval authority in the attested signing gateway; scope vault grants and OCR inputs per object/version/purpose/job with no arbitrary KEK use or raw-digest signing oracle.
- Prove supported attestation-bound encrypted input/TLS and protected derived-data storage so plaintext cannot first traverse an ordinary host proxy; retain hardware/software/isolation assumptions and independent denial evidence.
- Measure local stop, provider propagation, active jobs and key-copy containment separately; never promise cached plaintext recall or deterministic Java heap zeroization.
- Prove IAM-policy and service-account impersonation administration cannot silently bypass attested key-use governance; HSM-instance quorum is not assumed to govern IAM edits or business approval.
- Distinguish attestation-derived credential issuance from per-key-call hardware attestation; test image withdrawal with already issued federated tokens and measure the actual residual containment window instead of promising immediate recall.

Required closure evidence:

- Versioned reviewed decision or implementing commit/artifact for the exact scope.
- Reproducible positive/negative evidence, effective configuration and sanitized results.
- Independent assessment and retested findings where required; no fabricated approval.

### SOV-039

**Approve the first issuer jurisdiction and complete provider capability matrix**

Owner role: Issuer authority, privacy and platform architecture.
Gate: G0; proposed priority: p0; triage: needs-triage.
Progress: deferred_production (reviewed 2026-10-30).
Remaining/evidence scope: No actual real-data issuer/jurisdiction/provider capability approval recorded; demo hosting is a separate zero-charge qualification.
Dependencies: SOV-002, SOV-004.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/41).
Requirements: DR-01, DR-04, DR-11, SR-25, SR-33, INV-11, NFR-12, NFR-14.
Validation: SEC-40, SEC-41, SEC-44, MC-05, MC-06.
Open decisions: OD-07, OD-08, OD-10, OD-13, OD-17.

Acceptance criteria:

- Obtain explicit issuer-approved jurisdictions/operators and verify the supported intersection for identity metadata, ingress, compute/TEE, HSM protection/algorithms, database, storage, backups, telemetry, support and control-plane processing.
- Recheck current service availability, attestation claims, quotas, recovery/copy rules, contractual processing boundaries and administrative/support access using provider evidence.
- Do not substitute foreign regions or multi-tenant protection for a dedicated local HSM requirement; if no valid intersection exists, keep the node synthetic or qualify a separate sovereign/provider profile before real-data provisioning.

Required closure evidence:

- Versioned reviewed decision or implementing commit/artifact for the exact scope.
- Reproducible positive/negative evidence, effective configuration and sanitized results.
- Independent assessment and retested findings where required; no fabricated approval.

### SOV-040

**Harden issuer bindings, immutable approval identity and sealed trust snapshots**

Owner role: Authority backend and database security.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-29).
Remaining/evidence scope: Trust sealing, stable subject/quorum checks and production startup guards exist; BFF human trust changes, source provenance and actual issuer authority remain.
Dependencies: SOV-004, SOV-005, SOV-008, SOV-009.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/43).
Requirements: FR-23, FR-25, DR-05, DR-06, SR-01, SR-27, SR-34, SR-35, INV-03, INV-05, INV-06.
Validation: SEC-01, SEC-02, SEC-03, SEC-26, SEC-31, MC-01, MC-06, MC-09.
SRS acceptance: AC-02, AC-11, AC-14, AC-16.
Open decisions: OD-10, OD-11, OD-14, OD-17.
Evidence reference: `docs/engineering/sov-040-hardening-assessment.md`.

Acceptance criteria:

- Bind verified immutable principal identities and tenant-to-legal-issuer authority, current entitlement epochs and independently authenticated maker/checker evidence; two accounts controlled by one person do not satisfy independence.
- Seal published snapshot contents and restrict proposal, approval and activation writers so runtime INSERT rights or supplied actor names cannot fabricate approval or append issuer/policy rows to an active version.
- Require protected approved source/claim provenance at the signing authorization boundary and deny cross-issuer, stale-approval and arbitrary payload/digest requests.
- Add adversarial HTTP/service/direct-role tests and production startup/activation/restore tests rejecting synthetic keys, issuers, profiles and seed configuration on every path; document remaining database/root powers.

Required closure evidence:

- Versioned reviewed decision or implementing commit/artifact for the exact scope.
- Reproducible positive/negative evidence, effective configuration and sanitized results.
- Independent assessment and retested findings where required; no fabricated approval.

### SOV-041

**Add packaged two-instance consent-to-verification end-to-end suite**

Owner role: Integration and security E2E engineering.
Gate: G1; proposed priority: p0; triage: needs-triage.
Progress: partial (reviewed 2026-10-30).
Remaining/evidence scope: Both artifact-profile HTTP E2E suites exist, the packaged same-origin SPA/BFF delivery is implemented with HTTP evidence, and a pinned Playwright/Chromium suite proves DOM/JS login, holder consent, verification, and the SD-JWT wallet journeys (pre-authorized and authorization-code with browser-owned PKCE) with a CI job; full external selected-profile flow evidence remains. Keep issue 45 open.
Dependencies: SOV-010, SOV-011, SOV-012, SOV-015, SOV-036.
Tracker: [GitHub issue](https://github.com/apil-khadka/Sovra/issues/45).
Requirements: FR-08, FR-19, FR-20, FR-21, FR-22, SR-03, SR-04, SR-05, SR-06, INV-01, INV-02, INV-07, INV-08, NFR-01, NFR-07.
Validation: SEC-04, SEC-05, SEC-07, SEC-08, SEC-09, SEC-10, SEC-11, SEC-12, SEC-13, SEC-20, SEC-30.
SRS acceptance: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08.
Open decisions: OD-01, OD-03, OD-06.
Evidence reference: `docs/engineering/sov-041-holder-browser-assessment.md`.
Evidence reference: `docs/engineering/sov-041-same-origin-packaging.md`.
Evidence reference: `docs/engineering/sov-041-browser-e2e.md`.
Evidence reference: `scripts/e2e-verification.py`.
Evidence reference: `scripts/e2e-bff-login.py`.

Acceptance criteria:

- Run the packaged selected-profile issuer, actual holder consent/browser path and verifier over HTTP with real PostgreSQL and two backend instances; a Python signature check alone is not this verification test.
- Assert exactly one fresh accepted decision for healthy concurrent replay and none for tampered disclosures, wrong issuer/type/holder/audience/nonce, refusal or changed consent, expiry, stale/unknown authority and revoked keys/credentials.
- Kill/restart instances, lose responses and interrupt persistence to prove durable consumption, audit/decision consistency and authorized original-result retrieval without a second acceptance.
- Keep synthetic-harness and full-profile evidence distinct, assert persisted state and prohibited side effects independently, and retain clean-checkout commands, versioned fixtures and sanitized browser/API evidence.

Required closure evidence:

- Versioned reviewed decision or implementing commit/artifact for the exact scope.
- Reproducible positive/negative evidence, effective configuration and sanitized results.
- Independent assessment and retested findings where required; no fabricated approval.
