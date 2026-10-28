# Security and mission-critical design review for Sovra

**Research date:** 2026-10-27.
**Status:** primary-source research and proposed engineering recommendations, not a security audit, certification, deployed architecture, or completed validation.
**Audience:** product, architecture, engineering, security, and operations reviewers.

The review starts with the requested [Azure mission-critical guidance](https://learn.microsoft.com/en-us/azure/well-architected/mission-critical/) and applies it to Sovra's [business SRS](../requirements/software-requirements-specification.md), issuer-local documents, Java/Spring direction, and advisory AI boundary.
No cloud resources, application behavior, keys, or production settings were changed or tested.

## 1. Recommendation

Build a threat-driven security baseline with independently enforced issuer boundaries, minimal data exposure, constrained signing/decryption authority, secure enrollment, and recovery that preserves security state.
Make the declared threat model and independently reviewable evidence the acceptance criteria for security.
There is no universal configuration that establishes maximum security against every attacker.

Adopt the mission-critical framework's threat modeling, fault isolation, reproducible deployment, continuous validation, and operational health discipline.
Preserve consent, authority, locality, freshness, and at-most-once acceptance even when that makes an operation unavailable.
Azure, AKS, Cosmos DB, global active-active deployment, and any particular managed identity provider have not been selected by this review.

Microsoft's [mission-critical security article](https://learn.microsoft.com/en-us/azure/well-architected/mission-critical/mission-critical-security) explicitly focuses on threats to reliability/performance/availability and discusses tradeoffs with security controls.
The broader [Well-Architected Security checklist](https://learn.microsoft.com/en-us/azure/well-architected/security/checklist) is therefore a complementary baseline for confidentiality, integrity, segmentation, identity, monitoring, testing, and incidents.
The following recommendations are Sovra-specific conclusions, not claims that Microsoft prescribes Sovra's exact design.

## 2. Highest-impact threats

| Threat | Consequence to prevent | Required security boundary |
| --- | --- | --- |
| Wrong or fraudulent enrollment | Attacker receives technically valid credentials for unsupported claims or another person | Approved evidence validation, holder binding, assurance, and attributable review before signing |
| Compromised document/parser workload | Images/fields escape or attacker reaches signing/decryption infrastructure | Separate constrained worker identity/runtime, bounded input/work, local storage and deny-by-default egress |
| Compromised issuer or shared administrator | Cross-issuer document theft, unauthorized signing, or self-granted key access | Independently governed issuer permissions, privileged-role controls, separate signing/decryption/key administration, external audit evidence |
| Compromised application/build pipeline | Malicious code runs with trusted production identities | Reviewed source/configuration, protected build provenance, immutable deployment admission, and narrowly scoped runtime authority |
| Database restore or split-brain failover | Consumed nonce becomes usable, revoked evidence becomes active, or approval history rolls back | Durable security ledger, writer fencing, reviewed recovery-generation/session invalidation, and security-state reconciliation |
| Compromised federation metadata | New issuer/key/scope becomes trusted without proper authority | Pinned trust anchors, approved versioned changes, scope validation, and rollback protection |
| Credentialed API/SDK/dashboard attacker | Valid login accesses another holder/issuer or escalates disclosure | Per-operation object/tenant/purpose authorization, consent binding, and identical checks on every entry path |
| Operator error, ransomware, or key outage | Irrecoverable data loss or insecure emergency bypass | Protected backups, key-copy inventory, rehearsed recovery, and safe degraded operation |

Encryption cannot establish genuine source evidence, stop a permitted process from misusing plaintext, or prevent an authorized signer from signing the wrong claims by itself.
Treat these as separate controls and test the bypass paths between them.

## 3. Baseline before real sensitive data

### 3.1 Govern issuer authority and privileged identities

Use phishing-resistant authentication for production administrators, key/release approvers, and high-impact review actions.
Protect authenticator enrollment and account recovery to the same standard rather than leaving a weak recovery bypass.
Prefer hardware-backed security keys for privileged roles under an approved authenticator policy.
Microsoft distinguishes ordinary MFA from [phishing-resistant authentication strength](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths); an unspecified MFA checkbox does not establish the latter.

Use short-lived workload identities where the chosen platform supports them, with separate identities for ingestion, extraction, review, issuance, verification, deployment, and audit.
Remove standing privileged access, require attributable time-bounded elevation for designated operations, and independently approve high-impact trust/key/release changes.
Review role-delegation, root/subscription/tenant ownership, backup restore, pipeline editing, and emergency access as escalation paths.
A user who can grant themselves key-use permissions is not effectively isolated just because their current role lacks decrypt permission.

NIST's [Zero Trust architecture](https://csrc.nist.gov/pubs/sp/800/207/final) rejects implicit trust based solely on network location or enterprise ownership.
Private connectivity and mutual TLS establish useful network/peer controls, while application authorization still binds the actual issuer, tenant, object, purpose, and consent.
Document the ultimate administrative trust roots and remaining override powers; do not describe ordinary RBAC as protection from every compromised root administrator.

### 3.2 Keep source processing and keys inside governed issuer boundaries

Minimize collection before choosing encryption or storage: prefer approved narrow issuer evidence when a source image is unnecessary.
When an image is required, apply the [document lifecycle](../architecture/federated-document-lifecycle.md): private local vault, authenticated per-version envelope encryption, protected provenance, authorized extraction/review, and bounded retention.
Keep signing keys, wrapping keys, application credentials, and audit-integrity authority distinct.
The signing component should authorize an approved issuance operation, not expose an unrestricted sign-arbitrary-content service to the general API or OCR worker.
Verify actual provider support for the selected algorithms, key protections, identity permissions, and credential profile before choosing its integration.

Exclude source PII from shared federation, planner prompts, SDK diagnostics, global analytics, crash artifacts, and support exports.
Inventory every place data or key operations can occur, including TLS termination, temporary files, queues, thumbnails, replicas, backups, OCR subprocessors, and incident tooling.
A global HTTPS edge that terminates upload traffic is a processing location even if the object is finally stored locally.
Use an approved issuer-local upload/processing path and deny routing to an unapproved location during failure.

### 3.3 Isolate hostile document processing outside the Java application boundary

Java 25 is a suitable selected runtime, but it does not provide an in-process sandbox for hostile image/OCR code.
Oracle documents that the [Security Manager is permanently disabled since JDK 24](https://docs.oracle.com/en/java/javase/25/security/security-manager-is-permanently-disabled.html).
Do not design around enabling it with a JVM flag or a policy file.

Run file parsing/scanning/OCR in a separate least-privilege process/runtime, with reviewed OS/container/VM controls appropriate to the attacker model.
Constrain its filesystem, writable space, mounted secrets, system calls/capabilities, CPU, memory, wall time, child processes, network destinations, and permitted input objects.
Do not place issuer signing credentials in that runtime.
Use actual type/decoder/pixel limits and encrypted quarantine; a filename extension, MIME header, antivirus result, or a container label is not sufficient evidence of safety.
Choose stronger sandbox/VM separation where shared-kernel compromise is in scope, and test the actual deployment boundaries.

### 3.4 Protect persistence independently of controller correctness

Keep issuer databases/credentials separated as required by the existing architecture.
Within any approved shared-table tenant model, assess database row-level policy as defense in depth alongside application object authorization.
Application roles should not own protected tables, have superuser or BYPASSRLS rights, or perform migrations under the runtime identity.
Test pooled connections, transaction context, background jobs, reports, and alternate query paths for tenant leakage.

[PostgreSQL's row-security documentation](https://www.postgresql.org/docs/18/ddl-rowsecurity.html) states that superusers and BYPASSRLS roles bypass RLS and table owners normally bypass it; it also discusses constraint-related information leakage and policy races.
RLS does not establish isolation from a fully privileged database administrator or replace issuer boundary decisions.
A separate role/store remains preferable where the authority boundary requires it.

### 3.5 Make recovery preserve security, not just data availability

Choose exact freshness/snapshot rules and durable atomic nonce/decision handling before exposing verification.
Avoid conflict-resolution semantics that can overwrite terminal revocation, consumed challenges, or approved consent/policy history.
Microsoft's [mission-critical data guidance](https://learn.microsoft.com/en-us/azure/well-architected/mission-critical/mission-critical-data-platform) discusses consistency and multiwriter tradeoffs; the suitability of a database mode must be evaluated against Sovra's invariants.

Treat restoring an older backup as a security event: it can restore a formerly unconsumed session or pre-revocation status.
Fence old writers, reconcile revocation/trust/approval state, and make unsafe pre-recovery sessions unusable before accepting new evidence.
Use a reviewed session-generation/fencing design if the acceptance ledger cannot be recovered without ambiguity.
Do not resume verification merely because SQL connectivity and application health checks are green.
No data-loss tolerance for ordinary business records implicitly authorizes replay or resurrected trust.

### 3.6 Secure the build and deployment authority

Apply [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) as a secure-development reference covering prevention, vulnerability response, and root-cause improvement.
Inventory Maven dependencies, build plugins, JDK/container inputs, SDK packages, CI actions, and infrastructure modules, not just the application library list.
Review critical dependency ownership, licensing, provenance, update paths, and transitive permissions in addition to CVE scanning.

Use protected source/configuration review, isolated build execution, short-lived deployment credentials, independently verifiable provenance, immutable artifact digests, and an admission gate for the selected runtime.
The gate should reject an unapproved source/builder/artifact/configuration combination even when it is signed by some valid but untrusted key.
Prevent production deployment identities from automatically receiving document-decrypt or issuer-sign permissions.

[SLSA Build Track](https://slsa.dev/spec/v1.2/build-track-basics) distinguishes signed hosted-build provenance from hardened build isolation, and [artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts) checks provenance against expected identities and inputs.
Choose an explicit build-security target and assess the builder against it; an SBOM or signature file alone does not demonstrate that target.
Blue/green and rollback tests must preserve shared nonce/consent state and must not roll back security schema or revocation decisions.

### 3.7 Detect and contain compromise without creating a second data leak

Monitor unauthorized object/key access, abnormal signing/decrypt rates, role delegation, unusual image grants, trust/status age, denied egress, replay conflicts, source-review changes, and audit delivery failures.
Define responsible responders and test alert delivery and emergency access removal.
Separate diagnostic health from protected security-audit evidence and collect only necessary metadata in central operations.
Protect independent integrity/checkpoint copies so an application administrator cannot erase every trace of their own change.
Do not treat a local hash chain as independent tamper evidence if the same compromised actor can rewrite the entire chain and its reference.

Microsoft's [health-modeling guide](https://learn.microsoft.com/en-us/azure/well-architected/design-guides/health-modeling) supports modeling real flows and dependencies; [operational guidance](https://learn.microsoft.com/en-us/azure/well-architected/mission-critical/mission-critical-operational-procedures) addresses governed, repeatable recovery procedures.
Use synthetic flow probes for enrollment, consent, signing, and verification with strict containment, rather than a probe that exposes documents or performs uncontrolled production issuance.

## 4. Azure-specific findings if Azure is selected

These observations do not choose Azure as the hosting provider.
Recheck service, region, SKU, key-type, networking, and recovery behavior for the actual deployment.

| Finding from primary documentation | Sovra implication |
| --- | --- |
| Key Vault security guidance recommends boundaries by application/region/environment and tenant, managed identity, RBAC, and privileged-role controls | Map vault and identity boundaries to issuer authority and environment; do not create a federation-wide decrypt/sign identity |
| Private-network configuration has documented trusted-service bypass options | Validate the effective network and caller policy, not just a public-access setting |
| A restored key in another vault is independent of the original | Inventory and respond to compromise across every copy; disabling one key is insufficient |

Source: [Secure Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/secure-key-vault).

The [service-specific Key Vault reliability guide](https://learn.microsoft.com/en-us/azure/reliability/reliability-key-vault) describes asynchronous paired-region replication, potential recent-change loss, Microsoft-triggered regional recovery that can take hours, and a read-only mode that still permits signing/decryption but restricts configuration changes.
It also describes region exceptions, private-connectivity recovery delay, and backup restoration constraints.
Do not convert a short interruption during the failover transition into an end-to-end recovery guarantee.
Measure identity, DNS/network, key, database, security-state reconciliation, and safe readiness together.

Locality approval must cover the service's actual replication/recovery locations, not only the requested primary region.
Key disablement is not deletion of cached DEKs or previously released plaintext; the incident plan must cancel/contain affected workloads and reconcile copy/cache exposure.
Purge protection and recoverable backups protect against destructive deletion while constraining erasure promises.
Review the joint key/data retention and recovery design before representing either property to customers.

Managed HSM, immutable audit storage, protected posture monitoring, private endpoints, and workload identity are candidate control implementations, not automatic evidence of security.
Check exact cryptographic-module validation and configuration if a customer requires FIPS; Java, AES, a product name, or an HSM label alone does not establish a validated end-to-end system.

## 5. Security-preserving degradation

| Failure | Permitted response | Unsafe shortcut to prohibit |
| --- | --- | --- |
| AI planner unavailable | New dynamic planning unavailable/manual review; previously approved flows proceed only under their own valid requirements | Invent a model result or widen policy |
| Identity provider unavailable | No new privileged session/elevation; an existing request only if its token, scope, and revocation/freshness requirements remain satisfied | Accept unverified tokens, expired credentials, or stale permissions without an approved bound |
| Trust/status unavailable | Use only independently valid information within approved freshness; otherwise no verified result | Treat unknown as valid or accept a newly discovered issuer from an unverified cache |
| KMS denied/unavailable | Deny new operations that cannot meet current authorization and approved key policy | Plaintext key files, cross-issuer key fallback, or warm-cache access that bypasses a current deny |
| Replay/decision store uncertain | Stop new acceptance; reconcile or invalidate affected sessions | Process-local nonce sets, multiple writers, or restored READY sessions that can accept an old proof |
| Audit durability unavailable | Follow declared fail-closed/durably pending decision policy | Claim a completed accountable decision before the required durable record exists |
| Approved region unavailable | Recover only within approved destinations after security-state checks, or remain unavailable | Send images, fields, keys, or logs through a convenient unapproved region |
| Release rollback | Restore compatible code/artifacts with security state intact | Restore revoked keys, stale policies, weakened filters, or consumed challenges as active |

Availability metrics must count unauthorized acceptance as a security failure rather than a successful request.
Final numeric budgets and permitted freshness windows remain unresolved product/security decisions.

## 6. Targeted adversarial exercises

These are proposed extensions to the existing [44-case security plan](../engineering/security-validation-plan.md), not tests executed here.
The MC identifiers label research scenarios and do not renumber or claim completion of that plan.

| Exercise | Required evidence | Existing requirement/case connection |
| --- | --- | --- |
| MC-01 Revoke privileged access under load with warm tokens/grants/key caches | New prohibited operations fail under the actual bounded policy; caches and active work cannot silently extend privilege | SR-02, SR-13, SR-21; SEC-35, SEC-41 |
| MC-02 Simulate compromised image/parser worker | Worker cannot reach signer, another issuer, cloud metadata, unrestricted network, or unrelated document keys; resource bounds hold | SR-22, SR-23; SEC-36, SEC-37, SEC-40 |
| MC-03 Restore stale backup and partition old/new writers | Zero replay/terminal-revocation resurrection; old writers fenced and unsafe sessions invalidated before readiness | INV-01, INV-04, NFR-05; SEC-08, SEC-09, SEC-12, SEC-27 |
| MC-04 Disable/rotate original key while restored copy and cached DEK exist | Copy/cache inventory, deny propagation, containment and recovery behavior agree with the declared contract | FR-23, SR-13, SR-21; SEC-14, SEC-35, SEC-44 |
| MC-05 Attempt direct origin, alternate ingress, remote OCR, and unapproved failover | Identical business authorization and no forbidden plaintext/PII processing on every path | SR-09, SR-25; SEC-17, SEC-32, SEC-40, SEC-42 |
| MC-06 Attempt self-granted key/trust privileges through IAM/pipeline/admin changes | Governance/delegation denies or requires independently controlled approval, with attributable external evidence | SR-01, SR-13, SR-15, SR-16; SEC-03, SEC-26, SEC-28, SEC-29 |
| MC-07 Admit a substituted artifact or provenance from the wrong builder/source | Deployment rejects the artifact despite a syntactically valid signature, and records the rejection safely | SR-14, NFR-08; SEC-29 |
| MC-08 Keep HTTP probes green while status/trust is stale or audit delivery is lost | Affected verification readiness closes; alerts identify the actual unsafe dependency without restart storms or PII leakage | FR-29, NFR-11; SEC-11, SEC-19, SEC-20, SEC-28 |
| MC-09 Exercise pooled/database-owner/background-job authorization paths | Correct runtime role and scoped context prevent leakage; documented RLS bypass roles are never the application identity | DR-06, SR-01, SR-15; SEC-02, SEC-03, SEC-21, SEC-26 |
| MC-10 Fail key-management control plane and cryptographic data plane separately | Emergency change limits, available crypto operations, and safe deny behavior are observed rather than inferred from one health signal | NFR-05, OD-05, OD-13; SEC-14, SEC-27, SEC-35 |

Run failure experiments with realistic synthetic load in a representative isolated deployment, with cleanup, stop conditions, and independently checked assertions.
Microsoft's [deployment/testing guidance](https://learn.microsoft.com/en-us/azure/well-architected/mission-critical/mission-critical-deployment-testing) recommends production-like staging, repeatable artifacts and infrastructure, and combined load/fault validation.
Retain source/artifact/configuration identities, sanitized operation traces, database ordering/recovery points, key/role events, and observed failover destinations.
Run real HTTP, PostgreSQL, and the selected key provider; mocks cannot prove deployed IAM, replication, or recovery behavior.

## 7. Advanced controls and their decision criteria

| Control | When to require or evaluate it | Limit that still needs testing |
| --- | --- | --- |
| Confidential processing/attested key release | Host/cloud-operator visibility into source plaintext is unacceptable in the deployment threat model | Attestation, permitted image measurements, actual IO, locality, patching, and compromise of approved application code |
| Stronger workload sandbox/VM isolation | Untrusted native decoders, hostile multi-tenancy, or shared-kernel escape is in scope | Real runtime privileges, mounts, network and resource enforcement |
| Dedicated issuer infrastructure/HSM boundary | Shared platform administrators or cross-issuer compromise would exceed accepted blast radius | Root/control-plane ownership, algorithm support, recovery/copy policies and independent issuer authority |
| Additional approved-region capacity | The approved availability objective cannot be met within the current permitted region/zone topology | No security-state rollback, split brain, accidental disclosure, or unapproved replication |
| Hardened build platform target | Production source/build compromise is in scope, as it should be for key-bearing identity software | Actual builder isolation/provenance verification rather than an asserted SLSA level |

[Azure confidential computing](https://learn.microsoft.com/en-us/azure/confidential-computing/overview) describes protecting data in use with hardware-based attested execution environments.
This is useful for reducing host/operator exposure but does not establish correct enrollment, safe application logic, or protection from all compromised approved code.
Treat the limits in the table as Sovra threat-model requirements to validate, not capabilities inferred from a marketing label.

Kubernetes, a service mesh, global active-active databases, and a distributed event backbone are not security goals in themselves.
Adopt a platform component when a specific requirement needs its control and the team can independently demonstrate its safe operation and failure behavior.
Splitting deployment privileges and isolating a hostile parser are justified security boundaries even when the rest of the backend stays modular and small.

## 8. Implementation sequence and open decisions

**Before processing real source data:** resolve SRS OD-01, OD-03, OD-05, OD-06, OD-08, OD-09, OD-10, OD-11, OD-13, and OD-14 for the selected deployment/profile.
Assign named accountable owners and independent reviewers, choose explicit numeric bounds, and implement the minimal end-to-end flow under the proposed controls.
Produce the initial negative/concurrency/egress/key-access evidence before adding more integrations or privileged interfaces.

**Before a customer production release:** complete the applicable ASVS mapping and existing SRS gates, independent architecture/code/cryptographic-profile review and penetration assessment, package/admission validation, privileged-access exercises, representative recovery and MC scenarios, and retest of blocking findings.
A staging environment must represent the production controls being assessed, even when development environments use fewer resources and only synthetic data.
This review does not approve an availability SLA, a residency assertion, or a cryptographic-erasure claim.

**For each later change:** reevaluate the threat/data-flow inventory, dependency/provenance and configuration changes, relevant negative/fault tests, alert coverage, and recovery compatibility.
Maintain security work as an operating practice rather than treating the initial assessment as permanent assurance.

## 9. Source and evidence boundaries

Sources above are first-party documentation retrieved on the research date.
Microsoft Learn is living guidance; service-specific replication, key lifecycle, regions, SKUs, and control behavior take precedence over a generic architecture example when planning an actual deployment.

This report inspected project requirements/design documents, not a deployed Java system or every line of application code.
The controls and scenario results remain unimplemented/unverified unless separately accompanied by real evidence.
The [SRS](../requirements/software-requirements-specification.md), [security plan](../engineering/security-validation-plan.md), and [document lifecycle](../architecture/federated-document-lifecycle.md) remain the detailed baseline; this research proposes refinements rather than silently closing their open decisions.
