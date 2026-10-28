# Security validation for the Java backend

**Status:** required production validation baseline, dated 2026-10-27; implementation and execution pending.
The Java backend and the checks below are not implemented by this document.
Existing prototype test results do not establish that this plan has passed.

This reference is for engineers implementing and reviewing Sovra's issuer, verifier, trust, consent, and AI boundaries.
Read it with the [threat model](../architecture/security-privacy-threat-model.md), [consistency contracts](../architecture/consistency-and-failure-modes.md), and [Java baseline](../architecture/java-spring-baseline.md).

## Coverage model

Use [OWASP ASVS 5.0.0](https://asvs.owasp.org/) as the requirements catalog, with applicable requirements through Level 3 as the production assurance target for this sensitive identity service.
This is a Sovra engineering target, not a claim of ASVS verification or certification.
The [task backlog](implementation-backlog.md) assigns implementation/validation work; all security controls and scenario results remain pending until evidence is recorded.
Before production, map every applicable requirement to an owner, implementation, test or manual assessment, evidence, and review date.
Record version-qualified ASVS IDs from the actual standard rather than inventing mappings from chapter names.
An unmapped or unassessed requirement is an open gap, not a pass.
Document the rationale and independent review for requirements marked not applicable.

Inventory every HTTP route, administrative action, background job, database role, cache, external fetch, model/tool invocation, telemetry exporter, backup, and key operation.
For each boundary, enumerate unauthenticated callers, wrong tenants, wrong roles, hostile authenticated callers, compromised issuers, and dependency failure.
Expand the inventory and the matrix whenever a capability or data destination changes.
Neither a finite matrix nor a clean scanner report proves the absence of vulnerabilities.

## Evidence rules

Each automated case needs a stable ID, adversarial fixture, expected public result, expected persisted state, and expected absence of prohibited side effects.
Record the commit, artifact digest, JDK build, effective dependency graph, configuration, commands, seed or corpus, outcome, and sanitized evidence location.
Use synthetic fixtures and fake credentials only.
Test infrastructure may observe fake provider requests and fake signing operations; it must not collect production credentials or signing material.
Keep sensitive reports in access-controlled storage and publish only sanitized summaries.

For HTTP security cases, exercise the packaged application through real HTTP with the production security configuration and real PostgreSQL transactions.
MockMvc and mocked principals supplement these tests; they do not replace authentication, authorization, persistence, or deployed-configuration evidence.
Use isolated fixture services for issuer status, discovery, model responses, and network faults, with a separate live contract test for the actual model provider.

## Initial adversarial matrix

All cases in this table are **planned and unverified for the Java backend**.
The table seeds coverage; it is not a complete ASVS mapping.
The existing [demo checks T01-T15](../demo/evaluation-and-acceptance.md) remain synthetic demonstration criteria.

| ID | Boundary and attack | Required observation | Evidence layer |
| --- | --- | --- | --- |
| SEC-01 | Call each protected operation anonymously, with invalid authentication, and with the wrong role | Denied with no business-state change; intentional public endpoints expose only approved metadata | HTTP authorization matrix |
| SEC-02 | Tenant A uses tenant B's credential, session, consent, job, or issuer identifier | No record read, update, existence disclosure, signing, or presentation across the boundary | Two-tenant HTTP and database tests |
| SEC-03 | Invoke a protected service through alternate controllers or internal call paths | Authorization still applies; proxy/self-invocation behavior cannot bypass the rule | Service authorization and HTTP tests |
| SEC-04 | Modify a signed payload, use an unsigned token, confuse key/algorithm types, or provide unknown critical headers | Rejected under the selected proof profile; no trusted claims or downstream acceptance | Crypto fixtures and parser tests |
| SEC-05 | Use unknown key IDs, attacker-selected key URLs, wrong issuer keys, or a trusted issuer outside its authorized scope | Rejected; no attacker-directed key fetch and no expansion of issuer authority | Trust fixtures and outbound-network observation |
| SEC-06 | Exchange credential, holder proof, session token, or access token between contexts | Token-type-specific validation rejects substitution, wrong audience, and wrong holder binding | Cross-context negative fixtures |
| SEC-07 | Exercise expiry, not-before, challenge expiry, missing required times, and configured clock-skew boundaries | Only the exact policy-defined validity window succeeds | Injected-clock boundary tests |
| SEC-08 | Submit the same valid proof concurrently through two application instances | Exactly one fresh verification decision commits; duplicate submissions cannot authorize again | Real PostgreSQL and coordinated concurrency |
| SEC-09 | Restart a verifier or lose its response immediately after nonce consumption commits | Consumption survives restart; retry can recover the original result only under an explicit authorized idempotency contract | Process interruption and persisted-state checks |
| SEC-10 | Reuse issuance idempotency keys with identical and different request bodies | Identical authorized retry returns the original result; different content conflicts without minting another credential | HTTP concurrency and transaction tests |
| SEC-11 | Present revoked evidence, stale status, or status responses that are malformed, missing, or unavailable | Required freshness is enforced; uncertainty never becomes verified evidence | Fault-injected status fixtures |
| SEC-12 | Race revocation/trust changes against verification, or replay an older trust epoch | Outcome matches the declared snapshot/freshness contract and records its version; rollback cannot silently broaden trust | Controlled interleavings and audit checks |
| SEC-13 | Refuse consent, change purpose/claims/RP after approval, or reuse expired consent | No unauthorized proof delivery; the approved plan and presentation stay bound to the consent receipt | Browser flow plus HTTP/state checks |
| SEC-14 | Rotate, retire, or compromise an issuer key; attempt signing under another issuer's identity | Only authorized key versions sign; retired or compromised keys follow explicit rejection policy | Rotation fixtures and KMS authorization tests |
| SEC-15 | Put instructions in issuer metadata, retrieved policy text, or model output | Model cannot change approved policy, consent, trust, or tool privileges; deterministic guard remains authoritative | Adversarial planner fixtures |
| SEC-16 | Model requests a hidden tool, supplies another tenant, invents claims/citations, or repeats tool calls | Callback reauthorizes trusted caller context and validates arguments; unsupported plans rejected; execution bounded | Tool callback and dispatcher tests |
| SEC-17 | Discovery/status/tool input targets loopback, private/link-local addresses, cloud metadata, redirects, or DNS rebinding | Request blocked before reaching the forbidden destination, including redirected/resolved paths | Instrumented resolver, fixture network, and egress policy tests |
| SEC-18 | Model returns malformed JSON, extra fields, oversized output, invalid enums, or a plausible unsupported claim mapping | Bounded parse/schema/semantic rejection; Java conversion never establishes authorization | Generated input and deterministic guard tests |
| SEC-19 | Model provider times out, throttles, streams incomplete data, or emits repeated tool calls | Bounded deadlines/retries/tool budget; explicit unavailable/manual-review result without invented evidence | Provider contract and fault tests |
| SEC-20 | Synthetic sensitive canaries occur in requests, exception paths, tool results, or rejected proofs | No prohibited content in model requests, logs, traces, metric labels, crash reports, or responses | Captured egress/telemetry assertions |
| SEC-21 | Attempt SQL injection, duplicate/ambiguous JSON keys, unexpected polymorphic types, or mass assignment | Bounded rejection or safe parameter handling; no extra field changes or unsafe deserialization | Real persistence, parser fuzzing, and API tests |
| SEC-22 | Submit oversized bodies, deep JSON, excessive tool requests, slow upstreams, or sustained expensive crypto requests | Admission, size, concurrency, and deadline bounds hold without bypassing security checks | Bounded adversarial load and fault tests |
| SEC-23 | Forge browser origins, omit CSRF tokens on cookie-authenticated mutations, fix a session, or reuse it after logout | State-changing browser actions protected; cookies/session lifecycle and CORS match the authentication design | Real browser plus HTTP tests |
| SEC-24 | Put hostile markup in policy/issuer descriptions or use malicious navigation targets | No script execution, unsafe redirects, or unintended disclosure in consent and administrative screens | Browser security and rendered-content tests |
| SEC-25 | Access Actuator, debug endpoints, detailed health, API documentation, or error handlers from public and low-privilege networks | Only explicitly permitted management information is reachable; no configuration, heap, token, or stack disclosure | Packaged deployment and network tests |
| SEC-26 | Read another issuer's database, KMS key, backup, audit store, or object storage using application credentials | Least-privilege roles prevent access; encryption and key access evaluated independently | Deployment IAM and data isolation tests |
| SEC-27 | Restore backups, rotate encryption keys, revoke operator access, or test retention/deletion behavior | Recovery preserves security invariants and residency boundaries; removed access stays removed; retention policy enforced | Restore, retention, and access-removal drills |
| SEC-28 | Interrupt or tamper with audit delivery and try to erase the record of a security decision | Durable evidence or fail-closed/pending behavior follows the declared policy; tampering is detectable by an independent trust anchor | Audit outage/tamper tests and review |
| SEC-29 | Introduce vulnerable/unapproved dependencies, embedded secrets, mutable build inputs, or excessive container privileges | Pipeline blocks policy violations; effective dependency inventory and artifact provenance retained | SAST, SCA, secret, image, and infrastructure scans |
| SEC-30 | Issue/present with an independently implemented wallet against the selected immutable protocol profile | Positive and adversarial flows agree with that exact profile; unsupported features are explicit | External interoperability fixtures and independent review |
| SEC-31 | If browser OIDC login is selected, mismatch state/nonce/issuer/redirect, replay a code, or omit profile-required PKCE | Login rejected without establishing or escalating a session; protocol requirements tested against the chosen provider | Authentication-provider fixtures and real browser flow |
| SEC-32 | Use invalid TLS certificates, spoof reverse-proxy headers, or bypass the approved ingress path | Certificate validation holds; untrusted headers cannot alter caller identity, security decisions, or external callback URLs | TLS/proxy fixture and deployed-network tests |
| SEC-33 | Modify ciphertext/tag or substitute issuer/tenant/document/version/purpose envelope context or wrapped key | AEAD/context authentication fails before any user/worker plaintext output; protected provenance cannot be replaced to hide the change | Vault, decryptor, and context-substitution fixtures |
| SEC-34 | Repeat encrypted writes concurrently, retry after crashes, restore workers, or re-encrypt a document | Reviewed DEK/nonce policy holds across versions/retries/restarts; no reuse or unauthenticated partial/truncated output | Encryption-profile review and controlled retry/fault tests |
| SEC-35 | Use another principal's image grant, expired/revoked grant, wrong purpose/object, storage-admin role, or unavailable KMS | Current authorization and key-use policy deny unwrap/read; no key exposure or plaintext fallback | Actual KMS roles, grant bindings, and read-output observation |
| SEC-36 | Upload a spoofed/polyglot/malformed image, oversized/decompression-bomb input, or hostile scanner/OCR payload | Local encrypted quarantine, actual-type/size/pixel/decoder bounds, sandbox and egress prevent activation/escape | Synthetic hostile corpus and constrained-worker tests |
| SEC-37 | Treat confident but incorrect OCR, an uploaded document, or an extraction approval as verified identity/claims | Issuer evidence policy, holder binding, authoritative checks, and exact revision review remain required before signing | Extraction/review/enrollment/issuance bypass fixtures |
| SEC-38 | Enumerate hashed identity fields, correlate image digests, replace digest references, or change normalization/canonicalization | No public fingerprint lookup or anonymity claim; protected versioned integrity references prevent silent substitution | Dictionary/correlation, provenance, and canonicalization fixtures |
| SEC-39 | Correct fields or replace source images after review, reuse stale ETags/approvals, or request issuance from obsolete revisions | New attributable revision requires current approval; signed credentials are never rewritten and declared refresh/revocation policy applies | Concurrent correction/review/source-dependent issuance tests |
| SEC-40 | Fail local workers/storage and attempt remote OCR, cross-region replication/failover, central proxy, or analytics/support export | Approved locality holds across images, derived fields, digests, keys, backups, queues, and telemetry even under failure | Destination inventory, egress capture, and deployment/failover tests |
| SEC-41 | Switch issuer/RP/holder/federation dashboard roles or forge preview/search/export URLs | Same API object/purpose authorization holds; shared administrator/support privilege grants no source-image or KMS access | Role/issuer dashboard, browser, and original-image tests |
| SEC-42 | Use SDK wrong-origin/audience/scopes, revoke app credentials, retry unsafe writes/jobs, or change error/pagination/precondition contracts | Contract parity and current authorization hold; no secret logging/browser server credentials, cross-region fallback, or duplicate issuance/acceptance | Consumer/provider SDK fixtures, clean quickstarts, and bundle/egress checks |
| SEC-43 | Create a subject ID to self-verify, guess another local ID, merge records using PII hashes, or activate an unapproved application/issuer | Pending IDs/app registration confer no identity or trust authority; namespaces, approvals, uniqueness, holder binding, and scopes remain enforced | Enrollment/app onboarding and concurrent-ID tests |
| SEC-44 | Delete live images, rewrap/retire keys, restore backups, revoke image access, or inspect dependent extraction copies | Approved lifecycle and issuer scope survive recovery; no false universal-erasure/recall claim or unauthorized resurrected access | Artifact/key/retention inventory and rotation/deletion/restore drills |

The crypto cases should follow the selected credential specification together with [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
Application-specific trust, consent, status, and replay checks remain necessary even when a signature is valid.
Document cases follow the proposed [federated document lifecycle](../architecture/federated-document-lifecycle.md) and [developer-platform contracts](developer-platform.md).
These cases extend the seed matrix and still do not replace the full applicable ASVS assessment.

## Test methods and tooling

Use JUnit with [Spring Security test support](https://docs.spring.io/spring-security/reference/servlet/test/index.html) for request and service authorization cases.
Use [Testcontainers](https://docs.spring.io/spring-boot/reference/testing/testcontainers.html) for PostgreSQL and controlled dependencies, including multiple application instances for race tests.
Keep a real HTTP/browser suite for cookie, consent, tenant, and deployed security-filter behavior.

Add property-based generation for trust scopes, disclosure budgets, nonce state transitions, and time boundaries.
The important properties are that adding unauthorized claims cannot make a rejection succeed, reducing issuer authority cannot broaden acceptance, and changing an unapproved policy cannot authorize a plan.
Select a maintained property-testing dependency only after reviewing its current license and Java/JUnit compatibility.

Evaluate [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) for malformed token/JSON parsing and resource-exhaustion inputs, with bounded CPU, memory, and execution time.
Evaluate [PIT](https://pitest.org/) for mutation tests on pure policy, consent-binding, trust, expiry, and replay decision code.
In addition to generated mutations, deliberately remove a required security check in an isolated test build and require the corresponding negative test to fail.
Retain minimized failing inputs as regression fixtures.
Confirm Java 25 and build-plugin compatibility before adopting these tools; this plan does not certify their compatibility.

Use [SpotBugs with Find Security Bugs](https://find-sec-bugs.github.io/) as a static-analysis candidate, [OWASP Dependency-Check](https://dependency-check.github.io/DependencyCheck/) for dependency findings, and [CycloneDX Maven](https://cyclonedx.github.io/cyclonedx-maven-plugin/) for an SBOM.
Scan the packaged artifact and container as well as the declared dependency graph, and separately scan secrets and deployment configuration.
Scanner database/update failure is a failed gate, not a clean report.
Triaged false positives need evidence, an owner, and an expiry rather than an indefinite blanket suppression.

Run [ZAP API scans](https://www.zaproxy.org/docs/docker/api-scan/) against disposable synthetic deployments as anonymous, ordinary-user, and administrative test identities.
Verify that the scanner actually authenticated and reached protected routes.
Use a separate browser/security test for UI behavior; the API scan does not cover all browser attacks or Sovra's business invariants.

## Mandatory mission-critical production scenarios

SRS version 0.5 promotes the following scenarios from the [security research](../research/security-and-mission-critical-review.md) into required production evidence.
They extend the SEC cases without renumbering them; implementation and execution are pending.
Each run needs independent assertions, packaged production-equivalent controls, synthetic load, bounded fault/cleanup procedures, and measured detection/containment/recovery results.

| ID | Attack/failure | Required evidence | Requirement/case connection |
| --- | --- | --- | --- |
| MC-01 | Revoke privileged access under load with warm tokens/grants/key caches | New prohibited operations fail under the actual bounded policy; caches and active work cannot silently extend privilege | SR-02, SR-13, SR-21; SEC-35, SEC-41 |
| MC-02 | Simulate compromised image/parser worker | Worker cannot reach signer, another issuer, cloud metadata, unrestricted network, or unrelated document keys; resource bounds hold | SR-22, SR-23; SEC-36, SEC-37, SEC-40 |
| MC-03 | Restore stale backup, partition old/new writers, and perform blue/green rollback under load | Zero replay/terminal-revocation/trust/approval resurrection; old writers fenced and unsafe sessions invalidated before readiness | INV-01, INV-04, INV-12, INV-13, NFR-05, NFR-16; SEC-08, SEC-09, SEC-12, SEC-27 |
| MC-04 | Disable/rotate original key while restored copy and cached DEK exist | Copy/cache inventory, deny propagation, containment and recovery behavior agree with the declared contract | FR-23, SR-13, SR-21; SEC-14, SEC-35, SEC-44 |
| MC-05 | Attempt direct origin, alternate ingress, remote OCR, and unapproved failover | Identical business authorization and no forbidden plaintext/PII processing on every path | SR-09, SR-25; SEC-17, SEC-32, SEC-40, SEC-42 |
| MC-06 | Attempt self-granted key/trust privileges through IAM/pipeline/admin changes | Governance/delegation denies or requires independently controlled approval, with attributable external evidence | SR-01, SR-13, SR-15, SR-16; SEC-03, SEC-26, SEC-28, SEC-29 |
| MC-07 | Admit a substituted artifact or provenance from the wrong builder/source | Deployment rejects the artifact despite a syntactically valid signature, and records the rejection safely | SR-14, NFR-08; SEC-29 |
| MC-08 | Keep HTTP probes green while status/trust is stale or audit delivery is lost | Affected verification readiness closes; alerts identify the actual unsafe dependency without restart storms or PII leakage | FR-29, NFR-11; SEC-11, SEC-19, SEC-20, SEC-28 |
| MC-09 | Exercise pooled/database-owner/background-job authorization paths | Correct runtime role and scoped context prevent leakage; documented RLS bypass roles are never the application identity | DR-06, SR-01, SR-15; SEC-02, SEC-03, SEC-21, SEC-26 |
| MC-10 | Fail key-management control plane and cryptographic data plane separately | Emergency change limits, available crypto operations, and safe deny behavior are observed rather than inferred from one health signal | NFR-05, OD-05, OD-13; SEC-14, SEC-27, SEC-35 |

A stale restore must not reopen verification until consumed-session and revoked/trust/approval state is reconciled or affected sessions are made unusable with a reviewed fencing/generation mechanism.
Warm caches and independently restored keys must follow the approved current-authority/known-deny policy; disabling one original key is not evidence that every copy or previously unwrapped DEK stopped working.
An externally isolated image/OCR process must be tested without relying on the unavailable Java Security Manager.

## Provider and authority architecture follow-up

The [architecture assessment](../architecture/identity-key-provider-architecture.md) records ARCH-01 through ARCH-08 and SRS v0.6 provider/authority requirements.
These are static observations, not executed exploit or penetration tests.
SOV-006 and SOV-040 extend SEC-01/02/03/26/31/32/43 and MC-01/06/09 with actual OIDC/BFF/CSRF, hardware-authenticator enrollment/recovery, current entitlements, immutable actor identity, sealed snapshot and issuer-binding cases.
SOV-027 removes schema-owner credentials from serving processes and tests the actual runtime/migration privilege boundary.
SOV-038 extends SEC-14/33/35/40 and MC-02/04/05/06/07/10 with wrong/debug/revoked attestation, host/metadata/impersonation direct-key bypass, protected input channels and separate local/provider containment measurements.
Plaintext DEKs have no cross-request cache in the selected initial profile; best-effort buffer clearing must not be reported as deterministic JVM memory erasure.
SOV-036 qualifies the mandatory protocol/library profile and SOV-041 supplies packaged two-instance consent-to-verification evidence, including persisted state and absence of prohibited side effects.
SOV-037 and SOV-039 retain independent design and issuer/location approval before real-data provisioning/processing; synthetic development does not mark either complete.

## Release gates

| Stage | Required evidence |
| --- | --- |
| Every change | Unit/authorization/negative regression suite, generated invariant cases, HTTP/database cases for affected boundaries, source/dependency/secret scans, and reviewed effective dependency changes |
| Regular security run and release candidate | Coordinated replay/race tests, restart and dependency fault tests, bounded fuzzing, mutation analysis of security decisions, authenticated API scans, telemetry-canary checks, and bounded load tests |
| Before real sensitive data | Complete applicable ASVS mapping and evidence, independent architecture/code review and penetration test, tested key-compromise/recovery runbooks, verified deployment/IAM/egress and backup controls, privacy/retention/residency assessment, and retest of findings |

Any invalid evidence acceptance, cross-tenant access, sensitive-data leak, or bypass of consent/trust/replay is release-blocking regardless of a scanner's severity label.
Open high/critical security findings block production release; triage false positives separately rather than reclassifying a real issue to pass a gate.
Skipped, missing, stale, or failing mandatory evidence blocks a gate.
Line coverage is diagnostic only; a high percentage does not establish that tests detect a removed authorization check.

At implementation, assign named engineering and independent security reviewers, set numeric request/resource budgets, select immutable dependency versions, and define the evidence retention period.
Until that work and the required assessments are complete, use synthetic data and retain the existing prototype limitations.
