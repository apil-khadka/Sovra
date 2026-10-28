# Identity, key custody and confidential-processing architecture

**Review date:** 2026-10-28.
**Status:** recommended implementation direction; deployment qualification and independent review pending.
**Scope:** architecture and source inspection, provider research, and implementation requirements.
No runtime code, cloud account, identity tenant or live key was created by this review.

## Recommendation

Keep Java 25/Spring, PostgreSQL and the React client, with issuer-local authority and a small number of deliberately separated runtime identities.
Use issuer-local Keycloak for human OIDC authentication and Sovra-owned authorization, elevation and approval records.
Use Google Cloud KMS with Single-tenant Cloud HSM and Confidential Space as the reference implementation for attested sensitive processing where the issuer's approved locations support the complete combination.
Federation remains provider-independent: a reference implementation is not permission to move another issuer's data or key authority into its region or project.
Do not choose a global identity tenant, central document proxy, shared issuer signer or automatic foreign-region fallback.

This selects interfaces and an implementation target so development can proceed.
It does not approve a deployment jurisdiction, prove the provider integration, or complete an independent security assessment.
The [provider decision](decisions/SOV-004-provider-key-cache-contracts.md), [locality decision](decisions/SOV-002-locality-custody-boundaries.md), [SRS](../requirements/software-requirements-specification.md) and [backlog](../engineering/implementation-backlog.md) specify the remaining gates.

## Initial-phase budget constraint

The initial phase permits no new paid service, subscription or hardware purchase.
Self-hosted Keycloak has no software licence charge, but host capacity, operations and backups still need an identified source of resources.
Self-hosted Casdoor is also Apache-2.0 software; a managed Casdoor Cloud subscription is a separate product.
Licence references: [Keycloak](https://github.com/keycloak/keycloak/blob/main/LICENSE.txt), [Casdoor](https://github.com/casdoor/casdoor/blob/master/LICENSE).

The dedicated HSM/confidential-cloud reference above is a later deployment qualification target, not an initial-phase purchase requirement.
Google publishes [paid Single-tenant HSM instance pricing](https://cloud.google.com/kms/pricing); this is excluded from zero-spend initial provisioning.
Use existing resources and labelled synthetic key/provider fixtures for development, with no paid hosting, SMS, email, model API or cloud resource assumed available.
Free credits or quotas require verification of their scope, expiry and charge prevention before use; an alert alone is not a spending cap.

The confirmed initial launch is a public demo using synthetic identities and documents only.
Accept bundled/pre-approved fictional fixtures; real identity-document upload, real issuer connectivity and production credential issuance remain disabled.
Use self-hosted Keycloak and existing or independently verified no-charge resources; paid HSM/TEE, hosted identity, SMS, email and model services are outside initial provisioning.
Live model calls require confirmed no-charge capacity and charge prevention; unavailable or fixture-driven behavior must be labelled and does not count as live-model acceptance.
Before publication, prove bounded resource use, restricted demo accounts, rotated deployment secrets and private administrative interfaces; the local Compose harness is not automatically a hardened public deployment.
Login, visitor and operational metadata may still be personal data even though document fixtures are synthetic, so minimize and protect it.
Zero-spend development does not waive the real-data locality, key-custody, attestation or independent-assessment gates, and a software key double is not an HSM.
Existing or partner-provided qualified infrastructure could meet a requirement without a new Sovra payment, but no such resource is assumed provisioned.

## What exists now

Source inspection confirms service-token authentication, explicit role/action checks, tenant-scoped JDBC, audit writes, versioned trust data and a synthetic ES256 issuance path.
`KmsSigner` throws an unsupported-operation exception; there is no working production KMS adapter.
`SyntheticJwtEncoder` deliberately emits a custom synthetic JWS rather than the selected SD-JWT VC profile.
The React application currently displays backend health; it is not a holder consent or administrative dashboard.
No verifier/session/consent implementation was found under the inspected backend source tree.
An independently verified credential signature is useful issuance evidence but does not prove RP policy, holder consent, status freshness, audience or durable replay-safe presentation acceptance.

The previous report of 89 backend tests and a packaged issuance probe is historical implementation evidence.
This architecture review did not rerun those tests or establish that SOV-005/007/008/009 meet every business or production acceptance criterion.
Their current code must be assessed against the findings below rather than being treated as a completed production control plane.

## Identity architecture

Keycloak's [OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers) and [WebAuthn/step-up controls](https://www.keycloak.org/docs/latest/server_admin/index.html) supply the authentication building blocks.
Its [production guide](https://www.keycloak.org/server/configuration-production) still requires deliberate TLS, administrative exposure, capacity and operational configuration.
The recommendation follows Sovra's identity-metadata locality requirement; self-hosting is not inherently more secure than a well-governed managed IdP.
Assign an operator for supported releases, patch response, backup/recovery and authentication availability, and pin a maintained release/container during implementation.
Do not assume the Keycloak server must run on the same Java release as Sovra; use its own supported runtime/container.

Entra Workforce is a suitable alternative for operators whose issuer approves its [identity-data locations](https://learn.microsoft.com/en-us/entra/fundamentals/data-residency), assurance policy and administration boundary.
It is not evidence of arbitrary country-local identity custody, and putting a local broker in front of a managed IdP does not undo upstream metadata processing.
Microsoft's [PIM approval workflow](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow) does not implement Sovra's independent multi-approval business transaction merely by listing multiple approvers.
Entra External ID and SaaS identity remain separately qualified customer/operator profiles; do not transfer Workforce enforcement features by product name.

Casdoor is a viable self-hosted OIDC alternative with documented [standard-client integration](https://casdoor.ai/docs/how-to-connect/oidc-client/) and [WebAuthn sign-in](https://casdoor.ai/docs/how-to-connect/webauthn/).
A bounded check of [released v4.24.0 WebAuthn handling](https://github.com/casdoor/casdoor/blob/v4.24.0/controllers/webauthn.go#L49-L62) found attestation requested as `none`; equivalent approved-hardware/attestation and privileged-recovery enforcement was not established by this review.
This is a qualification gap, not proof that Casdoor is insecure or that every configuration lacks those controls.
Retain Keycloak as the preferred privileged-identity reference because its reviewed enforcement and [security-response policy](https://www.keycloak.org/security) provide clearer evidence for the selected requirements.
Both products still require deployment, authentication/recovery and current-authorization testing; neither is universally the most secure by product name.

Human users authenticate through an issuer-owned OIDC authority; the application maps the verified `(iss, sub)` tuple to local organization, issuer and resource entitlements.
An external IdP role claim does not confer sovereign issuer accreditation, signing permission or a document-decryption grant.
Federation administrators authenticate separately from issuer staff and gain no implicit source-data entitlement.
Keycloak realms are administrative namespaces, not protection against the root operator of the shared Keycloak deployment.
Independent issuer trust boundaries use separate deployments, databases, service identities and administrative custody where those operators must not trust one another.

Use a Spring backend-for-frontend with authorization code plus PKCE, exact redirect URIs, state/nonce checks and server-side token storage.
The browser receives a Secure, HttpOnly session cookie with an approved SameSite policy, CSRF protection and rotation on authentication/elevation.
Do not copy privileged bearer credentials into localStorage, frontend configuration or JavaScript bundles.
The present cookie-free API configuration disables CSRF; it must not be reused unchanged for the browser login chain.
Machine routes remain a separate resource-server policy with exact trusted issuer/audience validation, narrow scopes and short-lived client/workload credentials.
Sovra API credentials never double as cloud IAM credentials.

Privileged authentication requires hardware-bound phishing-resistant authenticators, user verification and controlled authenticator enrollment/recovery.
General passkey support does not by itself prove hardware binding, device provenance or high-assurance recovery.
Approve a credential/device policy, register at least two independently held recovery-capable factors where appropriate, and reject TOTP/email/SMS fallback for privileged elevation.
Do not assume video verification alone prevents impersonation.
The application must verify the authentication context actually established, not merely request a stronger context in the OIDC redirect.

Sovra owns ticket/purpose-bound elevation, independent approval, policy version, expiry and removal.
Four hours is an outer ceiling from the earlier decision, not a default entitlement duration; use shorter action-specific grants.
Check current local authorization and grant state on sensitive operations and queued-job execution, including after token refresh and during already running work.
Logout, IdP account disablement and local permission revocation have different semantics and require separate tests.
Cloud administrative access uses the cloud's supported federation and IAM controls; local Keycloak does not automatically implement cloud-wide PIM or independent HSM governance.

## Why this key-provider reference

| Option | Verified fit or limitation | Sovra decision |
| --- | --- | --- |
| Google Cloud KMS, Single-tenant Cloud HSM and Confidential Space | Confidential Space uses attestation-derived identity and workload identity policies to authorize protected resources; single-tenant HSM instances provide dedicated partitions and quorum-controlled instance operations | Preferred reference for an attestation-bound signer/unwrap authorization boundary, subject to exact region, algorithm and IAM proof |
| Azure Managed HSM and confidential computing | Managed HSM provides a single-tenant security domain and per-key access; Secure Key Release releases an exportable key under an attestation policy | Viable regional alternative; an SKR example does not establish non-exportable issuer-signing-key authorization from an approved workload |
| AWS KMS and Nitro Enclaves | Recipient-attested KMS operations document decrypt/data-key/random/shared-secret paths; that list does not establish recipient-attested `Sign` | Strong candidate for encrypted document processing; direct non-exportable ES256 signing requires a separately proven authorization design |
| Self-operated HSM or another sovereign platform | Can address an issuer's locality or operator-control requirements | Requires its own supported HSM, attestation, workload identity, recovery and operational qualification; no automatic equivalence |

Provider capability sources: [Confidential Space security model](https://docs.cloud.google.com/docs/security/confidential-space), [Single-tenant Cloud HSM](https://docs.cloud.google.com/kms/docs/single-tenant-hsm), [Azure Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview), [AWS attested operations](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html).
The preference is an engineering inference from these capabilities, not a completed cross-provider benchmark or a claim that other providers cannot meet the requirements.

### Location is an admission rule

Key material is confined to its selected Cloud KMS region, but protection-level availability varies by location.
The reviewed [location matrix](https://docs.cloud.google.com/kms/docs/locations) lists Sydney and Melbourne as multi-tenant HSM only.
Consequently the dedicated-HSM requirement cannot be claimed satisfied for an Australian issuer by silently selecting a US/EU instance or a different protection level.
A Nepal example does not establish an approved domestic cloud location or permission to use a neighboring country.
Verify the current intersection of issuer-approved compute, HSM protection/algorithm, confidential runtime, database, storage, backup, ingress, identity, telemetry and control-plane metadata locations before provisioning.
If that intersection is empty, the node remains synthetic or selects a separately reviewed regional/sovereign profile; locality is not relaxed by this recommendation.

### Keep key roles separate

Issuer-signing keys remain non-exportable HSM keys using P-256/ES256 and immutable, explicitly selected key-version references.
Sensitive request authorization, claim construction and provenance validation run in the attested authorization workload; ECDSA itself executes in the provider's HSM.
This distinguishes attested authorization of key use from an unsupported claim that a remote HSM operation executes inside the application TEE.
Document DEKs are fresh per immutable object version and encrypt with the approved AES-256-GCM envelope.
Dedicated wrapping keys protect those DEKs; signing keys never wrap document keys.
A provider adapter must verify the returned key resource/protection level, request/response integrity and signature encoding against the JOSE contract.
The Cloud KMS [signing API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign) exposes the key-version resource, integrity fields and protection level that support those checks.

The production key-use identity is available only through the approved attestation/federation path.
An ordinary host identity, attached VM service account, deploy pipeline or generic application token must have no direct signer/unwrap privilege and no impersonation route around that path.
Pin exact approved image digests, production/non-debug platform claims, intended issuer/project, expected workload identity and permitted location; retain explicit policy/version evidence.
Google documents the [workload authorization and attestation assertions](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources); the exact signing grant and credential path still require deployed denial tests.
Attestation proves an authorized measured workload under its trust assumptions, not that the workload's code is correct or that its caller has document or issuance authority.
This reference authorizes federated credentials from attestation; it does not claim Cloud KMS rechecks a fresh hardware quote for every signature.
Already issued federated credentials have their own lifetime and containment behavior, and image-policy withdrawal is not assumed to recall them immediately.
Credential exfiltration or compromise of the approved authorization workload remains an explicit risk; restrict token exposure and egress and measure the actual revocation window.

### Use narrow gateways

The attested signing gateway validates a typed issuance authorization against current issuer/type/purpose, approved source revision, maker/checker approval, holder binding, trust epoch, key version and bounded replay-safe request.
Do not expose a generic raw-payload or caller-chosen digest signing endpoint.
The existing `IssuerSigner.sign(keyRef, payload, aad)` method is an internal cryptographic adapter seam; a context string containing an issuer name is not independent authorization or cryptographic AAD for ECDSA.
The production gateway must validate and construct the signed content before invoking that adapter.
Source/approval evidence needs authenticated provenance under independently controlled authority; mutable database fields and caller-supplied reviewer names are insufficient when database/runtime compromise is in scope.

A separate attested vault gateway authorizes principal/object/version/purpose before unwrapping and releasing a document or job-scoped DEK.
OCR/decoder workers receive only the current job's approved input, cannot unwrap arbitrary issuer objects and cannot call the signer.
Every process that handles plaintext within the stated host-confidentiality boundary needs the approved confidential runtime plus its own hostile-code isolation and output limits.
A TEE is not a parser sandbox, and a malicious decoder inside a trusted TEE remains malicious code.
Original-image viewers are authorized disclosure endpoints, not general-purpose key-release clients.

Upload/decryption paths need confidential ingress as well as encrypted storage.
An ordinary reverse proxy terminating plaintext upload TLS outside the protected boundary can defeat the stated host-operator confidentiality goal before encryption starts.
Qualify a supported attestation-bound encrypted input channel or TLS termination inside the protected workload, including authenticated binding to the approved endpoint.
Do not invent a new cryptographic protocol or assert that generic HTTPS supplies remote attestation.
Encrypt sensitive extracted values/provenance before storage outside that boundary; KMS and database disk encryption alone do not hide application plaintext from database administrators.

## Findings from the current source

These are architecture findings and static source observations, not exploit demonstrations or completed penetration testing.

| ID | Observation and implication | Required action |
| --- | --- | --- |
| ARCH-01 | Both app containers receive Flyway owner credentials as well as runtime credentials in `compose.yaml`; separate database users in one process do not withstand that process's compromise | SOV-027 must remove migration credentials/capability from serving containers and run a separately approved migration job |
| ARCH-02 | `AuthorizationService` rechecks account liveness but derives roles from the request principal; its cache version tracks rules/trust activation, not a principal entitlement epoch | SOV-005/006 must define and test role removal after authentication, during warm caches and queued work; use current entitlements and bounded action grants |
| ARCH-03 | The runtime role can insert trust rows, approvals and activations; the V4 trigger compares supplied actor names, while published snapshot membership is not sealed against further inserts | SOV-040 must bind immutable actor identities, independently control approval/activation authority and seal published contents; distinct strings alone are not independent people |
| ARCH-04 | `TenantDataSource` sets a tenant session variable; this helps request isolation but a compromised role with arbitrary SQL is not confined to its original value | Retain issuer-specific database/runtime boundaries and test unwrapped JDBC, SQL injection and compromised-worker paths; do not describe this GUC as a sovereign security boundary |
| ARCH-05 | V6 unconditionally seeds a publicly known synthetic issuer/key and trust activation; production supersession alone leaves downgrade/restore/admission questions | Production startup, trust activation, signing and every verifier path must reject synthetic profiles/keys and fail closed on synthetic seed/configuration; use a reviewed production bootstrap ceremony |
| ARCH-06 | The G0 records require external review before G1 work, while that work already exists; SOV-036 remains optional in the registry despite the full-profile decision | Separate development milestones from live-data gates, qualify the chosen protocol before integration acceptance, and retain independent review as an explicit unsatisfied release gate |
| ARCH-07 | The old record proposes ten-minute/1,000-entry plaintext-DEK caching and broad permission/token cache claims without provider propagation evidence | Disable cross-request plaintext-DEK caching initially; define local deny/epoch checks separately from eventual cloud IAM containment and measure both |
| ARCH-08 | The holder design combines non-exportable secure-hardware keys with restoration of those same keys from backup | Keep device keys non-exportable; back up permitted encrypted credential state, recover through re-proof and new keys/reissuance, and obtain issuer approval of the custody amendment |

Relevant source: `backend/src/main/java/dev/sovra/{authz,tenancy,issuance,trust}`, migrations V4/V6, `backend/src/main/resources/application.yaml`, and `compose.yaml`.
The accepted G1 same-transaction audit tradeoff and synthetic genesis can remain in the synthetic harness; they do not satisfy independent production custody or governance.

## Revocation and memory policy

Keep local emergency-stop freshness at no more than five seconds and fail closed when the authoritative stop/epoch state cannot be checked within that bound.
For new privileged signing, decryption, approval or elevation operations, validate current local entitlement/grant/epoch state instead of relying on a positive authorization cache.
The 60-second cache may optimize non-privileged decisions only where the operation's declared policy permits it.
Retain the earlier trust/status freshness values as profile maxima, subject to current local terminal deny/epoch checks and stricter issuer policy.
Neither a one-hour trust snapshot nor a still-valid JWT overrides a known revocation.

Begin with zero cross-request plaintext-DEK cache entries.
Limit DEKs to one authorized operation, release references immediately, bound job duration and prohibit persisted key/plaintext diagnostics.
Use best-effort buffer clearing but do not promise deterministic zeroization of copied Java heap objects.
Review heap dumps, swap, crash collection, temporary files and library buffers in the actual confidential runtime.

Provider permissions are a second containment layer with their own measured delay.
Google documents [eventual IAM propagation](https://docs.cloud.google.com/iam/docs/access-change-propagation), so the local five-second stop target is not an assertion that all cloud credentials or already released plaintext are recalled within five seconds.
Test direct key-call denial, active jobs, cached/federated credentials, key disabling and independently restored copies separately.
Independent custody of IAM policy, HSM administration, deployment approval and audit must be real; a single person holding every approving credential defeats quorum.
HSM-instance quorum does not automatically impose two-person approval on Cloud KMS IAM policy edits or Sovra business transactions.
IAM/resource owners and organization roots that can replace the key-use policy remain explicit trust authorities and require independently controlled administration, external audit and break-glass testing.

## Development and live-data gates

Synthetic implementation can continue against these versioned contracts and a labelled local Keycloak environment without waiting for a production cloud account or a completed external assessment.
This changes the sequencing of the earlier draft gates; it does not mark those reviews complete.
SOV-006 covers local OIDC, privileged authentication/elevation, app credential lifecycle and denial tests.
SOV-036 qualifies the selected SD-JWT VC/OpenID library/adapters before profile-dependent integration acceptance.
SOV-010/011 implement consent and verification, and SOV-041 proves packaged two-instance end-to-end verification rather than only checking an issuer signature.

Before real-data provisioning or processing, SOV-039 must approve the actual issuer/location/capability matrix and SOV-037 must independently assess the design and custody amendments.
SOV-027/028/038 then provide isolated deployment, artifact admission and deployed attested key-use/input-path evidence.
SOV-040 closes the issuer/identity/governance boundaries before acceptance of their production behavior.
SOV-032/033/034 still require applicable SEC/MC/ASVS evidence, independent review, retested findings and accountable release approval.
No task is closed, no report is certified and no independent assessor is appointed by this document.
