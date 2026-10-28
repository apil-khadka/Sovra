# SOV-002: locality, lifecycle, custody and root trust boundaries

**Version:** 0.2 (recommended custody/provider clarification; independent/issuer approval pending).
**Date:** 2026-10-28.
**Task:** [SOV-002](https://github.com/apil-khadka/Sovra/issues/6)
(approve issuer locality, lifecycle, custody and root trust boundaries).
**Owner decisions:** hybrid holder custody with opt-in encrypted backup;
boundary rules fixed now with the provider pick deferred to G2;
attested confidential processing required before real data.

This record freezes OD-07 (data lifecycle), OD-08 (hosting/jurisdiction),
OD-09 (holder custody/recovery), OD-15 (digest and matching profile) and
OD-17 (root/workload and data-in-use boundary). It governs synthetic G1
work and sets the rules real-data work must satisfy.

## 1. Data-flow inventory (OD-07, OD-08)

| Data | Allowed locations | Never in |
| --- | --- | --- |
| Source identity originals (scans, photos) | Issuer-local encrypted vault only (G2); synthetic fixtures in-repo at G1 | Shared services, model requests, telemetry, logs, backups outside the issuer boundary, support tooling |
| Derived claims and credentials | Issuer vault; holder device/wallet; verifier memory only during an authorized session | AI planner context beyond approved schema/policy excerpts; shared analytics |
| Issuer signing keys | KMS/HSM only (see section 4); no exportable copies | Source code, prompts, browser storage, config files, container images |
| Holder private keys | Holder device; opt-in encrypted server backup (see section 3) | Issuer systems, verifier systems, logs, crash reports |
| TLS/session keys | Terminating workload memory only | Logs, packet captures retained beyond incident scope |
| OCR/extraction intermediates | Isolated hostile-processing workers, destroyed after use | Shared filesystem, model context, caches |
| Telemetry, metrics, traces | Sanitized (counts, reason codes, correlation IDs); no PII, key material, or complete proofs | Any store with weaker access control than the source system |
| Support and admin views | Metadata + redacted excerpts only; every access logged and justified | Standing access to originals or keys |
| Backups and failover copies | Same boundary, encryption, and access rules as the primary; same-region first | Cross-boundary replicas without a recorded approval |
| Identity/account and authentication metadata | Approved issuer-local IdP boundary, including subject mappings, factors, sign-in/device events, sessions, recovery, support and backups | Unapproved upstream IdP, factor-delivery, telemetry or administrative processing locations |

G1 synthetic data follows the same flow shapes with fixture values so the
boundary is tested before real data exists. No G1 evidence uses real
identity records.

## 2. Retention and deletion (OD-07)

| Record | Retention | Deletion |
| --- | --- | --- |
| Verification decisions + consent receipts | 7 years (dispute/audit window), then cryptographic erasure | Key destruction + tombstone; erasure evidenced per record |
| Audit log | 7 years, append-only | Same as decisions; no selective redaction |
| Issued credential registry entries | Credential lifetime + 7 years | Revocation entry retained; payload erased |
| Holder backup blobs (opt-in) | Until holder deletes or 1 year of account inactivity | Immediate on holder request (24-hour SLA), confirmed in writing |
| Session challenges/nonces | 5-minute lifetime + 24-hour replay window | Automatic expiry; no archive |
| Telemetry/operational logs | 90 days | Automatic expiry |
| Synthetic fixtures | Indefinite (no personal data) | N/A |

Retention values are proposed pending legal review in the operating
jurisdictions; the deletion mechanisms (expiry, key destruction, tombstones)
are frozen here.

## 3. Holder custody and recovery (OD-09)

Hybrid model: non-exportable device keys are primary; opt-in encrypted server backup may preserve permitted credential/application state for recovery.

- Non-exportable holder keys remain in device secure hardware and never enter a backup blob.
- Backup blobs are encrypted with a key derived from a holder secret the
  server never sees (envelope: holder-secret KEK wraps the backup DEK).
  The server stores opaque bytes it cannot decrypt.
- Recovery ceremony: fresh identity re-proof at the original assurance level, the approved delay/notifications, new device keys and profile-compliant reissuance or rebinding.
  Old device authority is revoked; the earlier 72-hour delay remains a proposed policy value pending issuer review.
- Loss/theft without backup: the holder re-enrolls; old credentials are
  revoked, never restored.
- Administrators, support staff, and operators have no technical path to
  holder private keys or backup plaintext; this is tested, not assumed.

## 4. Issuer keys and provider selection (OD-08)

Issuer signing keys live in KMS/HSM with per-issuer key permissions, tested
rotation, and compromise procedures. Production keys are never in source,
prompts, browser storage, config files, or images.

The [provider reference](SOV-004-provider-key-cache-contracts.md) now selects Google Cloud KMS Single-tenant Cloud HSM and Confidential Space for qualification.
SOV-039 must verify the actual issuer-approved location/capability intersection; this is not an approved cloud deployment or a fallback outside the issuer boundary.
The provider must satisfy all selection criteria before hosting real data:

1. In-region KMS plus dedicated HSM (CloudHSM or equivalent) with
   customer-controlled key material and export of audit logs.
2. TEE support matching section 6 (attested key use and matching).
3. Region pinning for compute, database, backups, telemetry, and any model
   endpoint; no silent cross-region replication.
4. Current SOC 2 Type II and ISO 27001 reports available under NDA;
   data-processing terms compatible with the operating jurisdictions.
5. Break-glass and support-access logging the Sovra operator can audit.

Issuer nodes stay logically separated per jurisdiction (own database,
credentials, configuration, signing permissions) even when they share a
provider account, until a recorded governance agreement changes that.

## 5. Digest and matching profile (OD-15)

- Original-document integrity hashes cover exact accepted bytes; image re-encoding creates a different artifact/version.
- Structured extraction digests use versioned business normalization followed by a reviewed RFC 8785 canonicalization profile over supported JSON types.
- Credential signatures, SD-JWT disclosure hashes and holder proofs use the selected protocol's exact byte rules, not a substituted extraction canonicalization rule.
- Field normalization: per-schema version, recorded alongside the schema;
  normalization rules are versioned and immutable once approved.
- Provenance: every digest references its source revision, schema version,
  and normalization version; digests without a protected provenance
  reference are not authoritative inputs.
- Keyed indexes: HMAC-SHA256 with per-purpose keys, annual rotation with
  overlap verification; rotation never silently re-links identities.
- Correlation: pairwise, purpose-scoped subject identifiers only. No global
  subject key, no cross-purpose joins, no cross-RP correlation by Sovra.
  This application policy is not proof of cryptographic unlinkability; repeated credentials, holder keys and status references require explicit correlation analysis under the selected profile.

## 6. Root, workload, and data-in-use boundary (OD-17)

Attested confidential processing is **required** before real data is
handled: sensitive key-use authorization and identity matching run inside attested TEEs (AWS Nitro
Enclaves, AMD SEV-SNP, Intel TDX, or provider equivalent selected under
section 4), with launch measurement verified against pinned values and
attestation evidence retained per operation batch.
Non-exportable issuer signing keys remain in the HSM; its ECDSA computation is outside the application TEE as clarified in section 8.

Remaining administrative overrides, explicitly inventoried:

| Override | Holder | Mitigation |
| --- | --- | --- |
| Cloud root / org admin | Provider + Sovra ops lead | Break-glass only, hardware-key MFA, immutable audit trail, quarterly access review |
| Database superuser | Sovra DBA role | No standing access; time-boxed elevation with ticket + peer approval |
| Deploy pipeline | Release engineering | Separate deploy identity; signed artifacts; production deploys need independent approval |
| Migration runner | Data engineering | Separate migration identity; migrations reviewed; no interactive production SQL |
| Key administrators | Security role | KMS/HSM admin quorum (2-of-n); no single-admin key destruction or export |
| Host/hypervisor introspection | Provider | TEE attestation for key use and matching; documented residual risk below |

What attestation does not cover (residual risk, accepted with review):
microarchitectural side channels, supply-chain compromise of the TEE
stack, and endpoint/device compromise. These are tracked as open risks,
not assumed away.

Workload separation is mandatory regardless of provider: hostile document
processing runs outside the Java runtime in isolated workers with their own
identity, constrained resources, and restricted egress. One modular
codebase never implies one runtime identity.

## 7. Approval

- [ ] SOV-037 independent security/privacy assessment before real-data provisioning or processing; synthetic implementation may proceed without asserting this approval.
- [ ] Legal review of section 2 retention values in each operating jurisdiction.
- [ ] Issuer-authority sign-off on sections 1, 3, and 6.
- [ ] Record revision on any boundary, custody, provider, or retention change.

## 8. Custody and confidential-boundary clarification (v0.2 revision)

This section supersedes the incompatible key-backup wording in section 3 and requires issuer/privacy approval before real custody use.
Non-exportable device hardware keys never enter a server backup and are never restored to a replacement device.
Opt-in backup may preserve permitted encrypted credential/application state; recovery re-proofs the holder, generates new device keys and reissues or rebinds credentials under the selected profile with old authority revoked.
Loss of the independent backup secret is not bypassed through an administrator decrypt path.
If a future profile permits exportable software holder keys, it requires a separate lower-assurance custody decision and is not described as non-exportable hardware custody.

Signing authorization and sensitive claim construction occur in the attested workload; the non-exportable issuer key's ECDSA computation remains in the HSM.
The reference does not assert that a remote HSM operation executes inside the application TEE.
Uploads, OCR/matching, decryption and sensitive derived values must remain inside the approved confidentiality boundary while in use, including input-channel/TLS termination and storage outside the TEE.
SOV-038 validates attestation-bound input/key-use paths and denial of host/ordinary-workload bypasses.
No public cloud location or corporate security report by itself establishes permission to process an issuer's data there.
