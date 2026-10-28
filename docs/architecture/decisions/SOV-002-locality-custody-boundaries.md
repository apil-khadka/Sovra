# SOV-002: locality, lifecycle, custody and root trust boundaries

**Version:** 0.1 (proposed G0 decision, pending independent review).
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

Hybrid model: device-held keys are primary; an opt-in encrypted server
backup exists for recovery.

- Holder private keys live in device secure hardware where available and
  never leave the device except inside the opt-in backup blob.
- Backup blobs are encrypted with a key derived from a holder secret the
  server never sees (envelope: holder-secret KEK wraps the backup DEK).
  The server stores opaque bytes it cannot decrypt.
- Recovery ceremony: fresh identity re-proof at the original assurance
  level, a 72-hour delay with out-of-band notification to all holder
  contact points, then backup release to the new device. The old device
  keys are revoked at release.
- Loss/theft without backup: the holder re-enrolls; old credentials are
  revoked, never restored.
- Administrators, support staff, and operators have no technical path to
  holder private keys or backup plaintext; this is tested, not assumed.

## 4. Issuer keys and provider selection (OD-08)

Issuer signing keys live in KMS/HSM with per-issuer key permissions, tested
rotation, and compromise procedures. Production keys are never in source,
prompts, browser storage, config files, or images.

The cloud provider pick is deferred to G2. The provider must satisfy all
selection criteria before hosting real data:

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

- Canonicalization: JSON Canonicalization Scheme (RFC 8785) over the exact
  disclosed bytes; no re-serialization before hashing.
- Field normalization: per-schema version, recorded alongside the schema;
  normalization rules are versioned and immutable once approved.
- Provenance: every digest references its source revision, schema version,
  and normalization version; digests without a protected provenance
  reference are not authoritative inputs.
- Keyed indexes: HMAC-SHA256 with per-purpose keys, annual rotation with
  overlap verification; rotation never silently re-links identities.
- Correlation: pairwise, purpose-scoped subject identifiers only. No global
  subject key, no cross-purpose joins, no cross-RP correlation by Sovra.

## 6. Root, workload, and data-in-use boundary (OD-17)

Attested confidential processing is **required** before real data is
handled: key use and identity matching run inside attested TEEs (AWS Nitro
Enclaves, AMD SEV-SNP, Intel TDX, or provider equivalent selected under
section 4), with launch measurement verified against pinned values and
attestation evidence retained per operation batch.

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

- [ ] Independent security and privacy review of this record (required before SOV-004/SOV-005 start).
- [ ] Legal review of section 2 retention values in each operating jurisdiction.
- [ ] Issuer-authority sign-off on sections 1, 3, and 6.
- [ ] Record revision on any boundary, custody, provider, or retention change.
