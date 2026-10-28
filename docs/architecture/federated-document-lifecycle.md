# Federated documents, encryption, and identity lifecycle

**Status:** proposed implementation design, 2026-10-27.
This expands the business [SRS](../requirements/software-requirements-specification.md); no document vault, OCR pipeline, or enrollment service is implemented by this document.
Production data remains subject to the SRS security and deployment gates.

## Federation and data locality

Sovra separates shared discovery/configuration from issuer-owned sensitive processing.
The federation publishes approved issuer metadata, schema/capability references, endpoints, credential signing public keys, and trust scope/version.
It does not receive source images, extracted personal fields, document digests, encryption keys, or a universal citizen identifier.
Organizational integration registration belongs to the shared control plane; subject and document registration belongs to the owning issuer node.

Each issuer controls its source database, private object vault, extraction/review workers, encryption authority, audit access, and permitted operators.
An issuer can operate its own node or use a separately approved regional managed deployment; that choice does not grant Sovra unrestricted source-data or key access.
Define locality across replicas, backups, temporary files, queues, thumbnails, browser delivery, support access, telemetry, and OCR/model providers, not just the main database.
Availability failover must respect the same location and access policy.
The RP receives only authorized consented evidence; the interoperability planner receives non-sensitive metadata and approved policy excerpts.

Google's [GFS](https://research.google/pubs/the-google-file-system/) supplies distributed-storage experience, not sovereign issuer governance.
Google's [location separation and BeyondCorp discussion](https://google.github.io/building-secure-and-reliable-systems/raw/ch08.html) distinguishes access trust from location controls.
[HDFS encryption](https://hadoop.apache.org/docs/r3.4.2/hadoop-project-dist/hadoop-hdfs/TransparentEncryption.html) separates file storage permissions from KMS use, but its documented default CTR mode does not supply application-level AEAD.
These are useful patterns rather than a reason to adopt Hadoop or assume a cluster enforces identity authority or residency.

## What an ID means

Create issuer-local opaque subject references using a secure random identifier format, with uniqueness enforced in the local store.
UUIDv4 under [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html) is a candidate, not a substitute for authorization or an asserted national identity.
Subject IDs, document IDs, enrollment IDs, credential IDs, and verification-session IDs are distinct.
Do not derive public IDs from a passport number, name, DOB, image digest, or a federation-wide person index.
Use separately governed RP-scoped/pairwise references where the selected presentation profile needs a subject reference.

A newly created subject record starts as pending enrollment.
It becomes eligible for particular issuer attestations only after the issuer's approved evidence validation and holder-binding process passes.
Generating an ID, successfully decrypting an image, reading OCR text, or clicking an admin approval button does not by itself establish the real-world identity.
[NIST identity-proofing guidance](https://pages.nist.gov/800-63-4/sp800-63a.html) distinguishes evidence validation, attribute validation, verification, and enrollment; referencing it here does not claim a NIST assurance level.

## Enrollment and information updates

1. An authorized issuer operator or scoped holder invitation creates an enrollment and pending local subject reference.
2. The issuer node authorizes a document upload and applies bounded file-type, signature, size, and decoder checks.
3. Incoming content is encrypted into local quarantine before durable persistence; scanners/parsers run with constrained local identities and egress.
4. Accepted images are processed by an approved local extraction pipeline; observations remain unverified candidate fields.
5. Schema, format, source, and holder-binding checks feed an authorized review with recorded assurance and policy provenance.
6. A permitted issuer workflow approves or rejects enrollment; signing becomes available only for approved claims and assurance under the selected credential profile.
7. New information creates new source/extraction/review revisions and reassesses affected attestations under an explicit refresh/revocation policy.

Never overwrite a signed credential or treat a new extraction as an automatic update to an issued claim.
Failed/ambiguous extraction requires a supported correction or review path rather than invented values.
A reviewer correction remains a new attributable revision and must not silently inherit approval.
No workflow claims government document authenticity unless an approved authoritative validation method actually establishes it.

## Image encryption and key control

Use an established envelope/AEAD implementation rather than a custom encryption protocol.
The candidate profile is AES-256-GCM with a fresh random data-encryption key (DEK) for every immutable object version.
A locally governed KMS/HSM key-encryption key (KEK) wraps each DEK; plaintext DEKs are not persisted.
Use distinct keys and permissions for document encryption and issuer signing.
[Google's envelope-encryption guidance](https://docs.cloud.google.com/kms/docs/envelope-encryption) explains this key hierarchy.

Store ciphertext with its wrapped DEK, KEK reference/version, crypto-format version, nonce, authentication tag, and authenticated immutable metadata.
Bind issuer, tenant, document ID, object version, artifact purpose, and envelope version using a deterministic AAD encoding.
AAD contains no personal values or secret material because AAD is authenticated rather than encrypted.
The decryptor derives expected context from trusted metadata and the authorized request, not attacker-selected envelope fields.
Protect the metadata/provenance reference itself; an untrusted hash beside untrusted ciphertext is insufficient.

The library/profile must document nonce uniqueness per key across concurrent workers, retries, and restarts.
Re-encryption or a content revision uses a fresh DEK/envelope rather than reusing a prior key/nonce pair.
Key wrapping and envelope metadata must remain bound to the correct artifact context.
Use reviewed whole-object authenticated handling within configured file limits; a future large-object streaming format requires explicit authentication, ordering, and truncation analysis.
[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf) is the GCM reference; the concrete Sovra envelope/profile still needs implementation and independent review.

## Secure decryption

Every decrypt/read operation requires current principal, issuer, subject/object, purpose, and role authorization before KMS use.
Original-image viewing additionally needs a short-lived, audited, resource/purpose/principal-bound access grant; the grant never replaces normal authentication.
OCR/scanner workloads use separately scoped workload permission rather than a dashboard user's unrestricted key access.
No SDK or browser receives the wrapped-key unwrap capability or a production DEK/KEK.

Invalid tags, wrong context, cross-issuer keys, expired/revoked grants, unavailable KMS, and denied unwrap fail without plaintext fallback.
No plaintext reaches a caller or extractor before authentication succeeds.
Bound memory, processing, temporary storage, and read concurrency; avoid plaintext logs, caches, crash artifacts, and persistent temporary files.
Authorized plaintext viewing is still a disclosure and cannot be recalled after delivery.
Separate storage administration, key lifecycle management, and cryptographic key use, including [KMS duties](https://docs.cloud.google.com/kms/docs/separation-of-duties).
An authorized-process compromise remains in the threat model; encryption at rest is not protection from every compromised decryptor.

## Hashes, extraction, and provenance

| Artifact | Integrity reference | Meaning and privacy rule |
| --- | --- | --- |
| Original uploaded bytes | SHA-256 of the exact accepted upload | Local integrity comparison against a protected reference; not evidence of document authenticity |
| Crop, thumbnail, redaction, or normalization | Separate digest and parent/version link | Never overwrite the original or reuse its digest for changed bytes |
| Extraction revision | Digest of versioned normalized/canonical structured content | Reproducibility/tamper evidence; not proof that OCR values are true |
| Issued credential | Selected issuer signature and profile checks | Attests only the issuer's approved claims/scope; not universal legal approval |

Record source artifact/version/digest, page/region references where supported, extractor/model/configuration version, schema/normalizer version, observation time, confidence, validation findings, and review history.
Keep observed text, normalized values, corrected values, and issuer-approved claims distinct.
Extracted personal values and review records require their own encrypted storage, key access, and retention controls; a hash does not replace that protection where an approved workflow still needs the value.
Confidence is a review signal, not automatic authority.
Use a reviewed canonicalization profile such as [JCS](https://www.rfc-editor.org/rfc/rfc8785.html) for supported JSON types, together with explicit business normalization and schema versions.
JCS is an informational RFC and does not define identity-field semantics or Unicode/business normalization by itself.

Raw image digests and extracted fields stay inside the authorized issuer boundary.
Do not publish hashes of names, DOBs, or identity numbers as anonymized values; [NISTIR 8053](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.8053.pdf) describes enumeration of guessable identifier hashes.
Public salts do not make a small input space unguessable.
If an approved issuer-local matching use case needs a keyed index, use a reviewed keyed-hash design with issuer/purpose key scope and rotation; equality leakage remains part of its privacy assessment.
There is no general public PII-hash lookup API.

## Retention and recovery

Policies must cover originals, derivatives, extraction revisions, queues, logs, grants, backups, and key versions.
Deleting a live object does not erase backups or already delivered plaintext.
Cryptographic erasure depends on removing every usable key copy and meeting the approved retention policy; do not promise instant universal erasure.
KEK rotation may rewrap DEKs without changing document bytes; changing an artifact or DEK produces a new authenticated envelope/version.
Recovery must preserve issuer scope, access removal, review provenance, and credential revocation/replay history.
Inventory independently restored keys and every token/grant/DEK/permission cache, with explicit expiry, deny propagation and active-job containment rules.
Disabling the original key does not disable independent restored copies or erase previously released plaintext and cached DEKs.
Reconcile or invalidate ambiguous security state and fence obsolete writers before recovered services reopen acceptance or document access.
Control-plane and data-plane outages require separate measured response procedures; all recovery paths retain approved locality.

## Privileged and processing isolation

Separate ingestion, extraction, review, signing, decryption, deployment, migration and audit identities with current object/purpose authorization.
Privileged enrollment, recovery and elevation require phishing-resistant authentication, bounded authority and independent approval where designated.
Hostile decoders run inside reviewed external runtime/OS isolation with finite resources and egress; Java Security Manager is not a sandbox option.
The approved host/root threat assessment determines whether attested confidential processing and constrained key release are necessary.
Source/builder/digest/configuration/runtime admission and semantic readiness apply to document workers as well as the API.

## Required verification

The [security plan](../engineering/security-validation-plan.md) must cover ciphertext/tag/context substitution, nonce safety, forbidden unwrap, grant replay, malicious files/decoders, extraction/review confusion, digest guessing/correlation, stale source revisions, locality egress, dashboards, SDKs, and recovery/deletion.
The [developer-platform contract](../engineering/developer-platform.md) describes authorized integrations and the proposed local-node API.
