# Data-flow inventory, trust boundaries and governance

## Separation by responsibility

| Domain | Can store | Cannot store or decide |
| --- | --- | --- |
| Synthetic country issuer | Source mock profiles, status, private signing key (dev only) | Another country's source database; final RP legal CDD decision |
| Wallet | Issued scoped signed credentials, holder key/proof | Issuer's authority key; unrequested third-party identifiers |
| Federation | Public key IDs, issuer scope, policy refs, accreditation simulation, status URI | Global user index, original citizen documents, private signing keys |
| AI agent service | Schema metadata, policy excerpts, pseudonymous intent, sanitized tool traces | Passport scans, real DOB, PII, private keys, raw credentials, unrestricted HTTP actions |
| Verification service | Consent-approved evidence, challenge cache, decision reason, key snapshots | Automatic bank-level `KYC_APPROVED` judgment |

The registry is **not** an implicit source of trust; its maintainers and trust-anchor configuration are assumed/pinned in the demo. A valid cryptographic signature establishes control of a key, **not** government authority, claim truth, issuance assurance or legal permission.

## Claim minimization rule

A credential such as `{ adultOver18: true }` must be signed as that narrow claim by the issuer. The wallet may choose this one instead of a more comprehensive identity credential. Deleting fields from a signed, complete JWT breaks the signature. This demonstrates scoped attestation selection, **not zero-knowledge proof or SD-JWT claim-level selective disclosure**.

## Verification challenge vs issuance nonce

A verifier-generated challenge (`nonce`) and audience are required for presentation replay resistance, ideally within a signed holder proof that binds the credential to the session. The issuer's OpenID4VCI `c_nonce` belongs to the **issuance proof**, and using it does not by itself protect later presentations. Storing `jti` alone is not equivalent to proof-holder-binding. Define, test and label the actual demo proof profile.

## Country residency nuance

Separate Docker containers and databases are **logical** isolation only. Residency also concerns backups, operational logs, model requests, telemetry and cross-border disclosures. Real deployments require local legal review, deployment region, procurement/data processor controls and approved egress pathways.

## Status, privacy and outage policy

A naive per-credential status endpoint can become a tracking oracle for issuers. A production system should investigate privacy-preserving status lists and cache freshness. Demo status API uses synthetic data and cannot claim privacy-preserving unlinkability. If a status source is unavailable, return unknown/error according to a documented risk policy; never silently treat unknown as valid.
