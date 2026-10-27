# Product vision, competitive claim, and scope

## Problem

Digital identity systems use incompatible data models, evidence requirements, schemas, trust anchors, and jurisdictional rules. Cross-border relying parties often demand excessive original identity documents because they cannot readily understand or trust locally issued evidence.

## Proposed solution

A federation of independently governed issuers, holder-controlled credentials, and a trust-metadata-only registry plus an AI-native **interoperability planner**. The planner discovers issuers and schemas, interprets *supplied* policy documents, and proposes evidence mappings with traceable source excerpts. A deterministic authorization gate validates every action; issuer signatures and revocation/status checks, not the model, establish evidence authenticity.

## Principle

**Centralize trust metadata; federate authority; minimize identity disclosure.**

## Distinguishing demonstration

Provide two mock jurisdiction configurations and one *previously unseen* third schema. The model should adapt by reading discovery metadata and policy specs, not by relying on hard-coded per-country branching. Show at least one correctly rejected incompatible or excessive request. Compare against a static mapping baseline.

## Non-goals and honesty

- No claims of actual state certification, sovereign accreditation or official Nepal/Australia deployment.
- No legal determination that a business completed KYC/AML obligations.
- No global citizen database, actual citizen records, facial recognition, production biometrics, blockchain, custom zero-knowledge protocols, or production residency guarantees.
- Separate databases/containers under one host **simulate jurisdictional separation** and do not prove physical data sovereignty.
- UI field hiding is not cryptographic selective disclosure. A dedicated signed age-over-threshold attestation can avoid exposing date of birth in a demo.

## Track framing

Use either 'Build for Your World' (practical cross-border identity interoperability) or 'Push the Frontier' (AI adapts to unfamiliar credential and policy environments), subject to the official organizer rules. A workflow must visibly use eligible Meta models for core logic, not merely a generic chatbot wrapping static verification.
