# Hackathon minimum viable product specification

This document defines the synthetic milestone only.
The [business SRS](../requirements/software-requirements-specification.md) governs the broader application requirements and production release gates.
Demo priorities do not waive its security or real-data requirements.
The [business implementation plan](implementation-plan.md) and [task backlog](implementation-backlog.md) govern delivery beyond this synthetic milestone.
The dated [hackathon schedule](hackathon-milestone-plan.md) remains a separate milestone reference.

## Actors

- Mock sovereign issuer administrator; synthetic holder; foreign relying-party operator; trust federation administrator; AI interoperability planner; deterministic authorization/verifier service.

## P0 user stories and acceptance criteria

| ID | Story | Acceptance |
|---|---|---|
| CRED-1 | Issuer signs a scoped credential | Known trusted issuer validates; altered bytes fail |
| FED-1 | Verifier discovers trusted issuer metadata | Trusted/untrusted issuer outcomes differ |
| WAL-1 | Holder sees and approves requested disclosure | Withheld consent results in no presentation |
| AI-1 | Meta model maps a natural-language requirement to an existing schema | Observed live model invocation; JSON passes runtime and policy validation |
| AI-2 | Planner supplies sourced compatibility reasoning | Policy citation identifiers resolve to actual source sections |
| VER-1 | Verifier validates presentation | Signature, status, audience, nonce and validity checks exercised |
| POL-1 | Prohibited request is blocked | AI-produced overly broad plan cannot bypass policy gate |
| E2E-1 | Nepal simulated issuer to Australia mock verifier | Complete happy path without accessing simulated issuer DB directly |
| TEST-1 | Security negative tests | Tampered, expired, revoked, replayed, wrong-audience rejected |

## P1 optional

- Unknown third jurisdiction schema discovery; agent observability console; multilingual explanation; performance measurement; signed age assertion without revealing DOB.

## P2 deferred

- Full official OpenID4VCI/VP interoperability; SD-JWT VC selective disclosure if tested end to end; real government integration; biometric proofing; production trust governance; Kubernetes; blockchain; distributed event bus; ZK implementation.

## Core conceptual contracts

- `IssuerMetadata`: issuer_id, jurisdiction, public_keys/key_ids, credential_types, schema_refs, status_endpoint, trust_status, assurance_metadata.
- `Credential`: id, issuer, subject pseudonym, type, scoped claims, issued_at, expires_at, status reference, signature.
- `VerificationIntent`: requesting_party, audience, desired_outcomes, policy_ref/version, purpose, disclosure_budget.
- `ProposedPlan`: desired_outcome, candidate_credential, requested_claims, policy_citations, reasons, unresolved_issues.
- `ProofRequest`: request_id, audience, nonce, exp, consent_summary, approved_plan_hash.
- `VerificationResult`: accepted/denied/manual_review, reason_codes, issuer_key_reference, privacy-safe trace correlation.

Define actual API types, tests and fixture JSON in code before developing services in parallel. Specify whether issuer and verifier endpoints use actual VC/SD-JWT formats or **demo signed JWT attestations**; never blur these terms.
