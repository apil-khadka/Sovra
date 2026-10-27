# Implementation critical path (27 Oct–4 Nov 2026)

## Day-by-day

| Date (Nepal) | Target |
|---|---|
| Oct 27 | Freeze core story, select actual Meta model, API access/credits smoke test, repo and contracts, synthetic country fixture specs |
| Oct 28 | Issuer keys, trust metadata, credential issuance and verification tests |
| Oct 29 | Minimal wallet consent and full end-to-end cross-node flow; deployable baseline |
| Oct 30 | AI schema/policy tools and live structured plan proposal; validate against deterministic guard |
| Oct 31 | Unseen third schema evaluation, hallucinated mapping and unsupported policy citation failures |
| Nov 1 | Revocation, replay, audience/expiry and malicious document tests; fault injection |
| Nov 2 | Traceable UI, demo observability, privacy review, integration/regression tests |
| Nov 3 | Feature freeze, fresh checkout deployment, record <=3-minute working-product demo, repo readme |
| Nov 4 | Final verification and submission well before the 9 PM US Eastern deadline (Nov 5, 7:45 AM Nepal Standard Time) |

## Preferred development pattern

Use a modular TypeScript monorepo with shared schema definitions. AI coding agents may own parallel bounded workstreams (credential library integration, UI, schemas and tests, meta agent, DevOps), but service interfaces must be agreed upfront. A human performs independent security review. Merge small tested units frequently; run CI, typecheck, e2e and signature negative tests after every change. Do not accept generated code solely on generated tests.

## Stop rules

- If Meta integration cannot be made live: fix API access before expanding the product; model integration is eligibility-critical.
- If a fully standards-compliant wallet takes too long: use explicitly labelled signed JWT attestations with correct signature verification; don't pretend it implements SD-JWT selective disclosure.
- If automated unfamiliar-schema adaptation is weak: demonstrate a smaller grounded extraction/planning task with test evidence, rather than scripted magic.
- If country-node distribution delays core flow: use logical isolation with separate configs/databases on one Docker host and clearly label simulation.
- By Nov 3, no new product capability unless it resolves a demo-breaking failure.

## Deliverables

Public running repository using only hackathon-eligible new project code (subject to organizer rules), reproducible startup script, demo fixtures, architecture docs, working verification workflow, live Meta integration, concise experiment report, recorded video and submission links. Identify prior research or idea explicitly; never commit unapproved private documents.
