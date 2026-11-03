# Demo acceptance scorecard and security test matrix

## Mandatory demonstrable checks

| Test | Trigger | Pass criterion |
| --- | --- | --- |
| T01 Signature | Modify signed payload | `INVALID_SIGNATURE`, no evidence accepted |
| T02 Key substitution | Point issuer to untrusted public key | `UNTRUSTED_ISSUER` / scope mismatch |
| T03 Revocation | Revoke credential and retry | `REVOKED`, never accepted |
| T04 Presentation retry (identical) | Resubmit the identical challenge-bound proof | HTTP 200 byte-identical stored response; exactly one decision row — the retry mints no new decision |
| T04b Presentation replay (altered) | Same nonce with changed content, or changed nonce/audience/holder without re-signing | Conflict/rejection; the stored decision stands and nothing is rewritten; the altered binding is rejected |
| T05 Wrong RP | Change verifier audience | `AUDIENCE_MISMATCH` |
| T06 Expiry | Present expired credential/session | `EXPIRED` |
| T07 Consent denial | Click refuse | No proof sent to RP |
| T08 AI fabricated schema | Submit candidate nonexistent claim | Guard rejection |
| T09 AI fabricated citation | Refer to absent section ID | Guard rejection |
| T10 Prompt injection | Add instructions to issuer `description` | No tool privilege change; guard intact |
| T11 Model unavailable | Disable eligible Meta endpoint | `MANUAL_REVIEW` or unavailable, no fake success |
| T12 Missing status | Simulate timeout | Configured conservative failure state |
| T13 Unknown third schema | Import new synthetic schema post-prompt freeze | No country-specific code change; report actual pass/fail |
| T14 Sensitive prompt | Generate model invocation | No passport, key, DOB or signed credential sent |
| T15 Fresh checkout | Clone public repo, follow README | Reproduces workflow with fake data |

Anti-replay contract (T04/T04b): the native verifier keeps an atomic
unique decision per `(tenant, request, nonce)`. An identical resubmission
replays the stored response byte-for-byte (a lost response is recoverable;
at most one fresh acceptance exists per nonce). The same nonce with
different content conflicts without rewriting the stored decision, and a
changed nonce, audience, or holder without a fresh signature fails
binding. The API emits no `REPLAY_DETECTED` code — do not claim one.
Pinned by `VerificationFlowTests`
(`replayAfterResponseLossReturnsByteIdenticalDecision`,
`twoInstancesRacingOneNonceCommitOneDecision`,
`concurrentSubmissionsCreateOneDecision`) and the frontend
`verification.spec` signed-POST retry (200, receipt equal to the first).
Insecure replays stay rejected wherever the profile requires it: altered
bindings never accept (see also T01/T02/T05).

## Judging evidence (from supplied participant guide)

Stage 1: fit an organizer theme and integrate eligible Meta tooling substantively. Stage 2: **Impact, Use of Meta AI Tooling, Technical Depth & Execution, Demo** — four equally weighted criteria. Earlier drafts with different weights are obsolete; use only this rubric.

## Recording and scoring evidence

Report a simple table in README: `N` fixtures run, `M` structurally valid model proposals, `K` grounded-citation-valid plans, `J` valid executed proofs, `0?` invalid accepted proofs, total cost and p50/p95 planning latency. Show raw fixture definitions and deterministic verifier test outputs. A good demo includes a grounded **refusal** for an impossible verification requirement.
