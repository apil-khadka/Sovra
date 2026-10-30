# SOV-021: demo SDK scope and release policy (OD-16)

**Version:** 0.1.
**Date:** 2026-10-30.
**Task:** [SOV-021](https://github.com/apil-khadka/Sovra/issues/26)
(tested Java and TypeScript SDKs).

This record freezes OD-16 for the synthetic demo: which APIs the
SDKs cover, how versions track the contract, and the client-side
safety rules. Registry publication and the customer developer
platform stay open (section 6).

## 1. Covered surface

Both SDKs cover the machine-chain integrator surface at
`docs/engineering/implemented-api.openapi.yaml`: health and
readiness, trust snapshot and the proposal lifecycle, issuance,
consent, verification, vault, quarantine, extraction,
enrollment, holder custody, service accounts, audit reads, and
alerts. BFF session endpoints are out of scope: SDKs are
server-side machine clients and never handle browser sessions.

Out of scope with rationale: OpenID4VCI/OpenID4VP protocol
endpoints (wallet-facing protocol flows with their own
conformance story, SOV-036) and plans/guard internals (planner
machinery, not an integrator surface). Telemetry stays
ops-internal for now.

## 2. Version policy

SDK versions equal the API contract version they target
(`0.13.0` at this writing). Additive-only changes within a
contract minor; any breaking wire change bumps the contract and
both SDKs together. Each SDK exposes its supported contract
version, and the release record pins the verified triple
(sdk-java, sdk-typescript, contract).

## 3. Client-side safety rules

- Base URLs must be HTTPS, except `http://localhost`,
  `http://127.0.0.1` (any port), and `http://<host>.svc` style
  demo origins rejected outright — anything else fails at
  construction. No automatic cross-region fallback exists: one
  client talks to one base URL.
- Tokens live in memory only and never appear in errors, logs,
  or diagnostics; typed errors carry status, code, and a
  sanitized message.
- Writes never retry automatically. Idempotent operations take
  caller idempotency keys (with a generator helper) so a retry
  replays the original response instead of duplicating work.
  Reads retry at most three times on connection failure or 503,
  with backoff, then surface the failure.
- Conditional reads accept ETags and report 304 as a miss, not
  an error. Pagination cursors pass through opaquely.

## 4. TypeScript package rules

The package is Node-only (`engines: node >= 22`) with zero
runtime dependencies. It is documented server-side-only: no
browser bundle may embed a service-account token, and the test
suite asserts error paths never echo tokens. Adding a browser
build is a recorded decision, not a default.

## 5. Verification

Each SDK ships contract tests against a live backend: typed
quickstarts per family, wrong-origin rejection, unauthorized
and forbidden mapping, idempotent retry byte-identity, ETag
304 handling, and token redaction. CI runs both suites against
the compose stack.

## 6. What stays open

Publication to Maven Central/npm (release approval, signing,
and provenance attestation), the customer developer platform
(SOV-022), wallet-protocol helper libraries, and independent
review (SOV-037).
