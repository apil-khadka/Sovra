# Synthetic OpenID browser wallet

**Implemented:** 2026-10-30.
**Scope:** the G1 SD-JWT demo on the packaged application origin.
This browser client does not establish external wallet interoperability, conformance-suite certification or production holder custody/recovery.

## Journey

The OpenID demo wallet keeps its P-256 holder key and received credential in React memory.
Leaving the view, reloading or selecting Forget wallet discards that state.
It does not write credential/key material to local storage, session storage or cookies.
Server-side issuer/RP actors publish an offer and open a proof/presentation request; the holder performs these steps in the actual UI:

1. Log in before creating the holder key, then redeem a pre-authorized offer code.
   Key creation is disabled until the BFF session is available, preventing login navigation from discarding a newly created key.
   The browser signs the VCI proof with the token's nonce and issuer audience and receives the credential through the public VCI endpoint.
   It checks the issuer JWT signature, expiry, type, credential identifier and holder binding using the application's issuer JWKS.
2. Load and review the exact consent request, including RP, audience, purpose, claims, plan hash, challenge, expiry and holder.
   The consent request must identify the in-memory credential and holder.
   Approval or denial uses the existing BFF/CSRF-protected WebCrypto consent path.
3. Load the signed presentation request from a session identifier.
   The wallet verifies the request signature against the application's public verifier JWKS and pins issuer/audience, session state, nonce presence, expiry, response transport and the exact supported DCQL claim set.
   It refuses arbitrary origins, remote key discovery and unsupported claim/transport shapes.
4. Explicitly share the full synthetic credential with a freshly signed `kb+jwt`, encrypted using `ECDH-ES+A256KW` and `A256GCM`.
   Consent and the signed request are checked again before sharing.
   The response is submitted as form-encoded `direct_post.jwt` through the public VP endpoint.
   The verifier retains its server-side consent, policy, status, trust, replay and audit gates.
5. Retry the identical in-memory ciphertext to recover a lost/refused response or confirm the stored decision.
   Retrying does not generate another binding proof or nonce.

Only the fixed same-origin protocol endpoints are used.
The synthetic verifier key identifier and G1 single-claim query are explicit supported-profile constraints.
The native Verify presentation screen still uses the synthetic message binding; the OpenID demo wallet is the selected-profile path.

## Library choice

The browser uses exact-pinned `jose` 6.1.3 for JWT signing, local JWKS verification and JWE encryption.
The library's [first-party documentation](https://github.com/panva/jose) describes browser support and JWS/JWE APIs.
The [package registry metadata](https://registry.npmjs.org/jose) dates version 6.1.3 to 2025-12-02.
This avoids implementing JWE key agreement, key wrapping and serialization in application code.
Backend Nimbus and walt-id adapters are unchanged.
The production-dependency audit reported no known vulnerabilities during this implementation; that check does not replace release provenance or independent review.

## Browser verification

`frontend/e2e/wallet.spec.ts` drives the actual React wallet and Keycloak/BFF session.
Issuer/RP setup uses the disposable machine account; holder issuance proofs, consent signatures, request checks, key binding and encryption execute in the browser.
The cases cover VCI issuance to ACCEPTED, exact encrypted-response replay, denial without a share action, refusal of a tampered request signature, and recovery after corrupted ciphertext is refused.
The happy path also checks for horizontal overflow at a 390-pixel viewport and captures desktop/mobile screenshots for local inspection.
CI runs separate `synthetic` and `sdjwt-vc` profile jobs.
Profile-specific native/wallet cases are explicitly skipped in the other profile; shared login and consent cases run in both.
The selected-profile final local run passed 14 applicable cases, including login-before-key creation; four native-binding cases were explicitly skipped.
The synthetic-profile final run also passed 14 applicable cases, with the four selected-wallet cases explicitly skipped.
Both runs used the rebuilt container image, and frontend typecheck/build/lint plus repository and whitespace checks passed.
These are local results; the hosted CI matrix has not been observed in this session.

## Remaining qualification

The UI currently implements the pre-authorized issuance grant, not the authorization-code/PKCE wallet journey.
Offer codes are single-use; a failed or lost credential receipt currently requires a fresh offer rather than persistent issuance recovery.
The browser credential check validates the issuer signature and holder binding; full SD-JWT disclosure, source eligibility, status and trust validation remain server-enforced.
Full disclosure is intentional for the frozen one-claim G1 profile; broader selective disclosure is unqualified.
The synthetic verifier key bootstrap is application-local and does not support arbitrary external verifier discovery.
Real third-party wallet builds, external conformance suites, artifact provenance, independent review and actual public deployment remain open.
SOV-036/041 stay open against those remaining criteria.
