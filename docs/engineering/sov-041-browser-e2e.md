# SOV-041 real-browser E2E evidence

**Updated:** 2026-10-30.
**Scope:** packaged native synthetic journey, not full selected-profile acceptance.
SOV-041 remains open for the complete SD-JWT/OpenID browser flow and its other acceptance requirements.

## Harness

Playwright Test is pinned exactly in `frontend/package.json`.
Chromium runs specs in `frontend/e2e/` against the packaged Spring origin.
The browser resolves `sovra-keycloak` to loopback through `--host-resolver-rules`, avoiding a host-file edit.
CI uses the `browser-e2e` job in `.github/workflows/app-checks.yml` with explicit synthetic profile and live-provider access disabled.
The CI stack is disposable and is removed with its volumes afterward.

```sh
SOVRA_AI_LIVE_ENABLED=false SOVRA_AI_API_KEY='' SOVRA_AI_BASE_URL='' SOVRA_AI_MODEL='' docker compose up --build -d
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend run test:e2e
```

Setup waits for semantic readiness and creates a disposable machine account for issuer/RP setup calls.
Holder keys are generated in the page and exported through the real clipboard control.
Consent and verification proofs are signed with WebCrypto in the page through the application UI.
Issuer-side setup signing uses Node crypto and is not a browser VCI issuance flow.

## Covered behavior

- Keycloak login asserts S256 PKCE, lands directly on the SPA root, shows the session roles, logs out of both the application and provider, and requires a fresh provider form afterward.
- Password-only privileged login withholds `TRUST_ADMIN`; wrong credentials and anonymous/machine-token BFF reads fail closed.
- Consent review displays the exact relying party, audience, purpose, claims, plan hash, challenge and holder binding before approval or denial.
- Denial produces no presentation; a wrong holder disables approval; a missing CSRF echo is rejected while the UI echo succeeds.
- A browser-signed native binding verifies to ACCEPTED and the stored decision is read back.
- Repeating the exact signed verification POST through the browser session returns the same decision.
- Wrong audience, a changed signature byte and a different holder key reject without acceptance.

## Login regression and correction

The previous suite navigated manually to `/` after the callback.
Removing that workaround reproduced a landing on `/api/bff/me?continue`, displaying raw JSON instead of the application.
Spring had cached the SPA's anonymous session probe as a saved request.
The BFF now uses `NullRequestCache`, so API calls cannot become login destinations.
Both the login regression and shared journey helper require direct landing at the SPA root.

## Limits

The current React verifier uses the native synthetic binding, not `kb+jwt` or encrypted OpenID4VP transport.
The consent presentation endpoint returns the synthetic consent artifact, not an SD-JWT holder-custody interface.
Backend protocol tests and independent JOSE fixtures exercise different boundaries and do not substitute for this missing browser flow.
Expiry, cross-instance races, restart recovery and the issuer/revocation matrix remain covered by backend and HTTP suites.
External wallet/conformance evidence remains open under [SOV-036](sov-036-protocol-assessment.md).

## Verification

The rebuilt local stack passed the original 11-test suite on 2026-10-30 after the login correction, with no manual navigation after the callback.
The expanded `pnpm --dir frontend run test:e2e` suite passed 13/13 on 2026-10-30, including signed-POST replay, signature tampering and wrong-holder rejection.
The two new rejection cases also passed six repeated executions after a local stack restart.
Earlier attempts included a local stack outage, browser timeouts and a view-transition race in the verification test helper.
The helper now waits for the verification heading before filling fields shared with the consent screen.
Failed attempts are not counted as passing evidence.
The local checks do not establish hosted CI or public-deployment results.
