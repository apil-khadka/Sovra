# Sovra frontend

React, TypeScript and Vite provide synthetic demo, holder consent and verification screens.
The backend container packages the production bundle, so SPA, BFF session, authorization callback and logout share `http://localhost:8080` locally.
The Vite server on port 5173 is for asset development; use the packaged origin for login E2E.

```sh
pnpm install --frozen-lockfile
pnpm run typecheck # checks application, tooling and E2E project references
pnpm run build     # typechecks and builds the production bundle
pnpm run lint
pnpm run dev
```

Keep `pnpm-lock.yaml` pinned as the reproducible dependency record.

## Browser E2E

Playwright and Chromium specs live in `e2e/`.
From the repository root:

```sh
SOVRA_AI_LIVE_ENABLED=false SOVRA_AI_API_KEY='' SOVRA_AI_BASE_URL='' SOVRA_AI_MODEL='' docker compose up --build -d
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend run test:e2e
```

Use a disposable synthetic database: global setup creates a machine account and the tests create journey records.
The suite drives real Keycloak login, direct SPA landing, holder consent, signed native verification, tampering/wrong-holder rejection and replay.
Issuer/RP setup uses the disposable machine account; holder consent and verification proofs use WebCrypto in the page.

Overrides are `SOVRA_BROWSER_BASE` (default `http://localhost:8080`), `SOVRA_E2E_DB_CONTAINER` (default `sovra-db-1`) and `SOVRA_DB_ADMIN_PASSWORD`.
The current verifier UI implements the native synthetic binding.
The SD-JWT/OpenID selected-profile browser journey is still pending; setting `SOVRA_PROFILE=sdjwt-vc` does not add it.
The CI `browser-e2e` job explicitly uses synthetic fixture mode with live provider access disabled.
See [browser evidence](../docs/engineering/sov-041-browser-e2e.md) and the [continuation guide](../docs/engineering/continuation-guide.md).
