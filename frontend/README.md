# Sovra frontend (SOV-003 bootstrap)

React + TypeScript + Vite browser client. Current scope is a backend status
page only; consent, session, and dashboard screens arrive with their backlog
tasks (SOV-010, SOV-021 and later).

```sh
pnpm install
pnpm run build    # typecheck + production bundle (packaged into the backend image)
pnpm run dev      # :5173, proxies /api /oauth2 /login to :8080 for local iteration
pnpm run lint
pnpm run test:e2e # real-browser login/consent/verification against compose (needs the stack up)
```

The packaged demo serves this bundle from the backend origin
itself (`http://localhost:8080` via `docker compose up --build`):
SPA, BFF session, authorization callback, and logout share one
origin, and the `:5173` dev server is never part of the login
loop. See `docs/engineering/sov-041-same-origin-packaging.md`.

## Real-browser E2E (SOV-041)

Playwright + Chromium specs live in `e2e/` with shared setup in
`e2e/sovra.ts` and `playwright.config.ts` at this directory root.
One-time browser install:

```sh
pnpm exec playwright install chromium
```

Then, from the repository root with the compose stack up:

```sh
docker compose up --build -d
pnpm --dir frontend run test:e2e
```

The suite drives DOM/JS login through Keycloak, holder consent
review/approval/refusal, and verification through the packaged
`:8080` origin; issuer/RP setup calls use a disposable machine
account minted by global setup. Overrides: `SOVRA_BROWSER_BASE`
(default `http://localhost:8080`), `SOVRA_E2E_DB_CONTAINER`
(default `sovra-db-1`), `SOVRA_DB_ADMIN_PASSWORD`,
`SOVRA_PROFILE` (asserts the matching decision profile label).
CI runs the same command in the `browser-e2e` job against a
disposable stack. Scope and observed behavior are recorded in
`docs/engineering/sov-041-browser-e2e.md`.

Keep `pnpm-lock.yaml` pinned; it is the reproducible dependency record.

This project started from the Vite `react-ts` template, which provides a
minimal setup to get React working in Vite with HMR and some Oxlint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend enabling type-aware lint rules by installing `oxlint-tsgolint` and editing `.oxlintrc.json`:

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["react", "typescript", "oxc"],
  "options": {
    "typeAware": true
  },
  "rules": {
    "react/rules-of-hooks": "error",
    "react/only-export-components": ["warn", { "allowConstantExport": true }]
  }
}
```

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.
