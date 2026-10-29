# Sovra frontend (SOV-003 bootstrap)

React + TypeScript + Vite browser client. Current scope is a backend status
page only; consent, session, and dashboard screens arrive with their backlog
tasks (SOV-010, SOV-021 and later).

```sh
pnpm install
pnpm run build    # typecheck + production bundle (packaged into the backend image)
pnpm run dev      # :5173, proxies /api /oauth2 /login to :8080 for local iteration
pnpm run lint
```

The packaged demo serves this bundle from the backend origin
itself (`http://localhost:8080` via `docker compose up --build`):
SPA, BFF session, authorization callback, and logout share one
origin, and the `:5173` dev server is never part of the login
loop. See `docs/engineering/sov-041-same-origin-packaging.md`.

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
