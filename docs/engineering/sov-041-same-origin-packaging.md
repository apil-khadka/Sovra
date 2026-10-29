# SOV-041 same-origin packaging decision (G1 synthetic)

Date: 2026-10-29. Status: implemented. This records the serving
decision that gap 2 of the [holder/browser
assessment](sov-041-holder-browser-assessment.md) left open. It does
not close SOV-041: real-browser DOM/JS evidence and the selected
protocol profile are still outstanding.

## Decision

Spring serves the built React bundle from each backend instance
(SOV-041). No separate web server and no same-origin gateway: the
container build compiles the SPA in a Node stage, copies
`frontend/dist` into `classpath:/static`, and every app instance
serves identical bytes from its own origin. Node/pnpm exist only in
the asset-build stage; the runtime image holds no Node toolchain.

## Origins

| Surface | Origin |
| --- | --- |
| Demo browser origin (SPA, BFF cookies, authorize, callback, logout) | `http://localhost:8080` (compose `app-a`) |
| Second instance (multi-instance API tests; serves its own SPA copy) | `http://localhost:8081` (compose `app-b`) |
| OIDC issuer (explicitly trusted, separate origin) | `http://sovra-keycloak:18080` (Keycloak) |
| Local frontend iteration only (never the login loop) | `http://localhost:5173` (Vite dev proxy) |

The browser demo loop is now: `docker compose up --build -d`,
open `http://localhost:8080`, log in, approve/verify, log out —
with no manual return from port 8080 to 5173. The
[continuation guide](continuation-guide.md) acceptance for step 2
is met at the HTTP level; browser-rendered proof still belongs to
step 3.

## Sessions

Backend sessions stay per-instance servlet sessions. No
shared/persistent session store and no affinity routing were
added: a BFF session created on `app-a` is not portable to
`app-b`, and the demo never claims otherwise. Multi-instance
suites keep addressing both instances directly for API behavior;
browser-visible session scope is exactly one instance origin.

## Redirect URIs

No change was needed. The Keycloak client already registers
exactly `http://localhost:8080/login/oauth2/code/sovra` and the
`:8081` twin, with matching post-logout URIs
(`keycloak/realm/sovra-realm.json`); those were already the
packaged origins, so no redirect/origin edit accompanied this
change.

## CORS, CSRF, and cookies

No CORS configuration exists and none was added: same-origin
delivery needs none, and no cross-origin browser caller is
supported. CSRF behavior is unchanged — the readable CSRF cookie
is minted on BFF reads and echoed on mutations. Session cookies
stay `Secure`/`HttpOnly`/`SameSite=Lax` without a `Domain`
attribute (`backend/src/main/resources/application.yaml`), which
is correct for a host-scoped same-origin loopback demo.

## Fallback boundary

`SpaServingConfig` serves exact files, falls back to `index.html`
for extensionless non-reserved paths, and 404s everything else;
`SpaRoutes` is the single boundary shared by the security matcher
and the resource fallback. Controllers keep dispatch precedence,
and `/api`, `/oauth2`, `/login`, `/error`, and `/actuator`
(including case variants) are never served static content:
unknown API paths still 401 anonymously, and SPA mutations still
require authentication.

## Local runs without the container

A plain `./mvnw spring-boot:run` has no bundle and 404s `/` while
the API is unaffected. To exercise the packaged path locally,
build the bundle and point Boot at it:

```sh
pnpm --dir frontend run build
SOVRA_DB_URL=jdbc:postgresql://localhost:5432/sovra \
SPRING_WEB_RESOURCES_STATIC_LOCATIONS=file:../frontend/dist/ \
  ./mvnw spring-boot:run
```

(Vite `pnpm dev` remains available for hot-reload frontend
iteration against either backend.)

## Evidence

- `SpaStaticServingTests`: entry HTML, nested history fallback,
  immutable hashed assets, controller precedence, anonymous 401s
  on API/auth surfaces, dotted-miss 404, authenticated mutations.
- `scripts/e2e-bff-login.py`: packaged-origin checks (entry HTML,
  history fallback, intact `/api/health`, anonymous 401) run ahead
  of the unchanged login/logout matrix.
- `docs/engineering/api-compatibility.md` section 1 records the
  browser origin alongside the API families.
