# Developer portal and RP dashboard (SOV-022, SOV-025)

**Status:** implemented in the synthetic demo, 2026-10-30.
Contract [`0.16.0`](implemented-api.openapi.yaml).
This is the as-built companion to the
[developer platform proposal](developer-platform.md): the
proposal states the business contract, this document states
what runs today and how an integrator uses it.

## Where things live

One origin serves everything in the demo: the API, the BFF,
and the packaged SPA share the compose app origin
(`http://localhost:8080` by default). Browser desks make no
cross-origin calls; Keycloak keeps its own hostname and is
reached only through the OIDC redirect dance, never through
page JavaScript. Machine clients pin the API base URL:
HTTPS everywhere except loopback, enforced by both SDKs.

`GET /api/discovery` is the first document an integrator
reads. It is public, static, and carries no identity data:

- `profile` and `contractVersion` (`synthetic`, `0.16.0`)
- `auth`: `Bearer service-account` for machines, `BFF
  session` for browsers
- `sandbox`: name shape, fixed roles, lifetime, demo profiles
- `sdks`: the compatible Java and TypeScript versions
- `rp`: the outcome and credential read boundaries

## Sandbox quickstart

A tenant member onboards one sandbox app per integration
under test. Every sandbox credential is identical in shape
— name `sandbox-<app>`, role `RP_CLIENT`, 24-hour expiry —
and exists only on demo profiles (`synthetic`, `sdjwt-vc`).
Production refuses with `403 SANDBOX_DEMO_ONLY`.

Through the portal UI (`#/portal` as `demo-member`):

1. Load the portal and read the discovery card.
2. Name the app (`sandbox-my-app`) and create it.
3. Copy the token once; it never reads back.

Through the machine chain with a member token:

```sh
curl -s -X POST "$BASE/api/sandbox/accounts" \
  -H "Authorization: Bearer $MEMBER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"sandbox-my-app"}'
# 201 {id, name, roles:[RP_CLIENT], revoked:false,
#      expiresAt:+24h, createdAt, token}
```

The minted token is a working RP credential: it can open
proof requests, verify presentations it submits, and read
its own outcomes and metrics. It cannot mint further
credentials, read other apps' outcomes, or touch the RP
credential desk.

## API, auth, scopes, errors, limits

The machine chain carries `Authorization: Bearer
<service-account-token>`; the browser desks ride the BFF
session cookie with an `X-XSRF-TOKEN` echo on mutations.
Both chains authorize the same actions: transport differs,
authority checks are identical.

| Call | Needs | Sees |
| ---- | ----- | ---- |
| `POST /api/sandbox/accounts` | `TENANT_MEMBER` | one-time token, once |
| `GET /api/sandbox/accounts` | `TENANT_MEMBER` | tenant sandbox metadata |
| `GET /api/rp/apps` | `TENANT_MEMBER` | RP-subset apps only |
| `POST /api/rp/credentials/{id}/rotate` | `TENANT_MEMBER` | one-time token, once |
| `POST /api/rp/credentials/{id}/revoke` | `TENANT_MEMBER` | revoked view |
| `GET /api/rp/outcomes?limit=` | `TENANT_MEMBER`, `RP_CLIENT` | own submissions unless member |
| `GET /api/rp/metrics` | `TENANT_MEMBER`, `RP_CLIENT` | own counts unless member |

Errors stay mechanical: `400` for malformed shapes,
`401` for missing or dead credentials, `403` with a reason
code for role or profile denials, `404` for unknown ids —
including ids outside the RP subset, which 404 exactly like
unknown ones so the desk never confirms or denies issuer,
trust, auditor, or member accounts. `409` means a revoked
account was rotated: revoked stays revoked, create a new
one. Outcome lists clamp `limit` to 1..100 and default to
20; outcome rows carry ids, outcome, and reason only —
decision bytes never cross this path.

## SDK compatibility

Both SDKs pin the contract in code and fail closed on
shape drift. Version `0.16.0` of each SDK targets contract
`0.16.0`:

| SDK | Location | Runtime deps |
| --- | -------- | ------------ |
| Java | `sdk/java` (`dev.sovra:sovra-sdk:0.16.0`) | Jackson only |
| TypeScript | `sdk/typescript` (`@sovra/sdk`) | none |

The 0.16.0 contract adds portal and RP routes that
integrators reach after out-of-band member provisioning;
the SDKs keep their core machine-chain surface and the
[release record](../../sdk/RELEASE.md) carries the delta.
SDK coverage of the onboarding flow itself stays a
follow-up.

## RP dashboard guide (`#/rpdash`)

Tenant members open the dashboard to manage authorized
apps and review verification evidence:

- **Authorized apps** lists every RP credential in the
  tenant with its roles, expiry, and state. Rotate shows
  the replacement token once; the old token dies
  immediately. Revoke is terminal and audit-logged.
- **Usage metrics** counts decisions this tenant submitted
  (this credential's, for pure RP callers): total,
  accepted, rejected, unknown.
- **Recent outcomes** lists decision id, request id,
  declared relying party, outcome, reason, and time.
  No claim content appears here by construction.

Rotation drill, end to end: create `sandbox-drill` in the
portal, confirm the token reads `/api/rp/metrics`,
rotate it in the dashboard, confirm the old token now
gets `401` and the new one `200`, then revoke and confirm
the new one also gets `401`. The browser suite runs this
drill against the live stack on every portal change.

## Boundaries that hold

- Sandbox credentials cannot exist on production: the
  profile gate refuses before any insert.
- One relying party can never rotate or revoke a sibling
  app: the credential desk needs `TENANT_MEMBER`.
- Relying parties read only decisions their own
  credential submitted, keyed by the server-set submitter
  — never by the self-asserted `rp_id` label.
- The dashboard shows no source images, OCR text,
  person-search, or key material; it cannot reach the
  vault, quarantine, custody, or trust desks.
- Cross-tenant navigation resolves nothing: every read
  filters by the caller's tenant first.
