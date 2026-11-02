# Integrate an age check (RP quickstart)

Ship a relying party against the synthetic Sovra stack: your server
holds an RP token, the visitor's browser holds a holder key, Sovra
verifies. The fastest path is copying
[`demo/minimal/`](../../demo/minimal/server.mjs) — one page plus one
zero-dependency server — and reading this page for the rules.

The normative API contract is
[implemented-api.openapi.yaml](../engineering/implemented-api.openapi.yaml);
sandbox onboarding is
[developer-portal.md](../engineering/developer-portal.md). Nothing here
overrides them.

## Actors and trust shape

- **Your RP server** holds the sandbox RP token and calls Sovra. Browsers
  never see the token.
- **The visitor's browser** generates a P-256 holder key, keeps the
  private half in page memory, and signs issuance, consent, and binding
  messages. Your server only forwards signed bytes.
- **Sovra** issues the synthetic credential, records the holder's signed
  decision, and verifies the presentation against the live trust
  snapshot.

## The four calls, in order

1. **Setup** — mint a credential for the browser-generated holder key.
   `POST /api/issuance/credentials` with the issuer id, credential type,
   holder public JWK, holder-signed issuance proof, `{"adultOver18":
   true}`, and a short expiry. Needs the setup token and an
   `Idempotency-Key`.
2. **Request** — open a proof request. `POST /api/consent/requests`
   with your RP id, audience, purpose, the credential id, the claim set,
   a guard plan plus its SHA-256 plan hash, a fresh CSPRNG challenge,
   and a short expiry. Returns the request id; `GET` the same id for
   the review your UI renders verbatim.
3. **Decision** — submit the holder's signed choice. `POST
   /api/consent/requests/{id}/decision` with `approve` or `deny`, the
   holder public JWK, and the signed consent message. Deny means deny:
   no presentation exists and none can be created.
4. **Verify** — prove with a fresh challenge. `POST
   /api/verification/presentations` with the request id, a fresh nonce,
   your audience constant, the holder public JWK, and the signed
   binding message. Read the durable outcome back with `GET
   /api/verification/decisions/{id}`; feed your ops view from `GET
   /api/rp/outcomes` and `GET /api/rp/metrics`.

## Nonce and audience discipline

- Mint a fresh CSPRNG nonce per verification and never reuse one.
- Pin your audience as a server constant; never accept it from client
  input. The holder signs it, so a mismatch fails closed.
- Keep request ids as opaque UUIDs; validate the shape before
  forwarding to avoid path confusion.

## UX states your page must render

- A visible progress sequence (key → credential → request → decision →
  proof), never a bare "Working…".
- The consent screen from exact bound values: RP, purpose, claims,
  issuer, expiry — plus a plain translation of what you will and will
  not learn, shown before the buttons.
- Three outcomes, three treatments: ACCEPTED (proceed), REJECTED
  (hold, with the reason code), UNKNOWN (retry with a fresh nonce —
  never treat as a pass). Deny gets its own quiet screen: nothing was
  shared.
- A receipt (decision id, reason, snapshot version, profile) and a
  restart that mints a fresh holder key.

## Error and retry rules

- Replay the durable decision read on transport failure; never
  re-submit a verification for the same request id with the same
  nonce — mint a fresh one.
- Treat every 4xx from Sovra as your bug or an expired artefact:
  surface it, expire the attempt, and start a new request id.
- UNKNOWN is a retry signal, not a verdict. Deny is final.

## Claims and copy

Every screen carries the synthetic-demo banner; the consent screen
carries the not-legal-KYC/AML line. Say "eligibility evidence" and
"threshold proof", never "KYC-approved" or "identity verified". The
full mandatory/forbidden list is
[claims-and-limitations.md](../compliance/claims-and-limitations.md),
and the worked demo stories are
[kyc-demo-apps.md](kyc-demo-apps.md).
