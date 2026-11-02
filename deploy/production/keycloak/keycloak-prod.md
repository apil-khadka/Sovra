# Production Keycloak (PROD-004)

Optimized build over durable PostgreSQL, TLS everywhere, exact
hostnames, private administration. The versioned inputs are
[Dockerfile](./Dockerfile) (build),
[realm](./realm/sovra-realm.prod.json) (import), and the `keycloak`
service in [compose.yaml](../compose.yaml).

## Provisioning

1. Place the login-host TLS pair at `/run/sovra/tls/login.crt` and
   `login.key` (PEM, read-only mount, mode 0400). The hostname must
   match `SOVRA_KC_HOSTNAME`.
2. Set the env file (`/run/sovra/prod.env`, never committed):
   `SOVRA_VERSION`, `SOVRA_KC_DB_PASSWORD`, `SOVRA_KC_HOSTNAME`,
   one-time `SOVRA_KC_BOOTSTRAP_ADMIN` /
   `SOVRA_KC_BOOTSTRAP_PASSWORD` (32+ random chars each).
3. Replace every `example.com` placeholder in the realm file and in
   app origins with the approved hosts (see
   `docs/engineering/production-deployment.md`); the app entry gate
   enforces absolute `https://` origins at boot.
4. `docker compose -f deploy/production/compose.yaml up -d
   keycloak-db keycloak`. First boot imports the realm (no users, no
   client secret — the server generates the `sovra-bff` secret on
   import).
5. Read back the generated client secret and store it in the vault
   as `SOVRA_BFF_CLIENT_SECRET`:
   `kcadm.sh get clients/sovra-bff-uuid/client-secret` (via exec on
   the private network; never print it to shared logs).

## Bootstrap removal

6. Create the first real admin (temporary password + required
   actions `CONFIGURE_TOTP` and `UPDATE_PASSWORD`), log in as that
   admin, verify the bootstrap user is redundant, then DELETE the
   bootstrap user via the admin console or `kcadm.sh delete
   users/<bootstrap-id>`.
7. UNSET `SOVRA_KC_BOOTSTRAP_ADMIN` /
   `SOVRA_KC_BOOTSTRAP_PASSWORD` from the env file and restart
   Keycloak. Leaving them set recreates the bootstrap account on
   the next restart. Verify: `kcadm.sh get users -q username=<boot>`
   returns nothing after the restart.

## Identity lifecycle

- Provisioning: create the user with a random temporary password,
  set the `tenant_slug` attribute (must match an allowed tenant or
  login denies), assign exactly the groups the role map needs
  (`sovra-members`, `sovra-rp`, `sovra-ops`,
  `sovra-trust-admins`), and attach required actions
  `CONFIGURE_TOTP` (+ `UPDATE_PASSWORD` when the password was
  communicated). Privileged groups additionally require a WebAuthn
  credential: the app withholds privileged roles from sessions
  whose `amr` lacks `webauthn` (pinned by
  `BffLoginTests.privilegedRoleNeedsHardwareAmr`).
- Reauthentication: step-up is per-action in the app (holder
  unlock); Keycloak-side, `ssoSessionIdleTimeout` (30 min) and
  `ssoSessionMaxLifespan` (8 h) bound session age, and admin
  console access requires its own authentication.
- Revocation: disable the user, then revoke sessions
  (`kcadm.sh delete users/<id>/sessions`); the app's mid-session
  revocation check picks up membership revocation without waiting
  for token expiry.
- Recovery: no self-service reset (`resetPasswordAllowed: false`,
  no SMTP dependency). An admin sets a temporary password with
  `UPDATE_PASSWORD` + `CONFIGURE_TOTP` required actions and
  communicates it out-of-band; the user re-enrolls OTP at next
  login. The recovery itself is audited in Keycloak's admin events
  (enable `admin-events` retention per the retention schedule,
  PROD-010).

## Rotation

- Client secret: regenerate in the admin console, update the vault,
  rolling-restart `app-a`/`app-b` one at a time (each replica reads
  the secret at boot; mixed-secret rolling is safe because either
  secret authenticates until the old one is revoked — revoke last).
- Signing keys: add a new `ecdsa-generated` provider with higher
  priority, wait out `accessTokenLifespan` (5 min) plus clock skew,
  verify the app resolves the new `kid` from JWKS, then remove the
  old provider. Never rotate to an algorithm the realm does not
  pin (`ES256`).
- TLS pair: replace the files, restart Keycloak (single identity
  node; schedule in the maintenance window until clustered).

## Recovery

- Database: `keycloak-db` is a standard PostgreSQL volume
  (`sovra-prod-kc-pgdata`); back up with the same base+WAL
  procedure as the app database (PROD-013). Point-in-time restore
  replays both consistently; realm sessions are re-establishable
  from credentials, so RPO follows the backup cadence.
- Realm definition drift: the realm file is the source of truth.
  After any console change, export (`kc.sh export --realm sovra`)
  and reconcile the file, or revert the console change. Untracked
  console edits are the top identity outage cause — treat them as
  incidents.

## Staging exercises (before production traffic)

Run on staging, record evidence for the PROD-017 gate:

1. Login burst: 10x expected peak logins/min through the real
   browser flow; watch Keycloak CPU, `keycloak-db` connections,
   and app login latency (p99 budget in the capacity contract).
2. Identity-node loss: kill Keycloak mid-session; in-flight app
   sessions continue (server-side sessions), new logins fail
   closed with `auth_error`, recovery is automatic on restart.
3. Database recovery: restore `keycloak-db` from the latest backup
   to a scratch host, point a scratch Keycloak at it, log in.
4. Signing-key rotation: perform the rotation above on staging;
   confirm zero failed logins across the overlap.
5. Session invalidation: revoke a user mid-session; confirm the
   next privileged action denies.
6. Clustered cache: single-node is the day-one topology. Do NOT
   add a second Keycloak node without enabling JGroups JDBC_PING
   over `sovra-back` and re-running exercises 1–5 against the
   pair — split-brain sessions lock users out intermittently.
