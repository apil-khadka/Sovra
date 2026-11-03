#!/usr/bin/env python3
"""Bootstrap demo tenants and service accounts for the dual-issuer topology.

Creates NEW demo tenants plus service accounts on EACH demo-issuer database
(db-a and db-b of compose.demo-issuers.yaml), with distinct maker/checker
TRUST_ADMIN identities per database and server-side RP/setup tokens:

  per DB:  tenant demo-issuers-<a|b>
           demo-issuers-maker    (TRUST_ADMIN, trust proposals)
           demo-issuers-checker  (TRUST_ADMIN, trust approve/activate)
           demo-issuers-setup    (TRUST_ADMIN, OPERATOR-HELD provisioning
                                  token: used once by this script's rp phase
                                  to mint runtime credentials. NEVER given
                                  to the runtime demo server — the demo's
                                  `setupToken` (InteropService) is the
                                  ISSUER_OPS issuance token below, and
                                  `rpToken` is the RP token.)
  per app: demo-issuers-rp       (RP_CLIENT, minted server-side through
                                  POST /api/auth/service-accounts with the
                                  setup token, 24h expiry)
           demo-issuers-issuer   (ISSUER_OPS + TENANT_MEMBER, minted the
                                  same server-side way; issuance requires
                                  ISSUER_OPS while consent/verify/plan/guard
                                  use RP_CLIENT — both share the node's demo
                                  tenant so issued rows stay visible)

Token format mirrors backend TokenHasher (sovra_test_ + base64url(32B));
hashes are stored with the same SHA-256 scheme the e2e scripts use.
Account inserts are the supported bootstrap pattern (same as
scripts/e2e-*.py); trust itself is NEVER seeded here — provision-trust.py
drives the real maker/checker HTTP flow.

Idempotency: deterministic names; a re-run revokes the previous same-name
row (terminal revoke, audit-friendly) and mints fresh tokens, because
tokens are shown once and cannot be recovered. Token files from a
previous run are overwritten.

Tokens are written to files only (0600, never stdout, never the repo):
  <tokens-dir>/a-maker.token  a-checker.token  a-setup.token
  <tokens-dir>/a-rp.token  a-issuer.token   (same set for b-*)
Default dir: /tmp/sovra-demo-issuers/tokens (mode 0700).

Phases: --phase db  (DB accounts; apps must be up past Flyway so the
                        tenant/service_account tables exist — health UP
                        is enough, full readiness is not required)
        --phase rp  (RP/issuer mint via HTTP; apps must be up and healthy)
        --phase all (default)

Bring-up order (true prerequisites): start the full stacks first so
app boot runs Flyway migrations, THEN run this script:

  docker compose -f compose.demo-issuers.yaml up -d --build
  python3 scripts/demo-issuers/bootstrap.py            # db + rp
  python3 scripts/demo-issuers/provision-trust.py
  python3 scripts/demo-issuers/qualify-runtime.py

--phase db refuses to run when the tables are missing and says so
(a fresh database has no migrations until an app boots against it).

Requires: demo DB containers up (docker exec psql) plus migrated
tables for db phase; app nodes up for rp phase. Prints no secrets;
exits nonzero on any failure.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import typing
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOKENS_DIR = Path("/tmp/sovra-demo-issuers/tokens")

NODES = {
    "a": {
        "url": os.environ.get("SOVRA_DEMO_A_URL", "http://127.0.0.1:8280"),
        "db_container": "sovra-demo-issuers-db-a",
        "admin_password_env": "SOVRA_DEMO_A_DB_ADMIN_PASSWORD",
        "admin_password_default": "sovra-demo-a-admin-dev-only",
        "tenant": "demo-issuers-a",
    },
    "b": {
        "url": os.environ.get("SOVRA_DEMO_B_URL", "http://127.0.0.1:8281"),
        "db_container": "sovra-demo-issuers-db-b",
        "admin_password_env": "SOVRA_DEMO_B_DB_ADMIN_PASSWORD",
        "admin_password_default": "sovra-demo-b-admin-dev-only",
        "tenant": "demo-issuers-b",
    },
}

DB_ACCOUNTS = (
    ("demo-issuers-maker", ("TRUST_ADMIN",)),
    ("demo-issuers-checker", ("TRUST_ADMIN",)),
    ("demo-issuers-setup", ("TRUST_ADMIN",)),
)
RP_ACCOUNTS = (
    ("demo-issuers-rp", ("RP_CLIENT",)),
    ("demo-issuers-issuer", ("ISSUER_OPS", "TENANT_MEMBER")),
)

TOKEN_PREFIX = "sovra_test_"


def fail(message: str) -> "typing.NoReturn":
    print(f"bootstrap: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kwargs)


def psql(node: str, sql: str) -> str:
    cfg = NODES[node]
    password = os.environ.get(
        cfg["admin_password_env"], cfg["admin_password_default"])
    proc = run([
        "docker", "exec", "-e", f"PGPASSWORD={password}",
        cfg["db_container"], "psql", "-U", "sovra", "-d", "sovra",
        "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql,
    ], timeout=60)
    if proc.returncode != 0:
        # Never echo the command: it carries PGPASSWORD in argv.
        detail = (proc.stderr or proc.stdout or "").strip()[:200]
        fail(f"psql on db-{node} failed: {detail}")
    return (proc.stdout or "").strip()


def http(node: str, method: str, path: str, *,
         body: bytes | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(
        NODES[node]["url"] + path, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def mint_token() -> tuple[str, str, str]:
    token = TOKEN_PREFIX + b64u_encode(secrets.token_bytes(32))
    assert len(token) == len(TOKEN_PREFIX) + 43
    prefix = token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, prefix, digest


def require_migrated_tables(node: str) -> None:
    """Fail fast with a helpful message when Flyway has not run yet."""
    out = psql(node,
               "SELECT to_regclass('tenant'), "
               "to_regclass('service_account');")
    if not out.strip() or "tenant" not in out or "service_account" not in out:
        fail(f"db-{node} has no tenant/service_account tables yet "
             f"(got {out.strip()!r}); start the app stacks first so "
             f"boot runs Flyway, then re-run: docker compose "
             f"-f compose.demo-issuers.yaml up -d --build")


def ensure_tenant(node: str) -> str:
    slug = NODES[node]["tenant"]
    psql(node,
         "INSERT INTO tenant (slug, display_name) "
         f"VALUES ('{slug}', 'Dual-issuer demo tenant ({node.upper()})') "
         "ON CONFLICT (slug) DO NOTHING;")
    tenant_id = psql(node,
                     f"SELECT id FROM tenant WHERE slug = '{slug}';"
                     ).splitlines()[0].strip()
    if not tenant_id:
        fail(f"tenant {slug} has no id on db-{node}")
    return tenant_id


def ensure_db_account(node: str, tenant_id: str, name: str,
                      roles: tuple[str, ...]) -> str:
    token, prefix, digest = mint_token()
    roles_literal = "{" + ",".join(roles) + "}"
    psql(node,
         "UPDATE service_account SET revoked = TRUE "
         f"WHERE tenant_id = '{tenant_id}' AND name = '{name}';")
    account_id = psql(node,
        "INSERT INTO service_account "
        "(tenant_id, name, token_prefix, token_hash, roles) "
        f"VALUES ('{tenant_id}', '{name}', '{prefix}', "
        f"decode('{digest}', 'hex'), '{roles_literal}') RETURNING id;"
    ).splitlines()[0].strip()
    if not account_id:
        fail(f"account insert returned no id ({node}/{name})")
    return token


def write_token(tokens_dir: Path, node: str, kind: str, token: str) -> Path:
    path = tokens_dir / f"{node}-{kind}.token"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(token + "\n")
    return path


def read_token(tokens_dir: Path, node: str, kind: str) -> str:
    path = tokens_dir / f"{node}-{kind}.token"
    if not path.exists():
        fail(f"missing token file {path} (run --phase db first)")
    return path.read_text().strip()


def phase_db(tokens_dir: Path) -> None:
    for node in ("a", "b"):
        require_migrated_tables(node)
        tenant_id = ensure_tenant(node)
        print(f"bootstrap: db-{node}: tenant "
              f"{NODES[node]['tenant']} ready", flush=True)
        for name, roles in DB_ACCOUNTS:
            token = ensure_db_account(node, tenant_id, name, roles)
            kind = name.rsplit("-", 1)[1]  # maker|checker|setup
            path = write_token(tokens_dir, node, kind, token)
            fingerprint = token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]
            print(f"bootstrap: db-{node}: {name} "
                  f"({','.join(roles)}) -> {path} "
                  f"[prefix {fingerprint}]", flush=True)


def wait_for_app(node: str, deadline_s: int = 120) -> None:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            status, body = http(node, "GET", "/api/health")
            if status == 200 and b'"status":"UP"' in body:
                return
        except OSError:
            pass
        time.sleep(3)
    fail(f"app node {node} ({NODES[node]['url']}) not UP within {deadline_s}s")


def phase_rp(tokens_dir: Path) -> None:
    expires = (datetime.now(timezone.utc).replace(microsecond=0)
               + timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    for node in ("a", "b"):
        wait_for_app(node)
        setup = read_token(tokens_dir, node, "setup")
        auth = {"Authorization": "Bearer " + setup}
        status, body = http(node, "GET", "/api/auth/service-accounts",
                            headers=auth)
        if status != 200:
            fail(f"setup token rejected on node {node} "
                 f"(HTTP {status}); re-run --phase db")
        existing = {item["name"]: item for item in json.loads(body)}
        for name, roles in RP_ACCOUNTS:
            stale = existing.get(name)
            if stale is not None and not stale.get("revoked"):
                status, _ = http(
                    node, "POST",
                    f"/api/auth/service-accounts/{stale['id']}/revoke",
                    headers=auth)
                if status != 200:
                    fail(f"could not revoke stale {name} "
                         f"on node {node} (HTTP {status})")
            payload = json.dumps({
                "name": name,
                "roles": list(roles),
                "expiresAt": expires,
            }).encode("utf-8")
            status, body = http(node, "POST", "/api/auth/service-accounts",
                                body=payload,
                                headers={**auth,
                                         "Content-Type": "application/json"})
            if status != 201:
                fail(f"server-side mint of {name} on node {node} "
                     f"returned {status}: {body[:200]!r}")
            created = json.loads(body)
            if not created.get("token"):
                fail(f"mint of {name} on node {node} returned "
                     f"no one-time token")
            kind = "rp" if name.endswith("-rp") else "issuer"
            path = write_token(tokens_dir, node, kind, created["token"])
            print(f"bootstrap: node-{node}: {name} ({','.join(roles)}, "
                  f"24h) -> {path}", flush=True)


def self_test() -> int:
    """No-network regression coverage for the offline gates."""
    failures = []

    def check(name: str, ok: bool) -> None:
        print(f"bootstrap --self-test: [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    token, prefix, digest = mint_token()
    check("token prefix literal", token.startswith(TOKEN_PREFIX))
    check("token body length 43", len(token) == len(TOKEN_PREFIX) + 43)
    import re
    body = token[len(TOKEN_PREFIX):]
    check("token body urlsafe alphabet",
          re.fullmatch(r"[A-Za-z0-9_-]{43}", body) is not None)
    check("prefix is first 8 of body", prefix == body[:8])
    check("digest is sha256 hex of token",
          digest == hashlib.sha256(token.encode("utf-8")).hexdigest()
          and len(digest) == 64)
    # Distinct mints must differ (CSPRNG, no fixed demo token).
    check("consecutive mints differ", mint_token()[0] != token)
    # Role literals must stay within the backend's closed Role set.
    known = {"AUDIT_READER", "ISSUER_OPS", "RP_CLIENT", "TENANT_MEMBER",
             "TRUST_ADMIN"}
    for name, roles in (*DB_ACCOUNTS, *RP_ACCOUNTS):
        check(f"roles known for {name}", set(roles) <= known)
    # Runtime mint names map 1:1 to token file kinds (no admin token
    # is ever written by the rp phase).
    kinds = {"rp" if n.endswith("-rp") else "issuer" for n, _ in RP_ACCOUNTS}
    check("rp-phase kinds are runtime-only", kinds == {"rp", "issuer"})
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap demo-issuer tenants and service accounts.")
    parser.add_argument("--phase", choices=("db", "rp", "all"), default="all",
                        help="db: container-local accounts (needs migrated "
                             "tables); rp: HTTP runtime mint; all: both "
                             "(default)")
    parser.add_argument("--tokens-dir", default=str(DEFAULT_TOKENS_DIR),
                        help="token output dir (0700, outside the repo)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline gate checks; touch nothing")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    tokens_dir = Path(args.tokens_dir)
    tokens_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(tokens_dir, 0o700)
    if args.phase in ("db", "all"):
        phase_db(tokens_dir)
    if args.phase in ("rp", "all"):
        phase_rp(tokens_dir)
    print("bootstrap: PASS (tokens in files only; nothing printed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
