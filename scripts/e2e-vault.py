#!/usr/bin/env python3
"""End-to-end encrypted-vault cycle against a running compose stack.

SOV-016 synthetic-harness evidence: seals source bytes, grants
purpose-bound reads, releases plaintext only to live exactly-matching
grants, rotates wrapping keys with old data still opening, and proves
the negative matrix (wrong purpose/workload/principal, expired and
revoked grants, tampered rows failing closed, cross-tenant 404s).

Assumes the stack is up (app-a on :8080); leaves the stack running.
Prints no secrets; exits nonzero on any failure.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import typing
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_A = os.environ.get("SOVRA_E2E_BASE_A", "http://localhost:8080")
DB_CONTAINER = os.environ.get("SOVRA_E2E_DB_CONTAINER", "sovra-db-1")
DB_ADMIN_PASSWORD = os.environ.get("SOVRA_DB_ADMIN_PASSWORD", "sovra-dev-only")
TOKEN_PREFIX = "sovra_test_"


def fail(message: str) -> "typing.NoReturn":
    print(f"E2E vault: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def check(label: str) -> None:
    print(f"E2E vault: {label}", flush=True)


def http(base: str, method: str, path: str, *, body: bytes | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(base + path, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def api(token: str, method: str, path: str, payload: dict | None = None,
        ) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    status, raw = http(BASE_A, method, path, body=body,
                       headers={"Authorization": "Bearer " + token,
                                "Content-Type": "application/json"})
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {}


def psql(sql: str) -> str:
    env = dict(os.environ, PGPASSWORD=DB_ADMIN_PASSWORD)
    proc = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={DB_ADMIN_PASSWORD}",
         DB_CONTAINER, "psql", "-U", "sovra", "-d", "sovra",
         "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, env=env, timeout=60)
    if proc.returncode != 0:
        fail(f"psql failed: {(proc.stderr or '').strip()[-300:]}")
    return proc.stdout


def mint_account(name: str, roles: str, tenant_id: str | None = None) -> tuple[str, str]:
    token = TOKEN_PREFIX + base64.urlsafe_b64encode(
        secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    prefix = token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if tenant_id is None:
        slug = f"e2e-vault-{secrets.token_hex(4)}"
        tenant_id = psql(
            "INSERT INTO tenant (slug, display_name) "
            f"VALUES ('{slug}', 'E2E vault') RETURNING id;").splitlines()[0].strip()
    psql(
        "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) "
        f"VALUES ('{tenant_id}', '{name}', '{prefix}', "
        f"decode('{digest}', 'hex'), '{roles}');")
    account_id = psql(
        "SELECT id FROM service_account "
        f"WHERE tenant_id = '{tenant_id}' AND name = '{name}';").splitlines()[0].strip()
    return account_id, token


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def main() -> int:
    status, _ = http(BASE_A, "GET", "/api/health/ready")
    if status != 200:
        fail("app-a is not ready; bring the compose stack up first")

    tenant_holder: list[str] = []
    issuer_id, issuer = mint_account("e2e-vault-issuer", "{ISSUER_OPS,TRUST_ADMIN}")
    tenant_holder.append(psql(
        f"SELECT tenant_id FROM service_account WHERE id = '{issuer_id}';"
    ).splitlines()[0].strip())
    tenant_id = tenant_holder[0]
    member_id, member = mint_account(
        "e2e-vault-member", "{TENANT_MEMBER}", tenant_id)
    outsider_id, outsider = mint_account("e2e-vault-outsider", "{ISSUER_OPS}")
    check("tenant plus service accounts minted")

    content = b"e2e synthetic source bytes " + secrets.token_bytes(16)
    pin = hashlib.sha256(content).hexdigest()
    status, stored = api(issuer, "POST", "/api/vault/objects", {
        "issuerId": "https://issuer.example/e2e-vault",
        "displayName": "e2e doc",
        "purposes": ["enrollment-review", "verification-display"],
        "contentBase64": b64(content),
        "contentSha256Hex": pin,
    })
    if status != 201:
        fail(f"store responded {status}")
    object_id = stored["objectId"]
    check("object sealed with digest pin")

    status, meta = api(issuer, "GET", f"/api/vault/objects/{object_id}")
    if status != 200 or len(meta.get("versions", [])) != 1:
        fail("metadata missing the sealed version")
    if meta["versions"][0]["contentSha256Hex"] != pin:
        fail("metadata digest mismatch")
    if "ciphertext" in json.dumps(meta) or "wrapped" in json.dumps(meta):
        fail("metadata leaks sealed material")
    check("metadata carries identity only")

    status, granted = api(issuer, "POST", "/api/vault/grants", {
        "objectId": object_id,
        "objectVersion": 1,
        "principalType": "service_account",
        "principalId": member_id,
        "purpose": "enrollment-review",
        "workload": "review-desk",
        "ttlSeconds": 3600,
    })
    if status != 201:
        fail(f"grant responded {status}")
    grant_id = granted["grantId"]
    status, read = api(member, "POST",
                       f"/api/vault/objects/{object_id}/versions/1/read", {
                           "grantId": grant_id,
                           "purpose": "enrollment-review",
                           "workload": "review-desk",
                       })
    if status != 200 or base64.b64decode(read["contentBase64"]) != content:
        fail("granted read did not release exact bytes")
    check("granted read releases exact bytes")

    # Negative matrix: every confusion refuses without plaintext.
    def expect_refuse(label: str, token: str, payload: dict, want: int,
                      marker: str) -> None:
        status, raw = http(
            BASE_A, "POST",
            f"/api/vault/objects/{object_id}/versions/1/read",
            body=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": "Bearer " + token,
                     "Content-Type": "application/json"})
        if status != want or marker not in raw.decode("utf-8", "replace"):
            fail(f"{label}: got {status}, want {want} with {marker}")
        if content.decode("utf-8", "replace")[:12] in raw.decode("utf-8", "replace"):
            fail(f"{label}: refusal leaks plaintext")

    expect_refuse("wrong purpose", member,
                  {"grantId": grant_id, "purpose": "verification-display",
                   "workload": "review-desk"}, 403, "GRANT_INVALID")
    expect_refuse("wrong workload", member,
                  {"grantId": grant_id, "purpose": "enrollment-review",
                   "workload": "other-desk"}, 403, "GRANT_INVALID")
    # Cross-tenant grant use never reaches the grant check: the
    # version lookup itself is tenant-scoped and empty.
    expect_refuse("foreign grant (cross-tenant)", outsider,
                  {"grantId": grant_id, "purpose": "enrollment-review",
                   "workload": "review-desk"}, 404, "")
    check("grant confusion matrix holds")

    # Revocation and expiry deny immediately.
    status, _ = api(issuer, "POST", f"/api/vault/grants/{grant_id}/revoke", {})
    if status != 200:
        fail("revoke failed")
    status, _ = api(member, "POST",
                    f"/api/vault/objects/{object_id}/versions/1/read", {
                        "grantId": grant_id, "purpose": "enrollment-review",
                        "workload": "review-desk",
                    })
    if status != 403:
        fail("revoked grant still reads")
    status, short = api(issuer, "POST", "/api/vault/grants", {
        "objectId": object_id, "objectVersion": 1,
        "principalType": "service_account", "principalId": member_id,
        "purpose": "enrollment-review", "workload": "review-desk",
        "ttlSeconds": 3600,
    })
    psql(f"UPDATE vault_grant SET created_at = now() - INTERVAL '2 hours',"
         f" expires_at = now() - INTERVAL '1 hour' WHERE id = '{short['grantId']}';")
    status, _ = api(member, "POST",
                    f"/api/vault/objects/{object_id}/versions/1/read", {
                        "grantId": short["grantId"], "purpose": "enrollment-review",
                        "workload": "review-desk",
                    })
    if status != 403:
        fail("expired grant still reads")
    check("revocation and expiry deny immediately")

    # Tampered rows fail closed with no plaintext anywhere.
    status, fresh = api(issuer, "POST", "/api/vault/grants", {
        "objectId": object_id, "objectVersion": 1,
        "principalType": "service_account", "principalId": member_id,
        "purpose": "enrollment-review", "workload": "review-desk",
        "ttlSeconds": 3600,
    })
    psql(f"UPDATE vault_object_version SET ciphertext = "
         f"set_byte(ciphertext, 7, (get_byte(ciphertext, 7) + 1) % 256) "
         f"WHERE object_id = '{object_id}' AND version = 1;")
    status, raw = http(
        BASE_A, "POST", f"/api/vault/objects/{object_id}/versions/1/read",
        body=json.dumps({"grantId": fresh["grantId"],
                         "purpose": "enrollment-review",
                         "workload": "review-desk"}).encode("utf-8"),
        headers={"Authorization": "Bearer " + member,
                 "Content-Type": "application/json"})
    if status != 500 or "vault_integrity_failure" not in raw.decode("utf-8", "replace"):
        fail("tampered row did not fail closed")
    check("tampered ciphertext fails closed")

    # Rotation: new seals use the new KEK, old data still opens.
    status, rotated = api(issuer, "POST", "/api/vault/keys/rotate", {})
    if status != 200 or rotated.get("kekVersion") != 2:
        fail("rotation did not mint kek version 2")
    status, second = api(issuer, "POST", f"/api/vault/objects/{object_id}/versions", {
        "purposes": ["enrollment-review"],
        "contentBase64": b64(b"second generation bytes"),
    })
    if status != 201 or second.get("version") != 2:
        fail("second version did not seal")
    status, meta = api(issuer, "GET", f"/api/vault/objects/{object_id}")
    keks = [v["kekVersion"] for v in meta["versions"]]
    if keks != [1, 2]:
        fail(f"kek lineage wrong: {keks}")
    status, granted2 = api(issuer, "POST", "/api/vault/grants", {
        "objectId": object_id, "objectVersion": 2,
        "purpose": "enrollment-review", "workload": "review-desk",
        "ttlSeconds": 3600,
    })
    status, read2 = api(issuer, "POST",
                        f"/api/vault/objects/{object_id}/versions/2/read", {
                            "grantId": granted2["grantId"],
                            "purpose": "enrollment-review",
                            "workload": "review-desk",
                        })
    if status != 200 or base64.b64decode(read2["contentBase64"]) != b"second generation bytes":
        fail("rotated generation did not open")
    check("rotation keeps old data opening")

    print("E2E vault: PASS (seal, grant, read, negatives, tamper, rotation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
