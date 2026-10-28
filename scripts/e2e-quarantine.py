#!/usr/bin/env python3
"""End-to-end quarantine cycle against a running compose stack.

SOV-017 synthetic-harness evidence: hostile bytes admit into the
sealed queue (202), the isolated worker process scans them to CLEAN
or REJECTED verdicts, only CLEAN verdicts promote into re-sealed
vault objects, and the negative matrix holds (non-image bytes,
wrong roles, cross-tenant reads, double promote, direct reads of
quarantine seals, and worker-role containment at the database).

Assumes the stack is up (app-a on :8080 plus quarantine-worker);
leaves the stack running. Prints no secrets; exits nonzero on any
failure.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import time
import typing
import urllib.error
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_A = os.environ.get("SOVRA_E2E_BASE_A", "http://localhost:8080")
DB_CONTAINER = os.environ.get("SOVRA_E2E_DB_CONTAINER", "sovra-db-1")
DB_ADMIN_PASSWORD = os.environ.get("SOVRA_DB_ADMIN_PASSWORD", "sovra-dev-only")
WORKER_CONTAINER = os.environ.get(
    "SOVRA_E2E_WORKER_CONTAINER", "sovra-quarantine-worker-1")
WORKER_DB_PASSWORD = os.environ.get(
    "SOVRA_QUARANTINE_DB_PASSWORD", "sovra-dev-quarantine-only")
TOKEN_PREFIX = "sovra_test_"


def fail(message: str) -> "typing.NoReturn":
    print(f"E2E quarantine: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def check(label: str) -> None:
    print(f"E2E quarantine: {label}", flush=True)


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


def psql(sql: str, user: str = "sovra",
         password: str = DB_ADMIN_PASSWORD) -> subprocess.CompletedProcess:
    env = dict(os.environ, PGPASSWORD=password)
    return subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}",
         DB_CONTAINER, "psql", "-U", user, "-d", "sovra",
         "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, env=env, timeout=60)


def psql_ok(sql: str) -> str:
    proc = psql(sql)
    if proc.returncode != 0:
        fail(f"psql failed: {(proc.stderr or '').strip()[-300:]}")
    return proc.stdout


def mint_account(name: str, roles: str, tenant_id: str | None = None,
                 ) -> tuple[str, str]:
    token = TOKEN_PREFIX + base64.urlsafe_b64encode(
        secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    prefix = token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if tenant_id is None:
        slug = f"e2e-quar-{secrets.token_hex(4)}"
        tenant_id = psql_ok(
            "INSERT INTO tenant (slug, display_name) "
            f"VALUES ('{slug}', 'E2E quarantine') RETURNING id;").splitlines()[0].strip()
    psql_ok(
        "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) "
        f"VALUES ('{tenant_id}', '{name}', '{prefix}', "
        f"decode('{digest}', 'hex'), '{roles}');")
    account_id = psql_ok(
        "SELECT id FROM service_account "
        f"WHERE tenant_id = '{tenant_id}' AND name = '{name}';").splitlines()[0].strip()
    return account_id, token


def chunk(ctype: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + ctype + data
            + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))


def solid_png(width: int, height: int, rgb: bytes) -> bytes:
    raw = b"".join(b"\x00" + rgb * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def grant(token: str, object_id: str, purpose: str, workload: str) -> str:
    status, granted = api(token, "POST", "/api/vault/grants", {
        "objectId": object_id, "objectVersion": 1,
        "purpose": purpose, "workload": workload, "ttlSeconds": 3600,
    })
    if status != 201:
        fail(f"grant for {purpose} responded {status}")
    return granted["grantId"]


def admit(token: str, content: bytes, claimed: str | None) -> tuple[int, dict]:
    payload: dict = {
        "issuerId": "https://issuer.example/e2e-quarantine",
        "contentBase64": b64(content),
    }
    if claimed is not None:
        payload["claimedType"] = claimed
    return api(token, "POST", "/api/quarantine/admissions", payload)


def await_verdict(token: str, admission_id: str) -> dict:
    deadline = time.time() + 90
    while time.time() < deadline:
        status, view = api(
            token, "GET", f"/api/quarantine/admissions/{admission_id}")
        if status != 200:
            fail(f"verdict read responded {status}")
        if view.get("status") not in ("QUARANTINED", "SCANNING"):
            return view
        time.sleep(1)
    fail("worker did not scan the admission in 90s")
    raise AssertionError("unreachable")


def main() -> int:
    status, _ = http(BASE_A, "GET", "/api/health/ready")
    if status != 200:
        fail("app-a is not ready; bring the compose stack up first")

    # The verdicts below must come from the isolated process, not from
    # an in-app code path: prove the worker container is alive first.
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", WORKER_CONTAINER],
        cwd=ROOT, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0 or proc.stdout.strip() != "running":
        fail("quarantine-worker container is not running")
    check("isolated worker container is running")

    issuer_id, issuer = mint_account("e2e-quar-issuer", "{ISSUER_OPS}")
    tenant_id = psql_ok(
        f"SELECT tenant_id FROM service_account WHERE id = '{issuer_id}';"
    ).splitlines()[0].strip()
    _, auditor = mint_account(
        "e2e-quar-auditor", "{AUDIT_READER}", tenant_id)
    _, outsider = mint_account("e2e-quar-outsider", "{ISSUER_OPS}")
    check("tenant plus service accounts minted")

    content = solid_png(8, 8, bytes((9, 120, 200)))
    pin = hashlib.sha256(content).hexdigest()
    status, admitted = admit(issuer, content, "png")
    if status != 202 or admitted.get("status") != "QUARANTINED":
        fail(f"admit responded {status}")
    if admitted.get("actualType") != "png":
        fail("admit mis-sniffed the actual type")
    admission_id = admitted["admissionId"]
    quarantine_object = admitted["objectId"]
    check("hostile bytes admitted into the sealed queue")

    verdict = await_verdict(issuer, admission_id)
    if verdict.get("status") != "CLEAN":
        fail(f"worker verdict is {verdict.get('status')}: {verdict.get('verdict')}")
    if verdict.get("imageWidth") != 8 or verdict.get("imageHeight") != 8:
        fail("worker dimensions wrong")
    if verdict.get("contentSha256Hex") != pin:
        fail("worker digest mismatch")
    check("isolated worker scanned CLEAN with dimensions")

    status, seen = api(auditor, "GET",
                       f"/api/quarantine/admissions/{admission_id}")
    if status != 200 or seen.get("status") != "CLEAN":
        fail("auditor cannot read the verdict")
    if "contentBase64" in json.dumps(seen) or "ciphertext" in json.dumps(seen):
        fail("verdict read leaks bytes")
    status, _ = api(outsider, "GET",
                    f"/api/quarantine/admissions/{admission_id}")
    if status != 404:
        fail(f"cross-tenant verdict read responded {status}")
    check("verdicts are metadata-only and tenant-scoped")

    # Quarantine seals never open through the content endpoint.
    scan_grant = grant(issuer, quarantine_object, "quarantine-scan", "scan-desk")
    status, refused = api(issuer, "POST",
                          f"/api/vault/objects/{quarantine_object}/versions/1/read", {
                              "grantId": scan_grant,
                              "purpose": "quarantine-scan",
                              "workload": "scan-desk",
                          })
    if status != 403 or "GRANT_INVALID" not in json.dumps(refused):
        fail(f"quarantine seal read responded {status}")
    check("quarantine seal refuses the content endpoint")

    status, promoted = api(issuer, "POST",
                           f"/api/quarantine/admissions/{admission_id}/promote", {
                               "grantId": scan_grant,
                               "purpose": "quarantine-scan",
                               "workload": "scan-desk",
                               "purposes": ["enrollment-review"],
                               "displayName": "e2e promoted",
                           })
    if status != 201:
        fail(f"promote responded {status}")
    object_id = promoted["objectId"]
    read_grant = grant(issuer, object_id, "enrollment-review", "review-desk")
    status, read = api(issuer, "POST",
                       f"/api/vault/objects/{object_id}/versions/1/read", {
                           "grantId": read_grant,
                           "purpose": "enrollment-review",
                           "workload": "review-desk",
                       })
    if status != 200 or base64.b64decode(read["contentBase64"]) != content:
        fail("promoted object did not release exact bytes")
    status, done = api(issuer, "GET",
                       f"/api/quarantine/admissions/{admission_id}")
    if status != 200 or done.get("status") != "PROMOTED":
        fail("admission did not reach PROMOTED")
    status, _ = api(issuer, "POST",
                    f"/api/quarantine/admissions/{admission_id}/promote", {
                        "grantId": scan_grant,
                        "purpose": "quarantine-scan",
                        "workload": "scan-desk",
                        "purposes": ["enrollment-review"],
                    })
    if status != 409:
        fail(f"second promote responded {status}")
    check("CLEAN promotes once into a grant-bound vault object")

    # Hostile tail: a polyglot seals (magic is intact) but never promotes.
    polyglot = content + b"PK\x03\x04EXTRA-ZIP-PAYLOAD"
    status, bad = admit(issuer, polyglot, "png")
    if status != 202:
        fail(f"polyglot admit responded {status}")
    bad_id = bad["admissionId"]
    bad_verdict = await_verdict(issuer, bad_id)
    if bad_verdict.get("status") != "REJECTED":
        fail("polyglot was not rejected")
    if not str(bad_verdict.get("verdict", "")).startswith("trailing-data"):
        fail(f"polyglot reason wrong: {bad_verdict.get('verdict')}")
    status, _ = api(issuer, "POST",
                    f"/api/quarantine/admissions/{bad_id}/promote", {
                        "grantId": scan_grant,
                        "purpose": "quarantine-scan",
                        "workload": "scan-desk",
                        "purposes": ["enrollment-review"],
                    })
    if status != 409:
        fail(f"rejected promote responded {status}")
    check("polyglot seals, scans REJECTED, and never promotes")

    # Admission negatives: non-images and wrong roles stop at the desk.
    status, _ = admit(issuer, b"not an image at all", None)
    if status != 400:
        fail(f"non-image admit responded {status}")
    status, _ = admit(outsider, content, "png")
    if status != 202:
        fail("outsider admit into their own tenant failed")
    _, member = mint_account("e2e-quar-member", "{TENANT_MEMBER}", tenant_id)
    status, _ = admit(member, content, "png")
    if status != 403:
        fail(f"member admit responded {status}")
    status, _ = api(member, "POST",
                    f"/api/quarantine/admissions/{admission_id}/promote", {
                        "grantId": scan_grant,
                        "purpose": "quarantine-scan",
                        "workload": "scan-desk",
                    })
    if status != 403:
        fail(f"member promote responded {status}")
    check("admission negatives hold")

    # Worker containment at the database, as the worker role itself.
    proc = psql("SELECT * FROM service_account LIMIT 1;",
                user="sovra_quarantine", password=WORKER_DB_PASSWORD)
    if proc.returncode == 0 or "permission denied" not in (proc.stderr or ""):
        fail("worker role reads credentials")
    proc = psql("SELECT created_by FROM vault_object_version LIMIT 1;",
                user="sovra_quarantine", password=WORKER_DB_PASSWORD)
    if proc.returncode == 0 or "permission denied" not in (proc.stderr or ""):
        fail("worker role reads non-seal columns")
    proc = psql(f"UPDATE quarantine_admission SET status = 'CLEAN' "
                f"WHERE id = '{bad_id}';",
                user="sovra_quarantine", password=WORKER_DB_PASSWORD)
    if proc.returncode != 0 or "UPDATE 0" not in (proc.stdout or ""):
        fail("worker role touched a REJECTED row")
    kept = psql_ok(f"SELECT status FROM quarantine_admission WHERE id = '{bad_id}';")
    if kept.splitlines()[0].strip() != "REJECTED":
        fail("REJECTED verdict did not stand")
    check("worker role containment holds live")

    print("E2E quarantine: PASS (admit, worker scan, promote, negatives, containment)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
