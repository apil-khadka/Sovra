#!/usr/bin/env python3
"""End-to-end issuance cycle against a local compose stack (G1 synthetic profile).

Boots `docker compose up --build -d`, mints a tenant plus service account,
issues a synthetic credential with holder proof-of-possession, replays the
idempotent request, verifies the artifact against the live JWKS, reads
metadata plus status, revokes, and asserts terminal REVOKED. Always tears
the stack down with `docker compose down -v`, even on failure.

Proof-message shape is read from IssuanceService.proofMessage /
IssuanceFixtures.proofOver, never guessed:
  sovra-issuance-proof/v1\\n<idempotencyKey>\\n<vct>\\n<thumbprint>\\nadultOver18=true
with the RFC 7638 P-256 thumbprint from LocalDevSigner.thumbprint, signed as
compact ES256 JWS (header {"alg":"ES256"}, raw R||S signature).

Requires: docker compose, psql inside the db container, and the python
`cryptography` package. Prints no secrets; exits nonzero on any failure.
"""

from __future__ import annotations

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

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
except ImportError:
    sys.exit(
        "ERROR: python package 'cryptography' is required "
        "(pip install cryptography); refusing to hand-roll ECDSA."
    )

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("SOVRA_E2E_BASE", "http://localhost:8080")
DB_CONTAINER = os.environ.get("SOVRA_E2E_DB_CONTAINER", "sovra-db-1")
DB_ADMIN_PASSWORD = os.environ.get("SOVRA_DB_ADMIN_PASSWORD", "sovra-dev-only")
HEALTH_DEADLINE_S = 180

ISSUER_ID = "https://sovra.example/issuers/synth-1"
VCT = "https://sovra.example/vct/adult-status/1"
PROOF_LABEL = "sovra-issuance-proof/v1"
TOKEN_PREFIX = "sovra_test_"


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kwargs)


def fail(message: str) -> "typing.NoReturn":
    print(f"E2E issuance: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def http(method: str, path: str, *, body: bytes | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(BASE + path, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_for_stack() -> None:
    deadline = time.monotonic() + HEALTH_DEADLINE_S
    healthy = jwks_ok = False
    while time.monotonic() < deadline:
        if not healthy:
            try:
                status, body = http("GET", "/api/health")
                healthy = status == 200 and b'"status":"UP"' in body
            except OSError:
                pass
        if healthy and not jwks_ok:
            try:
                status, _ = http("GET", "/api/issuance/jwks.json")
                jwks_ok = status == 200
            except OSError:
                pass
        if healthy and jwks_ok:
            return
        time.sleep(3)
    fail(f"stack not ready within {HEALTH_DEADLINE_S}s "
         f"(health_up={healthy}, jwks_200={jwks_ok})")


def psql(sql: str) -> str:
    base = ["docker", "exec", "-e", f"PGPASSWORD={DB_ADMIN_PASSWORD}",
            DB_CONTAINER, "psql", "-U", "sovra", "-d", "sovra",
            "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql]
    proc = run(base, timeout=60)
    if proc.returncode != 0 and "No such container" in (proc.stderr or ""):
        resolved = run(["docker", "compose", "ps", "-q", "db"], timeout=60)
        cid = (resolved.stdout or "").strip().splitlines()
        if cid:
            proc = run([*base[:2], base[3], cid[0], *base[5:]], timeout=60)
    if proc.returncode != 0:
        fail(f"psql failed: {(proc.stderr or proc.stdout or '').strip()[:300]}")
    return (proc.stdout or "").strip()


def mint_account() -> tuple[str, str]:
    token = TOKEN_PREFIX + b64u_encode(secrets.token_bytes(32))
    assert len(token) == len(TOKEN_PREFIX) + 43, "token body must be 43 urlsafe chars"
    prefix = token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    slug = f"e2e-{secrets.token_hex(4)}"
    tenant_id = psql(
        "INSERT INTO tenant (slug, display_name) "
        f"VALUES ('{slug}', 'E2E issuance') RETURNING id;").splitlines()[0].strip()
    if not tenant_id:
        fail("tenant insert returned no id")
    psql(
        "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) "
        f"VALUES ('{tenant_id}', 'e2e-issuer', '{prefix}', "
        f"decode('{digest}', 'hex'), '{{ISSUER_OPS,TENANT_MEMBER}}');")
    return tenant_id, token


def holder_key() -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    private = ec.generate_private_key(ec.SECP256R1())
    nums = private.public_key().public_numbers()
    return private, {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(nums.x.to_bytes(32, "big")),
        "y": b64u_encode(nums.y.to_bytes(32, "big")),
    }


def thumbprint(jwk: dict[str, str]) -> str:
    canonical = ('{"crv":"P-256","kty":"EC","x":"' + jwk["x"]
                 + '","y":"' + jwk["y"] + '"}')
    return b64u_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def proof_jws(private: ec.EllipticCurvePrivateKey, idempotency_key: str,
              vct: str, holder_thumbprint: str) -> str:
    message = (PROOF_LABEL + "\n" + idempotency_key + "\n" + vct + "\n"
               + holder_thumbprint + "\n" + "adultOver18=true")
    signing_input = (b64u_encode(b'{"alg":"ES256"}') + "."
                     + b64u_encode(message.encode("utf-8")))
    der = private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u_encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_artifact(artifact: str, jwks_body: bytes) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = artifact.split(".")
        header = json.loads(b64u_decode(header_b64))
        claims = json.loads(b64u_decode(payload_b64))
        raw_sig = b64u_decode(sig_b64)
        if header.get("alg") != "ES256" or len(raw_sig) != 64:
            fail("artifact is not compact ES256")
        jwks = json.loads(jwks_body)
        key = next((k for k in jwks.get("keys", [])
                    if k.get("kid") == header.get("kid")), None)
        if key is None or key.get("kty") != "EC" or key.get("crv") != "P-256":
            fail("no matching P-256 issuer key in live JWKS")
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(key["x"]), "big"),
            int.from_bytes(b64u_decode(key["y"]), "big"),
            ec.SECP256R1()).public_key()
        der = encode_dss_signature(
            int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big"))
        pub.verify(der, (header_b64 + "." + payload_b64).encode("ascii"),
                   ec.ECDSA(hashes.SHA256()))
        return claims
    except InvalidSignature:
        fail("artifact ES256 signature does not verify against live JWKS")
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        fail(f"artifact or JWKS is malformed: {exc}")
    raise AssertionError("unreachable")


def main() -> int:
    compose = run(["docker", "compose", "version"], timeout=30)
    if compose.returncode != 0:
        fail("docker compose is not available")
    print("E2E issuance: starting compose stack...", flush=True)
    up = run(["docker", "compose", "up", "--build", "-d"], timeout=900)
    if up.returncode != 0:
        tail = ((up.stderr or "") + (up.stdout or "")).strip()[-500:]
        fail(f"docker compose up --build -d failed: {tail}")
    try:
        wait_for_stack()
        print("E2E issuance: stack healthy (health UP, JWKS 200)", flush=True)

        _, token = mint_account()
        auth = {"Authorization": "Bearer " + token}
        print("E2E issuance: tenant plus service account minted", flush=True)

        private, jwk = holder_key()
        idem = "e2e-" + secrets.token_hex(16)
        proof = proof_jws(private, idem, VCT, thumbprint(jwk))
        expires = (datetime.now(timezone.utc).replace(microsecond=0)
                   + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        body = json.dumps({
            "issuerId": ISSUER_ID,
            "vct": VCT,
            "holderJwk": jwk,
            "holderProof": proof,
            "claims": {"adultOver18": True},
            "expiresAt": expires,
        }).encode("utf-8")

        headers = {**auth, "Idempotency-Key": idem,
                   "Content-Type": "application/json"}
        status, first = http("POST", "/api/issuance/credentials",
                             body=body, headers=headers)
        if status != 201:
            fail(f"issue returned {status}: {first[:300]!r}")
        status, second = http("POST", "/api/issuance/credentials",
                              body=body, headers=headers)
        if status != 201 or second != first:
            fail("idempotent replay was not byte-identical (status "
                 f"{status}, equal={second == first})")
        print("E2E issuance: 201 plus byte-identical replay", flush=True)

        response = json.loads(first)
        credential_id = response.get("credentialId")
        if not credential_id or not response.get("artifact"):
            fail("issue response lacks credentialId/artifact")
        _, jwks_body = http("GET", "/api/issuance/jwks.json")
        claims = verify_artifact(response["artifact"], jwks_body)
        if (claims.get("iss") != ISSUER_ID or claims.get("vct") != VCT
                or claims.get("jti") != credential_id
                or claims.get("synthetic") is not True):
            fail("artifact claims mismatch (iss/vct/jti/synthetic)")
        print("E2E issuance: artifact ES256 verifies against live JWKS",
              flush=True)

        status, meta_body = http("GET", f"/api/issuance/credentials/{credential_id}",
                                 headers=auth)
        status2, status_body = http(
            "GET", f"/api/issuance/credentials/{credential_id}/status", headers=auth)
        if status != 200 or status2 != 200:
            fail(f"metadata/status GET failed ({status}/{status2})")
        if (json.loads(meta_body).get("status") != "VALID"
                or json.loads(status_body).get("status") != "VALID"):
            fail("credential is not VALID before revocation")
        print("E2E issuance: metadata plus status read VALID", flush=True)

        status, revoke_body = http(
            "POST", f"/api/issuance/credentials/{credential_id}/revoke",
            headers=auth)
        if status != 200 or json.loads(revoke_body).get("status") != "REVOKED":
            fail(f"revoke failed ({status}): {revoke_body[:200]!r}")
        status, terminal_body = http(
            "GET", f"/api/issuance/credentials/{credential_id}/status", headers=auth)
        if status != 200 or json.loads(terminal_body).get("status") != "REVOKED":
            fail("revocation is not terminal")
        print("E2E issuance: revoked, terminal REVOKED", flush=True)
    finally:
        down = run(["docker", "compose", "down", "-v"], timeout=180)
        print(f"E2E issuance: stack torn down (down exit={down.returncode})",
              flush=True)

    print("E2E issuance: PASS (issue 201, replay identical, JWKS-verified, "
          "terminal REVOKED)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
