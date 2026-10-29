#!/usr/bin/env python3
"""End-to-end consent-to-verification cycle against a local compose stack.

SOV-041 synthetic-harness evidence (NOT full-profile interop evidence):
drives issue, consent-bound proof request, holder decision, presentation,
and verification over HTTP against real PostgreSQL plus two backend
instances; proves byte-identical cross-instance replay, durable
single-acceptance under concurrency, kill/restart and DB-restart recovery,
and the negative matrix (tampered proof, wrong audience, malformed nonce,
unapproved/denied consent, conflicting content, revoked credential,
cross-tenant reads). Always tears the stack down, even on failure.

Canonical shapes are read from server code, never guessed:
  consent: ConsentService.consentMessage / ConsentFixtures.consentMessage
  binding: VerificationService.presentationMessage (synthetic profile) or
    RFC 9901 section 8 KeyBinding JWT over the stored artifact bytes
    (sdjwt-vc profile, via KeyBindingVerifier)
  plan hash: PlanGuard.canonicalHash (sovra-plan/v1, trailing newline)
  thumbprint: RFC 7638 P-256 (LocalDevSigner.thumbprint)
All proofs are compact ES256 JWS (raw R||S).

Requires: docker compose, psql inside the db container, and the python
`cryptography` package. Prints no secrets; exits nonzero on any failure.
"""

from __future__ import annotations

import base64
import concurrent.futures
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
BASE_A = os.environ.get("SOVRA_E2E_BASE_A", "http://localhost:8080")
BASE_B = os.environ.get("SOVRA_E2E_BASE_B", "http://localhost:8081")
DB_CONTAINER = os.environ.get("SOVRA_E2E_DB_CONTAINER", "sovra-db-1")
DB_ADMIN_PASSWORD = os.environ.get("SOVRA_DB_ADMIN_PASSWORD", "sovra-dev-only")
HEALTH_DEADLINE_S = 180
RESTART_DEADLINE_S = 120

ISSUER_ID = "https://sovra.example/issuers/synth-1"
VCT = "https://sovra.example/vct/adult-status/1"
RP_ID = "https://rp.example/synth-shop"
AUDIENCE = "https://rp.example/synth-shop/callback"
ACTIVE_PROFILE = os.environ.get("SOVRA_PROFILE", "synthetic")
EXPECTED_DECISION_PROFILE = {
    "synthetic": "sovra-g1-synthetic/0.2",
    "sdjwt-vc": "sovra-g1-sdjwt-vc/0.2",
}[ACTIVE_PROFILE]
PURPOSE = "synthetic age check at checkout"
POLICY_ID = "sovra-synthetic-policy/age-check"
POLICY_VERSION = "1"
SECTION_ID = "age_eligibility"
TOKEN_PREFIX = "sovra_test_"


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kwargs)


def fail(message: str) -> "typing.NoReturn":
    print(f"E2E verification: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def http(base: str, method: str, path: str, *, body: bytes | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(base + path, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict((exc.headers or {}).items())


def wait_for_instance(base: str, deadline_s: int, what: str) -> None:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            status, body, _ = http(base, "GET", "/api/health")
            if status == 200 and b'"status":"UP"' in body:
                return
        except OSError:
            pass
        time.sleep(3)
    fail(f"{what} not UP within {deadline_s}s ({base})")


def wait_for_ready(base: str, deadline_s: int, what: str) -> None:
    # Readiness is DB-backed: after a database restart the app process
    # stays UP while its pool still holds dead connections, so liveness
    # alone would green-light requests the pool cannot serve yet.
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            status, body, _ = http(base, "GET", "/api/health/ready")
            if status == 200 and b'"status":"READY"' in body:
                return
        except OSError:
            pass
        time.sleep(3)
    fail(f"{what} not READY within {deadline_s}s ({base})")


def compose_container(service: str) -> str:
    proc = run(["docker", "compose", "ps", "-q", service], timeout=60)
    cids = (proc.stdout or "").strip().splitlines()
    if not cids:
        fail(f"no container id for compose service {service}")
    return cids[0].strip()


def psql(sql: str) -> str:
    base = ["docker", "exec", "-e", f"PGPASSWORD={DB_ADMIN_PASSWORD}",
            DB_CONTAINER, "psql", "-U", "sovra", "-d", "sovra",
            "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql]
    proc = run(base, timeout=60)
    if proc.returncode != 0 and "No such container" in (proc.stderr or ""):
        cid = compose_container("db")
        proc = run([*base[:2], base[3], cid, *base[5:]], timeout=60)
    if proc.returncode != 0:
        fail(f"psql failed: {(proc.stderr or proc.stdout or '').strip()[:300]}")
    return (proc.stdout or "").strip()


def mint_account(name: str, roles: str) -> tuple[str, str]:
    token = TOKEN_PREFIX + b64u_encode(secrets.token_bytes(32))
    assert len(token) == len(TOKEN_PREFIX) + 43, "token body must be 43 urlsafe chars"
    prefix = token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    slug = f"e2e-{secrets.token_hex(4)}"
    tenant_id = psql(
        "INSERT INTO tenant (slug, display_name) "
        f"VALUES ('{slug}', 'E2E verification') RETURNING id;").splitlines()[0].strip()
    if not tenant_id:
        fail("tenant insert returned no id")
    psql(
        "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) "
        f"VALUES ('{tenant_id}', '{name}', '{prefix}', "
        f"decode('{digest}', 'hex'), '{roles}');")
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


def sign_compact(private: ec.EllipticCurvePrivateKey, message: str) -> str:
    return sign_compact_with_header(private, '{"alg":"ES256"}', message)


def sign_compact_with_header(private: ec.EllipticCurvePrivateKey,
                             header: str, payload: str) -> str:
    signing_input = (b64u_encode(header.encode("utf-8")) + "."
                     + b64u_encode(payload.encode("utf-8")))
    der = private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u_encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def key_binding(private: ec.EllipticCurvePrivateKey, audience: str,
                nonce: str, artifact: str) -> str:
    # RFC 9901 section 8 KeyBinding JWT: sd_hash binds the exact
    # presented bytes (here the full-disclosure stored artifact).
    sd_hash = b64u_encode(hashlib.sha256(artifact.encode("ascii")).digest())
    payload = json.dumps({
        "aud": audience,
        "nonce": nonce,
        "sd_hash": sd_hash,
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }, separators=(",", ":"))
    return sign_compact_with_header(
        private, '{"alg":"ES256","typ":"kb+jwt"}', payload)


def stored_artifact(credential_id: str) -> str:
    row = psql("SELECT artifact FROM credential_artifact "
               f"WHERE id = '{credential_id}';").splitlines()
    if not row or not row[0]:
        fail("stored artifact missing for issued credential")
    return row[0].strip()


def verify_compact(compact: str, jwk: dict[str, str]) -> str:
    try:
        header_b64, payload_b64, sig_b64 = compact.split(".")
        header = json.loads(b64u_decode(header_b64))
        payload = b64u_decode(payload_b64).decode("utf-8")
        raw_sig = b64u_decode(sig_b64)
        if header.get("alg") != "ES256" or len(raw_sig) != 64:
            fail("JWS is not compact ES256")
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(jwk["x"]), "big"),
            int.from_bytes(b64u_decode(jwk["y"]), "big"),
            ec.SECP256R1()).public_key()
        der = encode_dss_signature(
            int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big"))
        pub.verify(der, (header_b64 + "." + payload_b64).encode("ascii"),
                   ec.ECDSA(hashes.SHA256()))
        return payload
    except InvalidSignature:
        fail("JWS signature does not verify against holder key")
    except (ValueError, KeyError, json.JSONDecodeError,
            UnicodeDecodeError) as exc:
        fail(f"JWS is malformed: {exc}")
    raise AssertionError("unreachable")


def plan_hash(plan_id: str) -> str:
    canonical = ("\n".join([
        "sovra-plan/v1",
        plan_id,
        "age_over_18",
        ISSUER_ID,
        VCT,
        "adultOver18",
        f"{POLICY_ID}#{SECTION_ID}",
        POLICY_ID,
        POLICY_VERSION,
        "CANDIDATE_ONLY",
        "",
    ]))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def plan_wire(plan_id: str) -> dict:
    return {
        "plan_id": plan_id,
        "requested_outcome": "age_over_18",
        "candidate_issuer_id": ISSUER_ID,
        "credential_type": VCT,
        "claim_paths": ["adultOver18"],
        "evidence": [{"document_id": POLICY_ID, "section_id": SECTION_ID}],
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "recommendation": "CANDIDATE_ONLY",
    }


def issue_credential(auth: dict[str, str], jwk: dict, private, thumb: str) -> str:
    idem = "e2e-v-" + secrets.token_hex(16)
    message = ("sovra-issuance-proof/v1\n" + idem + "\n" + VCT + "\n"
               + thumb + "\nadultOver18=true")
    expires = (datetime.now(timezone.utc).replace(microsecond=0)
               + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    body = json.dumps({
        "issuerId": ISSUER_ID, "vct": VCT, "holderJwk": jwk,
        "holderProof": sign_compact(private, message),
        "claims": {"adultOver18": True}, "expiresAt": expires,
    }).encode("utf-8")
    status, raw, _ = http(BASE_A, "POST", "/api/issuance/credentials", body=body,
                          headers={**auth, "Idempotency-Key": idem,
                                   "Content-Type": "application/json"})
    if status != 201:
        fail(f"issue returned {status}: {raw[:300]!r}")
    credential_id = json.loads(raw).get("credentialId")
    if not credential_id:
        fail("issue response lacks credentialId")
    return credential_id


def create_request(auth: dict[str, str], credential_id: str) -> dict:
    plan_id = "pln_e2e_" + secrets.token_hex(6)
    challenge = b64u_encode(secrets.token_bytes(24))
    expires = (datetime.now(timezone.utc).replace(microsecond=0)
               + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    body = json.dumps({
        "rpId": RP_ID, "audience": AUDIENCE, "purpose": PURPOSE,
        "credentialId": credential_id, "claims": {"adultOver18": True},
        "plan": plan_wire(plan_id), "policyId": POLICY_ID,
        "policyVersion": POLICY_VERSION, "planHash": plan_hash(plan_id),
        "challenge": challenge, "expiresAt": expires,
    }).encode("utf-8")
    status, raw, _ = http(BASE_B, "POST", "/api/consent/requests", body=body,
                          headers={**auth, "Content-Type": "application/json"})
    if status != 201:
        fail(f"consent create returned {status}: {raw[:300]!r}")
    return json.loads(raw)


def consent_message(review: dict, decision: str) -> str:
    return "\n".join([
        "sovra-consent/v1",
        review["requestId"],
        decision,
        review["rpId"],
        review["audience"],
        review["purpose"],
        "adultOver18=true",
        review["planHash"],
        review["challenge"],
        review["expiresAt"],
        review["holderThumbprint"],
    ])


def decide(auth: dict[str, str], request_id: str, decision: str,
           jwk: dict, proof: str) -> dict:
    body = json.dumps({
        "decision": decision, "holderJwk": jwk, "consentProof": proof,
    }).encode("utf-8")
    status, raw, _ = http(BASE_A, "POST",
                          f"/api/consent/requests/{request_id}/decision",
                          body=body,
                          headers={**auth, "Content-Type": "application/json"})
    if status != 200:
        fail(f"decide returned {status}: {raw[:300]!r}")
    return json.loads(raw)


def binding_message(request_id: str, nonce: str, audience: str, thumb: str) -> str:
    return "\n".join([
        "sovra-presentation/v1", request_id, nonce, audience, thumb,
    ])


def binding_proof(private: ec.EllipticCurvePrivateKey, request_id: str,
                  nonce: str, audience: str, thumb: str, artifact: str) -> str:
    # Profile-dependent holder binding, mirroring VerificationService:
    # the synthetic profile takes the Sovra proof message, the
    # interoperable profile takes a KeyBinding JWT.
    if ACTIVE_PROFILE == "sdjwt-vc":
        return key_binding(private, audience, nonce, artifact)
    return sign_compact(private, binding_message(request_id, nonce, audience, thumb))


def verify(auth: dict[str, str], base: str, request_id: str, nonce: str,
           audience: str, jwk: dict, proof: str) -> tuple[int, bytes]:
    body = json.dumps({
        "requestId": request_id, "nonce": nonce, "audience": audience,
        "holderJwk": jwk, "bindingProof": proof,
    }).encode("utf-8")
    status, raw, _ = http(base, "POST", "/api/verification/presentations",
                          body=body,
                          headers={**auth, "Content-Type": "application/json"})
    return status, raw


def main() -> int:
    compose = run(["docker", "compose", "version"], timeout=30)
    if compose.returncode != 0:
        fail("docker compose is not available")
    print("E2E verification: starting compose stack...", flush=True)
    up = run(["docker", "compose", "up", "--build", "-d"], timeout=900)
    if up.returncode != 0:
        tail = ((up.stderr or "") + (up.stdout or "")).strip()[-500:]
        fail(f"docker compose up --build -d failed: {tail}")
    try:
        wait_for_instance(BASE_A, HEALTH_DEADLINE_S, "app-a")
        wait_for_instance(BASE_B, HEALTH_DEADLINE_S, "app-b")
        print("E2E verification: both instances UP", flush=True)

        tenant_id, token = mint_account(
            "e2e-verifier", "{ISSUER_OPS,RP_CLIENT,TENANT_MEMBER}")
        auth = {"Authorization": "Bearer " + token}
        print("E2E verification: tenant plus service account minted", flush=True)

        private, jwk = holder_key()
        thumb = thumbprint(jwk)
        credential_id = issue_credential(auth, jwk, private, thumb)
        artifact = stored_artifact(credential_id)
        print(f"E2E verification: credential issued ({credential_id[:8]}...)",
              flush=True)

        created = create_request(auth, credential_id)
        request_id = created["requestId"]
        status, review_raw, headers = http(
            BASE_A, "GET", f"/api/consent/requests/{request_id}", headers=auth)
        if status != 200:
            fail(f"review GET returned {status}")
        etag = headers.get("ETag") or headers.get("Etag")
        if not etag:
            fail("review response lacks ETag")
        status, _, _ = http(BASE_A, "GET", f"/api/consent/requests/{request_id}",
                            headers={**auth, "If-None-Match": etag})
        if status != 304:
            fail(f"review If-None-Match returned {status}, want 304")
        review = json.loads(review_raw)
        print("E2E verification: consent created, review + ETag/304 OK", flush=True)

        expected_consent = consent_message(review, "approve")
        proof = sign_compact(private, expected_consent)
        decided = decide(auth, request_id, "approve", jwk, proof)
        if decided.get("state") != "VERIFIED":
            fail(f"decision state is {decided.get('state')}, want VERIFIED")
        status, pres_raw, _ = http(
            BASE_B, "GET", f"/api/consent/requests/{request_id}/presentation",
            headers=auth)
        if status != 200:
            fail(f"presentation GET returned {status}")
        presentation = json.loads(pres_raw)
        if not presentation.get("presentation"):
            fail("presentation response lacks presentation JWS")
        delivered = verify_compact(presentation["presentation"], jwk)
        if delivered != expected_consent:
            fail("delivered presentation is not the consented message")
        print("E2E verification: approved, presentation verifies", flush=True)

        nonce = secrets.token_urlsafe(16)
        binding = binding_proof(private, request_id, nonce, AUDIENCE, thumb, artifact)
        status, first = verify(auth, BASE_A, request_id, nonce, AUDIENCE,
                               jwk, binding)
        if status != 200:
            fail(f"verify returned {status}: {first[:300]!r}")
        decision = json.loads(first)
        if decision.get("outcome") != "ACCEPTED" or not decision.get("decisionId"):
            fail(f"healthy verify outcome is {decision.get('outcome')}")
        if decision.get("synthetic") is not True:
            fail("decision is not labeled synthetic")
        if decision.get("profile") != EXPECTED_DECISION_PROFILE:
            fail(f"decision profile is {decision.get('profile')!r}, want "
                 f"{EXPECTED_DECISION_PROFILE!r} for SOVRA_PROFILE={ACTIVE_PROFILE}")
        decision_id = decision["decisionId"]
        print(f"E2E verification: ACCEPTED ({decision_id[:8]}...)", flush=True)

        status, replay = verify(auth, BASE_B, request_id, nonce, AUDIENCE,
                                jwk, binding)
        if status != 200 or replay != first:
            fail("cross-instance replay was not byte-identical")
        print("E2E verification: cross-instance replay identical", flush=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(verify, auth,
                            BASE_A if i % 2 == 0 else BASE_B,
                            request_id, nonce, AUDIENCE, jwk, binding)
                for i in range(8)
            ]
            results = [f.result(timeout=120) for f in futures]
        if any(s != 200 or b != first for s, b in results):
            fail("concurrent healthy replay diverged")
        rows = psql(
            "SELECT COUNT(*) FROM verification_decision "
            f"WHERE tenant_id = '{tenant_id}' AND request_id = '{request_id}' "
            f"AND nonce = '{nonce}';").strip()
        if rows != "1":
            fail(f"expected exactly 1 decision row for the nonce, found {rows}")
        print("E2E verification: 8-way concurrent replay, one decision row",
              flush=True)

        # Negative matrix (fresh nonces unless the case needs the replay).
        tampered = binding[:-2] + ("AA" if not binding.endswith("AA") else "BB")
        status, raw = verify(auth, BASE_A, request_id, secrets.token_urlsafe(16),
                             AUDIENCE, jwk, tampered)
        if status == 200 and json.loads(raw).get("outcome") == "ACCEPTED":
            fail("tampered binding proof was accepted")
        nonce_evil = secrets.token_urlsafe(16)
        status, raw = verify(auth, BASE_A, request_id, nonce_evil,
                             "https://evil.example/callback", jwk,
                             binding_proof(private, request_id, nonce_evil,
                                           "https://evil.example/callback", thumb, artifact))
        # Note: mismatched audience must not accept (400 malformed or REJECTED).
        if status == 200 and json.loads(raw).get("outcome") == "ACCEPTED":
            fail("wrong-audience proof was accepted")
        status, _ = verify(auth, BASE_A, request_id, "short", AUDIENCE,
                           jwk, binding)
        if status != 400:
            fail(f"malformed nonce returned {status}, want 400")
        pending = create_request(auth, credential_id)
        nonce2 = secrets.token_urlsafe(16)
        status, raw = verify(auth, BASE_A, pending["requestId"], nonce2,
                             AUDIENCE, jwk,
                             binding_proof(private, pending["requestId"], nonce2,
                                           AUDIENCE, thumb, artifact))
        if status != 200 or json.loads(raw).get("outcome") != "REJECTED":
            fail(f"unapproved request returned {status}/{raw[:120]!r}")
        denied_req = create_request(auth, credential_id)
        _, denied_review_raw, _ = http(
            BASE_A, "GET", f"/api/consent/requests/{denied_req['requestId']}",
            headers=auth)
        denied = decide(auth, denied_req["requestId"], "deny", jwk,
                        sign_compact(private, consent_message(
                            json.loads(denied_review_raw), "deny")))
        if denied.get("state") != "DENIED":
            fail("deny decision did not stick")
        nonce3 = secrets.token_urlsafe(16)
        status, raw = verify(auth, BASE_A, denied_req["requestId"], nonce3,
                             AUDIENCE, jwk,
                             binding_proof(private, denied_req["requestId"], nonce3,
                                           AUDIENCE, thumb, artifact))
        if status != 200 or json.loads(raw).get("outcome") != "REJECTED":
            fail(f"denied request returned {status}/{raw[:120]!r}")
        status, _ = verify(auth, BASE_A, request_id, nonce,
                           "https://evil.example/callback", jwk, binding)
        if status != 422:
            fail(f"conflicting content on stored nonce returned {status}, want 422")
        print("E2E verification: negative matrix holds (tamper, audience, "
              "nonce, unapproved, denied, conflict)", flush=True)

        status, _, _ = http(BASE_A, "POST",
                           f"/api/issuance/credentials/{credential_id}/revoke",
                           headers=auth)
        if status != 200:
            fail(f"revoke returned {status}")
        nonce4 = secrets.token_urlsafe(16)
        status, raw = verify(auth, BASE_A, request_id, nonce4, AUDIENCE, jwk,
                             binding_proof(private, request_id, nonce4,
                                           AUDIENCE, thumb, artifact))
        if status != 200 or json.loads(raw).get("outcome") != "REJECTED":
            fail(f"revoked credential returned {status}/{raw[:120]!r}")
        print("E2E verification: revoked credential rejects on fresh nonce",
              flush=True)

        _, other_token = mint_account("e2e-other", "{TENANT_MEMBER}")
        other_auth = {"Authorization": "Bearer " + other_token}
        status, raw, _ = http(BASE_A, "GET",
                              f"/api/verification/decisions/{decision_id}",
                              headers=other_auth)
        if status != 404 or raw:
            fail("cross-tenant decision read was not empty-404")
        print("E2E verification: cross-tenant read is empty-404", flush=True)

        # Kill/restart one instance, then prove durable retrieval.
        app_a = compose_container("app-a")
        proc = run(["docker", "restart", app_a], timeout=120)
        if proc.returncode != 0:
            fail("docker restart app-a failed")
        wait_for_ready(BASE_A, RESTART_DEADLINE_S, "restarted app-a")
        status, after_kill = verify(auth, BASE_A, request_id, nonce, AUDIENCE,
                                    jwk, binding)
        if status != 200 or after_kill != first:
            fail(f"post-restart replay failed (status={status}, "
                 f"match={after_kill == first}): {after_kill[:200]!r}")
        status, got_raw, _ = http(
            BASE_A, "GET", f"/api/verification/decisions/{decision_id}",
            headers=auth)
        if status != 200 or json.loads(got_raw).get("decisionId") != decision_id:
            fail("stored decision not retrievable after restart")
        print("E2E verification: restart recovery, identical replay", flush=True)

        # Interrupt persistence: restart PostgreSQL itself, then replay.
        db = compose_container("db")
        proc = run(["docker", "restart", db], timeout=120)
        if proc.returncode != 0:
            fail("docker restart db failed")
        wait_for_ready(BASE_A, RESTART_DEADLINE_S, "app-a after db restart")
        status, after_db = verify(auth, BASE_A, request_id, nonce, AUDIENCE,
                                  jwk, binding)
        if status != 200 or after_db != first:
            fail(f"post-db-restart replay failed (status={status}, "
                 f"match={after_db == first}): {after_db[:200]!r}")
        print("E2E verification: db-restart recovery, identical replay", flush=True)

        rows = psql(
            "SELECT COUNT(*) FROM verification_decision "
            f"WHERE tenant_id = '{tenant_id}' AND request_id = '{request_id}' "
            f"AND nonce = '{nonce}';").strip()
        audits = psql(
            "SELECT COUNT(*) FROM audit_event "
            f"WHERE tenant_id = '{tenant_id}' AND action = 'VERIFY_PRESENTATION' "
            "AND decision = 'PERMIT';").strip()
        if rows != "1" or not audits.isdigit() or int(audits) < 1:
            fail(f"decision/audit consistency failed (rows={rows}, audits={audits})")
        print("E2E verification: one decision row, audit evidence present",
              flush=True)
    finally:
        down = run(["docker", "compose", "down", "-v"], timeout=180)
        print(f"E2E verification: stack torn down (down exit={down.returncode})",
              flush=True)

    print("E2E verification: PASS (consent-to-accept, replay, negatives, "
          "restart + db recovery)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
