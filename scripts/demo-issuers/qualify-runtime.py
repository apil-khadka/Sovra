#!/usr/bin/env python3
"""Runtime qualification for the standalone dual-issuer demo topology.

Executes ONLY with built apps up, bootstrapped accounts, and provisioned
trust (see docs/demo/dual-issuer-topology.md bring-up order; use
--dry-run to preview without touching anything).
All checks use real HTTP against the two nodes plus read-only DB probes:

  plan+guard   -> node A ONLY (single central ledger; both nodes are
                  never armed independently on one provider account)
  issuance       -> the plan's issuer node with that node's own
                  ISSUER_OPS token (synth-1 -> A, synth-2 -> B)
  consent/verify -> the same node with its RP token (same tenant)

Checks:
  01 health/ready on both nodes (READY with live authority)
  02 status probe: discoveryScopeSupported + mapped policy binding
  03 JWKS: both issuer public keys present on both nodes and DISTINCT
  04 E2E known (synth-1/adult-status): plan->guard->issue->consent->
     presentation->verify ACCEPTED, exact plan passed through
  05 E2E fjord (synth-2/isAdult) via scoped discovery on node A,
     executed on node B, ACCEPTED
  06 E2E harbor (synth-2/qualifiesAsAdult), same routing, ACCEPTED
  07 employment scoped request: actual HTTP 200 NO_PATH, null plan,
     no credential created (artifact counts unchanged)
  08 exact API roles: RP token cannot issue (403), issuer token
     cannot propose trust (403), and no admin token is loaded at all;
     same-tenant RP/issuer binding proven by 04-06 ACCEPTED
  09 cross-issuer issuance refused with the EXACT per-leg contract
     (A x synth-2: HTTP 400 invalid_request registry gate before any
     crypto; B x synth-1: HTTP 500 internal signer backstop with a
     log marker, because genesis seeded a synth-1 registry row on
     db-B too; any other status is drift and fails), after
     same-node success controls, with artifact+idempotency leak checks
  10 artifact locality: db-A holds only synth-1 rows, db-B only
     synth-2 rows (issuer + type evidence)
  11 cross-DB auth rejected: A's app credential fails on db-B and converse
     with a genuine scram password-auth failure, plus positive
     own-credential TCP controls (no down/network false positives)
  12 trust snapshots compared FIELD BY FIELD — issuer authority fields,
     validity windows, public JWKs, and RP policies (equal version
     numbers are never treated as proof of identical contents)

Canonical message shapes are taken from the backend sources
(IssuanceService proof label, PlanGuard.canonicalHash,
ConsentService.consentMessage, VerificationService.presentationMessage)
and the schema-demo contract — never guessed.

Writes sanitized evidence JSON (no tokens, no passwords, no private
keys) to <evidence-dir>/evidence-<utc-ts>.json and prints a PASS/FAIL
line per check. Exits nonzero if any check fails.

Requires: python package `cryptography`, both app nodes up,
bootstrap.py + provision-trust.py done.
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
import typing
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )
except ImportError:
    sys.exit("ERROR: python package 'cryptography' is required "
             "(pip install cryptography); refusing to hand-roll ECDSA.")

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOKENS_DIR = Path("/tmp/sovra-demo-issuers/tokens")
DEFAULT_EVIDENCE_DIR = Path("/tmp/sovra-demo-issuers")

NODE_URLS = {
    "a": os.environ.get("SOVRA_DEMO_A_URL", "http://127.0.0.1:8280"),
    "b": os.environ.get("SOVRA_DEMO_B_URL", "http://127.0.0.1:8281"),
}
DB_CONTAINERS = {"a": "sovra-demo-issuers-db-a",
                 "b": "sovra-demo-issuers-db-b"}

ISSUER_1 = "https://sovra.example/issuers/synth-1"
ISSUER_2 = "https://sovra.example/issuers/synth-2"
ADULT_VCT = "https://sovra.example/vct/adult-status/1"
FJORD_VCT = "https://sovra.example/vct/fjord-adult/1"
HARBOR_VCT = "https://sovra.example/vct/harbor-adult/1"
EMPLOYMENT_VCT = "https://sovra.example/vct/employment-tenure/1"
SYNTH2_TYPES = [FJORD_VCT, HARBOR_VCT, EMPLOYMENT_VCT]

OLD_POLICY = ("sovra-synthetic-policy/age-check", "1")
MAPPED_POLICY = ("sovra-synthetic-policy/age-check-mapped", "1")

ISSUE_LABEL = "sovra-issuance-proof/v1"
PLAN_LABEL = "sovra-plan/v1"
CONSENT_LABEL = "sovra-consent/v1"
PRESENT_LABEL = "sovra-presentation/v1"

RP_ID = "https://rp.example/synth-shop"
AUDIENCE = "https://rp.example/synth-shop/callback"
PURPOSE = "synthetic age check at checkout"

CHECKS: list[dict] = []


def fail(message: str) -> "typing.NoReturn":
    print(f"qualify-runtime: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def record(name: str, passed: bool, detail: str) -> None:
    CHECKS.append({"name": name, "pass": passed, "detail": detail})
    print(f"qualify-runtime: [{'PASS' if passed else 'FAIL'}] "
          f"{name}: {detail}", flush=True)


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


READ_TOKENS: set[str] = set()


def read_token(tokens_dir: Path, node: str, kind: str) -> str:
    # Only runtime (non-admin) tokens are ever loaded here; check 08
    # asserts no maker/checker/setup (TRUST_ADMIN) token was touched,
    # proving the runtime path needs no admin credential.
    if kind not in ("rp", "issuer"):
        fail(f"refusing to load non-runtime token kind {kind!r}")
    path = tokens_dir / f"{node}-{kind}.token"
    if not path.exists():
        fail(f"missing token file {path}")
    READ_TOKENS.add(path.name)
    return path.read_text().strip()


def http(node: str, method: str, path: str, *,
         body: bytes | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(
        NODE_URLS[node] + path, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def psql_admin(node: str, sql: str) -> str:
    # Operator-level read with the per-DB admin credential (bypasses
    # RLS like any owner probe); this gathers locality evidence, it is
    # not an app data path.
    if node == "a":
        password = os.environ.get("SOVRA_DEMO_A_DB_ADMIN_PASSWORD",
                                  "sovra-demo-a-admin-dev-only")
    else:
        password = os.environ.get("SOVRA_DEMO_B_DB_ADMIN_PASSWORD",
                                  "sovra-demo-b-admin-dev-only")
    proc = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}",
         DB_CONTAINERS[node], "psql", "-U", "sovra", "-d", "sovra",
         "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:200]
        fail(f"psql on db-{node} failed: {detail}")
    return (proc.stdout or "").strip()


# --- holder crypto (mirrors IssuanceFixtures/TestAccounts shapes) ---

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


def sign_compact(private: ec.EllipticCurvePrivateKey,
                 message: str) -> str:
    signing_input = (b64u_encode(b'{"alg":"ES256"}') + "."
                     + b64u_encode(message.encode("utf-8")))
    der = private.sign(signing_input.encode("ascii"),
                       ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u_encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def canonical_plan_hash(plan: dict) -> str:
    claims_csv = ",".join(plan["claim_paths"])
    evidence_csv = ",".join(
        f"{c['document_id']}#{c['section_id']}" for c in plan["evidence"])
    canonical = (PLAN_LABEL + "\n" + plan["plan_id"] + "\n"
                 + plan["requested_outcome"] + "\n"
                 + plan["candidate_issuer_id"] + "\n"
                 + plan["credential_type"] + "\n" + claims_csv + "\n"
                 + evidence_csv + "\n" + plan["policy_id"] + "\n"
                 + plan["policy_version"] + "\n"
                 + plan["recommendation"] + "\n")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def expiry(hours: int = 1) -> str:
    return (datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


# --- checks ---

def check_health() -> None:
    for node in ("a", "b"):
        status, body = http(node, "GET", "/api/health")
        if status != 200 or b'"status":"UP"' not in body:
            record(f"01-health-{node}", False, f"HTTP {status}")
            return
        status, body = http(node, "GET", "/api/health/ready")
        try:
            ready = json.loads(body)
        except json.JSONDecodeError:
            ready = {}
        ok = (status == 200 and ready.get("status") == "READY"
              and "authority_live" in body.decode("utf-8", "replace"))
        record(f"01-health-ready-{node}", ok,
               f"HTTP {status} status={ready.get('status')} "
               f"authority_live={'authority_live' in body.decode('utf-8', 'replace')}")


def check_status(tokens_dir: Path) -> None:
    rp = read_token(tokens_dir, "a", "rp")
    status, body = http("a", "GET", "/api/plans/status",
                        headers={"Authorization": "Bearer " + rp})
    if status != 200:
        record("02-status-probe", False, f"HTTP {status}")
        return
    view = json.loads(body)
    bindings = {(b.get("policyId"), b.get("policyVersion"))
                for b in view.get("supportedPolicyBindings", [])}
    ok = (view.get("discoveryScopeSupported") is True
          and MAPPED_POLICY in bindings and OLD_POLICY in bindings)
    record("02-status-probe", ok,
           f"discoveryScopeSupported={view.get('discoveryScopeSupported')} "
           f"bindings={sorted(f'{p}v{v}' for p, v in bindings)} "
           f"guard={view.get('guardRulesVersion')} "
           f"registry={view.get('schemaRegistryVersion')}")


def check_jwks() -> dict:
    fetched = {}
    for node in ("a", "b"):
        status, body = http(node, "GET", "/api/issuance/jwks.json")
        if status != 200:
            record("03-jwks-distinct", False,
                   f"node {node} JWKS HTTP {status}")
            return {}
        fetched[node] = json.loads(body)
    by_kid = {}
    for node in ("a", "b"):
        for key in fetched[node].get("keys", []):
            by_kid.setdefault(key.get("kid"), {})[node] = key
    kids = sorted(by_kid)
    distinct = ("synth-1" in by_kid and "synth-2" in by_kid
                and (by_kid["synth-1"]["a"]["x"],
                     by_kid["synth-1"]["a"]["y"])
                != (by_kid["synth-2"]["a"]["x"],
                    by_kid["synth-2"]["a"]["y"]))
    synced = all("a" in v and "b" in v
                 and v["a"]["x"] == v["b"]["x"]
                 and v["a"]["y"] == v["b"]["y"] for v in by_kid.values())
    record("03-jwks-distinct", distinct and synced,
           f"kids={kids} distinct={distinct} nodeA==nodeB(public)={synced}")
    return fetched


def propose(case: str, tokens_dir: Path, requested_claims: list[str],
           policy: tuple[str, str], scope: dict | None = None) -> dict:
    rp = read_token(tokens_dir, "a", "rp")
    intent: dict = {
        "rpId": RP_ID,
        "audience": AUDIENCE,
        "purpose": PURPOSE,
        "outcome": "age_over_18",
        "policyId": policy[0],
        "policyVersion": policy[1],
        "requestedClaims": requested_claims,
    }
    if scope:
        intent.update(scope)
    status, body = http("a", "POST", "/api/plans/propose",
                        body=json.dumps(intent).encode("utf-8"),
                        headers={"Authorization": "Bearer " + rp,
                                 "Content-Type": "application/json"})
    if status != 200:
        fail(f"{case}: propose returned {status}: {body[:200]!r}")
    return json.loads(body)


def guard(plan: dict, policy: tuple[str, str],
          tokens_dir: Path) -> dict:
    rp = read_token(tokens_dir, "a", "rp")
    status, body = http("a", "POST", "/api/guard/validate",
                        body=json.dumps({
                            "plan": plan,
                            "policyId": policy[0],
                            "policyVersion": policy[1],
                        }).encode("utf-8"),
                        headers={"Authorization": "Bearer " + rp,
                                 "Content-Type": "application/json"})
    if status != 200:
        fail(f"guard returned {status}: {body[:200]!r}")
    return json.loads(body)


def issue(node: str, tokens_dir: Path, issuer: str, vct: str,
          claim: str) -> tuple[str, dict, ec.EllipticCurvePrivateKey,
                               dict[str, str]]:
    # Issuance requires ISSUER_OPS; consent/verify below use the same
    # tenant's RP token. Both accounts share the node's demo tenant.
    rp = read_token(tokens_dir, node, "issuer")
    private, jwk = holder_key()
    thumb = thumbprint(jwk)
    idem = "diq-" + secrets.token_hex(16)
    claims_canonical = f"{claim}=true"
    message = (ISSUE_LABEL + "\n" + idem + "\n" + vct + "\n"
               + thumb + "\n" + claims_canonical)
    body = json.dumps({
        "issuerId": issuer,
        "vct": vct,
        "holderJwk": jwk,
        "holderProof": sign_compact(private, message),
        "claims": {claim: True},
        "expiresAt": expiry(2),
    }).encode("utf-8")
    status, resp = http(node, "POST", "/api/issuance/credentials",
                        body=body,
                        headers={"Authorization": "Bearer " + rp,
                                 "Idempotency-Key": idem,
                                 "Content-Type": "application/json"})
    if status != 201:
        fail(f"issue {vct} on node {node} returned {status}: "
             f"{resp[:200]!r}")
    return idem, json.loads(resp), private, jwk


def consent_and_verify(node: str, tokens_dir: Path, plan: dict,
                       credential_id: str, claim: str,
                       private: ec.EllipticCurvePrivateKey,
                       holder_jwk: dict[str, str]) -> str:
    rp = read_token(tokens_dir, node, "rp")
    auth = {"Authorization": "Bearer " + rp,
            "Content-Type": "application/json"}
    plan_hash = canonical_plan_hash(plan)
    challenge = secrets.token_urlsafe(24)
    status, resp = http(
        node, "POST", "/api/consent/requests",
        body=json.dumps({
            "rpId": RP_ID,
            "audience": AUDIENCE,
            "purpose": PURPOSE,
            "credentialId": credential_id,
            "claims": {claim: True},
            "plan": plan,
            "policyId": plan["policy_id"],
            "policyVersion": plan["policy_version"],
            "planHash": plan_hash,
            "challenge": challenge,
            "expiresAt": expiry(1),
        }).encode("utf-8"), headers=auth)
    if status != 201:
        fail(f"consent create on node {node} returned {status}: "
             f"{resp[:200]!r}")
    review = json.loads(resp)
    if review.get("planHash") != plan_hash:
        fail("consent echo planHash differs from the client-computed "
             "canonical hash (plan was not passed through exactly)")
    claims_canonical = f"{claim}=true"
    message = (CONSENT_LABEL + "\n" + review["requestId"] + "\napprove\n"
               + review["rpId"] + "\n" + review["audience"] + "\n"
               + review["purpose"] + "\n" + claims_canonical + "\n"
               + review["planHash"] + "\n" + review["challenge"] + "\n"
               + review["expiresAt"] + "\n" + review["holderThumbprint"])
    status, resp = http(
        node, "POST",
        f"/api/consent/requests/{review['requestId']}/decision",
        body=json.dumps({
            "decision": "approve",
            "holderJwk": holder_jwk,
            "consentProof": sign_compact(private, message),
        }).encode("utf-8"), headers=auth)
    # The decision endpoint returns the DERIVED view state: an
    # approved, unexpired, credential-backed request reads VERIFIED
    # ("consent verified; presentation authorized"), not the stored
    # APPROVED. Anything else means the approval did not take.
    if status != 200 or json.loads(resp).get("state") != "VERIFIED":
        fail(f"consent approve on node {node} returned {status}: "
             f"{resp[:200]!r}")
    status, _ = http(node, "GET",
                     f"/api/consent/requests/{review['requestId']}/presentation",
                     headers={"Authorization": "Bearer " + rp})
    if status != 200:
        fail(f"presentation on node {node} returned {status}")
    nonce = secrets.token_urlsafe(24)
    pres_message = (PRESENT_LABEL + "\n" + review["requestId"] + "\n"
                    + nonce + "\n" + AUDIENCE + "\n"
                    + thumbprint(holder_jwk))
    status, resp = http(
        node, "POST", "/api/verification/presentations",
        body=json.dumps({
            "requestId": review["requestId"],
            "nonce": nonce,
            "audience": AUDIENCE,
            "holderJwk": holder_jwk,
            "bindingProof": sign_compact(private, pres_message),
        }).encode("utf-8"), headers=auth)
    if status != 200:
        fail(f"verify on node {node} returned {status}: {resp[:200]!r}")
    decision = json.loads(resp)
    return decision.get("outcome", "")


def owner_node(plan: dict) -> str:
    issuer = plan["candidate_issuer_id"]
    if issuer == ISSUER_1:
        return "a"
    if issuer == ISSUER_2:
        return "b"
    fail(f"plan names an unexpected issuer {issuer}")


def check_e2e(label: str, tokens: Path, requested_claims: list[str],
              policy: tuple[str, str], scope: dict | None,
              expect_issuer: str, expect_type: str,
              expect_claim: str) -> None:
    view = propose(label, tokens, requested_claims, policy, scope)
    if view.get("recommendation") != "CANDIDATE_ONLY" or not view.get("plan"):
        record(label, False,
               f"recommendation={view.get('recommendation')} "
               f"reason={view.get('reason')}")
        return
    plan = view["plan"]
    if (plan["candidate_issuer_id"] != expect_issuer
            or plan["credential_type"] != expect_type
            or plan["claim_paths"] != [expect_claim]):
        record(label, False, f"unexpected plan {plan}")
        return
    verdict = guard(plan, policy, tokens)
    if not (verdict.get("accepted") is True
            and verdict.get("code") == "GUARD_ACCEPTED"
            and verdict.get("rulesVersion") == "sovra-guard/2"):
        record(label, False, f"guard verdict={verdict}")
        return
    node = owner_node(plan)
    _, issued, private, holder_jwk = issue(node, tokens, expect_issuer,
                                          expect_type, expect_claim)
    outcome = consent_and_verify(node, tokens, plan,
                                issued["credentialId"], expect_claim,
                                private, holder_jwk)
    record(label, outcome == "ACCEPTED",
           f"plan={plan['plan_id']} node={node} guard=GUARD_ACCEPTED "
           f"verify={outcome} (exact plan id threaded propose->guard"
           f"->consent->verify)")


ARTIFACT_CENSUS_SQL = (
    "SELECT issuer_id, vct, COUNT(*) FROM credential_artifact "
    "GROUP BY issuer_id, vct ORDER BY issuer_id, vct;"
)
IDEMPOTENCY_CENSUS_SQL = "SELECT COUNT(*) FROM issuance_idempotency;"


def parse_census(out: str) -> dict[str, int]:
    """Parse psql -tA rows (fields separated by `|`)."""
    counts: dict[str, int] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        issuer, vct, count = line.split("|")
        counts[f"{issuer} :: {vct}"] = int(count)
    return counts


def artifact_counts(node: str) -> dict[str, int]:
    # Owner-level row census per database; each DB only holds its own
    # node's rows, so these counts ARE the locality evidence.
    return parse_census(psql_admin(node, ARTIFACT_CENSUS_SQL))


def idempotency_count(node: str) -> int:
    out = psql_admin(node, IDEMPOTENCY_CENSUS_SQL).strip()
    return int(out) if out else 0


def check_employment(tokens_dir: Path) -> None:
    before = {n: artifact_counts(n) for n in ("a", "b")}
    view = propose("07-employment-nopath", tokens_dir, ["adultOver18"],
                   MAPPED_POLICY,
                   {"scopeIssuerIds": [ISSUER_2],
                    "scopeCredentialTypes": [EMPLOYMENT_VCT]})
    after = {n: artifact_counts(n) for n in ("a", "b")}
    ok = (view.get("recommendation") == "NO_PATH"
          and view.get("plan") is None
          and view.get("scopeCredentialTypes") == [EMPLOYMENT_VCT]
          and before == after)
    record("07-employment-nopath", ok,
           f"HTTP 200 recommendation={view.get('recommendation')} "
           f"plan={view.get('plan')} scopeEcho={view.get('scopeCredentialTypes')} "
           f"artifactsUnchanged={before == after} "
           f"reason={(view.get('reason') or '')[:120]}")


def check_exact_roles(tokens_dir: Path) -> None:
    # Exact API role assertions (AuthorizationService map):
    #   ISSUE_CREDENTIAL -> ISSUER_OPS only (RP_CLIENT gets 403)
    #   PROPOSE_TRUST_CHANGE -> TRUST_ADMIN only (issuer token gets 403)
    # Same-tenant issuance/RP binding is proven by checks 04-06: consent
    # and verification run under the RP token against credentials the
    # issuer token created — cross-tenant reads 404 with an empty body,
    # so ACCEPTED through that pair means one shared demo tenant.
    results = []
    for node, vct, claim in (("a", ADULT_VCT, "adultOver18"),
                             ("b", FJORD_VCT, "isAdult")):
        rp = read_token(tokens_dir, node, "rp")
        private, jwk = holder_key()
        idem = "diq-role-" + secrets.token_hex(8)
        message = (ISSUE_LABEL + "\n" + idem + "\n" + vct + "\n"
                   + thumbprint(jwk) + "\n" + f"{claim}=true")
        issuer = ISSUER_1 if node == "a" else ISSUER_2
        status, _ = http(
            node, "POST", "/api/issuance/credentials",
            body=json.dumps({
                "issuerId": issuer, "vct": vct, "holderJwk": jwk,
                "holderProof": sign_compact(private, message),
                "claims": {claim: True}, "expiresAt": expiry(2),
            }).encode("utf-8"),
            headers={"Authorization": "Bearer " + rp,
                     "Idempotency-Key": idem,
                     "Content-Type": "application/json"})
        results.append((f"{node}-rp-issue", status, 403))
        ops = read_token(tokens_dir, node, "issuer")
        status, _ = http(
            node, "POST", "/api/trust/proposals",
            body=json.dumps({"issuers": [], "policies": [],
                             "note": "role probe"}).encode("utf-8"),
            headers={"Authorization": "Bearer " + ops,
                     "Content-Type": "application/json"})
        results.append((f"{node}-issuer-propose", status, 403))
    admin_touched = [t for t in READ_TOKENS
                     if "maker" in t or "checker" in t or "setup" in t]
    ok = (all(status == want for _, status, want in results)
          and not admin_touched)
    record("08-exact-roles", ok,
           " ".join(f"{label}=HTTP{status}(want{want})"
                    for label, status, want in results)
           + f" adminTokensTouched={admin_touched or 'none'} "
           f"(same-tenant RP/issuer binding proven by 04-06 ACCEPTED)")


def signer_refusal_marks() -> int:
    """Count node-B 'signer refused' markers in container logs.

    ApiExceptionHandler.signingRefused logs
    "signer refused a signing call" with the SigningRefusedException
    on every backstop refusal, synchronously before the HTTP 500 is
    sent — so a count increase across the cross-issuer attempt proves
    the 500 below IS the signer backstop, not an unrelated bug that
    happens to return 500 too.
    """
    proc = subprocess.run(
        ["docker", "logs", "sovra-demo-issuers-app-b"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    return (proc.stdout + proc.stderr).count("signer refused a signing call")


def check_cross_issuer(tokens_dir: Path) -> None:
    # Exact refusal contract for THIS topology (separate DBs). Both
    # wrong-node requests are fully authorized (ISSUER_OPS token) and
    # trust-authorized for the attempted vct — but they refuse at
    # DIFFERENT layers, and the check pins each leg exactly:
    #
    # node A x synth-2 -> HTTP 400 {"error":"invalid_request"}.
    #   db-A's signing-key registry names ONLY synth-1, so
    #   IssuanceService.authorizeIssuer throws InvalidIssuanceException
    #   ("issuer signing key is not active") BEFORE any crypto;
    #   ApiExceptionHandler maps that to 400/invalid_request.
    #
    # node B x synth-1 -> HTTP 500 {"error":"internal"}.
    #   The V6 genesis migration seeds an ACTIVE synth-1 registry row
    #   on EVERY fresh database INCLUDING db-B, so node B's registry
    #   gate passes — and then LocalDevSigner (which holds only the
    #   synth-2 scalar) throws SigningRefusedException("unknown
    #   signing key"), which ApiExceptionHandler maps to
    #   500/internal. This is the backend's INTENDED second layer:
    #   the migration comment itself says "registration alone grants
    #   nothing — the signer refuses any key whose private half it
    #   does not hold". Revoking the genesis row instead would be
    #   wrong: revocation poisons JWKS and verification (both honor
    #   it), while the key is not compromised — node B simply never
    #   held its private half.
    #
    # Any other outcome (401/403/404/unreachable/201, or the legs
    # swapped) is contract drift and FAILS; a 201 would be a
    # cross-signing breach. The 500 leg additionally requires its
    # log marker (see signer_refusal_marks), so an unrelated 500 bug
    # cannot masquerade as the backstop.
    #
    # Control first: same-node issuance must succeed on both nodes with
    # the same caller and the identical (vct, claim) shapes, proving
    # the refusals below are about the foreign issuer rather than a
    # broken node, caller, or malformed claims. Trust precondition
    # second: each refusing node must authorize the foreign issuer for
    # the attempted vct right now, so neither refusal can be
    # unknown-trust. Leak check: artifact and idempotency row counts
    # must be identical before/after the refusal attempts (control
    # rows land before the baseline).
    try:
        issue("a", tokens_dir, ISSUER_1, ADULT_VCT, "adultOver18")
        issue("b", tokens_dir, ISSUER_2, FJORD_VCT, "isAdult")
    except SystemExit as exc:
        record("09-cross-issuer-refused", False,
               f"control same-node issuance failed ({exc}); refusals "
               f"would be meaningless")
        return
    control_artifacts = {n: artifact_counts(n) for n in ("a", "b")}
    control_idem = {n: idempotency_count(n) for n in ("a", "b")}
    now = datetime.now(timezone.utc)
    for node, issuer, vct in (("a", ISSUER_2, FJORD_VCT),
                             ("b", ISSUER_1, ADULT_VCT)):
        status, body = http(node, "GET", "/api/trust/snapshots/current")
        if status != 200:
            record("09-cross-issuer-refused", False,
                   f"node-{node} snapshot read HTTP {status}; refusals "
                   f"would be meaningless")
            return
        entries = [i for i in json.loads(body).get("issuers", [])
                   if i.get("issuerId") == issuer]
        trusted = False
        for entry in entries:
            try:
                valid_from = datetime.fromisoformat(
                    entry["validFrom"].replace("Z", "+00:00"))
                valid_through = datetime.fromisoformat(
                    entry["validThrough"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
            if (entry.get("status") == "ACTIVE"
                    and valid_from <= now <= valid_through
                    and vct in entry.get("credentialTypes", [])):
                trusted = True
        if not trusted:
            record("09-cross-issuer-refused", False,
                   f"node-{node} does not trust-authorize {issuer} "
                   f"for {vct} right now; a refusal here would be "
                   f"unknown-trust, not a signing refusal")
            return
    marks_before = signer_refusal_marks()
    results = []
    for node, issuer, vct, claim in (
            ("a", ISSUER_2, FJORD_VCT, "isAdult"),
            ("b", ISSUER_1, ADULT_VCT, "adultOver18")):
        rp = read_token(tokens_dir, node, "issuer")
        private, jwk = holder_key()
        idem = "diq-x-" + secrets.token_hex(8)
        message = (ISSUE_LABEL + "\n" + idem + "\n" + vct + "\n"
                   + thumbprint(jwk) + "\n" + f"{claim}=true")
        status, resp = http(
            node, "POST", "/api/issuance/credentials",
            body=json.dumps({
                "issuerId": issuer, "vct": vct, "holderJwk": jwk,
                "holderProof": sign_compact(private, message),
                "claims": {claim: True}, "expiresAt": expiry(2),
            }).encode("utf-8"),
            headers={"Authorization": "Bearer " + rp,
                     "Idempotency-Key": idem,
                     "Content-Type": "application/json"})
        try:
            body = json.loads(resp)
        except json.JSONDecodeError:
            body = {}
        results.append((node, status, body.get("error"),
                        bool(body.get("credentialId"))))
    marks_after = signer_refusal_marks()
    backstop_marked = marks_after > marks_before
    after_artifacts = {n: artifact_counts(n) for n in ("a", "b")}
    after_idem = {n: idempotency_count(n) for n in ("a", "b")}
    no_leak = (after_artifacts == control_artifacts
               and after_idem == control_idem)
    by_node = {n: (s, e, c) for n, s, e, c in results}
    leg_a = by_node.get("a") == (400, "invalid_request", False)
    leg_b = by_node.get("b") == (500, "internal", False)
    record("09-cross-issuer-refused",
           leg_a and leg_b and backstop_marked and no_leak,
           "control=same-node-issue-OK-both "
           + " ".join(f"node-{n}=HTTP{s}/{e}"
                      f"{'' if not c else ' CREDENTIAL LEAKED!'}"
                      for n, s, e, c in results)
           + f" backstopLogMarks={marks_before}->{marks_after}"
           f"{'' if backstop_marked else ' (WANT INCREASE!)'}"
           + f" leak={'none' if no_leak else 'ROWS APPEARED!'} "
           f"(want exactly A=400/invalid_request registry-gate, "
           f"B=500/internal signer-backstop)")


def check_locality() -> None:
    counts = {n: artifact_counts(n) for n in ("a", "b")}
    a_ok = counts["a"] and all(k.startswith(ISSUER_1) for k in counts["a"])
    b_ok = counts["b"] and all(k.startswith(ISSUER_2) for k in counts["b"])
    record("10-artifact-locality", bool(a_ok and b_ok),
           f"db-A={counts['a']} db-B={counts['b']}")


def container_ip(container: str) -> str:
    proc = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
         container],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        fail(f"could not resolve IP of {container}")
    return (proc.stdout or "").strip().split()[0]


def tcp_connect(target_node: str, password: str) -> tuple[int, str]:
    """Run SELECT 1 as sovra_app over the target's bridge address (where
    pg_hba applies scram-sha-256), NOT loopback: the postgres image
    trusts loopback inside the container, so a 127.0.0.1 probe would
    accept even a wrong password and prove nothing."""
    ip = container_ip(DB_CONTAINERS[target_node])
    proc = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}",
         DB_CONTAINERS[target_node], "psql",
         f"postgresql://sovra_app@{ip}:5432/sovra",
         "-v", "ON_ERROR_STOP=1", "-tA", "-c", "SELECT 1;"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    return proc.returncode, (proc.stderr or proc.stdout or "")[:200]


def try_cross_connect(target_node: str, password_env: str,
                      password_default: str) -> bool:
    """True ONLY on a genuine password-authentication rejection: nonzero
    exit AND psql reporting password authentication failure. Any other
    error (container down, network, auth-method drift) is inconclusive
    and must NOT count as a pass."""
    password = os.environ.get(password_env, password_default)
    code, detail = tcp_connect(target_node, password)
    return code != 0 and "password authentication failed" in detail


def own_credential_ok(target_node: str, password_env: str,
                      password_default: str) -> bool:
    """Positive TCP control: the node's OWN app credential must succeed
    over the same bridge path, excluding down/network false positives."""
    password = os.environ.get(password_env, password_default)
    code, _ = tcp_connect(target_node, password)
    return code == 0


def check_cross_db() -> None:
    a_rejected_on_b = try_cross_connect(
        "b", "SOVRA_DEMO_A_APP_DB_PASSWORD", "sovra-demo-a-app-dev-only")
    b_rejected_on_a = try_cross_connect(
        "a", "SOVRA_DEMO_B_APP_DB_PASSWORD", "sovra-demo-b-app-dev-only")
    a_own_ok = own_credential_ok(
        "a", "SOVRA_DEMO_A_APP_DB_PASSWORD", "sovra-demo-a-app-dev-only")
    b_own_ok = own_credential_ok(
        "b", "SOVRA_DEMO_B_APP_DB_PASSWORD", "sovra-demo-b-app-dev-only")
    record("11-cross-db-rejected",
           a_rejected_on_b and b_rejected_on_a and a_own_ok and b_own_ok,
           f"A-cred-on-dbB={'pw-rejected' if a_rejected_on_b else 'NOT-REJECTED!'} "
           f"B-cred-on-dbA={'pw-rejected' if b_rejected_on_a else 'NOT-REJECTED!'} "
           f"ownCredTCP={'OK-both' if a_own_ok and b_own_ok else 'CONTROL FAILED!'} "
           f"(rejection = scram password-auth failure; host admin can "
           f"still reach both containers — no host-isolation claim)")


def snapshot_entries(node: str) -> tuple[int, list[dict], list[dict]]:
    status, body = http(node, "GET", "/api/trust/snapshots/current")
    if status != 200:
        fail(f"snapshot read on node {node} returned {status}")
    snap = json.loads(body)
    return snap["version"], snap.get("issuers", []), snap.get("policies", [])


def normalize_snapshot(issuers: list[dict],
                       policies: list[dict]) -> tuple[dict, list]:
    """Canonical comparable form: every issuer field that grants authority
    (ids, types, key ref, status, scope, validity window, public JWK),
    plus the full RP policy list. Versions are excluded on purpose —
    equal numbers never prove identical contents."""
    fields = ("issuerId", "credentialTypes", "keyId", "keyVersion",
              "status", "scope", "validFrom", "validThrough",
              "displayName")
    norm_issuers = {
        i["issuerId"]: (
            {f: (sorted(i[f]) if isinstance(i[f], list) else i[f])
             for f in fields},
            i["publicKeyJwk"].get("kid"),
            i["publicKeyJwk"].get("x"),
            i["publicKeyJwk"].get("y"),
        )
        for i in issuers
    }
    norm_policies = sorted(
        (p.get("rpId"), p.get("purpose"),
         tuple(sorted(p.get("allowedTypes", []))), p.get("maxAssurance"))
        for p in policies
    )
    return norm_issuers, norm_policies


def check_snapshot_compare() -> None:
    ver_a, iss_a, pol_a = snapshot_entries("a")
    ver_b, iss_b, pol_b = snapshot_entries("b")
    norm_a = normalize_snapshot(iss_a, pol_a)
    norm_b = normalize_snapshot(iss_b, pol_b)
    match = norm_a == norm_b
    detail = (f"vA={ver_a} vB={ver_b} "
              f"(versions recorded only — equality judged field-by-field) "
              f"issuersA={sorted(norm_a[0])} issuersB={sorted(norm_b[0])} "
              f"policiesA={len(norm_a[1])} policiesB={len(norm_b[1])} "
              f"fieldMatch={match}")
    if not match:
        only_a = sorted(set(norm_a[0]) - set(norm_b[0]))
        only_b = sorted(set(norm_b[0]) - set(norm_a[0]))
        diff_issuers = sorted(k for k in set(norm_a[0]) & set(norm_b[0])
                              if norm_a[0][k] != norm_b[0][k])
        detail += (f" onlyA={only_a} onlyB={only_b} "
                   f"diffIssuers={diff_issuers} "
                   f"policiesMatch={norm_a[1] == norm_b[1]}")
    record("12-snapshot-contents", match, detail)


def dry_run() -> int:
    print("qualify-runtime: DRY RUN — no HTTP, no DB writes. Planned:")
    for step in (
            "01 health + /api/health/ready on 8280/8281",
            "02 GET /api/plans/status on node A (scope + bindings)",
            "03 GET /api/issuance/jwks.json on both (distinct keys)",
            "04 E2E known synth-1: propose+guard on A, "
            "issue/consent/verify on A",
            "05 E2E fjord synth-2: propose+guard on A, "
            "issue/consent/verify on B",
            "06 E2E harbor synth-2: propose+guard on A, "
            "issue/consent/verify on B",
            "07 employment scoped propose on A: expect 200 NO_PATH, "
            "no artifacts",
            "08 exact API roles: RP cannot issue, issuer cannot propose",
            "09 cross-issuer issuance on both nodes: expect refusal",
            "10 artifact row counts/types/issuer per DB (locality)",
            "11 cross-DB credential attempts: expect rejection",
            "12 snapshot field-by-field comparison (both nodes)"):
        print(f"  - {step}")
    return 0


def self_test() -> int:
    """No-network regression coverage for the offline gates: canonical
    builders (recomputed by a second inline method), SQL shapes, census
    parsing, snapshot normalization sensitivity, and token-kind refusal."""
    failures = []

    def check(name: str, ok: bool) -> None:
        print(f"qualify-runtime --self-test: "
              f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    # Canonical plan hash: script builder vs independent inline form.
    plan = json.loads((ROOT / "docs/engineering/fixtures"
                       / "candidate-plan-mapped.example.json").read_text())
    expected = hashlib.sha256(
        ("sovra-plan/v1\npln_demo_mapped_001\nage_over_18\n"
         "https://sovra.example/issuers/synth-2\n"
         "https://sovra.example/vct/fjord-adult/1\n"
         "isAdult\n"
         "sovra-synthetic-policy/age-check-mapped#mapped_age_eligibility,"
         "sovra-schema/fjord-adult-v1#adult_eligibility\n"
         "sovra-synthetic-policy/age-check-mapped\n1\nCANDIDATE_ONLY\n")
        .encode("utf-8")).hexdigest()
    check("canonical_plan_hash matches independent form",
          canonical_plan_hash(plan) == expected)
    # Thumbprint: builder vs manual RFC 7638 construction.
    jwk = {"kty": "EC", "crv": "P-256", "x": "axfR8uEsQkf4vOblY6RA8ncD"
                                             "fYEt6zOg9KE5RdiYwpY",
           "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}
    manual = b64u_encode(hashlib.sha256(
        ('{"crv":"P-256","kty":"EC","x":"' + jwk["x"] + '","y":"'
         + jwk["y"] + '"}').encode("utf-8")).digest())
    check("thumbprint matches RFC 7638 construction",
          thumbprint(jwk) == manual)
    # Census SQL: valid GROUP BY over plain columns (no aggregate in
    # the group key); parser handles -tA rows and empty output.
    check("census SQL groups by plain columns",
          "GROUP BY issuer_id, vct" in ARTIFACT_CENSUS_SQL
          and "|| COUNT" not in ARTIFACT_CENSUS_SQL)
    sample = (f"{ISSUER_2} :: {FJORD_VCT} :: 2\n"
              if False else
              f"{ISSUER_2}|{FJORD_VCT}|2\n{ISSUER_2}|{HARBOR_VCT}|1\n")
    parsed = parse_census(sample)
    check("census parser counts rows",
          parsed == {f"{ISSUER_2} :: {FJORD_VCT}": 2,
                     f"{ISSUER_2} :: {HARBOR_VCT}": 1})
    check("census parser tolerates empty output", parse_census("\n") == {})
    # Snapshot normalization: detects window/policy/type drift.
    base_issuers = [{
        "issuerId": ISSUER_2, "displayName": "d", "scope": "synthetic-only",
        "credentialTypes": list(SYNTH2_TYPES), "keyId": "synth-2",
        "keyVersion": 1,
        "publicKeyJwk": {"kid": "synth-2", "x": "x", "y": "y"},
        "validFrom": "2026-11-03T00:00:00Z",
        "validThrough": "2036-11-01T00:00:00Z", "status": "ACTIVE"}]
    base_policies = [{"rpId": "r", "purpose": "p",
                      "allowedTypes": [ADULT_VCT], "maxAssurance": "AAL1"}]
    norm = normalize_snapshot(base_issuers, base_policies)
    drifted = [dict(base_issuers[0], validThrough="2036-11-02T00:00:00Z")]
    check("normalization detects window drift",
          normalize_snapshot(drifted, base_policies) != norm)
    drifted_pol = [dict(base_policies[0], purpose="q")]
    check("normalization detects policy drift",
          normalize_snapshot(base_issuers, drifted_pol) != norm)
    reordered = [dict(base_issuers[0],
                      credentialTypes=list(reversed(SYNTH2_TYPES)))]
    check("normalization ignores type order",
          normalize_snapshot(reordered, base_policies) == norm)
    # Token-kind refusal: admin kinds must abort, never load.
    for kind in ("maker", "checker", "setup"):
        try:
            read_token(Path("/nonexistent"), "a", kind)
        except SystemExit:
            check(f"refuses to load {kind} token", True)
        else:
            check(f"refuses to load {kind} token", False)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Qualify the dual-issuer demo topology at runtime.")
    parser.add_argument("--tokens-dir", default=str(DEFAULT_TOKENS_DIR))
    parser.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR))
    parser.add_argument("--dry-run", action="store_true",
                        help="print planned steps; touch nothing")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline gate checks; touch nothing")
    args = parser.parse_args()
    if args.dry_run:
        return dry_run()
    if args.self_test:
        return self_test()
    tokens_dir = Path(args.tokens_dir)
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    check_health()
    check_status(tokens_dir)
    check_jwks()
    check_e2e("04-e2e-known-synth1", tokens_dir, ["adultOver18"],
              OLD_POLICY, None, ISSUER_1, ADULT_VCT, "adultOver18")
    check_e2e("05-e2e-fjord-synth2", tokens_dir, ["adultOver18"],
              MAPPED_POLICY, {"scopeIssuerIds": [ISSUER_2],
                              "scopeCredentialTypes": [FJORD_VCT]},
              ISSUER_2, FJORD_VCT, "isAdult")
    check_e2e("06-e2e-harbor-synth2", tokens_dir, ["adultOver18"],
              MAPPED_POLICY, {"scopeIssuerIds": [ISSUER_2],
                              "scopeCredentialTypes": [HARBOR_VCT]},
              ISSUER_2, HARBOR_VCT, "qualifiesAsAdult")
    check_employment(tokens_dir)
    check_exact_roles(tokens_dir)
    check_cross_issuer(tokens_dir)
    check_locality()
    check_cross_db()
    check_snapshot_compare()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_path = evidence_dir / f"evidence-{stamp}.json"
    evidence_path.write_text(json.dumps({
        "topology": "compose.demo-issuers.yaml",
        "nodeA": NODE_URLS["a"],
        "nodeB": NODE_URLS["b"],
        "utc": stamp,
        "checks": CHECKS,
    }, indent=2) + "\n")
    failed = [c for c in CHECKS if not c["pass"]]
    print(f"qualify-runtime: evidence -> {evidence_path} "
          f"({len(CHECKS) - len(failed)}/{len(CHECKS)} passed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
