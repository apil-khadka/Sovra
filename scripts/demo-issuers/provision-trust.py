#!/usr/bin/env python3
"""Provision dual-issuer trust on BOTH demo-issuer databases.

Drives the real two-person flow over HTTP on each node — maker proposes,
distinct checker approves and activates — until the current snapshot on
each database authorizes BOTH synthetic issuers:

  synth-1  https://sovra.example/issuers/synth-1  [adult-status/1]
  synth-2  https://sovra.example/issuers/synth-2  [fjord-adult/1,
                                                  harbor-adult/1,
                                                  employment-tenure/1]

The synth-2 public JWK is read back from node B's own signing-key
registry (public half only, written at boot by B's local-dev signer).
An ACTIVE synth-1 entry keeps every field except its validity window,
which takes the canonical run window: each genesis store minted its
own window edges at migration time, so verbatim carry would leave the
two snapshots differing in exactly that field. Non-ACTIVE synth-1
rows, third-party issuers, and RP policies pass through untouched.

Safety rules (idempotent, never destructive):
  * If the current snapshot already authorizes both issuers with the
    expected type lists (ACTIVE, validity bracketing now) AND its
    synth-1 public entry is byte-identical to the peer's, the node is
    skipped — no proposal is filed. The cross-node clause converges
    stores whose genesis windows were minted independently; a
    converged topology re-run files nothing on either node.
  * A SUSPENDED synth-2 row is NEVER flipped back to ACTIVE here; the
    run aborts loudly so an operator can decide.
  * A missing synth-1 (no genesis) aborts; trust is never fabricated.
  * An ACTIVE-but-expired synth-2 entry gets its validity window
    renewed only (status and all other fields preserved, loudly
    reported) — renewal is not reactivation.
  * The synth-2 validity window is computed ONCE per run and reused
    for both nodes, so fresh stores receive byte-identical public
    entries; per-node `now` timestamps would contradict that.
  * Activation only moves forward (server-enforced).

Maker/checker tokens come from bootstrap.py token files
(<tokens-dir>/{a,b}-{maker,checker}.token). Prints versions and
proposal ids only — no tokens, no key material beyond public JWK kids.

Requires: both app nodes up, bootstrap --phase db done. Exits nonzero
on any failure.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import typing
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOKENS_DIR = Path("/tmp/sovra-demo-issuers/tokens")

NODE_URLS = {
    "a": os.environ.get("SOVRA_DEMO_A_URL", "http://127.0.0.1:8280"),
    "b": os.environ.get("SOVRA_DEMO_B_URL", "http://127.0.0.1:8281"),
}
DB_B_CONTAINER = "sovra-demo-issuers-db-b"

ISSUER_1 = "https://sovra.example/issuers/synth-1"
ISSUER_2 = "https://sovra.example/issuers/synth-2"
ADULT_VCT = "https://sovra.example/vct/adult-status/1"
FJORD_VCT = "https://sovra.example/vct/fjord-adult/1"
HARBOR_VCT = "https://sovra.example/vct/harbor-adult/1"
EMPLOYMENT_VCT = "https://sovra.example/vct/employment-tenure/1"
SYNTH2_TYPES = [FJORD_VCT, HARBOR_VCT, EMPLOYMENT_VCT]


def fail(message: str) -> "typing.NoReturn":
    print(f"provision-trust: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


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


def read_token(tokens_dir: Path, node: str, kind: str) -> str:
    path = tokens_dir / f"{node}-{kind}.token"
    if not path.exists():
        fail(f"missing token file {path} (run bootstrap.py first)")
    return path.read_text().strip()


def current_snapshot(node: str) -> dict:
    status, body = http(node, "GET", "/api/trust/snapshots/current")
    if status == 404:
        fail(f"node {node} has no trust snapshot (migrations not applied?)")
    if status != 200:
        fail(f"snapshot read on node {node} returned {status}")
    return json.loads(body)


def usable(entry: dict, now: datetime) -> bool:
    try:
        valid_from = datetime.fromisoformat(
            entry["validFrom"].replace("Z", "+00:00"))
        valid_through = datetime.fromisoformat(
            entry["validThrough"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return False
    return (entry.get("status") == "ACTIVE"
            and valid_from <= now <= valid_through)


def authorizes_both(snapshot: dict, now: datetime) -> bool:
    issuers = snapshot.get("issuers", [])
    first = any(i.get("issuerId") == ISSUER_1
                and usable(i, now)
                and ADULT_VCT in i.get("credentialTypes", [])
                for i in issuers)
    second = any(i.get("issuerId") == ISSUER_2
                 and usable(i, now)
                 and all(t in i.get("credentialTypes", [])
                         for t in SYNTH2_TYPES)
                 for i in issuers)
    return first and second


def synth2_jwk_from_registry() -> dict:
    """Public-only JWK node B registered for itself at boot."""
    password = os.environ.get("SOVRA_DEMO_B_DB_ADMIN_PASSWORD",
                              "sovra-demo-b-admin-dev-only")
    proc = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}",
         DB_B_CONTAINER, "psql", "-U", "sovra", "-d", "sovra",
         "-v", "ON_ERROR_STOP=1", "-tA", "-c",
         "SELECT public_key_jwk::text FROM issuer_signing_key "
         f"WHERE issuer_id = '{ISSUER_2}' AND key_id = 'synth-2' "
         "AND key_version = 1;"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        fail("could not read node-B signing-key registry "
             "(is app-node-b up so its signer registered?)")
    raw = (proc.stdout or "").strip()
    if not raw:
        fail("node-B signing-key registry has no synth-2 row "
             "(is app-node-b up so its signer registered?)")
    jwk = json.loads(raw)
    if jwk.get("kid") != "synth-2":
        fail("registry JWK kid is not synth-2; refusing to propose it")
    for field in ("kty", "crv", "x", "y"):
        if not jwk.get(field):
            fail(f"registry JWK lacks {field}; refusing to propose it")
    if "d" in jwk:
        fail("registry row carries private material; refusing to propose it")
    return jwk


ISSUER_FIELDS = (
    "issuerId", "displayName", "scope", "credentialTypes",
    "keyId", "keyVersion", "publicKeyJwk", "validFrom",
    "validThrough", "status")


def build_proposal(snapshot: dict, synth2_jwk: dict,
                   valid_from: str, valid_through: str) -> dict:
    """Carry every live entry verbatim; add synth-2 from the ONE canonical
    entry (validity window computed once by the caller so both fresh
    stores receive byte-identical public contents)."""
    now = datetime.now(timezone.utc)
    issuers: list[dict] = []
    seen_synth1 = False
    for entry in snapshot.get("issuers", []):
        if entry.get("issuerId") == ISSUER_1:
            seen_synth1 = True
            carried = {k: entry[k] for k in ISSUER_FIELDS}
            if carried.get("status") == "ACTIVE":
                # Each genesis store minted its own window edges at
                # migration time, so verbatim carry would leave the
                # two snapshots differing in exactly the validity
                # window. The dual-issuer run establishes ONE
                # canonical federation snapshot: ACTIVE synth-1
                # takes the canonical window too (status and every
                # other field preserved, loudly reported). Non-ACTIVE
                # rows pass through untouched below.
                carried["validFrom"] = valid_from
                carried["validThrough"] = valid_through
                print("provision-trust: canonicalizing window of ACTIVE "
                      "synth-1 entry (status preserved)", flush=True)
            issuers.append(carried)
        elif entry.get("issuerId") == ISSUER_2:
            if entry.get("status") == "SUSPENDED":
                fail("snapshot carries a SUSPENDED synth-2 entry; "
                     "refusing to silently reactivate it — an operator "
                     "must decide (revoke/renew out of band, then re-run)")
            carried = {k: entry[k] for k in ISSUER_FIELDS}
            try:
                through = datetime.fromisoformat(
                    carried["validThrough"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                through = None
            if through is not None and through <= now:
                # ACTIVE but expired: renew the window only, keep every
                # other field (status untouched — this is not reactivation).
                carried["validFrom"] = valid_from
                carried["validThrough"] = valid_through
                print("provision-trust: renewing window of expired ACTIVE "
                      "synth-2 entry (status preserved)", flush=True)
            issuers.append(carried)
        else:
            # Unknown/third-party entries pass through untouched.
            issuers.append({k: entry[k] for k in ISSUER_FIELDS})
    if not seen_synth1:
        fail("no synth-1 entry in the live snapshot; refusing to "
             "fabricate genesis trust")
    if not any(e.get("issuerId") == ISSUER_2 for e in issuers):
        issuers.append({
            "issuerId": ISSUER_2,
            "displayName": "Synthetic second issuer (non-production)",
            "scope": "synthetic-only",
            "credentialTypes": list(SYNTH2_TYPES),
            "keyId": "synth-2",
            "keyVersion": 1,
            "publicKeyJwk": synth2_jwk,
            "validFrom": valid_from,
            "validThrough": valid_through,
            "status": "ACTIVE",
        })
    policies = [
        {k: p[k] for k in ("rpId", "purpose", "allowedTypes", "maxAssurance")}
        for p in snapshot.get("policies", [])
    ]
    return {"issuers": issuers, "policies": policies,
            "note": "demo-issuers: authorize dual synthetic issuers"}


def synth1_entry(snapshot: dict) -> dict | None:
    for entry in snapshot.get("issuers", []):
        if entry.get("issuerId") == ISSUER_1:
            return {k: entry.get(k) for k in ISSUER_FIELDS}
    return None


def converged(own: dict, peer: dict | None, now: datetime) -> bool:
    """Steady state: this node authorizes both issuers AND its synth-1
    public entry is byte-identical to the peer's. The second clause is
    what converges stores that were provisioned before the canonical
    synth-1 window existed (independent genesis edges): authorizing
    both alone is not enough. A missing peer (single-node mode with
    the other node down) falls back to the legacy authorize-only
    SKIP, loudly warned by the caller."""
    if not authorizes_both(own, now):
        return False
    if peer is None:
        return True
    own_entry = synth1_entry(own)
    return own_entry is not None and own_entry == synth1_entry(peer)


def provision_node(node: str, tokens_dir: Path, synth2_jwk: dict,
                   valid_from: str, valid_through: str,
                   peer_snapshot: dict | None) -> None:
    now = datetime.now(timezone.utc)
    snapshot = current_snapshot(node)
    if converged(snapshot, peer_snapshot, now):
        print(f"provision-trust: node-{node}: SKIP "
              f"(snapshot v{snapshot['version']} already authorizes "
              f"synth-1 + synth-2 with a converged synth-1 entry)",
              flush=True)
        return
    proposal = build_proposal(snapshot, synth2_jwk, valid_from, valid_through)
    maker = read_token(tokens_dir, node, "maker")
    checker = read_token(tokens_dir, node, "checker")
    if maker == checker:
        fail(f"node {node}: maker and checker tokens are identical; "
             f"refusing (need distinct identities)")
    maker_auth = {"Authorization": "Bearer " + maker,
                  "Content-Type": "application/json"}
    checker_auth = {"Authorization": "Bearer " + checker,
                    "Content-Type": "application/json"}
    status, body = http(node, "POST", "/api/trust/proposals",
                        body=json.dumps(proposal).encode("utf-8"),
                        headers=maker_auth)
    if status != 201:
        fail(f"node {node}: propose returned {status}: {body[:200]!r}")
    created = json.loads(body)
    version, proposal_id = created["version"], created["proposalId"]
    status, body = http(node, "POST",
                        f"/api/trust/proposals/{proposal_id}/approve",
                        headers=checker_auth)
    if status != 200:
        fail(f"node {node}: approve returned {status}: {body[:200]!r}")
    status, body = http(node, "POST",
                        f"/api/trust/snapshots/{version}/activate",
                        headers=checker_auth)
    if status != 200:
        fail(f"node {node}: activate returned {status}: {body[:200]!r}")
    snapshot = current_snapshot(node)
    if not authorizes_both(snapshot, datetime.now(timezone.utc)):
        fail(f"node {node}: snapshot v{snapshot['version']} still does "
             f"not authorize both issuers after activation")
    print(f"provision-trust: node-{node}: propose->approve->activate "
          f"complete (proposal {proposal_id}, now v{snapshot['version']}, "
          f"issuers {[i['issuerId'].rsplit('/', 1)[1] for i in snapshot['issuers']]})",
          flush=True)


def _entry(issuer: str, types: list, status: str = "ACTIVE",
             valid_from: str = "2026-01-01T00:00:00Z",
             valid_through: str = "2036-01-01T00:00:00Z",
             **over: object) -> dict:
    base: dict = {
        "issuerId": issuer,
        "displayName": f"display for {issuer}",
        "scope": "synthetic-only",
        "credentialTypes": types,
        "keyId": issuer.rsplit("/", 1)[1].replace("issuers", "synth"),
        "keyVersion": 1,
        "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "x-" + issuer[-6:],
                         "y": "y-" + issuer[-6:],
                         "kid": issuer.rsplit("/", 1)[1]},
        "validFrom": valid_from,
        "validThrough": valid_through,
        "status": status,
    }
    base.update(over)
    return base


def self_test() -> int:
    """No-network regression coverage for the proposal gates."""
    failures = []

    def check(name: str, ok: bool) -> None:
        print(f"provision-trust --self-test: "
              f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    def expect_abort(name: str, fn) -> None:
        try:
            fn()
        except SystemExit:
            check(name, True)
        else:
            check(name, False)

    jwk2 = {"kty": "EC", "crv": "P-256", "x": "xx", "y": "yy",
            "kid": "synth-2"}
    vf, vt = "2026-11-03T00:00:00Z", "2036-11-01T00:00:00Z"
    genesis = {
        "version": 1,
        "issuers": [_entry(ISSUER_1, [ADULT_VCT]),
                    _entry("https://third.example/issuer",
                           ["https://third.example/vct/1"])],
        "policies": [{"rpId": "https://rp.example/x", "purpose": "p",
                      "allowedTypes": [ADULT_VCT],
                      "maxAssurance": "AAL1"}],
    }
    now = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
    check("genesis does not authorize both",
          not authorizes_both(genesis, now))
    proposal = build_proposal(genesis, jwk2, vf, vt)
    added = [i for i in proposal["issuers"]
             if i["issuerId"] == ISSUER_2]
    check("synth-2 added once", len(added) == 1)
    check("canonical window used verbatim",
          added[0]["validFrom"] == vf and added[0]["validThrough"] == vt)
    check("synth-2 types exact", added[0]["credentialTypes"] == SYNTH2_TYPES)
    check("synth-2 ACTIVE", added[0]["status"] == "ACTIVE")
    carried1 = [i for i in proposal["issuers"]
                if i["issuerId"] == ISSUER_1][0]
    check("synth-1 window canonicalized",
          carried1["validFrom"] == vf and carried1["validThrough"] == vt)
    check("synth-1 identity fields carried verbatim",
          {k: carried1[k] for k in
           ("issuerId", "displayName", "scope", "credentialTypes",
            "keyId", "keyVersion", "publicKeyJwk", "status")}
          == {k: genesis["issuers"][0][k] for k in
              ("issuerId", "displayName", "scope", "credentialTypes",
               "keyId", "keyVersion", "publicKeyJwk", "status")})
    suspended1 = {"version": 1,
                  "issuers": [_entry(ISSUER_1, [ADULT_VCT],
                                     status="SUSPENDED")],
                  "policies": []}
    carried_susp = [i for i in
                    build_proposal(suspended1, jwk2, vf, vt)["issuers"]
                    if i["issuerId"] == ISSUER_1][0]
    check("non-ACTIVE synth-1 passes through untouched",
          carried_susp == suspended1["issuers"][0])
    check("third-party entry preserved",
          "https://third.example/issuer" in
          [i["issuerId"] for i in proposal["issuers"]])
    check("policies preserved verbatim",
          proposal["policies"] == genesis["policies"])
    # Same canonical window twice => identical synth-2 entries.
    again = build_proposal(genesis, jwk2, vf, vt)
    check("canonical entry reproducible",
          [i for i in again["issuers"] if i["issuerId"] == ISSUER_2]
          == added)
    dual = {"version": 2,
            "issuers": [_entry(ISSUER_1, [ADULT_VCT]),
                        _entry(ISSUER_2, list(SYNTH2_TYPES))],
            "policies": []}
    check("dual snapshot authorizes both", authorizes_both(dual, now))
    import copy
    twin = copy.deepcopy(dual)
    check("identical peers converged", converged(dual, twin, now))
    drifted_peer = copy.deepcopy(dual)
    drifted_peer["issuers"][0]["validThrough"] = "2036-11-02T00:00:00Z"
    check("genesis-edge drift not converged",
          not converged(dual, drifted_peer, now))
    check("genesis not converged", not converged(genesis, twin, now))
    check("missing peer falls back to authorize-only",
          converged(dual, None, now)
          and not converged(genesis, None, now))
    suspended = {"version": 2,
                 "issuers": [_entry(ISSUER_1, [ADULT_VCT]),
                             _entry(ISSUER_2, list(SYNTH2_TYPES),
                                    status="SUSPENDED")],
                 "policies": []}
    expect_abort("SUSPENDED synth-2 aborts (no silent reactivate)",
                 lambda: build_proposal(suspended, jwk2, vf, vt))
    expect_abort("missing synth-1 aborts (no fabricated genesis)",
                 lambda: build_proposal({"version": 1, "issuers": [],
                                         "policies": []}, jwk2, vf, vt))
    expired = {"version": 2,
               "issuers": [_entry(ISSUER_1, [ADULT_VCT]),
                           _entry(ISSUER_2, list(SYNTH2_TYPES),
                                  valid_through="2026-01-02T00:00:00Z")],
               "policies": []}
    check("expired ACTIVE does not authorize",
          not authorizes_both(expired, now))
    renewed = build_proposal(expired, jwk2, vf, vt)
    row = [i for i in renewed["issuers"] if i["issuerId"] == ISSUER_2][0]
    check("expired ACTIVE window renewed",
          row["validFrom"] == vf and row["validThrough"] == vt)
    check("renewal preserves status ACTIVE", row["status"] == "ACTIVE")
    check("renewal preserves JWK",
          row["publicKeyJwk"] == expired["issuers"][1]["publicKeyJwk"])
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provision dual-issuer trust on both demo databases.")
    parser.add_argument("--tokens-dir", default=str(DEFAULT_TOKENS_DIR),
                        help="bootstrap.py token dir")
    parser.add_argument("--node", choices=("a", "b"), default=None,
                        help="provision one node only (default: both)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline gate checks; touch nothing")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    tokens_dir = Path(args.tokens_dir)
    synth2_jwk = synth2_jwk_from_registry()
    print("provision-trust: synth-2 public JWK read from node-B "
          "signing-key registry (kid synth-2)", flush=True)
    # Canonical window computed ONCE so both fresh stores receive
    # byte-identical synth-2 public entries (separate per-node `now`
    # timestamps would contradict the same-contents claim).
    now = datetime.now(timezone.utc).replace(microsecond=0)
    valid_from = (now - timedelta(seconds=60)).isoformat() \
        .replace("+00:00", "Z")
    valid_through = (now + timedelta(days=3650)).isoformat() \
        .replace("+00:00", "Z")
    # Peer snapshots up front: the SKIP decision needs the cross-node
    # comparison (snapshot reads are public, no auth). Both-nodes mode
    # requires both peers; single-node mode warns and falls back to
    # the legacy authorize-only SKIP when the peer is down.
    peers: dict[str, dict | None] = {}
    for name in ("a", "b"):
        status, body = http(name, "GET", "/api/trust/snapshots/current")
        peers[name] = json.loads(body) if status == 200 else None
    nodes = ("a", "b") if args.node is None else (args.node,)
    if args.node is None and (peers["a"] is None or peers["b"] is None):
        fail("need both live snapshots to establish convergence; "
             "is one node down? (use --node for single-node mode)")
    for node in nodes:
        peer = "b" if node == "a" else "a"
        if peers[peer] is None:
            print(f"provision-trust: WARNING: peer node-{peer} "
                  f"snapshot unreadable; converging node-{node} alone "
                  f"(legacy authorize-only SKIP)", flush=True)
        provision_node(node, tokens_dir, synth2_jwk,
                       valid_from, valid_through, peers[peer])
    print("provision-trust: PASS (both snapshots authorize synth-1+synth-2)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
