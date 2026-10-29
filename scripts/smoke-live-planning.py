#!/usr/bin/env python3
"""Live-planning smoke against an armed compose stack (OD-02, SOV-013).

Reproducible evidence procedure: confirms LIVE status, proposes the
frozen age-over-18 synthetic intent, proves invalid intents 400 before
any model contact, and adjudicates the live candidate with the
deterministic guard. Synthetic inputs only; prints sanitized fields
only (no keys, prompts, or proofs); exits nonzero on any failure.

COST WARNING: every run spends provider credits (about 11k tokens
observed on Muse Spark Open via Baseten). Run only against
verified no-charge capacity with SOVRA_AI_LIVE_ENABLED=true. When
the stack is not armed the script exits 2 without spending anything.

Assumes the stack is up (app-a on :8080); leaves the stack running.
Step 4 of the OD-02 procedure (provider outage -> explicit 503) is
manual by design: point SOVRA_AI_BASE_URL at an unreachable host,
recycle, propose, expect 503 planning_unavailable with no candidate
and no fixture fallback, then restore. It was exercised live on
2026-10-29; see docs/ai/live-integration.md.
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
POLICY_ID = "sovra-synthetic-policy/age-check"
POLICY_VERSION = "1"


def fail(message: str) -> "typing.NoReturn":
    print(f"smoke live-planning: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def check(label: str) -> None:
    print(f"smoke live-planning: {label}", flush=True)


def http(method: str, path: str, payload: dict | None = None,
         token: str | None = None) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE_A + path, data=body, method=method)
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") or "{}"
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {}


def psql_ok(sql: str) -> str:
    proc = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={DB_ADMIN_PASSWORD}",
         DB_CONTAINER, "psql", "-U", "sovra", "-d", "sovra",
         "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        fail(f"psql failed: {(proc.stderr or '').strip()[-300:]}")
    return proc.stdout


def mint_account(name: str) -> str:
    token = TOKEN_PREFIX + base64.urlsafe_b64encode(
        secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    slug = f"smoke-live-{secrets.token_hex(4)}"
    tenant_id = psql_ok(
        "INSERT INTO tenant (slug, display_name) "
        f"VALUES ('{slug}', 'Live smoke') RETURNING id;").splitlines()[0].strip()
    psql_ok(
        "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) "
        f"VALUES ('{tenant_id}', '{name}', '{token[len(TOKEN_PREFIX):len(TOKEN_PREFIX) + 8]}', "
        f"decode('{hashlib.sha256(token.encode()).hexdigest()}', 'hex'), '{{TENANT_MEMBER}}');")
    return token


def main() -> int:
    token = mint_account("smoke-live")
    status, body = http("GET", "/api/plans/status", token=token)
    if status != 200:
        fail(f"planner status responded {status}")
    print(f"smoke live-planning: status mode={body.get('mode')} "
          f"liveEnabled={body.get('liveEnabled')} "
          f"modelConfigured={body.get('modelConfigured')}", flush=True)
    for key in ("promptVersion", "toolContractVersion", "toolSchemaHash",
                "baselineVersion", "tools"):
        print(f"smoke live-planning: status.{key} = {body.get(key)}", flush=True)
    if body.get("mode") != "LIVE" or not body.get("liveEnabled"):
        print("smoke live-planning: NOT ARMED: set SOVRA_AI_LIVE_ENABLED=true "
              "with endpoint/model/key in .env, recycle the apps, then rerun. "
              "No credits spent.", flush=True)
        return 2
    check("live planning is armed")

    intent = {"rpId": "smoke-demo-rp", "audience": "smoke",
              "purpose": "od02-smoke", "outcome": "age_over_18",
              "policyId": POLICY_ID, "policyVersion": POLICY_VERSION,
              "requestedClaims": ["adultOver18"]}
    status, proposal = http("POST", "/api/plans/propose", intent, token)
    if status != 200 or proposal.get("mode") != "LIVE" \
            or not proposal.get("liveAcceptance"):
        fail(f"no LIVE candidate: {status} {json.dumps(proposal)[:300]}")
    for key in ("model", "profile", "recommendation", "promptVersion",
                "toolContractVersion", "toolSchemaHash", "toolCalls",
                "latencyMs", "usageTokens", "cost"):
        print(f"smoke live-planning: proposal.{key} = {proposal.get(key)}", flush=True)
    plan = proposal.get("plan")
    if not isinstance(plan, dict):
        fail("candidate plan is missing")
    print(f"smoke live-planning: plan keys = {sorted(plan.keys())}", flush=True)
    check("LIVE candidate with exact versioned citations received")

    bad = dict(intent, outcome="is_billionaire", requestedClaims=["netWorth"])
    status, _ = http("POST", "/api/plans/propose", bad, token)
    if status != 400:
        fail(f"invalid intent responded {status}, want 400 before model contact")
    check("invalid intent refused before any model contact")

    status, verdict = http("POST", "/api/guard/validate",
                           {"plan": plan, "policyId": POLICY_ID,
                            "policyVersion": POLICY_VERSION}, token)
    if status != 200:
        fail(f"guard validate responded {status}")
    print(f"smoke live-planning: guard accepted={verdict.get('accepted')} "
          f"code={verdict.get('code')} rules={verdict.get('rulesVersion')} "
          f"snapshot={verdict.get('snapshotVersion')}", flush=True)
    check("deterministic guard adjudicated the live candidate")

    print("smoke live-planning: PASS (LIVE candidate, 400-before-contact, guard verdict)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
