#!/usr/bin/env python3
"""Reproducible scorer for sovra-planning-corpus/2 (scoped discovery).

Reads the frozen v2 fixtures plus manifest, verifies SHA-256 digests and
governing versions, then either scores a captures/replays file
(`score-replay`, default, never spends) or — only with explicit
`capture-live --confirm-spend` — drives one central planner node through
the corpus and retains every proposal, guard verdict, failure, latency,
and usage field with immutable case/config hashes.

Defaults never spend provider credits: without `capture-live
--confirm-spend`, no POST /api/plans/propose fires. Guard adjudication
in score-replay (optional --base-url) is local only (no model call).
Live capture stays PENDING until the operator confirms no-charge grant
balance/expiry, no-overage terms, and processing/retention approval;
see docs/ai/planner-evaluation.md. No billing or inference calls run
from this scorer unless the operator explicitly opts into capture-live.

Synthetic fixtures only. Tokens arrive from the environment by name and
are never printed; capture/replay files carry sanitized proposal/guard
fields only (no tokens, no raw prompts, no proofs).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import typing
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "backend" / "src" / "test" / "resources" / "planning-corpus-v2"
MANIFEST = CORPUS_DIR / "manifest.json"


def fail(message: str) -> typing.NoReturn:
    print(f"evaluate-planner-corpus2: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def warn(message: str) -> None:
    print(f"evaluate-planner-corpus2: WARN: {message}", file=sys.stderr)


def info(message: str) -> None:
    print(f"evaluate-planner-corpus2: {message}", flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest() -> dict:
    if not MANIFEST.is_file():
        fail(f"manifest is missing: {MANIFEST}")
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except ValueError as exc:
        fail(f"manifest is not JSON: {exc}")
    if not isinstance(manifest, dict):
        fail("manifest is not a JSON object")
    return manifest


def verify_corpus(manifest: dict) -> list[dict]:
    files = manifest.get("files")
    cases = manifest.get("cases")
    if not isinstance(files, dict) or not isinstance(cases, list):
        fail("manifest files/cases are malformed")
    for name, want in files.items():
        path = CORPUS_DIR / name
        if not path.is_file():
            fail(f"corpus file is missing: {name}")
        got = sha256_file(path)
        if got != want:
            fail(f"digest mismatch for {name}: want {want} got {got}")
    loaded: list[dict] = []
    for name in cases:
        path = CORPUS_DIR / name
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            fail(f"case {name} is not JSON: {exc}")
        for key in ("caseId", "outcome", "policyId", "policyVersion",
                    "requestedClaims", "expectBaseline", "expectCandidate"):
            if key not in case:
                fail(f"case {name} is missing {key}")
        loaded.append(case)
    loaded.sort(key=lambda c: str(c.get("caseId")))
    return loaded


def http_json(method: str, base: str, path: str,
              payload: dict | None, token: str,
              timeout: int) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(base.rstrip("/") + path, data=body, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") or "{}"
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return 0, {"_transport_error": f"{type(exc).__name__}: {exc}"}


def read_token(env_name: str) -> str:
    value = os.environ.get(env_name)
    if not value:
        fail(f"token env {env_name} is empty or missing; pass --token-env with a set variable")
    return value


def in_scope(case: dict, plan: dict) -> tuple[bool, str]:
    issuer = plan.get("candidate_issuer_id", plan.get("candidateIssuerId"))
    cred_type = plan.get("credential_type", plan.get("credentialType"))
    want_issuers = case.get("scopeIssuerIds", []) or []
    want_types = case.get("scopeCredentialTypes", []) or []
    if want_issuers and issuer not in want_issuers:
        return False, "candidate issuer is outside scopeIssuerIds"
    if want_types and cred_type not in want_types:
        return False, "candidate type is outside scopeCredentialTypes"
    return True, "in scope"


def percentile(sorted_values: list[float], pct: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * pct / 100.0
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] * (1.0 - frac) + sorted_values[high] * frac


def summarize_latency(latencies: list[float]) -> dict:
    ordered = sorted(latencies)
    return {
        "n": len(ordered),
        "p50_ms": percentile(ordered, 50),
        "p95_ms": percentile(ordered, 95),
        "note": ("n=%d: p50/p95 are illustrative over this tiny sample, "
                 "not statistically robust claims" % len(ordered)),
    }


def score_replay(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    cases = verify_corpus(manifest)
    info(f"corpus {manifest.get('corpusVersion')} verified "
         f"({len(cases)} cases, digests match)")
    replay_path = Path(args.replay)
    if not replay_path.is_file():
        fail(f"replay file is missing: {replay_path}")
    try:
        replay = json.loads(replay_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        fail(f"replay file is not JSON: {exc}")
    entries = replay.get("results", replay) if isinstance(replay, dict) else None
    if not isinstance(entries, dict):
        fail("replay file must carry a {\"results\": {caseId: entry}} object")
    base_url = args.base_url
    token = read_token(args.token_env) if base_url else ""
    scored: list[dict] = []
    complete = True
    for case in cases:
        case_id = str(case["caseId"])
        entry = entries.get(case_id)
        if entry is None:
            scored.append({"caseId": case_id, "recommendation": "MISSING",
                           "expected": False, "provenance": "missing",
                           "guardCode": "NOT_EVALUATED",
                           "reason": "no replay entry; unavailable stays missing"})
            complete = False
            continue
        if not isinstance(entry, dict):
            scored.append({"caseId": case_id, "recommendation": "NULL",
                           "expected": False, "provenance": "null-injection",
                           "guardCode": "NOT_EVALUATED",
                           "reason": "replay entry is not an object"})
            complete = False
            continue
        mode = entry.get("mode")
        live_accept = entry.get("liveAcceptance") is True
        if mode != "LIVE" or not live_accept:
            scored.append({"caseId": case_id,
                           "recommendation": str(entry.get("recommendation", "NULL")),
                           "expected": False, "provenance": "injected-fixture",
                           "guardCode": "NOT_EVALUATED",
                           "reason": "fixture-shaped replay never satisfies live acceptance"})
            complete = False
            continue
        rec = entry.get("recommendation")
        plan = entry.get("plan")
        want_candidate = case.get("expectCandidate") is True
        if not want_candidate:
            if rec == "CANDIDATE_ONLY" or plan is not None:
                scored.append({"caseId": case_id, "recommendation": str(rec),
                               "expected": False,
                               "provenance": "injected-live-shaped",
                               "guardCode": "NOT_EVALUATED",
                               "reason": "refusal case must be NO_PATH/MANUAL_REVIEW "
                                         "with no plan"})
            else:
                scored.append({"caseId": case_id, "recommendation": str(rec),
                               "expected": True,
                               "provenance": "injected-live-shaped",
                               "guardCode": "NOT_APPLICABLE",
                               "reason": str(entry.get("reason", ""))})
            continue
        if rec != "CANDIDATE_ONLY" or not isinstance(plan, dict):
            scored.append({"caseId": case_id, "recommendation": str(rec),
                           "expected": False, "provenance": "injected-live-shaped",
                           "guardCode": "NOT_EVALUATED",
                           "reason": "candidate case must be CANDIDATE_ONLY with a plan"})
            continue
        ok, why = in_scope(case, plan)
        if not ok:
            scored.append({"caseId": case_id, "recommendation": str(rec),
                           "expected": False, "provenance": "injected-live-shaped",
                           "guardCode": "NOT_EVALUATED", "reason": why})
            continue
        exp_issuer = case.get("expectedIssuerId")
        exp_type = case.get("expectedCredentialType")
        exp_claims = case.get("expectedClaimPaths")
        got_issuer = plan.get("candidate_issuer_id", plan.get("candidateIssuerId"))
        got_type = plan.get("credential_type", plan.get("credentialType"))
        got_claims = plan.get("claim_paths", plan.get("claimPaths"))
        if got_issuer != exp_issuer or got_type != exp_type or got_claims != exp_claims:
            scored.append({"caseId": case_id, "recommendation": str(rec),
                           "expected": False, "provenance": "injected-live-shaped",
                           "guardCode": "NOT_EVALUATED",
                           "reason": f"plan {got_issuer} {got_type} {got_claims} "
                                     f"does not match expected {exp_issuer} "
                                     f"{exp_type} {exp_claims}"})
            continue
        guard_code = "NOT_EVALUATED"
        guard_reason = ""
        if base_url:
            status, verdict = http_json(
                "POST", base_url, "/api/guard/validate",
                {"plan": plan, "policyId": case.get("policyId"),
                 "policyVersion": case.get("policyVersion")},
                token, args.timeout)
            if status != 200 or not isinstance(verdict, dict):
                guard_reason = f"guard adjudication unavailable (http {status})"
            else:
                guard_code = str(verdict.get("code", "UNKNOWN"))
                guard_reason = str(verdict.get("reason", ""))
                if verdict.get("accepted") is not True:
                    scored.append({"caseId": case_id, "recommendation": str(rec),
                                   "expected": False,
                                   "provenance": "injected-live-shaped",
                                   "guardCode": guard_code,
                                   "reason": f"real guard rejects with {guard_code}"
                                             + (f": {guard_reason}" if guard_reason else "")})
                    continue
        else:
            guard_reason = "guard not re-adjudicated (no --base-url); replay score " \
                "covers shape/scope/expected binding only"
        scored.append({"caseId": case_id, "recommendation": str(rec),
                       "expected": guard_code == "GUARD_ACCEPTED" if base_url else True,
                       "provenance": "injected-live-shaped",
                       "guardCode": guard_code, "reason": guard_reason
                       or str(entry.get("reason", ""))})
    all_expected = bool(scored) and all(s["expected"] for s in scored)
    print(json.dumps({"corpusVersion": manifest.get("corpusVersion"),
                      "complete": complete, "allExpected": all_expected,
                      "proofExecution": "NOT_EXECUTED",
                      "provenance": "injected/replayed (shape only, "
                                    "not proof of provider execution)",
                      "results": scored}, indent=2, sort_keys=True))
    if not complete or not all_expected:
        return 1
    return 0


def capture_live(args: argparse.Namespace) -> int:
    if not args.confirm_spend:
        info("NOT ARMED: capture-live requires --confirm-spend plus a funded "
             "no-charge grant; no credits spent.")
        return 2
    manifest = load_manifest()
    cases = verify_corpus(manifest)
    base_url = args.base_url
    if not base_url:
        fail("capture-live requires --base-url pointing at ONE central planner node")
    token = read_token(args.token_env)
    status, body = http_json("GET", base_url, "/api/plans/status", None,
                             token, args.timeout)
    if status != 200 or not isinstance(body, dict):
        fail(f"planner status responded {status}; refusing to spend")
    info(f"status mode={body.get('mode')} liveEnabled={body.get('liveEnabled')} "
         f"modelConfigured={body.get('modelConfigured')}")
    for key in ("promptVersion", "toolContractVersion", "toolSchemaHash",
                "baselineVersion", "schemaRegistryVersion", "guardRulesVersion"):
        want = manifest.get(key)
        got = body.get(key)
        info(f"status.{key} = {got} (manifest {want})")
        if want is not None and got != want:
            fail(f"version drift for {key}: live {got!r} != manifest {want!r}")
    if body.get("mode") != "LIVE" or not body.get("liveEnabled"):
        info("NOT ARMED: planner reports fixture mode; no credits spent.")
        return 2
    results: dict[str, dict] = {}
    latencies: list[float] = []
    for case in cases:
        case_id = str(case["caseId"])
        intent = {
            "rpId": case.get("rpId"),
            "audience": case.get("audience"),
            "purpose": case.get("purpose"),
            "outcome": case.get("outcome"),
            "policyId": case.get("policyId"),
            "policyVersion": case.get("policyVersion"),
            "requestedClaims": case.get("requestedClaims"),
        }
        for scope_key in ("scopeIssuerIds", "scopeCredentialTypes",
                          "scopeJurisdictions"):
            values = case.get(scope_key) or []
            if values:
                intent[scope_key] = values
        status, proposal = http_json("POST", base_url, "/api/plans/propose",
                                     intent, token, args.timeout)
        if status != 200 or not isinstance(proposal, dict):
            results[case_id] = {"caseId": case_id, "status": "unavailable",
                                "httpStatus": status,
                                "reason": "propose failed or timed out; retained, "
                                          "never replaced by a fixture",
                                "detail": proposal}
            continue
        entry: dict = {
            "caseId": case_id,
            "mode": proposal.get("mode"),
            "liveAcceptance": proposal.get("liveAcceptance"),
            "recommendation": proposal.get("recommendation"),
            "reason": proposal.get("reason"),
            "model": proposal.get("model"),
            "promptVersion": proposal.get("promptVersion"),
            "toolContractVersion": proposal.get("toolContractVersion"),
            "toolSchemaHash": proposal.get("toolSchemaHash"),
            "toolCalls": proposal.get("toolCalls"),
            "latencyMs": proposal.get("latencyMs"),
            "usageTokens": proposal.get("usageTokens"),
            "cost": proposal.get("cost"),
            "snapshotVersion": proposal.get("snapshotVersion"),
            "plan": proposal.get("plan"),
        }
        try:
            if entry.get("latencyMs") is not None:
                latencies.append(float(entry["latencyMs"]))
        except (TypeError, ValueError):
            pass
        plan = entry.get("plan")
        if entry.get("recommendation") == "CANDIDATE_ONLY" and isinstance(plan, dict):
            g_status, verdict = http_json(
                "POST", base_url, "/api/guard/validate",
                {"plan": plan, "policyId": case.get("policyId"),
                 "policyVersion": case.get("policyVersion")},
                token, args.timeout)
            entry["guardHttpStatus"] = g_status
            entry["guard"] = verdict
        results[case_id] = entry
    capture = {
        "corpusVersion": manifest.get("corpusVersion"),
        "capturedFrom": base_url,
        "provenance": "authenticated server capture (single planner node)",
        "manifest": {k: manifest.get(k) for k in (
            "corpusVersion", "promptVersion", "toolContractVersion",
            "toolSchemaHash", "baselineVersion", "schemaRegistryVersion",
            "guardRulesVersion")},
        "caseDigests": manifest.get("files", {}),
        "latencySummary": summarize_latency(latencies),
        "costNote": "proposal cost is recorded exactly as returned "
                    "(null/unreported when the provider omits it); never "
                    "zero-filled. Future sanitized billing corroboration via "
                    "the provider Management API stays separate: account-wide "
                    "daily totals cannot attribute exact cost to one run when "
                    "other callers share the account.",
        "proofExecution": "NOT_EXECUTED",
        "results": results,
    }
    out = Path(args.out)
    out.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    info(f"capture wrote {out} ({len(results)} cases retained)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score corpus v2 replays or capture a live run (explicit only).")
    sub = parser.add_subparsers(dest="command")
    replay = sub.add_parser("score-replay",
                            help="Score a replay file (default; never spends).")
    replay.add_argument("--replay", required=True,
                        help="Path to a {results: {caseId: entry}} JSON file.")
    replay.add_argument("--base-url", default="",
                        help="Optional backend for local guard re-adjudication "
                             "(no model call, no spend).")
    replay.add_argument("--token-env", default="SOVRA_EVAL_TOKEN",
                        help="Env var holding the backend token (never printed).")
    replay.add_argument("--timeout", type=int, default=30)
    capture = sub.add_parser("capture-live",
                             help="Capture one live run (spends credits; "
                                  "requires --confirm-spend).")
    capture.add_argument("--base-url", default="",
                         help="ONE central planner node base URL.")
    capture.add_argument("--token-env", default="SOVRA_EVAL_TOKEN")
    capture.add_argument("--timeout", type=int, default=180)
    capture.add_argument("--out", required=True,
                         help="Capture output path (sanitized JSON).")
    capture.add_argument("--confirm-spend", action="store_true",
                         help="Explicit spend confirmation. Without it, exits 2 "
                              "without calling the planner.")
    args = parser.parse_args()
    if args.command == "capture-live":
        return capture_live(args)
    if args.command == "score-replay":
        return score_replay(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
