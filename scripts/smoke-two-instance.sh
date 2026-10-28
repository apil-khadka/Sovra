#!/usr/bin/env bash
# SOV-003 smoke: build and boot two backend instances against one PostgreSQL,
# then prove both serve the liveness and semantic-readiness probes.
# Tears everything down on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

cleanup() {
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose up -d --build

for port in 8080 8081; do
  for i in $(seq 1 40); do
    if curl -sf "http://localhost:${port}/api/health" | grep -q '"status":"UP"'; then
      echo "instance on ${port} is UP"
      break
    fi
    if [ "$i" = 40 ]; then
      echo "instance on ${port} never became healthy" >&2
      docker compose logs --tail=50
      exit 1
    fi
    sleep 3
  done
done

# SOV-029: both instances also report semantic flow readiness. A fresh
# stack ships the synthetic genesis snapshot and key (V6), so readiness
# is READY with live authority; the closed-readiness paths (stale
# authority, commit failure, freeze) are covered by backend tests.
ready_body="$(mktemp)"
trap 'rm -f "$ready_body"; cleanup' EXIT
for port in 8080 8081; do
  ready_code=$(curl -s -o "$ready_body" -w '%{http_code}' \
    "http://localhost:${port}/api/health/ready")
  if [ "$ready_code" != 200 ] \
      || ! grep -q '"status":"READY"' "$ready_body" \
      || ! grep -q 'authority_live' "$ready_body"; then
    echo "instance on ${port} should report READY/authority_live" >&2
    echo "got HTTP ${ready_code}: $(cat "$ready_body")" >&2
    exit 1
  fi
  echo "instance on ${port} reports READY with live authority"
done

echo "smoke passed: two instances share one PostgreSQL"
