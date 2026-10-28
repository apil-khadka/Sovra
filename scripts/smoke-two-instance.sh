#!/usr/bin/env bash
# SOV-003 smoke: build and boot two backend instances against one PostgreSQL,
# then prove both serve the health probe. Tears everything down on exit.
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

echo "smoke passed: two instances share one PostgreSQL"
