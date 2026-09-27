#!/usr/bin/env bash
# Usage: ./wave-rollout.sh <percent> [version]
set -e
PCT="${1:?usage: wave-rollout.sh <percent> [version]}"
VERSION="${2:-v2.0}"
FLEET_URL="${FLEET_URL:-http://localhost:8081}"

echo ">> Rolling out $VERSION to $PCT% of the fleet"
curl -sf -X POST -H 'Content-Type: application/json' \
  -d "{\"version\":\"$VERSION\",\"percent\":$PCT}" \
  "$FLEET_URL/rollout"
echo
echo ">> Each unit finds out on its next check-in (poll GET /update-check?ek_hash=...)."
echo ">> Current fleet status:"
curl -s "$FLEET_URL/status" | jq .
