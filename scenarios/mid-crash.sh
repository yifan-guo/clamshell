#!/usr/bin/env bash
# Usage: ./mid-crash.sh <container-name>
# Times a hard kill for right after cert issuance but before the first
# successful Fleet check-in — the exact window where a naive duplicate-EK
# check would wrongly treat a legitimate retry as theft. Watch the
# Clamshell logs for "retrying after an unconfirmed prior attempt".
set -e
C="${1:?usage: mid-crash.sh <container-name>}"

echo ">> Starting $C fresh"
docker compose stop "$C" >/dev/null 2>&1 || true
docker compose rm -f "$C" >/dev/null 2>&1 || true
docker compose up -d "$C"

echo ">> Watching for cert issuance, then killing -9 before first check-in..."
( docker compose logs -f "$C" & echo $! > /tmp/logpid ) | \
  while read -r line; do
    echo "$line"
    if echo "$line" | grep -q "Cert issued"; then
      sleep 1
      echo ">> KILLING -9 NOW (simulating a crash mid-provisioning)"
      docker kill "$(docker compose ps -q "$C")" 2>/dev/null
      kill "$(cat /tmp/logpid)" 2>/dev/null
      break
    fi
  done

sleep 1
echo ">> Restarting the same unit — it should retry attestation and succeed,"
echo "   because Clamshell never saw a confirmed check-in for that cert."
docker compose start "$C"
docker compose logs -f "$C"
