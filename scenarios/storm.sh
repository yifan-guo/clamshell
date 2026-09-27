#!/usr/bin/env bash
# Usage: ./storm.sh <container-name, e.g. clamshell-fleet-demo-battery-1>
set -e
C="${1:?usage: storm.sh <container-name>}"

echo ">> Storm hits — cutting power to $C"
docker compose stop "$C"
sleep 3

echo ">> Power restored — starting $C back up"
docker compose start "$C"

echo ">> Tailing logs (Ctrl-C to stop). Watch for:"
echo "   - TPM unseals fine on reboot (no security event, PCRs unchanged)"
echo "   - health check-in loop resuming with Fleet"
docker compose logs -f "$C"
