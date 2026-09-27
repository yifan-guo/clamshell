#!/usr/bin/env bash
# Usage: ./steal-compute.sh <container-name>
# Clones the TPM identity state out of a running, already-healthy unit
# (representing "attacker physically pried out compute + TPM") and boots
# a fresh one-off container with that stolen state but NO disk — the
# attacker's own blank disk — pointed at a different simulated network.
set -e
C="${1:?usage: steal-compute.sh <container-name>}"
TMP="/tmp/stolen-tpm-$$"

echo ">> Physically removing compute+TPM from $C (copying its TPM state only)"
mkdir -p "$TMP"
docker compose cp "$C":/var/lib/battery/tpm/. "$TMP" || {
  echo "!! docker compose cp failed — try: docker cp \$(docker compose ps -q $C):/var/lib/battery/tpm/. $TMP"
  exit 1
}
echo "   (the disk stays behind in $C — the attacker does not have it)"

echo ">> Attacker boots the stolen board on their own network with a blank disk"
docker compose run --rm --name stolen-unit \
  -e NETWORK_ID=attacker-lan \
  -v "$TMP":/var/lib/battery/tpm \
  battery

echo ">> Expect: quote passes (genuine TPM), but Clamshell rejects —"
echo "   this EK already has a CONFIRMED cert issued to the real unit."
rm -rf "$TMP"
