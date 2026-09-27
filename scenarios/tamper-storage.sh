#!/usr/bin/env bash
# Usage: ./tamper-storage.sh <container-name>
set -e
C="${1:?usage: tamper-storage.sh <container-name>}"
IMG="/tmp/stolen-disk-$$.img"

echo "=== PART 1: raw disk pulled, read attempted on attacker's own rig ==="
docker compose cp "$C":/var/lib/battery/disk.img "$IMG" || {
  echo "!! docker compose cp failed — try: docker cp \$(docker compose ps -q $C):/var/lib/battery/disk.img $IMG"
  exit 1
}
echo ">> Attempting to read the disk with no matching TPM (forensics rig, dummy key)"
docker run --rm --privileged -v "$IMG":/disk.img ubuntu:22.04 bash -c '
  apt-get update -qq >/dev/null && apt-get install -y -qq cryptsetup util-linux >/dev/null
  LOOP=$(losetup -f); losetup "$LOOP" /disk.img
  echo "--- LUKS2 header is readable (metadata is not secret) ---"
  cryptsetup luksDump "$LOOP" | head -15
  echo "--- attempting open with a made-up key (this is all an attacker without the TPM has) ---"
  head -c32 /dev/urandom > /tmp/wrong.key
  cryptsetup open "$LOOP" attacker-attempt --key-file /tmp/wrong.key && echo "!!! OPENED (should not happen)" || echo "=== FAILED TO OPEN: ciphertext only, as expected ==="
  losetup -d "$LOOP"
'
rm -f "$IMG"

echo
echo "=== PART 2: disk reinserted into original unit with a tampered bootloader ==="
echo ">> Simulating a modified boot chain by extending a PCR the seal policy covers"
docker compose exec "$C" bash -c '
  source /usr/local/bin/tpm-common.sh
  echo "PCR[4] before tamper:"; tpm2_pcrread sha256:4
  tpm2_pcrextend 4:sha256=$(echo -n "malicious-bootloader" | openssl dgst -sha256 -binary | xxd -p -c32)
  echo "PCR[4] after tamper:"; tpm2_pcrread sha256:4
  echo "-- attempting to unseal the LUKS key against the ORIGINAL policy --"
  tpm_unseal_key "sha256:0,1,2,3,7" >/tmp/attempt.key 2>&1 && echo "!!! UNSEALED (should not happen)" || echo "=== KEY RELEASE DENIED: PCR mismatch, as expected ==="
'
