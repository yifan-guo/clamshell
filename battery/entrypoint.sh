#!/usr/bin/env bash
# Battery unit entrypoint — plays the role of the compute board's boot
# sequence, from cold power-on through to a steady-state health loop.
#
# Stages map directly to the PRD bring-up flow:
#   1. iPXE bootstrap (stubbed: no real PXE/DHCP inside a container)
#   2. TPM attestation handshake with Clamshell
#   3. Cert issuance + OS image fetch (only on success)
#   4. LUKS provisioning, key sealed to TPM PCR policy
#   5. Steady-state health check-in loop with Fleet
#
# After a hard power loss (scenarios/storm.sh) the same entrypoint runs
# again. If the disk is already provisioned we skip attestation/LUKS
# format — re-attesting a confirmed EK would look like theft — and just
# unseal the existing key.
set -e
source /usr/local/bin/tpm-common.sh

CLAMSHELL_URL="${CLAMSHELL_URL:-http://clamshell:8080}"
FLEET_URL="${FLEET_URL:-http://fleet:8081}"
DISK_IMG="/var/lib/battery/disk.img"
DISK_SIZE_MB=256
NETWORK_ID="${NETWORK_ID:-$(hostname)-net}"   # stand-in for "which network segment"

log() { echo "[$(date +%H:%M:%S)] $*"; }

already_provisioned() {
  [ -f "$DISK_IMG" ] && \
    [ -f "$STATE_DIR/seal.pub" ] && \
    [ -f "$STATE_DIR/seal.priv" ] && \
    [ -f "$STATE_DIR/device.crt" ] && \
    [ -f "$STATE_DIR/cert_serial" ]
}

# Retries a curl call with backoff instead of failing on the first hiccup —
# a real unit doesn't give up because Clamshell took an extra second to
# come up, and this is genuinely required by the PRD's resumable-connection
# requirement, not just a sandbox workaround.
curl_retry() {
  local max=10 delay=1
  for i in $(seq 1 $max); do
    if OUT=$(curl -sf "$@" 2>/tmp/curl_err); then
      echo "$OUT"
      return 0
    fi
    log "  (attempt $i/$max failed, retrying in ${delay}s: $(cat /tmp/curl_err))"
    sleep "$delay"
    delay=$((delay * 2 > 15 ? 15 : delay * 2))
  done
  return 1
}

health_loop() {
  local cert_serial
  cert_serial=$(cat "$STATE_DIR/cert_serial")
  log "=== STEADY-STATE HEALTH LOOP ==="
  while true; do
    CHECKIN=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d "{\"ek_hash\":\"$(cat "$STATE_DIR/ek_hash.txt")\",\"cert_serial\":\"$cert_serial\",\"network_id\":\"$NETWORK_ID\",\"version\":\"${OS_VERSION:-v1.0}\"}" \
      "$FLEET_URL/checkin" 2>/dev/null) || CHECKIN='{"status":"unreachable"}'
    log "check-in: $CHECKIN"
    sleep 10
  done
}

unlock_existing_disk() {
  cryptsetup luksClose battery-disk >/dev/null 2>&1 || true
  local existing
  existing=$(losetup -j "$DISK_IMG" -O NAME -n 2>/dev/null || true)
  if [ -n "$existing" ]; then
    losetup -d $existing || true
  fi
  local loopdev
  loopdev=$(losetup -f)
  losetup "$loopdev" "$DISK_IMG"
  tpm_unseal_key "sha256:0,1,2,3,7" > "$STATE_DIR/luks.key"
  cryptsetup luksOpen "$loopdev" battery-disk --key-file "$STATE_DIR/luks.key"
  shred -u "$STATE_DIR/luks.key"
}

log "=== POWER ON ==="
if already_provisioned; then
  log "TPM present, encrypted disk found — this is a reboot, not a blank unit."
else
  log "No network config, no identity yet. TPM present, disk blank."
fi

log "=== iPXE BOOTSTRAP (stubbed) ==="
log "Would acquire DHCP lease + resolve clamshell.internal via DNS here."
curl -sf "$CLAMSHELL_URL/boot.ipxe" >/tmp/boot.ipxe && log "fetched boot.ipxe:" && cat /tmp/boot.ipxe
BUNDLE=$(curl_retry "$CLAMSHELL_URL/bootstrap-bundle") || { log "Clamshell unreachable after retries, aborting"; exit 1; }
log "CA root fetched (trust anchor established)."

log "=== TPM BOOT ==="
tpm_boot
tpm_identity
log "EK hash: $(cat "$STATE_DIR/ek_hash.txt")"

if already_provisioned; then
  log "=== RESUME AFTER POWER LOSS ==="
  log "Skipping attestation (EK already has a confirmed cert) and LUKS format."
  log "Unsealing disk key against current PCR[0,1,2,3,7]..."
  unlock_existing_disk
  log "TPM unseal OK — PCRs match the seal policy, disk unlocked."
  log "battery-$(cut -c1-8 "$STATE_DIR/ek_hash.txt") is now HEALTHY."
  health_loop
fi

log "=== ATTESTATION HANDSHAKE ==="
QUOTE_OUT=$(tpm_quote) || {
  log "!! tpm_quote failed. tpm2_quote log:"
  cat "$STATE_DIR/quote-tool.log" 2>/dev/null
  exit 1
}
MSG_B64=$(echo "$QUOTE_OUT" | sed -n '1p')
SIG_B64=$(echo "$QUOTE_OUT" | sed -n '2p')
if [ -z "$MSG_B64" ] || [ -z "$SIG_B64" ]; then
  log "!! tpm_quote produced empty output, aborting"
  exit 1
fi
PCR_DIGEST_B64=$(base64 -w0 "$STATE_DIR/pcrs.out")
AK_PEM_JSON=$(python3 -c "import json,sys; print(json.dumps(open('$STATE_DIR/ak.pem').read()))" 2>/dev/null || jq -Rs . < "$STATE_DIR/ak.pem")

REQ=$(cat <<JSON
{
  "ek_hash": "$(cat "$STATE_DIR/ek_hash.txt")",
  "ak_pub_pem": ${AK_PEM_JSON},
  "quote_msg_b64": "$MSG_B64",
  "quote_sig_b64": "$SIG_B64",
  "pcr_digest_b64": "$PCR_DIGEST_B64"
}
JSON
)

HTTP_CODE=""
for i in $(seq 1 10); do
  BODY_AND_CODE=$(curl -s -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -d "$REQ" "$CLAMSHELL_URL/attest")
  CURL_EXIT=$?
  if [ $CURL_EXIT -eq 0 ]; then
    HTTP_CODE=$(echo "$BODY_AND_CODE" | tail -1)
    RESP=$(echo "$BODY_AND_CODE" | sed '$d')
    break
  fi
  log "  (attempt $i/10: Clamshell not reachable yet, retrying)"
  sleep 2
done

if [ -z "$HTTP_CODE" ]; then
  log "!! Clamshell never became reachable after retries. Aborting."
  exit 1
fi
# A real HTTP response — 200 (issued) or 403 (denied) — is a real decision
# from Clamshell, not a network hiccup. We do NOT retry a 403: that's the
# whole point of the duplicate-EK / revocation checks actually working.
STATUS=$(echo "$RESP" | jq -r .status)

if [ "$STATUS" != "issued" ]; then
  REASON=$(echo "$RESP" | jq -r .reason)
  log "!! ATTESTATION REJECTED: $REASON"
  log "Stuck at bootstrap. No OS ever installed on this unit."
  exit 1
fi

log "Attestation OK. Cert issued: $(echo "$RESP" | jq -r .cert_serial)"
echo "$RESP" | jq -r .cert_pem > "$STATE_DIR/device.crt"
echo "$RESP" | jq -r .cert_serial > "$STATE_DIR/cert_serial"
OS_IMAGE_URL=$(echo "$RESP" | jq -r .os_image_url)

log "=== OS IMAGE FETCH ==="
# --max-time bounds this: without it, a stalled connection to clamshell (or
# a clamshell that's itself stuck reaching the upstream image URL) would
# hang here indefinitely instead of failing so `set -e` can catch it.
curl -sf --max-time 30 "$OS_IMAGE_URL" -o /var/lib/battery/os-image.bin
log "Downloaded $(du -h /var/lib/battery/os-image.bin | cut -f1) OS image."

log "=== LUKS PROVISIONING ==="
mkdir -p /var/lib/battery
dd if=/dev/zero of="$DISK_IMG" bs=1M count=$DISK_SIZE_MB status=none
LOOPDEV=$(losetup -f)
losetup "$LOOPDEV" "$DISK_IMG"
tpm_seal_new_key "sha256:0,1,2,3,7"
tpm_unseal_key "sha256:0,1,2,3,7" > "$STATE_DIR/luks.key"
cryptsetup luksFormat --type luks2 --batch-mode "$LOOPDEV" "$STATE_DIR/luks.key"
cryptsetup luksOpen "$LOOPDEV" battery-disk --key-file "$STATE_DIR/luks.key"
shred -u "$STATE_DIR/luks.key"
log "Disk encrypted, key sealed to TPM PCR[0,1,2,3,7]. Key never leaves this host."

log "=== REBOOT INTO FULL OS (simulated) ==="
sleep 1
log "battery-$(cut -c1-8 "$STATE_DIR/ek_hash.txt") is now HEALTHY."

health_loop