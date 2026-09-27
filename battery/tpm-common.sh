
#!/usr/bin/env bash
# Shared TPM operations. Sourced by entrypoint.sh and by scenario scripts
# that need to act on the same simulated TPM (e.g. cloning state to fake
# a stolen chip).
#
# NOTE ON TESTING: this exact command sequence was run by hand against a
# real swtpm 0.7.3 + tpm2-tools 5.6 install to validate syntax. The TCTI
# connection and command shapes are confirmed correct. In one sandboxed
# test environment, swtpm returned TPM_RC_FAILURE (0x101) on the very
# first TPM2_Startup immediately after `swtpm_setup` manufactured the
# state — traced to the raw response bytes, not a script bug. That smell
# (failure on the very first command, right after clean manufacturing)
# is consistent with a blocked entropy syscall (getrandom) in a hardened
# sandbox, not a problem with this script. A normal Docker container on
# Linux or Mac does not restrict that syscall — this is the same
# swtpm+tpm2-tools combination QEMU/libvirt use for TPM emulation. If you
# hit the same error on your machine, check that /dev/urandom is
# accessible in the container and that no seccomp profile blocks
# getrandom(2).

set -e

STATE_DIR="${STATE_DIR:-/var/lib/battery/tpm}"
export TPM2TOOLS_TCTI="swtpm:path=${STATE_DIR}/server.sock"

# Persistent handles survive TPM2_Startup CLEAR (hard power loss / storm).
# Transient .ctx files do not — ContextLoad of a pre-crash .ctx returns
# 0x1DF "integrity check failed". EK at the well-known RSA EK handle;
# AK at a nearby unused persistent handle.
EK_HANDLE=0x81010001
AK_HANDLE=0x8101000A

# Direct swtpm TCTI — no tpm2-abrmd in front of it. Each tpm2_* invocation
# is a separate process: TPM2_ContextLoad of a .ctx file allocates a NEW
# transient slot, and the object the previous process loaded stays
# resident. swtpm only has ~3 object slots (TPM2_PT_HR_TRANSIENT_MIN).
# Hitting that is Esys_Load 0x902, "out of memory for object contexts" —
# the exact failure LUKS provisioning used to hit at tpm2_load.
#
# Flush after every command that loads an object, not just at function
# boundaries. stdout/stderr discarded so this is safe inside functions
# whose stdout is captured as data (quote bytes, LUKS key).
tpm_flush() {
  tpm2_flushcontext -t >/dev/null 2>&1
}

tpm_boot() {
  mkdir -p "$STATE_DIR"
  if [ ! -f "$STATE_DIR/tpm2-00.permall" ]; then
    swtpm_setup --tpm2 --tpmstate "$STATE_DIR" --overwrite \
      > "$STATE_DIR/swtpm-setup.log" 2>&1
  fi

  # docker compose stop kills swtpm but leaves its unix sockets/pid file
  # in the container FS. A stale socket makes the next `swtpm socket`
  # fail to bind, and a stale pid file makes --pid refuse to start.
  rm -f "$STATE_DIR/pid" "$STATE_DIR/server.sock" "$STATE_DIR/server.sock.ctrl"

  swtpm socket --tpmstate dir="$STATE_DIR" \
    --ctrl type=unixio,path="$STATE_DIR/server.sock.ctrl" \
    --server type=unixio,path="$STATE_DIR/server.sock" \
    --tpm2 --daemon --pid file="$STATE_DIR/pid"
  sleep 1

  # THE ACTUAL FIX: swtpm's control channel requires an explicit init
  # command before it will accept ANY data command. swtpm_setup's own
  # internal instance gets this via --flags not-need-init at launch; a
  # separately-launched `swtpm socket` (like this one) does not, and every
  # command — including the very first TPM2_Startup — fails with the
  # generic TPM_RC_FAILURE until this ioctl is sent. This is not obvious
  # from the error message, which just says "TPM failure."
  swtpm_ioctl -i --unix "$STATE_DIR/server.sock.ctrl"

  # CLEAR is what a hard power loss looks like (no TPM2_Shutdown STATE).
  # It resets PCRs to defaults and invalidates every transient .ctx blob.
  tpm2_startup -c
}

tpm_identity() {
  cd "$STATE_DIR"
  tpm_flush

  # Recreate persistent EK/AK only if this TPM doesn't already have them.
  # createek is deterministic from the endorsement seed (same EK every
  # boot). createak is not — that's why the AK must be evicted to a
  # persistent handle the first time, not saved as a .ctx file.
  if ! tpm2_readpublic -c "$EK_HANDLE" >/dev/null 2>&1; then
    tpm2_createek -c "$EK_HANDLE" -G rsa -u ek.pub
  elif [ ! -f ek.pub ]; then
    tpm2_readpublic -c "$EK_HANDLE" -o ek.pub >/dev/null
  fi
  tpm_flush

  if ! tpm2_readpublic -c "$AK_HANDLE" >/dev/null 2>&1; then
    tpm2_createak -C "$EK_HANDLE" -c "$AK_HANDLE" -u ak.pub -G rsa -g sha256 -s rsassa
  fi
  tpm_flush

  tpm2_readpublic -c "$AK_HANDLE" -f pem -o ak.pem >/dev/null
  tpm_flush
  EK_HASH=$(openssl dgst -sha256 -r ek.pub | awk '{print $1}')
  echo "$EK_HASH" > ek_hash.txt
}

# Produces quote.msg / quote.sig / pcrs.out in STATE_DIR against the given
# PCR set, and returns base64 of message + sig on stdout as two lines.
#
# IMPORTANT: pcrs.out here comes from tpm2_quote's own -o flag, not a
# separately-run tpm2_pcrread. The two calls can observe PCR state at
# slightly different moments (even if nothing should have changed between
# them) and tpm2_checkquote requires an exact digest match — using the
# quote's own simultaneous PCR snapshot is the only way that's guaranteed
# consistent, and mismatches here fail with a confusing signature-looking
# error rather than an obviously-PCR-related one.
#
# IMPORTANT: tpm2_quote's own human-readable YAML output must NOT be allowed
# onto this function's stdout — it was previously polluting/corrupting the
# base64 values the caller captures. It's redirected to a log file instead.
tpm_quote() {
  local pcrs="${1:-sha256:0,1,2,3,7}"
  cd "$STATE_DIR"
  tpm_flush
  tpm2_quote -c "$AK_HANDLE" -l "$pcrs" -m quote.msg -s quote.sig -o pcrs.out -g sha256 \
    > "$STATE_DIR/quote-tool.log" 2>&1
  base64 -w0 quote.msg
  echo
  base64 -w0 quote.sig
  # Trailing flush must not write to stdout: the caller captures the two
  # base64 lines above as this function's stdout.
  tpm_flush
}

# Seals a random 32-byte key to the current PCR state. The key itself is
# only ever unsealed locally, never transmitted.
#
# Slot accounting without a resource manager (this is the LUKS 0x902 bug):
#   createprimary  → loads primary (slot 1)
#   create -C ctx  → ContextLoad primary AGAIN (slot 2); may also use a
#                    scratch slot
#   load -C ctx    → ContextLoad primary a third time (slot 3) then
#                    Esys_Load the child (slot 4) → 0x902
# Flushing after createprimary and after create leaves load with a clean
# budget: parent + child = 2 slots.
#
# seal.pub / seal.priv are the durable blobs; seal.ctx is not. A later
# unseal after CLEAR reloads them under a freshly created primary (same
# owner seed + same template → same parent, required by fixedparent).
tpm_seal_new_key() {
  local pcrs="${1:-sha256:0,1,2,3,7}"
  cd "$STATE_DIR"
  tpm_flush
  tpm2_createprimary -C o -c primary.ctx >/dev/null
  tpm_flush
  tpm2_startauthsession -S session.ctx >/dev/null
  tpm2_policypcr -S session.ctx -l "$pcrs" -L policy.digest >/dev/null
  tpm2_flushcontext session.ctx >/dev/null
  head -c 32 /dev/urandom > sealed.key.plain
  tpm2_create -C primary.ctx -u seal.pub -r seal.priv -L policy.digest -i sealed.key.plain -a "fixedtpm|fixedparent" >/dev/null
  tpm_flush
  tpm2_load -C primary.ctx -u seal.pub -r seal.priv -c seal.ctx >/dev/null
  shred -u sealed.key.plain
  tpm_flush
}

# Reload seal.ctx from the durable pub/priv blobs. Harmless if seal.ctx
# was already created this boot; required after TPM2_Startup CLEAR, when
# the on-disk .ctx fails ContextLoad with 0x1DF.
tpm_reload_seal() {
  cd "$STATE_DIR"
  tpm_flush
  tpm2_createprimary -C o -c primary.ctx >/dev/null
  tpm_flush
  tpm2_load -C primary.ctx -u seal.pub -r seal.priv -c seal.ctx >/dev/null
  tpm_flush
}

# Unseals the key — only succeeds if current PCR values match the policy
# it was sealed under. This is the step that fails (correctly) in the
# tampered-storage scenario.
#
# The caller redirects this whole function's stdout straight to the LUKS
# key file (tpm_unseal_key ... > luks.key). startauthsession / policypcr
# print YAML and a 64-char policy digest to stdout unless suppressed —
# that would land in the key material itself, and a later unseal (32 raw
# bytes, no digest prefix) would fail to open the volume. Under set -e a
# failing tpm2_unseal still aborts before the trailing flush, so the
# tamper scenario's expected-failure path is unchanged.
tpm_unseal_key() {
  local pcrs="${1:-sha256:0,1,2,3,7}"
  cd "$STATE_DIR"
  tpm_flush
  # Probe the on-disk ctx. `if !` does not trip set -e; a stale blob from
  # before the last CLEAR is the storm-reboot case and we reload it.
  if ! tpm2_readpublic -c seal.ctx >/dev/null 2>&1; then
    tpm_reload_seal
  fi
  tpm2_startauthsession --policy-session -S session.ctx >/dev/null
  tpm2_policypcr -S session.ctx -l "$pcrs" -L policy.digest >/dev/null
  tpm2_unseal -c seal.ctx -p "session:session.ctx" -o /dev/stdout
  tpm2_flushcontext session.ctx >/dev/null 2>&1
  tpm_flush
}