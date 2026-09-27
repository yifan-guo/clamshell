# Clamshell — Battery Fleet Provisioning Demo

A runnable, mostly-real demo of the architecture from the PRD: a battery unit
attests to Clamshell via TPM, gets a device certificate from a real CA
(step-ca), seals its disk-encryption key to the TPM (real LUKS2 +
tpm2-tools against a software TPM), and checks in with a Fleet server.

**Testing notes:** this sandbox has no Docker, so the full multi-container
stack was never run via `docker compose up` here. What *was* verified
directly, for real, against a real `swtpm` + `tpm2-tools` install (not
guessed at from documentation):

- Both Go services compile cleanly, and every shell script passes `bash -n`.
- The complete TPM attestation chain — `swtpm socket` startup, `tpm2_createek`,
  `tpm2_createak`, `tpm2_quote`, and `tpm2_checkquote` on the Clamshell side —
  was run end-to-end and produces a genuine cryptographic pass. Two real bugs
  were found and fixed in the process, not guessed at:
  1. **The actual root cause of `TPM_RC_FAILURE` on startup:** swtpm's control
     channel requires an explicit init command (`swtpm_ioctl -i --unix
     <ctrl-socket>`) before it will accept *any* TPM command. `swtpm_setup`'s
     own internal instance gets this automatically via `--flags
     not-need-init`; a separately-launched `swtpm socket` (what our script
     does) does not, and every command — including the very first
     `TPM2_Startup` — fails with the generic, unhelpful `TPM_RC_FAILURE`
     until that ioctl is sent. This was found by `strace`-ing `swtpm_setup`
     to see its own internal invocation, not by guessing. (Earlier drafts of
     this README speculated about entropy syscalls and container isolation
     layers — that was wrong; this is the real cause, and it's
     environment-independent, which is why it reproduced identically both in
     this sandbox and in your Docker Desktop / Apple Silicon setup.)
  2. **`tpm2_checkquote`'s `-q` flag is the nonce/qualifying-data, not the
     PCR values** — the correct flag is `-f`/`--pcr`, and it must be given
     the exact PCR-values file that `tpm2_quote` wrote via its own `-o` flag
     at quote time, not a separately-run `tpm2_pcrread` snapshot (the two
     can observe PCR state at very slightly different moments, and any
     mismatch fails as if the signature itself were bad, which is
     misleading). Both `battery/tpm-common.sh` and `clamshell/main.go` are
     updated accordingly.
  3. Software TPMs have very few transient object slots without a resource
     manager (`tpm2-abrmd`); `tpm2_flushcontext -t` is now called between
     steps to avoid `out of memory for object contexts` errors.
- step-ca's exact provisioner/token flags were written from documentation,
  not run against a live step-ca — still the most likely remaining spot to
  need a small local adjustment.

## A real design gap this surfaced

Building the mid-crash scenario exposed a genuine bug in the naive version
of the duplicate-EK check: if a legitimate unit crashes *after* getting its
certificate but *before* its first successful Fleet check-in, retrying
attestation looks cryptographically identical to a thief replaying the same
EK — both are "this EK already has a cert, requesting another." Fixed by
adding a `confirmed` state: a cert starts *provisional*, Fleet tells
Clamshell once a unit's first successful check-in happens, and only a
**confirmed** cert blocks re-issuance. An unconfirmed one (crashed before
ever checking in) is allowed to retry. This is now in `clamshell/main.go`
and `fleet/main.go` (see the `Confirmed` field and `/confirm` endpoint).

## What's real vs. simulated

| Piece | Real | Simulated / stubbed |
|---|---|---|
| TPM | swtpm (software TPM) — real TPM2 protocol, real tpm2-tools | Not physical hardware, by design (locked in earlier) |
| Disk encryption | Real LUKS2 on a loopback file via `cryptsetup` | The "disk" is a file, not a physical eMMC |
| Key sealing | Real `tpm2_create` + PCR policy via `tpm2_policypcr` | PCR values are the container's own boot measurements, not real firmware/bootloader measurements — there's no real firmware to measure inside a container |
| Certificate Authority | Real step-ca, real X.509 certs | — |
| OS image | Real Ubuntu 22.04 cloud image, if `OS_IMAGE_URL` points at Canonical's real URL | Defaults to a small local placeholder file so the demo works offline; swap the env var for the real download |
| iPXE | An HTTP endpoint serving a real iPXE script | Not an actual PXE/DHCP boot — no container can netboot itself; the battery entrypoint fetches and "executes" (logs) the script instead |
| Bootloader chain (ROM → iPXE) | — | Skipped; container starts already past that stage |

## Layout

```
clamshell/    Go service: attestation verification, duplicate-EK detection, cert issuance via step-ca, image serving
fleet/        Go service: health check-ins, anomaly flagging, wave rollout control
battery/      The simulated unit: entrypoint.sh runs the real boot sequence (swtpm, tpm2-tools, cryptsetup, curl)
stepca/       step-ca bootstrap config
scenarios/    Scripts to trigger each demo scenario against a running stack
docker-compose.yml
```

## Running it

```
docker compose up --build
docker compose up --build --scale battery=5   # multiple units
```

Then in another terminal:
```
./scenarios/storm.sh battery-1          # kill power, watch it recover
./scenarios/steal-compute.sh battery-1  # clone the TPM state, no disk, watch it get rejected
./scenarios/tamper-storage.sh battery-1 # pull the disk, try to read it cold
./scenarios/mid-crash.sh battery-1      # kill -9 mid-provisioning, watch it resume safely
./scenarios/wave-rollout.sh 20          # roll a patch out to 20% of the fleet
```

Everything logs to stdout per-container (`docker compose logs -f battery-1`) —
no UI, as decided; this is meant to be read live in a terminal during a demo.
