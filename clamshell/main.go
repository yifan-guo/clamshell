// Clamshell — the provisioning server.
//
// Responsibilities, in strict order (never reversed — see PRD "no unlocking
// material is ever transmitted before full verification completes"):
//   1. Serve an iPXE-style bootstrap script + CA root (no secrets yet).
//   2. Verify a TPM2 attestation quote from the unit.
//   3. Only if valid AND the EK has no existing active cert: issue one
//      via step-ca, and hand back the OS image location.
//   4. Track every issued EK -> cert-serial mapping so a second request
//      for the same EK (stolen-compute scenario) is refused outright.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const stateDir = "/state"

// jsonError writes a JSON body ({"status":"error","reason":...}) instead of
// Go's default http.Error(), which writes plain text. The battery side
// always does `jq -r .status` / `jq -r .reason` on responses from this
// service, so any error path that isn't valid JSON breaks that parsing with
// a confusing, unrelated-looking jq error instead of the real reason.
func jsonError(w http.ResponseWriter, reason string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"status": "error", "reason": reason})
}

type registryEntry struct {
	EKHash     string    `json:"ek_hash"`
	CertSerial string    `json:"cert_serial"`
	IssuedAt   time.Time `json:"issued_at"`
	Revoked    bool      `json:"revoked"`
	// Confirmed becomes true only once Fleet reports the unit's first
	// successful health check-in on this cert. Until then, a cert is
	// "provisional" — if the unit crashed mid-provision and retries, that
	// looks identical to a thief replaying the same EK. We can't tell
	// those apart from the attestation alone, so we allow re-issuance for
	// an unconfirmed EK (legitimate retry after a crash) but permanently
	// refuse it once confirmed (now it would mean two claimants for one
	// real, working device — the actual theft signal).
	Confirmed bool `json:"confirmed"`
}

type registry struct {
	mu      sync.Mutex
	path    string
	entries map[string]registryEntry // key: EKHash
}

func loadRegistry() *registry {
	r := &registry{path: filepath.Join(stateDir, "registry.json"), entries: map[string]registryEntry{}}
	if b, err := os.ReadFile(r.path); err == nil {
		_ = json.Unmarshal(b, &r.entries)
	}
	return r
}

func (r *registry) save() {
	b, _ := json.MarshalIndent(r.entries, "", "  ")
	_ = os.MkdirAll(stateDir, 0o755)
	_ = os.WriteFile(r.path, b, 0o644)
}

// checkAndReserve returns (allowed, reason). It's the duplicate-EK gate —
// see the Confirmed field comment above for why "unconfirmed" is allowed
// to retry rather than being permanently blocked.
func (r *registry) checkAndReserve(ekHash string) (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.entries[ekHash]; ok {
		if existing.Revoked {
			return false, "ek_revoked"
		}
		if existing.Confirmed {
			return false, "duplicate_ek_active_cert"
		}
		// Unconfirmed prior attempt — likely a crash before first
		// check-in. Allow the retry; the stale cert serial is simply
		// superseded (it was never used successfully).
		return true, "reissue_unconfirmed"
	}
	return true, ""
}

func (r *registry) confirm(ekHash string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[ekHash]
	if !ok {
		return false
	}
	e.Confirmed = true
	r.entries[ekHash] = e
	r.save()
	return true
}

func (r *registry) record(ekHash, serial string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[ekHash] = registryEntry{EKHash: ekHash, CertSerial: serial, IssuedAt: time.Now()}
	r.save()
}

func (r *registry) revoke(ekHash string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[ekHash]
	if !ok {
		return false
	}
	e.Revoked = true
	r.entries[ekHash] = e
	r.save()
	return true
}

type attestRequest struct {
	EKHash    string `json:"ek_hash"`     // sha256 of the EK public key, sent as the stable identity
	AKPubPEM  string `json:"ak_pub_pem"`  // attestation key public, PEM
	QuoteMsg  string `json:"quote_msg_b64"`
	QuoteSig  string `json:"quote_sig_b64"`
	PCRDigest string `json:"pcr_digest_b64"` // expected PCR composite digest, from tpm2_pcrread
}

func writeTemp(dir, name string, b []byte) string {
	p := filepath.Join(dir, name)
	_ = os.WriteFile(p, b, 0o600)
	return p
}

// verifyQuote shells out to tpm2_checkquote — the real verification tool
// shipped with tpm2-tools, rather than reimplementing TPM2's attestation
// structure parsing here. Exact flags depend on your installed tpm2-tools
// version; run `tpm2_checkquote --help` in the clamshell container if this
// needs adjusting locally.
func verifyQuote(req attestRequest) error {
	dir, err := os.MkdirTemp("", "attest-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	akPub := writeTemp(dir, "ak.pem", []byte(req.AKPubPEM))
	msgB, err := b64decode(req.QuoteMsg)
	if err != nil {
		return fmt.Errorf("bad quote message: %w", err)
	}
	sigB, err := b64decode(req.QuoteSig)
	if err != nil {
		return fmt.Errorf("bad quote signature: %w", err)
	}
	pcrB, err := b64decode(req.PCRDigest)
	if err != nil {
		return fmt.Errorf("bad pcr values: %w", err)
	}
	msg := writeTemp(dir, "quote.msg", msgB)
	sig := writeTemp(dir, "quote.sig", sigB)
	// Despite the field name (kept for wire-compatibility with the
	// battery's request payload), this must be the PCR *values* file that
	// tpm2_quote itself wrote via its own -o flag — not a separately-run
	// tpm2_pcrread — since the two can observe PCR state at very slightly
	// different moments and tpm2_checkquote requires an exact match.
	pcrFile := writeTemp(dir, "pcrs.out", pcrB)

	cmd := exec.Command("tpm2_checkquote",
		"-u", akPub,
		"-m", msg,
		"-s", sig,
		"-f", pcrFile,
		"-g", "sha256",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tpm2_checkquote failed: %v: %s", err, string(out))
	}
	return nil
}

// issueCert shells out to the step CLI against step-ca. Requires the
// clamshell container to be bootstrapped against step-ca (see Dockerfile).
func issueCert(ekHash string) (certPEM string, serial string, err error) {
	dir, err := os.MkdirTemp("", "cert-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)

	cn := "battery-" + ekHash[:12]
	crtPath := filepath.Join(dir, "device.crt")
	keyPath := filepath.Join(dir, "device.key")

	// STEPCA_PASSWORD arrives as a plain env var from docker-compose.yml —
	// there is no Docker secret actually wired up (the earlier
	// /run/secrets/stepca-password path pointed at a file that was never
	// going to exist). step's --password-file flag still needs an actual
	// file, so write the env var out to one, scoped to this cert's temp dir
	// and cleaned up with it.
	pass := os.Getenv("STEPCA_PASSWORD")
	if pass == "" {
		return "", "", fmt.Errorf("STEPCA_PASSWORD is not set")
	}
	passPath := filepath.Join(dir, "stepca-password")
	if err := os.WriteFile(passPath, []byte(pass), 0600); err != nil {
		return "", "", fmt.Errorf("writing password file: %v", err)
	}

	tokenCmd := exec.Command("step", "ca", "token", cn,
		"--provisioner", os.Getenv("STEPCA_PROVISIONER"),
		"--password-file", passPath,
		"--ca-url", os.Getenv("STEPCA_URL"),
		"--root", "/stepca/certs/root_ca.crt",
	)
	// step writes the token itself to stdout and human-readable status
	// lines (e.g. "✔ Provisioner: ...") to stderr. CombinedOutput() merges
	// the two, which would corrupt the token with that confirmation text.
	// Capture the streams separately instead.
	var tokenStdout, tokenStderr bytes.Buffer
	tokenCmd.Stdout = &tokenStdout
	tokenCmd.Stderr = &tokenStderr
	if err := tokenCmd.Run(); err != nil {
		return "", "", fmt.Errorf("step ca token failed: %v: %s", err, tokenStderr.String())
	}
	token := strings.TrimSpace(tokenStdout.String())
	if token == "" {
		return "", "", fmt.Errorf("step ca token produced no output on stdout (stderr: %s)", tokenStderr.String())
	}

	// step-ca's JWK provisioner defaults to a 24h maxTLSCertDuration with no
	// way to raise it via the docker-init env vars this stack uses
	// (DOCKER_STEPCA_INIT_*) — only editing ca.json or `step ca provisioner
	// update` against a running admin API can do that. 2160h (90 days) was
	// well past that ceiling and got a hard 403 from the CA every time.
	// Falling back to 23h — comfortably under the 24h limit while still
	// giving the demo real cert issuance/expiry/revocation behavior to show.
	// A production deployment issuing genuinely 90-day device certs would
	// need to raise maxTLSCertDuration in the provisioner's own claims.
	certCmd := exec.Command("step", "ca", "certificate", cn, crtPath, keyPath,
		"--token", token,
		"--ca-url", os.Getenv("STEPCA_URL"),
		"--root", "/stepca/certs/root_ca.crt",
		"--not-after", "23h",
	)
	certOut, err := certCmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("step ca certificate failed: %v: %s", err, string(certOut))
	}

	crtBytes, err := os.ReadFile(crtPath)
	if err != nil {
		return "", "", err
	}
	// Serial is embedded in the cert; for the demo, use a timestamp-based
	// placeholder if you want to avoid parsing x509 here.
	serial = fmt.Sprintf("%s-%d", cn, time.Now().Unix())
	_ = certOut
	return string(crtBytes), serial, nil
}

func main() {
	reg := loadRegistry()

	http.HandleFunc("/boot.ipxe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, `#!ipxe
echo Fetching bootstrap bundle from Clamshell...
echo (in this demo, the battery entrypoint does this over HTTP directly)
chain http://clamshell:8080/bootstrap-bundle
`)
	})

	http.HandleFunc("/bootstrap-bundle", func(w http.ResponseWriter, r *http.Request) {
		root, err := os.ReadFile("/stepca/certs/root_ca.crt")
		if err != nil {
			jsonError(w, "CA root not available yet: "+err.Error(), 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ca_root_pem": string(root)})
	})

	http.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		var req attestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request: "+err.Error(), 400)
			return
		}
		log.Printf("attestation attempt from EK %s", req.EKHash)

		allowed, reason := reg.checkAndReserve(req.EKHash)
		if !allowed {
			log.Printf("REJECTED EK %s: %s", req.EKHash, reason)
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"status": "denied", "reason": reason})
			return
		}
		if reason == "reissue_unconfirmed" {
			log.Printf("EK %s retrying after an unconfirmed prior attempt (likely a crash before first check-in) — allowing", req.EKHash)
		}

		if err := verifyQuote(req); err != nil {
			log.Printf("REJECTED EK %s: quote verification failed: %v", req.EKHash, err)
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"status": "denied", "reason": "quote_verification_failed"})
			return
		}

		certPEM, serial, err := issueCert(req.EKHash)
		if err != nil {
			log.Printf("cert issuance failed for EK %s: %v", req.EKHash, err)
			jsonError(w, "cert issuance failed: "+err.Error(), 500)
			return
		}
		reg.record(req.EKHash, serial)
		log.Printf("ISSUED cert %s for EK %s", serial, req.EKHash)

		json.NewEncoder(w).Encode(map[string]string{
			"status":        "issued",
			"cert_pem":      certPEM,
			"cert_serial":   serial,
			"os_image_url":  "http://clamshell:8080/image",
			"pcr_policy":    "sha256:0,1,2,3,7",
		})
	})

	http.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EKHash string `json:"ek_hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "bad request", 400)
			return
		}
		ok := reg.confirm(body.EKHash)
		if ok {
			log.Printf("CONFIRMED EK %s (first successful check-in reported by Fleet)", body.EKHash)
		}
		json.NewEncoder(w).Encode(map[string]bool{"confirmed": ok})
	})

	http.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EKHash string `json:"ek_hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "bad request", 400)
			return
		}
		ok := reg.revoke(body.EKHash)
		json.NewEncoder(w).Encode(map[string]bool{"revoked": ok})
	})

	http.HandleFunc("/image", func(w http.ResponseWriter, r *http.Request) {
		url := os.Getenv("OS_IMAGE_URL")
		// http.Get uses http.DefaultClient, which has NO timeout. If the
		// real OS_IMAGE_URL (cloud-images.ubuntu.com) isn't reachable from
		// inside this container — e.g. no outbound internet on the compose
		// network — the connection just hangs forever instead of erroring,
		// so the OS_IMAGE_FALLBACK_LOCAL path below never gets a chance to
		// run. A bounded client makes the "can't reach it" case fail fast
		// instead of wedging the whole attestation flow.
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(url)
		if err != nil || resp.StatusCode != 200 {
			if os.Getenv("OS_IMAGE_FALLBACK_LOCAL") == "true" {
				log.Printf("real image unreachable (%v), serving local placeholder", err)
				f, ferr := os.Open("/state/placeholder-os-image.bin")
				if ferr != nil {
					jsonError(w, "no image available", 503)
					return
				}
				defer f.Close()
				io.Copy(w, f)
				return
			}
			jsonError(w, "image fetch failed", 502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, resp.Body)
	})

	log.Println("Clamshell listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func b64decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
