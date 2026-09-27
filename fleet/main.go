// Fleet Server — receives health check-ins, flags network anomalies
// (the piece that catches a technically-valid-but-stolen unit that
// Clamshell's duplicate-EK check didn't have to deal with because it's
// a *different* unit re-checking-in from a *different* place), and
// controls staged ("wave") patch rollout.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// confirmWithClamshell tells Clamshell this EK has now completed a full
// provisioning cycle (attested + issued + booted + checked in), so its
// cert moves from "provisional" to "confirmed" — see the Confirmed field
// comment in clamshell/main.go for why this distinction exists.
func confirmWithClamshell(ekHash string) {
	url := os.Getenv("CLAMSHELL_URL")
	if url == "" {
		url = "http://clamshell:8080"
	}
	body, _ := json.Marshal(map[string]string{"ek_hash": ekHash})
	resp, err := http.Post(url+"/confirm", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("could not confirm EK %s with Clamshell: %v", ekHash, err)
		return
	}
	resp.Body.Close()
}

const stateDir = "/state"
const unhealthyAfter = 45 * time.Second // demo-scale timeout, not real-world

type unit struct {
	EKHash          string    `json:"ek_hash"`
	CertSerial      string    `json:"cert_serial"`
	FirstNetwork    string    `json:"first_network"`
	LastNetwork     string    `json:"last_network"`
	LastCheckin     time.Time `json:"last_checkin"`
	Status          string    `json:"status"` // healthy | unhealthy | quarantined
	Version         string    `json:"version"`
	AnomalyReason   string    `json:"anomaly_reason,omitempty"`
	ConfirmedWithCA bool      `json:"confirmed_with_ca"`
}

type rollout struct {
	Version string `json:"version"`
	Percent int    `json:"percent"`
}

type store struct {
	mu      sync.Mutex
	units   map[string]*unit
	rollout rollout
	path    string
}

func loadStore() *store {
	s := &store{units: map[string]*unit{}, path: filepath.Join(stateDir, "fleet.json")}
	if b, err := os.ReadFile(s.path); err == nil {
		var payload struct {
			Units   map[string]*unit `json:"units"`
			Rollout rollout          `json:"rollout"`
		}
		if json.Unmarshal(b, &payload) == nil {
			s.units = payload.Units
			s.rollout = payload.Rollout
		}
	}
	return s
}

func (s *store) save() {
	payload := struct {
		Units   map[string]*unit `json:"units"`
		Rollout rollout          `json:"rollout"`
	}{s.units, s.rollout}
	b, _ := json.MarshalIndent(payload, "", "  ")
	_ = os.MkdirAll(stateDir, 0o755)
	_ = os.WriteFile(s.path, b, 0o644)
}

// inWave deterministically buckets an EK into 0-99 so the same unit stays
// in or out of a wave consistently rather than re-rolling dice each check.
func inWave(ekHash string, percent int) bool {
	h := sha256.Sum256([]byte(ekHash))
	bucket := int(h[0]) % 100
	return bucket < percent
}

func main() {
	s := loadStore()

	go func() {
		for range time.Tick(10 * time.Second) {
			s.mu.Lock()
			for _, u := range s.units {
				if u.Status == "healthy" && time.Since(u.LastCheckin) > unhealthyAfter {
					u.Status = "unhealthy"
					log.Printf("%s missed check-in window -> unhealthy", u.EKHash)
				}
			}
			s.save()
			s.mu.Unlock()
		}
	}()

	http.HandleFunc("/checkin", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EKHash     string `json:"ek_hash"`
			CertSerial string `json:"cert_serial"`
			NetworkID  string `json:"network_id"` // stand-in for "which network segment this came from"
			Version    string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()

		u, exists := s.units[body.EKHash]
		if !exists {
			u = &unit{EKHash: body.EKHash, FirstNetwork: body.NetworkID}
			s.units[body.EKHash] = u
		}
		u.CertSerial = body.CertSerial
		u.LastCheckin = time.Now()
		u.LastNetwork = body.NetworkID
		u.Version = body.Version

		if u.Status == "quarantined" {
			// Once quarantined, a check-in alone doesn't clear it — that
			// needs an explicit /clear-quarantine action (a human decision).
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"status": "quarantined"})
			return
		}

		if exists && u.FirstNetwork != "" && body.NetworkID != u.FirstNetwork && u.AnomalyReason == "" {
			// This is deliberately naive for the demo: any network change trips it.
			// A real version would compare against known-good IP/ASN/geo ranges,
			// not exact string equality.
			u.Status = "quarantined"
			u.AnomalyReason = fmt.Sprintf("network changed from %s to %s", u.FirstNetwork, body.NetworkID)
			log.Printf("ANOMALY %s: %s", u.EKHash, u.AnomalyReason)
			s.save()
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"status": "quarantined", "reason": u.AnomalyReason})
			return
		}

		u.Status = "healthy"
		firstConfirm := !u.ConfirmedWithCA
		if firstConfirm {
			u.ConfirmedWithCA = true
		}
		s.save()
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})

		if firstConfirm {
			go confirmWithClamshell(body.EKHash)
		}
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		json.NewEncoder(w).Encode(s.units)
	})

	http.HandleFunc("/rollout", func(w http.ResponseWriter, r *http.Request) {
		var body rollout
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		s.mu.Lock()
		s.rollout = body
		s.save()
		s.mu.Unlock()
		log.Printf("rollout set: version=%s percent=%d%%", body.Version, body.Percent)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/update-check", func(w http.ResponseWriter, r *http.Request) {
		ek := r.URL.Query().Get("ek_hash")
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.rollout.Version == "" || !inWave(ek, s.rollout.Percent) {
			json.NewEncoder(w).Encode(map[string]bool{"update_available": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"update_available": true,
			"version":          s.rollout.Version,
		})
	})

	log.Println("Fleet server listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
