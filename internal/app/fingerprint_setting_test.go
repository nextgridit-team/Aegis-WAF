package app

import (
	"context"
	"encoding/json"
	"testing"
)

// Traffic fingerprinting phase 1: a stable, computed JA4 TLS fingerprint per
// connection, exposed as a per-site opt-in identity dimension. The settings
// test must compile against unpatched main (it references no new symbols):
// on main the PUT is rejected, which is the behavioral red.

func TestProtectionClientFingerprintingSetting(t *testing.T) {
	a, c := investigationReplica(t)
	site := investigationSite(t, c, "Fingerprint setting", "fp-set.example.com")
	body := map[string]any{"mode": "off", "requests_per_second": 20, "burst": 60, "site_requests_per_second": 1000, "site_burst": 2000, "bot_mode": "off", "client_fingerprinting": true}
	var saved map[string]any
	json.Unmarshal(c.call("PUT", "/api/protection-settings/"+itoa(site), body, 200), &saved)
	if saved["client_fingerprinting"] != true {
		t.Fatalf("client_fingerprinting not persisted: %v", saved)
	}
	var raw []byte
	if e := a.db.QueryRow(context.Background(), "SELECT settings FROM protection_settings WHERE site_id=$1", site).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var stored map[string]any
	if e := json.Unmarshal(raw, &stored); e != nil || stored["client_fingerprinting"] != true {
		t.Fatalf("stored settings missing the opt-in: %s (%v)", raw, e)
	}
}
