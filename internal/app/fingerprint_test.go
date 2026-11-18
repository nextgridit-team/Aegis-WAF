package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fingerprintTLSServer mirrors the production HTTPS listener shape: the raw
// TCP listener is wrapped for ClientHello capture, TLS termination happens
// above it and ConnContext carries the connection into request contexts.
func fingerprintTLSServer(t *testing.T, a *App) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(a.Public))
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	listener := tls.NewListener(NewFingerprintListener(raw), a.TLSConfig())
	server.Listener = listener
	server.Config.ConnContext = a.ConnectionContext
	server.Start()
	return server, "https://" + listener.Addr().String()
}

func fingerprintSites(t *testing.T, c *testAPI, upstream *httptest.Server) (int64, int64) {
	t.Helper()
	now := time.Now()
	chain, key := testCertificate(t, []string{"fp.example.com", "fp2.example.com"}, 300, now.Add(-time.Hour), now.Add(24*time.Hour))
	certID := mustID(t, c.call("POST", "/api/certificates", map[string]string{"name": "FP TLS", "chain_pem": chain, "private_key_pem": key}, 200))
	optedIn := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Fingerprinted", "hostnames": []string{"fp.example.com"}, "upstream": upstream.URL, "certificate_id": certID, "redirect_https": false, "enabled": true}, 200))
	defaultOff := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Not fingerprinted", "hostnames": []string{"fp2.example.com"}, "upstream": upstream.URL, "certificate_id": certID, "redirect_https": false, "enabled": true}, 200))
	return optedIn, defaultOff
}

// latestRows polls the management API until the site's newest access rows
// arrive (the access logger batches once per second).
func latestRows(t *testing.T, c *testAPI, site int64, want int) []map[string]any {
	t.Helper()
	var rows []map[string]any
	eventually(t, func() bool {
		rows = decodeAccessRows(t, c.call("GET", "/api/access-logs?site_id="+itoa(site), nil, 200))
		return len(rows) >= want
	})
	return rows
}

func rowFingerprint(row map[string]any) string {
	value, _ := row["client_fingerprint"].(string)
	return value
}

func TestClientFingerprintIdentity(t *testing.T) {
	a, c := investigationReplica(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		io.WriteString(w, "application response")
	}))
	defer upstream.Close()
	optedIn, defaultOff := fingerprintSites(t, c, upstream)

	flood := map[string]any{"mode": "block", "requests_per_second": 1, "burst": 1, "site_requests_per_second": 1000, "site_burst": 2000, "bot_mode": "off", "trusted_proxies": []string{"127.0.0.1/32"}, "client_ip_header": "x-forwarded-for"}
	// The opted-in site gets the fingerprint identity dimension; the second
	// site keeps the same flood shape without the opt-in as the control.
	c.call("PUT", "/api/protection-settings/"+itoa(optedIn), fingerprintOverlay(flood, map[string]any{"client_fingerprinting": true}), 200)
	c.call("PUT", "/api/protection-settings/"+itoa(defaultOff), fingerprintOverlay(flood, map[string]any{"client_fingerprinting": false}), 200)
	capture := defaultTrafficSettings()
	capture.Enabled = true
	capture.CapturePath = true
	c.call("PUT", "/api/traffic-settings/"+itoa(optedIn), capture, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	// The access logger batches rows in a background worker; start it so
	// live rows reach the management API.
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go a.Background(workerCtx)
	server, base := fingerprintTLSServer(t, a)
	t.Cleanup(server.Close)
	clients := map[string]*http.Client{}
	get := func(host, forwardedFor string) *http.Response {
		t.Helper()
		client, ok := clients[host]
		if !ok {
			// Generous timeout: under -race and concurrent gate stacks the
			// first handshake and upstream round trip can be slow, and the
			// assertions below care about decisions, not wall time.
			client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}}, Timeout: 60 * time.Second}
			clients[host] = client
		}
		r, _ := http.NewRequest("GET", base+"/", nil)
		r.Host = host
		r.Header.Set("X-Forwarded-For", forwardedFor)
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		return res
	}

	// Opt-in site: the hashed fingerprint lands on the access row. All three
	// budget-probing requests fire back-to-back with no polling in between,
	// so the fingerprint bucket (rate 1/s, burst 1) cannot refill between
	// them.
	if res := get("fp.example.com", "198.51.100.10"); res.StatusCode != 202 {
		t.Fatalf("first fingerprinted request: got %d want 202", res.StatusCode)
	}
	// A second request from a different resolved client IP but the same TLS
	// stack: the per-client budget is fresh, so only the shared
	// fingerprint-keyed budget can deny it.
	if res := get("fp.example.com", "198.51.100.11"); res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("fingerprint budget: got %d want 429", res.StatusCode)
	}
	// The same client stack on a fresh connection keeps the same identity and
	// the same shared budget.
	clients["fp.example.com"].CloseIdleConnections()
	if res := get("fp.example.com", "198.51.100.12"); res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("fresh connection: got %d want 429 (the fingerprint budget persists across IPs)", res.StatusCode)
	}
	rows := latestRows(t, c, optedIn, 3)
	allowed, denied, fresh := rows[2], rows[1], rows[0]
	fingerprint := rowFingerprint(allowed)
	if len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("client_fingerprint = %q, want a 64-character lowercase hex HMAC", fingerprint)
	}
	if !strings.Contains(fmt.Sprint(denied["signals"]), "fingerprint_rate") {
		t.Fatalf("limited row missing the fingerprint_rate signal: %v", denied)
	}
	if got := rowFingerprint(denied); got != fingerprint {
		t.Fatalf("fingerprint changed between requests: %q then %q", fingerprint, got)
	}
	if got := rowFingerprint(fresh); got != fingerprint {
		t.Fatalf("fingerprint changed across connections: %q then %q", fingerprint, got)
	}

	// Control site without the opt-in: same traffic shape, no fingerprint
	// stored and no shared-identity denial.
	if res := get("fp2.example.com", "198.51.100.20"); res.StatusCode != 202 {
		t.Fatalf("first control request: got %d want 202", res.StatusCode)
	}
	if res := get("fp2.example.com", "198.51.100.21"); res.StatusCode != 202 {
		t.Fatalf("control request from another IP: got %d want 202 (no fingerprint budget without the opt-in)", res.StatusCode)
	}
	control := latestRows(t, c, defaultOff, 2)
	for n, row := range control {
		if got := rowFingerprint(row); got != "" {
			t.Fatalf("control row %d stored a fingerprint without the opt-in: %q", n, got)
		}
	}

	// Plain HTTP carries no TLS handshake, so the opted-in site records no
	// fingerprint even though the setting is on.
	plain := httptest.NewRequest("GET", "http://fp.example.com/plain", nil)
	plain.Host = "fp.example.com"
	plainRecorder := httptest.NewRecorder()
	a.Public(plainRecorder, plain)
	if plainRecorder.Code != 202 {
		t.Fatalf("plain HTTP request through the opted-in site: got %d want 202", plainRecorder.Code)
	}
	after := latestRows(t, c, optedIn, 4)
	if got := rowFingerprint(after[0]); got != "" {
		t.Fatalf("plain HTTP row stored a fingerprint: %q", got)
	}

	// The opt-in site's retained evidence carries the same hashed value as a
	// captured fact alongside client_ip.
	var samples [][]byte
	eventually(t, func() bool {
		rows, e := a.db.Query(context.Background(), "SELECT data FROM traffic_evidence WHERE site_id=$1 ORDER BY at DESC LIMIT 5", optedIn)
		if e != nil {
			t.Fatal(e)
		}
		defer rows.Close()
		samples = nil
		for rows.Next() {
			var raw []byte
			if e := rows.Scan(&raw); e != nil {
				t.Fatal(e)
			}
			samples = append(samples, raw)
		}
		return len(samples) > 0
	})
	found := false
	for _, raw := range samples {
		var retained TrafficEvidence
		if e := json.Unmarshal(raw, &retained); e != nil {
			t.Fatal(e)
		}
		if fact, ok := retained.Facts[factKey("client_fingerprint", "")]; ok && fact.State == "present" && len(fact.Values) == 1 && fact.Values[0] == fingerprint {
			found = true
		}
	}
	if !found {
		t.Fatalf("retained evidence missing the fingerprint fact in %d samples", len(samples))
	}
}

func fingerprintOverlay(base map[string]any, overlay map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

// The fingerprint budget rides the shared rate-state operation: when the
// shared backend cannot be evaluated, a blocking site fails closed exactly
// like the existing flood budgets.
func TestClientFingerprintSharedStateFailClosed(t *testing.T) {
	a, c := investigationReplica(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
	}))
	defer upstream.Close()
	optedIn, _ := fingerprintSites(t, c, upstream)
	c.call("PUT", "/api/protection-settings/"+itoa(optedIn), map[string]any{"mode": "block", "requests_per_second": 20, "burst": 60, "site_requests_per_second": 1000, "site_burst": 2000, "bot_mode": "off", "client_fingerprinting": true}, 200)
	var current map[string]any
	json.Unmarshal(c.call("GET", "/api/rate-state", nil, 200), &current)
	c.call("PUT", "/api/rate-state", map[string]any{"backend": "redis", "address": "127.0.0.1:1", "timeout_ms": 20, "revision": current["revision"]}, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	// The access logger batches rows in a background worker; start it so
	// live rows reach the management API.
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go a.Background(workerCtx)
	server, base := fingerprintTLSServer(t, a)
	t.Cleanup(server.Close)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "fp.example.com"}}, Timeout: 20 * time.Second}
	r, _ := http.NewRequest("GET", base+"/", nil)
	r.Host = "fp.example.com"
	res, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("shared state outage: got %d want 503 (fail closed)", res.StatusCode)
	}
	rows := latestRows(t, c, optedIn, 1)
	if !strings.Contains(fmt.Sprint(rows[0]["signals"]), "rate_state_unavailable") {
		t.Fatalf("outage row missing rate_state_unavailable: %v", rows[0])
	}
}
