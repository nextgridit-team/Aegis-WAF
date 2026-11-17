package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A minimal replica whose site policy blocks automation user agents, with the
// proxy built the way the snapshot loader builds real routes.
func blockTestApp(t *testing.T, site Site, protection ProtectionSettings, target *url.URL) *App {
	t.Helper()
	compiled, e := compileProtection(protection)
	if e != nil {
		t.Fatal(e)
	}
	headers, e := normalizeHeaders(HeaderSettings{})
	if e != nil {
		t.Fatal(e)
	}
	a := &App{access: make(chan accessEvent, 16)}
	rt := &route{site: site, proxy: newSiteProxy(target, site, headers, a)}
	a.active.Store(&snapshot{version: 1, routes: map[string]*route{"blocked.test": rt}, protection: map[int64]*protectionPolicy{site.ID: compiled}})
	return a
}

func botBlockProtection() ProtectionSettings {
	settings := defaultProtection()
	settings.Mode = "off"
	settings.BotMode = "block"
	return settings
}

func deniedRequest(a *App, accept string) (*httptest.ResponseRecorder, accessEvent) {
	r := httptest.NewRequest("GET", "http://blocked.test/login", nil)
	r.Header.Set("User-Agent", "sqlmap/1")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	a.Public(w, r)
	return w, <-a.access
}

func allowedRequest(a *App) (*httptest.ResponseRecorder, accessEvent) {
	r := httptest.NewRequest("GET", "http://blocked.test/allowed", nil)
	r.Header.Set("User-Agent", "curl/8")
	w := httptest.NewRecorder()
	a.Public(w, r)
	return w, <-a.access
}

func blockTestTarget(t *testing.T) *url.URL {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	return target
}

func deadTestTarget(t *testing.T) *url.URL {
	t.Helper()
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	target, _ := url.Parse(dead.URL)
	return target
}

func TestBlockedResponseCarriesRequestID(t *testing.T) {
	a := blockTestApp(t, Site{ID: 7, Hostnames: []string{"blocked.test"}}, botBlockProtection(), blockTestTarget(t))
	w, event := deniedRequest(a, "")
	id := w.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("denied response carries no X-Request-ID header")
	}
	if event.requestID != id {
		t.Fatalf("access event request id %q does not match response header %q", event.requestID, id)
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("browser denial content type %q, want HTML", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache control %q, want no-store", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, id) {
		t.Fatal("block page does not show the correlation ID")
	}
	if len(body) > 4096 {
		t.Fatalf("block page is %d bytes, exceeds the bounded size", len(body))
	}
	if strings.Contains(body, "blocked.test") || strings.Contains(body, "sqlmap") || strings.Contains(body, "automation_user_agent") {
		t.Fatal("block page leaks request or policy detail")
	}
}

func TestForwardedResponseCarriesRequestID(t *testing.T) {
	a := blockTestApp(t, Site{ID: 8, Hostnames: []string{"blocked.test"}}, botBlockProtection(), blockTestTarget(t))
	w, event := allowedRequest(a)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	id := w.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("forwarded response carries no X-Request-ID header")
	}
	if event.requestID != id {
		t.Fatalf("access event request id %q does not match response header %q", event.requestID, id)
	}
}

func TestBlockedResponseJSONNegotiation(t *testing.T) {
	a := blockTestApp(t, Site{ID: 9, Hostnames: []string{"blocked.test"}}, botBlockProtection(), blockTestTarget(t))
	w, event := deniedRequest(a, "application/json")
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("JSON client content type %q, want application/json", ct)
	}
	var decoded map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatalf("JSON client body %q", w.Body.String())
	}
	if decoded["error"] != "gateway_protection_denied" {
		t.Fatalf("JSON error code %q", decoded["error"])
	}
	if w.Header().Get("X-Request-ID") != event.requestID {
		t.Fatal("JSON denial correlation header does not match the access event")
	}
}

func TestBlockedResponseMachineEndpointJSON(t *testing.T) {
	a := blockTestApp(t, Site{ID: 10, Hostnames: []string{"blocked.test"}, TrafficProfile: "api"}, botBlockProtection(), blockTestTarget(t))
	w, event := deniedRequest(a, "")
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("machine endpoint content type %q, want application/json", ct)
	}
	var decoded map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatalf("machine endpoint body %q", w.Body.String())
	}
	if decoded["error"] != "gateway_protection_denied" {
		t.Fatalf("machine endpoint error code %q", decoded["error"])
	}
	if w.Header().Get("X-Request-ID") != event.requestID {
		t.Fatal("machine endpoint correlation header does not match the access event")
	}
}

func TestUpstreamErrorCarriesRequestID(t *testing.T) {
	a := blockTestApp(t, Site{ID: 11, Hostnames: []string{"blocked.test"}}, botBlockProtection(), deadTestTarget(t))
	w, event := allowedRequest(a)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", w.Code)
	}
	id := w.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("gateway error response carries no X-Request-ID header")
	}
	if event.requestID != id {
		t.Fatalf("access event request id %q does not match response header %q", event.requestID, id)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("browser gateway error content type %q, want HTML", ct)
	}
	if !strings.Contains(w.Body.String(), id) {
		t.Fatal("gateway error page does not show the correlation ID")
	}
}

func TestFloodDenialStatusPreserved(t *testing.T) {
	settings := defaultProtection()
	settings.Mode = "block"
	settings.RequestsPerSecond = 1
	settings.Burst = 1
	settings.BotMode = "off"
	a := blockTestApp(t, Site{ID: 12, Hostnames: []string{"blocked.test"}}, settings, deadTestTarget(t))
	w, event := allowedRequest(a)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("first request status %d, want 502", w.Code)
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Fatal("first response carries no X-Request-ID header")
	}
	w, event = allowedRequest(a)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status %d, want 429", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Fatalf("retry after %q, want 1", ra)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("flood denial content type %q, want HTML", ct)
	}
	id := w.Header().Get("X-Request-ID")
	if id == "" || event.requestID != id {
		t.Fatalf("flood denial correlation %q / event %q", id, event.requestID)
	}
	if !strings.Contains(w.Body.String(), id) {
		t.Fatal("flood denial page does not show the correlation ID")
	}
}

func TestEarlyUnroutedResponseCarriesRequestID(t *testing.T) {
	a := blockTestApp(t, Site{ID: 13, Hostnames: []string{"blocked.test"}}, botBlockProtection(), blockTestTarget(t))
	r := httptest.NewRequest("GET", "http://unknown.test/", nil)
	r.Header.Set("User-Agent", "curl/8")
	w := httptest.NewRecorder()
	a.Public(w, r)
	event := <-a.access
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status %d, want 421", w.Code)
	}
	id := w.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("unrouted response carries no X-Request-ID header")
	}
	if event.requestID != id {
		t.Fatalf("access event request id %q does not match response header %q", event.requestID, id)
	}
}

func TestBlockPageRequestIDPersistenceIntegration(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	srv := httptest.NewServer(a.Management())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, srv.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "block page correlation password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "block page correlation password"}, 200), &login)
	c.csrf = login["csrf"]
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Block page", "hostnames": []string{"blocked.example.com"}, "upstream": "http://127.0.0.1:1", "enabled": true, "traffic_profile": "web"}, 200))
	c.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), map[string]any{"mode": "block", "requests_per_second": 1, "burst": 1, "site_requests_per_second": 1000, "site_burst": 2000, "bot_mode": "off"}, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	s := a.active.Load()
	if s == nil || s.routes["blocked.example.com"] == nil {
		t.Fatal("created site missing from the active snapshot")
	}
	// newTestReplica does not start the access-log worker; run it so the
	// rows this test correlates actually reach PostgreSQL.
	logCtx, cancelLogs := context.WithCancel(context.Background())
	logDone := make(chan struct{})
	go func() { defer close(logDone); a.logWorker(logCtx) }()
	defer func() { cancelLogs(); <-logDone }()
	first := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "http://blocked.example.com/", nil)
	r1.Header.Set("User-Agent", "curl/8")
	a.Public(first, r1)
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first request status %d, want 502", first.Code)
	}
	second := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "http://blocked.example.com/login", nil)
	r2.Header.Set("User-Agent", "curl/8")
	a.Public(second, r2)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status %d, want 429", second.Code)
	}
	firstID, secondID := first.Header().Get("X-Request-ID"), second.Header().Get("X-Request-ID")
	if firstID == "" || secondID == "" {
		t.Fatalf("missing correlation IDs: %q %q", firstID, secondID)
	}
	if firstID == secondID {
		t.Fatal("correlation IDs are not per-request")
	}
	if ct := second.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("flood denial content type %q, want HTML", ct)
	}
	if !strings.Contains(second.Body.String(), secondID) {
		t.Fatal("flood denial page does not show the correlation ID")
	}
	eventually(t, func() bool {
		var count int
		e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM access_logs WHERE (request_id=$1 AND status=502) OR (request_id=$2 AND status=429 AND blocked)", firstID, secondID).Scan(&count)
		return e == nil && count == 2
	})
}
