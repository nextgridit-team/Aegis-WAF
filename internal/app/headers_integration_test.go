package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeadersAndExemptionsIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	m := httptest.NewServer(a.Management())
	defer m.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, m.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "header and exemption test password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "header and exemption test password"}, 200), &login)
	c.csrf = login["csrf"]
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream")
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(r.Header)
	}))
	defer upstream.Close()
	protection := defaultProtection()
	protection.Mode = "block"
	protection.BotMode = "block"
	protection.RequestsPerSecond = 1
	protection.Burst = 1
	protection.TrustedProxies = []string{"10.0.0.1"}
	protection.FloodExemptCIDRs = []string{"192.168.1.0/24"}
	headers := HeaderSettings{RequestSet: map[string]string{"X-App": "saved"}, ResponseSet: map[string]string{"X-Frame-Options": "DENY"}, ResponseRemove: []string{"Server"}}
	body := map[string]any{"name": "Header app", "hostnames": []string{"headers.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "protection": protection, "headers": headers}
	site := mustID(t, c.call("POST", "/api/sites", body, 200))
	path := fmt.Sprintf("/api/sites/%d", site)
	for _, r := range []*App{a, b} {
		if e := r.refresh(ctx); e != nil {
			t.Fatal(e)
		}
	}
	request := func(replica *App, ip, ua, uri string, want int) accessEvent {
		r := httptest.NewRequest("GET", "http://headers.test"+uri, nil)
		r.RemoteAddr = "10.0.0.1:1234"
		r.Header.Set("X-Forwarded-For", ip)
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		replica.Public(w, r)
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
		if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Server") != "" {
			t.Fatal("response policy missing on proxy/block")
		}
		if want == 202 {
			var h http.Header
			json.Unmarshal(w.Body.Bytes(), &h)
			if h.Get("X-App") != "saved" || h.Get("X-Forwarded-For") != ip {
				t.Fatal("upstream lost headers/client IP", h)
			}
		}
		return <-replica.access
	}
	events := []accessEvent{}
	for _, replica := range []*App{a, b} {
		for range 3 {
			ev := request(replica, "192.168.1.42", "ordinary", "/", 202)
			if len(ev.exemptions) != 1 || len(ev.signals) != 0 {
				t.Fatal("exemption missing/flagged")
			}
			events = append(events, ev)
		}
	}
	events = append(events, request(a, "198.51.100.5", "ordinary", "/", 202), request(a, "198.51.100.5", "ordinary", "/", 429), request(b, "192.168.1.42", "sqlmap", "/", 403))
	rule := probeRule("path", "", "equals", "/.env")
	rule.Scope.SiteID = site
	id := mustID(t, c.call("POST", "/api/rules", rule, 200))
	c.call("POST", fmt.Sprintf("/api/rules/%d/activate", id), map[string]any{"action": "block", "ttl_seconds": 60}, 200)
	if e := a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	events = append(events, request(a, "192.168.1.42", "ordinary", "/.env", 403))
	if e := a.storeAccessBatch(ctx, events); e != nil {
		t.Fatal(e)
	}
	var report struct {
		Totals struct{ Requests, Exempt, Blocked int }
	}
	json.Unmarshal(c.call("GET", "/api/dashboard", nil, 200), &report)
	if report.Totals.Requests != 10 || report.Totals.Exempt != 8 || report.Totals.Blocked != 3 {
		t.Fatalf("bad exemption statistics %+v", report)
	}
	body["headers"] = HeaderSettings{RequestSet: map[string]string{"X-Forwarded-For": "spoof"}}
	c.call("PUT", path, body, 400)
	if !strings.Contains(string(c.call("GET", "/api/sites", nil, 200)), "saved") {
		t.Fatal("failed edit lost working settings")
	}
	// Cached header/exemption policy remains effective without database access.
	a.db.Close()
	ev := request(a, "192.168.1.42", "ordinary", "/", 202)
	if len(ev.exemptions) != 1 {
		t.Fatal("cached exemptions lost during outage")
	}
}
