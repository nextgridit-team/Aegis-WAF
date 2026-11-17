package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The forwarding leg must be measured, not estimated: a slow upstream has to
// show up as upstream time on the access event, with the WAF-added remainder
// staying small.
func TestUpstreamTimeMeasuredOnForwardingPath(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(200)
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	a := &App{access: make(chan accessEvent, 10)}
	a.active.Store(&snapshot{version: 1, routes: map[string]*route{"app.example.com": {site: Site{ID: 1}, proxy: newProxy(u, true)}}})
	r := httptest.NewRequest("GET", "http://app.example.com/api/items/42", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	event := <-a.access
	if event.upstreamUS < 70000 {
		t.Fatalf("upstream time not measured: %dµs", event.upstreamUS)
	}
	// duration_ms is millisecond-truncated while upstream is microsecond
	// precise, so the upstream leg may exceed it by at most rounding.
	if event.upstreamUS > event.duration*1000+1500 {
		t.Fatalf("upstream %dµs exceeds total %dms", event.upstreamUS, event.duration)
	}
	if event.pathClass != "/api/items/{id}" {
		t.Fatalf("path class = %q", event.pathClass)
	}
	if event.responseSource != "upstream" {
		t.Fatalf("response source = %q", event.responseSource)
	}
}

// Requests the WAF answers itself (redirects, blocks) never reach the
// forwarding leg, so they record no upstream time.
func TestUpstreamTimeAbsentWhenNotForwarded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	a := &App{access: make(chan accessEvent, 10)}
	a.active.Store(&snapshot{version: 1, routes: map[string]*route{"app.example.com": {site: Site{ID: 1, RedirectHTTPS: true}, proxy: newProxy(u, true)}}})
	r := httptest.NewRequest("GET", "http://app.example.com/api/items/42", nil)
	w := httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != http.StatusPermanentRedirect {
		t.Fatalf("status %d", w.Code)
	}
	event := <-a.access
	if event.upstreamUS != 0 {
		t.Fatalf("unforwarded request recorded upstream time: %dµs", event.upstreamUS)
	}
	if event.responseSource != "redirect" {
		t.Fatalf("response source = %q", event.responseSource)
	}
}

func TestEndpointCostsAPI(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	c := testAPI{t, client, server.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "correct horse battery gateway", "secret": cfg.BootstrapSecret}, 201)
	data := c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery gateway"}, 200)
	var login map[string]string
	json.Unmarshal(data, &login)
	c.csrf = login["csrf"]
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Cost app", "hostnames": []string{"cost.example.com"}, "upstream": up.URL, "enabled": true}, 200))
	// Two requests to one normalized class (one forwarded, one blocked) plus
	// a quieter class, exactly as the forwarding path would record them.
	events := []accessEvent{
		{at: time.Now(), site: site, method: "GET", status: 200, duration: 60, upstreamUS: 55000, peer: "192.0.2.10", pathClass: "/api/items/{id}", responseSource: "upstream", results: []RuleResult{{RuleID: 4, Action: "block", Result: "matched"}}},
		{at: time.Now(), site: site, method: "GET", status: 403, duration: 8, peer: "192.0.2.11", pathClass: "/api/items/{id}", responseSource: "waf", blocked: true},
		{at: time.Now(), site: site, method: "GET", status: 200, duration: 30, upstreamUS: 28000, peer: "192.0.2.12", pathClass: "/health", responseSource: "upstream"},
		{at: time.Now(), site: site, method: "GET", status: 200, duration: 5, peer: "192.0.2.13", pathClass: "", responseSource: "waf"},
	}
	if e := a.storeAccessBatch(context.Background(), events); e != nil {
		t.Fatal(e)
	}
	data = c.call("GET", "/api/endpoint-costs?site_id="+itoa(site)+"&hours=2", nil, 200)
	if strings.Contains(string(data), "192.0.2.") {
		t.Fatalf("endpoint costs leak client addresses: %s", data)
	}
	var report struct {
		SiteID    int64 `json:"site_id"`
		Hours     int   `json:"hours"`
		Endpoints []struct {
			PathClass  string  `json:"path_class"`
			Requests   int64   `json:"requests"`
			Blocked    int64   `json:"blocked"`
			Forwarded  int64   `json:"forwarded"`
			TotalP50MS float64 `json:"total_p50_ms"`
			TotalP95MS float64 `json:"total_p95_ms"`
			AddedP50MS float64 `json:"added_p50_ms"`
			AddedP95MS float64 `json:"added_p95_ms"`
			TopRules   []struct {
				RuleID int64 `json:"rule_id"`
				Count  int64 `json:"count"`
			} `json:"top_rules"`
		} `json:"endpoints"`
	}
	if e := json.Unmarshal(data, &report); e != nil {
		t.Fatalf("invalid report: %v (%s)", e, data)
	}
	if report.SiteID != site || report.Hours != 2 {
		t.Fatalf("unexpected scope: %+v", report)
	}
	if len(report.Endpoints) != 2 {
		t.Fatalf("endpoints = %+v", report.Endpoints)
	}
	first := report.Endpoints[0]
	if first.PathClass != "/api/items/{id}" || first.Requests != 2 || first.Blocked != 1 || first.Forwarded != 1 {
		t.Fatalf("first endpoint = %+v", first)
	}
	// The only forwarded row took 60ms total with 55ms upstream: 5ms added.
	if first.AddedP50MS != 5 || first.AddedP95MS != 5 {
		t.Fatalf("added percentiles = %v/%v, want 5/5", first.AddedP50MS, first.AddedP95MS)
	}
	if first.TotalP50MS != 8 && first.TotalP50MS != 60 {
		t.Fatalf("total p50 = %v", first.TotalP50MS)
	}
	if first.TotalP95MS != 60 {
		t.Fatalf("total p95 = %v", first.TotalP95MS)
	}
	if len(first.TopRules) != 1 || first.TopRules[0].RuleID != 4 || first.TopRules[0].Count != 1 {
		t.Fatalf("top rules = %+v", first.TopRules)
	}
	second := report.Endpoints[1]
	if second.PathClass != "/health" || second.Requests != 1 || second.AddedP50MS != 2 {
		t.Fatalf("second endpoint = %+v", second)
	}
	// Parameter validation.
	c.call("GET", "/api/endpoint-costs", nil, 400)
	c.call("GET", "/api/endpoint-costs?site_id="+strconv.FormatInt(site, 10)+"&hours=0", nil, 400)
	c.call("GET", "/api/endpoint-costs?site_id="+strconv.FormatInt(site, 10)+"&hours=169", nil, 400)
	c.call("GET", "/api/endpoint-costs?site_id=abc", nil, 400)
	// The lookback is honored: rows outside the window disappear.
	if _, e := a.db.Exec(context.Background(), "UPDATE access_logs SET at=now()-interval '10 hours'"); e != nil {
		t.Fatal(e)
	}
	data = c.call("GET", "/api/endpoint-costs?site_id="+strconv.FormatInt(site, 10)+"&hours=2", nil, 200)
	json.Unmarshal(data, &report)
	if len(report.Endpoints) != 0 {
		t.Fatalf("rows outside the lookback still reported: %+v", report.Endpoints)
	}
}

// A percent-decoded path carrying invalid UTF-8 must not poison the access-log
// batch: one invalid path_class fails the whole CopyFrom (SQLSTATE 22021),
// dropping every event in the batch — including valid sibling rows.
func TestGarbagePathClassStoresThroughBatch(t *testing.T) {
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	aDB := newTestReplica(t, cfg)
	ctx := context.Background()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	aPub := &App{access: make(chan accessEvent, 10)}
	aPub.active.Store(&snapshot{version: 1, routes: map[string]*route{"app.example.com": {site: Site{ID: 1}, proxy: newProxy(u, true)}}})
	r := httptest.NewRequest("GET", "http://app.example.com/api/items/%ff%fe", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	aPub.Public(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	event := <-aPub.access
	if !utf8.ValidString(event.pathClass) {
		t.Fatalf("path class %q is not valid UTF-8", event.pathClass)
	}
	// The sanitized garbage-path event stores, and a valid sibling in the same
	// batch persists alongside it.
	if err := aDB.storeAccessBatch(ctx, []accessEvent{event}); err != nil {
		t.Fatalf("batch store failed: %v", err)
	}
}
