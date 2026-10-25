package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuleFeedValidation(t *testing.T) {
	for _, raw := range []string{"http://example.com/rules", "https://user:secret@example.com/rules", "https://example.com:8443/rules", "https://example.com/rules?token=secret", "https://127.0.0.1/a", "https://169.254.169.254/a", "https://[::ffff:127.0.0.1]/a"} {
		if _, e := feedURL(raw); e == nil {
			t.Errorf("accepted unsafe feed %s", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "::1", "169.254.169.254", "100.100.100.200", "192.0.2.4", "198.18.0.1", "fc00::1", "2002:7f00:1::"} {
		if feedPublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("public: %s", raw)
		}
	}
	if !feedPublicIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IP rejected")
	}
	req := httptest.NewRequest("GET", "https://localhost/rules", nil)
	_, e := feedTransport().RoundTrip(req)
	if e == nil {
		t.Fatal("dialer accepted private DNS result")
	}
	raw, e := os.ReadFile("../../rules/starter.json")
	if e != nil {
		t.Fatal(e)
	}
	doc, e := parseFeed(raw, 42)
	if e != nil {
		t.Fatal(e)
	}
	if len(doc.Rules) != 3 || doc.Rules[0].Rule.Scope.SiteID != 42 || doc.Rules[0].Rule.Action != "observe" {
		t.Fatal("incorrect feed remapping")
	}
	doc.Rules = append(doc.Rules, doc.Rules[0])
	raw, _ = json.Marshal(doc)
	if _, e = parseFeed(raw, 42); e == nil {
		t.Fatal("accepted duplicate source IDs")
	}
	if _, e = parseFeed([]byte(`{"schema_version":1,"rules":[],"execute":"no"}`), 42); e == nil {
		t.Fatal("accepted unknown field")
	}
}
func TestRuleFeedIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	c.call("GET", "/api/rule-feeds", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "long password for feed test", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "long password for feed test"}, 200), &login)
	c.csrf = login["csrf"]
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Feed app", "hostnames": []string{"feed.test"}, "upstream": "http://127.0.0.1:8000", "enabled": true, "redirect_https": false}, 200))
	source := map[string]any{"name": "Test feed", "url": "https://example.com/aegis.json", "site_id": site}
	bad := map[string]any{"name": "bad", "url": "https://127.0.0.1/a", "site_id": site}
	c.call("POST", "/api/rule-feeds", bad, 400)
	id := mustID(t, c.call("POST", "/api/rule-feeds", source, 201))
	path := fmt.Sprintf("/api/rule-feeds/%d", id)
	spec := probeRule("path", "", "equals", "/.env")
	spec.Scope.SiteID = 999
	spec.Action = "block"
	doc := feedDocument{1, []feedCandidate{{"config-probe", spec}}}
	raw, _ := json.Marshal(doc)
	status := 200
	var downloads atomic.Int64
	var sawETag atomic.Bool
	transport := dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		downloads.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			sawETag.Store(true)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{`"v1"`}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	a.feedHTTP = transport
	b.feedHTTP = transport
	c.call("POST", path+"/sync", map[string]any{}, 200)
	if e := b.syncFeed(ctx, id, false, "scheduler"); e != nil {
		t.Fatal(e)
	}
	if downloads.Load() != 1 {
		t.Fatal("scheduler repeated a completed sync")
	}
	var next time.Time
	if e := a.db.QueryRow(ctx, "SELECT next_sync FROM rule_feeds WHERE id=$1", id).Scan(&next); e != nil || time.Until(next) < 11*time.Hour {
		t.Fatal("incorrect sync interval", e)
	}
	var result struct {
		IDs []int64 `json:"rule_ids"`
	}
	json.Unmarshal(c.call("POST", path+"/import", map[string]any{}, 200), &result)
	if len(result.IDs) != 1 {
		t.Fatal(result)
	}
	first := result.IDs[0]
	var enabled bool
	var actualSite int64
	var saved []byte
	if e := a.db.QueryRow(ctx, "SELECT enabled,site_id,spec FROM rules WHERE id=$1", first).Scan(&enabled, &actualSite, &saved); e != nil || enabled || actualSite != site {
		t.Fatal("unsafe feed import", e)
	}
	var imported RuleSpec
	json.Unmarshal(saved, &imported)
	if imported.Action != "observe" {
		t.Fatal("feed imported proposed blocking action")
	}
	json.Unmarshal(c.call("POST", path+"/import", map[string]any{}, 200), &result)
	if len(result.IDs) != 0 {
		t.Fatal("unchanged feed duplicated drafts")
	}
	c.call("POST", fmt.Sprintf("/api/rules/%d/activate", first), map[string]any{"action": "block", "ttl_seconds": 60}, 200)
	status = 304
	c.call("POST", path+"/sync", map[string]any{}, 200)
	if !sawETag.Load() {
		t.Fatal("conditional sync absent")
	}
	status = 200
	raw = []byte(`{"schema_version":1,"rules":[{"id":"bad","rule":{}}]}`)
	c.call("POST", path+"/sync", map[string]any{}, 400)
	var pending int
	var available int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FILTER(WHERE available),count(*) FILTER(WHERE spec IS DISTINCT FROM imported_spec) FROM rule_feed_items WHERE feed_id=$1", id).Scan(&available, &pending); e != nil || available != 1 || pending != 0 {
		t.Fatal("failed sync damaged good candidates", e)
	}
	spec.Name = "Updated configuration probe"
	spec.All[0].Value = json.RawMessage(`"/.env.local"`)
	doc.Rules[0].Rule = spec
	raw, _ = json.Marshal(doc)
	c.call("POST", path+"/sync", map[string]any{}, 200)
	json.Unmarshal(c.call("POST", path+"/import", map[string]any{}, 200), &result)
	if len(result.IDs) != 1 || result.IDs[0] == first {
		t.Fatal("changed feed did not create separate draft")
	}
	if e := a.db.QueryRow(ctx, "SELECT enabled FROM rules WHERE id=$1", first).Scan(&enabled); e != nil || !enabled {
		t.Fatal("feed replaced enabled rule", e)
	}
	// A competing replica cannot download while another owns this source's lease.
	entered := make(chan struct{})
	release := make(chan struct{})
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 304, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	done := make(chan error, 1)
	go func() { done <- a.syncFeed(ctx, id, true, "test") }()
	<-entered
	if e := b.syncFeed(ctx, id, true, "test"); e == nil {
		t.Fatal("competing replica acquired sync")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	c.call("DELETE", path, nil, 200)
	var count int
	a.db.QueryRow(ctx, "SELECT count(*) FROM rules WHERE site_id=$1", site).Scan(&count)
	if count != 2 {
		t.Fatal("removing source removed imported rules")
	}
}

func TestGitHubContentsFeed(t *testing.T) {
	a := &App{}
	sawRaw := false
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		sawRaw = r.Header.Get("Accept") == "application/vnd.github.raw+json"
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"schema_version":1,"rules":[]}`))}, nil
	})
	if _, _, _, e := a.fetchFeed(context.Background(), "https://api.github.com/repos/example/rules/contents/rules.json", "", 1); e != nil {
		t.Fatal(e)
	}
	if !sawRaw {
		t.Fatal("GitHub raw media type missing")
	}
}
