package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRulesIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, management.URL, ""}
	c.call("GET", "/api/rules", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "a strong test password for rules", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "a strong test password for rules"}, 200), &login)
	c.csrf = login["csrf"]
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.WriteHeader(202)
		io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Rules app", "hostnames": []string{"rules.example.test"}, "upstream": upstream.URL, "redirect_https": false, "enabled": true}, 200))
	otherSite := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Other app", "hostnames": []string{"other.example.test"}, "upstream": upstream.URL, "redirect_https": false, "enabled": true}, 200))
	s := defaultTrafficSettings()
	s.Enabled = true
	s.CapturePath = true
	s.QueryKeys = []string{"q"}
	s.HeaderKeys = []string{"user-agent"}
	s.JSONBodyKeys = []string{"/file"}
	c.call("PUT", fmt.Sprintf("/api/traffic-settings/%d", site), s, 200)
	spec := probeRule("path", "", "equals", "/.env")
	spec.Scope.SiteID = site
	rule := mustID(t, c.call("POST", "/api/rules", spec, 200))
	path := fmt.Sprintf("/api/rules/%d", rule)
	refresh := func() {
		t.Helper()
		for _, replica := range []*App{a, b} {
			if e := replica.refresh(ctx); e != nil {
				t.Fatal(e)
			}
		}
	}
	refresh()
	request := func(replica *App, host, target string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "http://"+host+target, nil)
		w := httptest.NewRecorder()
		replica.Public(w, r)
		if w.Code != want {
			t.Fatalf("%s: got %d want %d: %s", target, w.Code, want, w.Body.String())
		}
	}
	request(a, "rules.example.test", "/.env", 202)
	activate := func(action string) {
		c.call("POST", path+"/activate", map[string]any{"action": action, "ttl_seconds": 60}, 200)
		refresh()
	}
	activate("observe")
	for _, replica := range []*App{a, b} {
		request(replica, "rules.example.test", "/.env", 202)
	}
	activate("block")
	before := upstreamRequests.Load()
	for _, replica := range []*App{a, b} {
		request(replica, "rules.example.test", "/.env?q=Bearer+topsecret&password=notpersisted", 403)
	}
	if upstreamRequests.Load() != before {
		t.Fatal("blocked request reached upstream")
	}
	request(b, "other.example.test", "/.env", 202)
	// CSRF, strict JSON and failed edits cannot replace an active rule.
	saved := c.csrf
	c.csrf = "wrong"
	c.call("POST", path+"/disable", map[string]any{}, 403)
	c.csrf = saved
	bad := map[string]any{}
	data, _ := json.Marshal(spec)
	json.Unmarshal(data, &bad)
	bad["execute"] = "forbidden"
	c.call("PUT", path, bad, 400)
	badSpec := spec
	badSpec.All = nil
	c.call("PUT", path, badSpec, 400)
	refresh()
	request(a, "rules.example.test", "/.env", 403)
	var activeExpiry time.Time
	if e := a.db.QueryRow(ctx, "SELECT expires_at FROM rules WHERE id=$1", rule).Scan(&activeExpiry); e != nil {
		t.Fatal(e)
	}
	c.call("POST", path+"/disable", map[string]any{}, 200)
	refresh()
	request(a, "rules.example.test", "/.env", 202)
	c.call("POST", path+"/rollback", map[string]any{}, 200)
	refresh()
	request(b, "rules.example.test", "/.env", 403)
	var rolledExpiry time.Time
	a.db.QueryRow(ctx, "SELECT expires_at FROM rules WHERE id=$1", rule).Scan(&rolledExpiry)
	if !rolledExpiry.Equal(activeExpiry) {
		t.Fatal("rollback extended expiry")
	}
	// Editing is always a draft, even when a previous version blocked.
	c.call("PUT", path, spec, 200)
	refresh()
	request(a, "rules.example.test", "/.env", 202)
	// Persist captured requests atomically with access metadata; inspect only selected facts.
	batch := []accessEvent{}
	for {
		select {
		case event := <-a.access:
			batch = append(batch, event)
		default:
			goto drained
		}
	}
drained:
	if e := a.storeAccessBatch(ctx, batch); e != nil {
		t.Fatal(e)
	}
	var events []struct {
		ID   string          `json:"id"`
		Data TrafficEvidence `json:"data"`
	}
	raw := c.call("GET", fmt.Sprintf("/api/traffic-events?site_id=%d", site), nil, 200)
	if strings.Contains(string(raw), "topsecret") || strings.Contains(string(raw), "notpersisted") {
		t.Fatal("secret in evidence")
	}
	if e := json.Unmarshal(raw, &events); e != nil || len(events) == 0 {
		t.Fatal(string(raw), e)
	}
	ids := []string{}
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	before = upstreamRequests.Load()
	var replay struct {
		Counts map[string]int `json:"counts"`
		Sent   int            `json:"live_requests_sent"`
	}
	json.Unmarshal(c.call("POST", "/api/rules/replay", map[string]any{"rule": spec, "event_ids": ids}, 200), &replay)
	if replay.Counts["matched"] != len(ids) || replay.Sent != 0 || upstreamRequests.Load() != before {
		t.Fatal(replay)
	}
	unknownSpec := probeRule("query", "not_captured", "equals", "x")
	unknownSpec.Scope.SiteID = site
	json.Unmarshal(c.call("POST", "/api/rules/replay", map[string]any{"rule": unknownSpec, "event_ids": ids}, 200), &replay)
	if replay.Counts["unknown"] != len(ids) {
		t.Fatal(replay)
	}
	foreignSpec := spec
	foreignSpec.Scope.SiteID = otherSite
	c.call("POST", "/api/rules/replay", map[string]any{"rule": foreignSpec, "event_ids": ids}, 400)
	c.call("GET", path+"/history", nil, 200)
	c.call("GET", "/api/rules/schema", nil, 200)
	// Deleted sites in a stale snapshot cannot poison the entire logging batch.
	c.call("DELETE", fmt.Sprintf("/api/sites/%d", otherSite), nil, 200)
	stale := accessEvent{site: otherSite, at: time.Now(), method: "GET", status: 202, evidence: &evidenceEvent{id: token(), site: otherSite, at: time.Now(), expires: time.Now().Add(time.Hour), data: []byte(`{"schema_version":1}`)}}
	if e := a.storeAccessBatch(ctx, []accessEvent{stale}); e != nil {
		t.Fatal(e)
	}
	// A failed audit insert rolls back the rule, history and version together.
	var oldRevision, oldVersion int64
	a.db.QueryRow(ctx, "SELECT revision FROM rules WHERE id=$1", rule).Scan(&oldRevision)
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&oldVersion)
	if _, e := a.db.Exec(ctx, `CREATE FUNCTION fail_rule_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; CREATE TRIGGER fail_rule_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_rule_audit()`); e != nil {
		t.Fatal(e)
	}
	c.call("POST", path+"/activate", map[string]any{"action": "block", "ttl_seconds": 60}, 503)
	if _, e := a.db.Exec(ctx, "DROP TRIGGER fail_rule_audit ON audit_events; DROP FUNCTION fail_rule_audit()"); e != nil {
		t.Fatal(e)
	}
	var revision, version int64
	a.db.QueryRow(ctx, "SELECT revision FROM rules WHERE id=$1", rule).Scan(&revision)
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&version)
	if revision != oldRevision || version != oldVersion {
		t.Fatal("failed audit committed a rule or version change")
	}
	// Local expiry must work even without subsequent database refreshes.
	activate("block")
	expiry := time.Now().Add(200 * time.Millisecond)
	if _, e := a.db.Exec(ctx, "UPDATE rules SET expires_at=$2 WHERE id=$1", rule, expiry); e != nil {
		t.Fatal(e)
	}
	if _, e := a.db.Exec(ctx, "UPDATE config_version SET version=version+1 WHERE id"); e != nil {
		t.Fatal(e)
	}
	refresh()
	b.db.Close() // Cached rules must still enforce and expire without database access.
	request(b, "rules.example.test", "/.env", 403)
	time.Sleep(time.Until(expiry) + 20*time.Millisecond)
	request(b, "rules.example.test", "/.env", 202)
	// Database failures accurately reject administrative mutations while proxying from cache.
	a.db.Close()
	c.call("POST", path+"/activate", map[string]any{"action": "block", "ttl_seconds": 60}, 503)
	request(a, "rules.example.test", "/safe", 202)
}

func TestRulesSchemaUpgrade(t *testing.T) {
	cfg := testDB(t)
	a, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	ctx := context.Background()
	// Start from the actual previous schema, with pre-existing access metadata.
	legacy := strings.Split(schema, "-- Version 2:")[0]
	if _, e = a.db.Exec(ctx, legacy); e != nil {
		t.Fatal(e)
	}
	if _, e = a.db.Exec(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer) VALUES(now(),123,'GET',200,1,'192.0.2.1')"); e != nil {
		t.Fatal(e)
	}
	if e = a.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	if e = a.initialize(ctx); e != nil {
		t.Fatal("migration is not idempotent", e)
	}
	var results, event string
	if e = a.db.QueryRow(ctx, "SELECT rule_results::text,event_id FROM access_logs WHERE site_id=123").Scan(&results, &event); e != nil || results != "[]" || event != "" {
		t.Fatal("legacy row changed", results, event, e)
	}
	var version int
	if e = a.db.QueryRow(ctx, "SELECT max(version) FROM schema_version").Scan(&version); e != nil || version != 16 {
		t.Fatal(version, e)
	}
}
