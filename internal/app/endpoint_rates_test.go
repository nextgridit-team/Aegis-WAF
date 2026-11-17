package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func endpointPolicy(t *testing.T, rates ...endpointRateRule) *protectionPolicy {
	t.Helper()
	spec := policySpec{Mode: "block", FloodEnabled: true, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, EndpointRates: rates}
	policy, e := policyProtection(nil, spec, 5)
	if e != nil {
		t.Fatal(e)
	}
	return policy
}

func endpointRequest(path string) *http.Request {
	return httptest.NewRequest("GET", "http://example.test"+path, nil)
}

func hasSignal(signals []string, want string) bool {
	for _, s := range signals {
		if s == want {
			return true
		}
	}
	return false
}

// The policy default continues to apply unchanged to paths with no override.
func TestEndpointRateDefaultUnchanged(t *testing.T) {
	policy := endpointPolicy(t)
	a := &App{}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.4")
	for n := 0; n < 2; n++ {
		signals, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), ip, now, true)
		if blocked || hasSignal(signals, "endpoint_rate") {
			t.Fatalf("request without an override was limited: %v %v", signals, blocked)
		}
	}
}

func TestEndpointRateLimitEnforced(t *testing.T) {
	policy := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	a := &App{}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.4")
	signals, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), ip, now, true)
	if blocked {
		t.Fatal("first request within burst was refused")
	}
	signals, blocked, status := a.protectResolved(policy, 1, endpointRequest("/login/step"), ip, now, true)
	if !blocked || status != http.StatusTooManyRequests {
		t.Fatalf("second request in window not refused by the endpoint budget: %v %d", signals, status)
	}
	if !hasSignal(signals, "endpoint_rate") {
		t.Fatalf("endpoint denial carries no endpoint_rate signal: %v", signals)
	}
	if hasSignal(signals, "client_rate") {
		t.Fatalf("endpoint denial misclassified as client_rate: %v", signals)
	}
}

func TestEndpointRateFirstMatchWins(t *testing.T) {
	policy := endpointPolicy(t,
		endpointRateRule{PathPattern: "/api/", Match: "prefix", RequestsPerSecond: 100, Burst: 100, Scope: "per-client"},
		endpointRateRule{PathPattern: "/api/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	a := &App{}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.4")
	for n := 0; n < 3; n++ {
		signals, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/api/login"), ip, now, true)
		if blocked || hasSignal(signals, "endpoint_rate") {
			t.Fatalf("the looser first-matching pattern did not win: %v %v", signals, blocked)
		}
	}
	reversed := endpointPolicy(t,
		endpointRateRule{PathPattern: "/api/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"},
		endpointRateRule{PathPattern: "/api/", Match: "prefix", RequestsPerSecond: 100, Burst: 100, Scope: "per-client"})
	if _, blocked, _ := a.protectResolved(reversed, 1, endpointRequest("/api/login"), ip, now, true); blocked {
		t.Fatal("first request in burst refused")
	}
	if _, blocked, _ := a.protectResolved(reversed, 1, endpointRequest("/api/login"), ip, now, true); !blocked {
		t.Fatal("the tighter first-matching pattern did not win")
	}
}

func TestEndpointRateExactMatch(t *testing.T) {
	policy := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "exact", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	a := &App{}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.4")
	if _, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), ip, now, true); blocked {
		t.Fatal("first request in burst refused")
	}
	if _, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), ip, now, true); !blocked {
		t.Fatal("exact pattern did not limit its own path")
	}
	if _, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login/two"), ip, now, true); blocked {
		t.Fatal("exact pattern limited a longer path")
	}
}

func TestEndpointRateScopes(t *testing.T) {
	now := time.Now()
	first := netip.MustParseAddr("203.0.113.4")
	second := netip.MustParseAddr("198.51.100.9")
	perClient := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	a := &App{}
	if _, blocked, _ := a.protectResolved(perClient, 1, endpointRequest("/login"), first, now, true); blocked {
		t.Fatal("first client refused")
	}
	if _, blocked, _ := a.protectResolved(perClient, 1, endpointRequest("/login"), second, now, true); blocked {
		t.Fatal("per-client endpoint budget leaked across clients")
	}
	siteWide := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "site-wide"})
	if _, blocked, _ := a.protectResolved(siteWide, 1, endpointRequest("/login"), first, now, true); blocked {
		t.Fatal("first client refused")
	}
	signals, blocked, _ := a.protectResolved(siteWide, 1, endpointRequest("/login"), second, now, true)
	if !blocked || !hasSignal(signals, "endpoint_rate") {
		t.Fatalf("site-wide endpoint budget did not span clients: %v %v", signals, blocked)
	}
}

func TestEndpointRateSiteAggregateStillApplies(t *testing.T) {
	spec := policySpec{Mode: "block", FloodEnabled: true, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1, SiteBurst: 1, EndpointRates: []endpointRateRule{{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 100, Burst: 100, Scope: "site-wide"}}}
	policy, e := policyProtection(nil, spec, 5)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	now := time.Now()
	first := netip.MustParseAddr("203.0.113.4")
	second := netip.MustParseAddr("198.51.100.9")
	if _, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), first, now, true); blocked {
		t.Fatal("first request refused")
	}
	signals, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), second, now, true)
	if !blocked || !hasSignal(signals, "application_rate") {
		t.Fatalf("site aggregate no longer applies underneath endpoint budgets: %v %v", signals, blocked)
	}
}

func TestEndpointRateObserveRecordsWithoutRefusing(t *testing.T) {
	spec := policySpec{Mode: "observe", FloodEnabled: true, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, EndpointRates: []endpointRateRule{{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"}}}
	policy, e := policyProtection(nil, spec, 5)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.4")
	if _, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), ip, now, true); blocked {
		t.Fatal("observe refused a request")
	}
	signals, blocked, _ := a.protectResolved(policy, 1, endpointRequest("/login"), ip, now, true)
	if blocked || !hasSignal(signals, "endpoint_rate") {
		t.Fatalf("observe did not record the endpoint budget: %v %v", signals, blocked)
	}
}

func TestEndpointRateValidation(t *testing.T) {
	base := func() policySpec {
		return policySpec{Mode: "block", FloodEnabled: true, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000}
	}
	over := base()
	over.EndpointRates = make([]endpointRateRule, 33)
	if _, e := policyProtection(nil, over, 1); e == nil {
		t.Fatal("accepted more than 32 endpoint overrides")
	}
	for name, mutate := range map[string]func(*policySpec){
		"missing path": func(s *policySpec) { s.EndpointRates = []endpointRateRule{{RequestsPerSecond: 1, Burst: 1}} },
		"relative path": func(s *policySpec) {
			s.EndpointRates = []endpointRateRule{{PathPattern: "login", RequestsPerSecond: 1, Burst: 1}}
		},
		"long path": func(s *policySpec) {
			s.EndpointRates = []endpointRateRule{{PathPattern: "/" + strings.Repeat("a", 1100), RequestsPerSecond: 1, Burst: 1}}
		},
		"bad match": func(s *policySpec) {
			s.EndpointRates = []endpointRateRule{{PathPattern: "/login", Match: "glob", RequestsPerSecond: 1, Burst: 1}}
		},
		"bad scope": func(s *policySpec) {
			s.EndpointRates = []endpointRateRule{{PathPattern: "/login", RequestsPerSecond: 1, Burst: 1, Scope: "global"}}
		},
		"zero rate": func(s *policySpec) {
			s.EndpointRates = []endpointRateRule{{PathPattern: "/login", RequestsPerSecond: 0, Burst: 1}}
		},
		"burst below": func(s *policySpec) {
			s.EndpointRates = []endpointRateRule{{PathPattern: "/login", RequestsPerSecond: 10, Burst: 5}}
		},
	} {
		spec := base()
		mutate(&spec)
		if _, e := policyProtection(nil, spec, 1); e == nil {
			t.Fatalf("%s: accepted invalid endpoint override", name)
		}
	}
}

func TestEndpointRateSimulation(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	policy := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	binding := compiledPolicyBinding{ID: 1, Name: "Endpoint", Priority: 10000, Protection: policy}
	a := &App{access: make(chan accessEvent, 16)}
	a.active.Store(&snapshot{routes: map[string]*route{"example.test": {site: Site{ID: 1}, proxy: newProxy(target, false)}}, policyBindings: map[int64][]compiledPolicyBinding{1: {binding}}})
	payload := simulationPayload{Host: "example.test", ClientIP: "203.0.113.4", Path: "/login", Headers: map[string]string{"User-Agent": "curl/8"}}
	harness := &App{}
	if out, _, e := simulatePayload(context.Background(), harness, a.active.Load(), payload); e != nil || out != "allow" {
		t.Fatalf("first simulation in burst not allowed: %s %v", out, e)
	}
	if out, _, e := simulatePayload(context.Background(), harness, a.active.Load(), payload); e != nil || out != "block" {
		t.Fatalf("simulation does not reflect the endpoint budget: %s %v", out, e)
	}
}

func TestEndpointRatePublicEnforced(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	policy := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	a := &App{access: make(chan accessEvent, 16)}
	a.active.Store(&snapshot{routes: map[string]*route{"example.test": {site: Site{ID: 1, Hostnames: []string{"example.test"}, TrafficProfile: "web"}, proxy: newProxy(target, false)}}, policyBindings: map[int64][]compiledPolicyBinding{1: {{ID: 1, Name: "Endpoint", Priority: 10000, Protection: policy}}}})
	for n := 0; n < 2; n++ {
		r := httptest.NewRequest("GET", "http://example.test/login", nil)
		r.Header.Set("User-Agent", "curl/8")
		w := httptest.NewRecorder()
		a.Public(w, r)
		event := <-a.access
		if n == 0 {
			if w.Code != 200 {
				t.Fatalf("first request got %d", w.Code)
			}
			continue
		}
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("second request got %d, want 429", w.Code)
		}
		if !event.blocked || !hasSignal(event.signals, "endpoint_rate") {
			t.Fatalf("access row lacks the endpoint_rate signal: blocked=%v %v", event.blocked, event.signals)
		}
	}
}

func TestEndpointRateStrictKeysIntegration(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	srv := httptest.NewServer(a.Management())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, srv.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "endpoint rate keys password", "secret": cfg.BootstrapSecret}, 201)
	body := c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "endpoint rate keys password"}, 200)
	login := map[string]string{}
	if e := json.Unmarshal(body, &login); e != nil {
		t.Fatal(e)
	}
	c.csrf = login["csrf"]
	raw := `{"spec":{"name":"Endpoint rates","mode":"block","flood_enabled":true,"requests_per_second":20,"burst":60,"site_requests_per_second":1000,"site_burst":2000,"endpoint_rates":[{"path_pattern":"/login","requests_per_second":1,"burst":1,"scope":"per-client","rat":1}]},"applications":[]}`
	request, e := http.NewRequest("POST", srv.URL+"/api/policies", strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Requested-With", "aegis-waf")
	request.Header.Set("X-CSRF-Token", c.csrf)
	res, e := c.client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != 400 {
		t.Fatalf("unknown endpoint-rate key not rejected: %d %s", res.StatusCode, data)
	}
	if !strings.Contains(string(data), "unknown key") || !strings.Contains(string(data), "rat") {
		t.Fatalf("unknown endpoint-rate key not rejected by name: %s", data)
	}
}

// The sealed disk snapshot cache must carry endpoint overrides: a cache
// restored at startup enforces the same budgets as a database refresh.
func TestEndpointRateSnapshotCacheRoundTrip(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	policy := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
	binding := compiledPolicyBinding{ID: 9, Revision: 1, Name: "Cached endpoint budget", Priority: 10000, Protection: policy}
	sealed, e := a.archiveSnapshot(&snapshot{version: 5, policyBindings: map[int64][]compiledPolicyBinding{3: {binding}}}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	restored, e := a.decodeSnapshot(sealed, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	selected := selectPolicy(restored.policyBindings[3], netip.MustParseAddr("203.0.113.4"), true)
	if selected == nil {
		t.Fatal("restored cache lost the policy binding")
	}
	enforcer := &App{}
	ip := netip.MustParseAddr("203.0.113.4")
	now := time.Now()
	if _, blocked, _ := enforcer.protectResolved(selected.Protection, 3, endpointRequest("/login"), ip, now, true); blocked {
		t.Fatal("first request in burst refused after cache restore")
	}
	if _, blocked, _ := enforcer.protectResolved(selected.Protection, 3, endpointRequest("/login"), ip, now, true); !blocked {
		t.Fatal("restored cache lost the endpoint budget: second request allowed")
	}
}

// A corrupted cached override fails the restore instead of reaching
// enforcement, falling back to a full database rebuild.
func TestEndpointRateSnapshotCacheRejectsCorruption(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	for name, mutate := range map[string]func(*cachedBinding){
		"zeroed rate": func(b *cachedBinding) {
			b.EndpointRates[0].Rate = 0
		},
		"burst below rate": func(b *cachedBinding) {
			b.EndpointRates[0].Burst = 0
		},
		"reordered rules": func(b *cachedBinding) {
			b.EndpointRates[0].Index = 4
		},
		"over budget": func(b *cachedBinding) {
			first := b.EndpointRates[0]
			b.EndpointRates = nil
			for n := 0; n <= maxEndpointRateRules; n++ {
				rule := first
				rule.Index = n
				b.EndpointRates = append(b.EndpointRates, rule)
			}
		},
	} {
		policy := endpointPolicy(t, endpointRateRule{PathPattern: "/login", Match: "prefix", RequestsPerSecond: 1, Burst: 1, Scope: "per-client"})
		binding := compiledPolicyBinding{ID: 9, Revision: 1, Name: "Corrupt", Priority: 10000, Protection: policy}
		sealed, e := a.archiveSnapshot(&snapshot{version: 5, policyBindings: map[int64][]compiledPolicyBinding{3: {binding}}}, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		raw, e := open(cfg.Key, a.cacheAAD(), sealed)
		if e != nil {
			t.Fatal(e)
		}
		var cached cachedSnapshot
		if e = json.Unmarshal(raw, &cached); e != nil {
			t.Fatal(e)
		}
		mutate(&cached.Bindings[3][0])
		tampered, e := seal(cfg.Key, a.cacheAAD(), mustJSON(t, cached))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = a.decodeSnapshot(tampered, time.Now()); e == nil {
			t.Fatalf("%s: corrupted cached endpoint rates restored", name)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
