package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// Tests for issue #49: union-at-compile policy composition. Every test here
// asserts behavior main before the fix lacked (proven red on pristine main:
// twelve of thirteen failed with acceptance messages; the thirteenth guards
// the rule dedup the union must not break).

func compositionFixture(t *testing.T) (*App, testAPI, int64) {
	t.Helper()
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "long composition password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "long composition password"}, 200), &login)
	api.csrf = login["csrf"]
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	t.Cleanup(up.Close)
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Composition app", "hostnames": []string{"stack.test"}, "upstream": up.URL, "enabled": true, "redirect_https": false, "protection": defaultProtection()}, 200))
	return a, api, site
}

func compositionPolicy(name, mode string, rules []int64, site int64, cidrs []string, priority int) policyInput {
	groups := []policyGroupInput{}
	if len(rules) > 0 {
		groups = append(groups, policyGroupInput{Name: name + " group", PathPrefix: "/", RuleIDs: rules})
	}
	return policyInput{Spec: policySpecInput{Name: name, Mode: mode, FloodEnabled: true, RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: groups}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: cidrs, Priority: priority}}}
}

func compositionRequest(a *App, path, remote string) int {
	r := httptest.NewRequest("GET", "https://stack.test"+path, nil)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	a.Public(w, r)
	return w.Code
}

// Two policies assigned to the same client scope must compose: the union
// blocks what either member blocks. Main resolves the scope to ONE policy by
// priority, so the second member's rule never applies.
func TestPolicyStackUnionBlocksWhatEitherMemberBlocks(t *testing.T) {
	a, api, site := compositionFixture(t)
	ruleAlpha := mustID(t, api.call("POST", "/api/rules", probeRule("path", "", "equals", "/stack/alpha"), 200))
	ruleBeta := mustID(t, api.call("POST", "/api/rules", probeRule("path", "", "equals", "/stack/beta"), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Stack fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Stack lead", "block", []int64{ruleAlpha}, site, []string{"10.0.0.0/8"}, 10), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Stack second", "block", []int64{ruleBeta}, site, []string{"10.0.0.0/8"}, 20), 200))
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.1.2.3"), true)
	if binding == nil {
		t.Fatal("no policy selected for the stacked client scope")
	}
	seen := map[int64]bool{}
	for _, rule := range binding.Rules {
		seen[rule.ID] = true
	}
	if !seen[ruleAlpha] || !seen[ruleBeta] {
		t.Fatal("a stacked scope must compose the union of both members' rules")
	}
	if code := compositionRequest(a, "/stack/alpha", "10.1.2.3:4000"); code != 403 {
		t.Fatal("stacked union must block the lead member's path, got", code)
	}
	if code := compositionRequest(a, "/stack/beta", "10.1.2.3:4000"); code != 403 {
		t.Fatal("stacked union must block the second member's path, got", code)
	}
	if code := compositionRequest(a, "/stack/beta", "203.0.113.9:4000"); code != 202 {
		t.Fatal("clients outside the stacked scope use the default policy, got", code)
	}
}

// Mode composition: the most protective member wins (off < observe < block).
func TestPolicyStackComposesMostProtectiveMode(t *testing.T) {
	a, api, site := compositionFixture(t)
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Observing member", "observe", nil, site, []string{"10.0.0.0/8"}, 10), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Blocking member", "block", nil, site, []string{"10.0.0.0/8"}, 20), 200))
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.7.7.7"), true)
	if binding == nil || binding.Protection == nil {
		t.Fatal("missing composed binding")
	}
	if binding.Protection.Mode != "block" {
		t.Fatal("most protective member mode must win, got", binding.Protection.Mode)
	}
}

// Body-limit winner is the strictest (minimum) across members.
func TestPolicyStackComposesStrictestBodyLimit(t *testing.T) {
	a, api, site := compositionFixture(t)
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]any{"id": set.ID}, 200)
	wide := compositionPolicy("Wide bodies", "block", nil, site, []string{"10.0.0.0/8"}, 10)
	wide.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", BodyLimit: 1 << 20, Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	tight := compositionPolicy("Tight bodies", "block", nil, site, []string{"10.0.0.0/8"}, 20)
	tight.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", BodyLimit: 8192, Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", wide, 200))
	mustID(t, api.call("POST", "/api/policies", tight, 200))
	if e = a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.3.3.3"), true)
	if binding == nil {
		t.Fatal("missing composed binding")
	}
	if binding.ManagedOptions.BodyLimit != 8192 {
		t.Fatal("stacked body limit must be the strictest member's, got", binding.ManagedOptions.BodyLimit)
	}
}

// Exception sets union across members: every rule any member excluded is
// excluded from the composed engine (the documented, visible widening).
func TestPolicyStackComposesExceptionUnion(t *testing.T) {
	a, api, site := compositionFixture(t)
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]any{"id": set.ID}, 200)
	first := compositionPolicy("Excludes sqli", "block", nil, site, []string{"10.0.0.0/8"}, 10)
	first.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Exclusions: []int{942100}, Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10, ScopedExclusions: []signatureException{{RuleIDs: []int{942100}, PathPrefix: "/legacy/"}}}
	second := compositionPolicy("Excludes session fixation", "block", nil, site, []string{"10.0.0.0/8"}, 20)
	second.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Exclusions: []int{943100}, Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10, ScopedExclusions: []signatureException{{RuleIDs: []int{943100}, PathPrefix: "/uploads/"}}}
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", first, 200))
	mustID(t, api.call("POST", "/api/policies", second, 200))
	if e = a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.4.4.4"), true)
	if binding == nil {
		t.Fatal("missing composed binding")
	}
	if len(binding.ManagedOptions.Exclusions) != 2 || binding.ManagedOptions.Exclusions[0] != 942100 || binding.ManagedOptions.Exclusions[1] != 943100 {
		t.Fatal("stacked rule exclusions must union across members, got", binding.ManagedOptions.Exclusions)
	}
	if len(binding.ManagedOptions.ScopedExclusions) != 2 {
		t.Fatal("stacked scoped exclusions must union across members, got", binding.ManagedOptions.ScopedExclusions)
	}
}

// Allowed methods intersect: only methods every member allows survive.
func TestPolicyStackComposesMethodIntersection(t *testing.T) {
	a, api, site := compositionFixture(t)
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]any{"id": set.ID}, 200)
	writer := compositionPolicy("Writer methods", "block", nil, site, []string{"10.0.0.0/8"}, 10)
	writer.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", AllowedMethods: []string{"GET", "POST"}, Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	reader := compositionPolicy("Reader methods", "block", nil, site, []string{"10.0.0.0/8"}, 20)
	reader.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", AllowedMethods: []string{"GET", "OPTIONS"}, Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", writer, 200))
	mustID(t, api.call("POST", "/api/policies", reader, 200))
	if e = a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.5.5.5"), true)
	if binding == nil {
		t.Fatal("missing composed binding")
	}
	if len(binding.ManagedOptions.AllowedMethods) != 1 || binding.ManagedOptions.AllowedMethods[0] != "GET" {
		t.Fatal("stacked allowed methods must intersect, got", binding.ManagedOptions.AllowedMethods)
	}
}

// Flood budgets compose most-restrictively across flood-enabled members.
func TestPolicyStackComposesMostRestrictiveFloodBudget(t *testing.T) {
	a, api, site := compositionFixture(t)
	generous := compositionPolicy("Generous flood", "block", nil, site, []string{"10.0.0.0/8"}, 10)
	generous.Spec.RequestsPerSecond, generous.Spec.Burst, generous.Spec.SiteRequestsPerSecond, generous.Spec.SiteBurst = 100, 300, 2000, 6000
	strict := compositionPolicy("Strict flood", "block", nil, site, []string{"10.0.0.0/8"}, 20)
	strict.Spec.RequestsPerSecond, strict.Spec.Burst, strict.Spec.SiteRequestsPerSecond, strict.Spec.SiteBurst = 10, 30, 500, 1500
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", generous, 200))
	mustID(t, api.call("POST", "/api/policies", strict, 200))
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.6.6.6"), true)
	if binding == nil || binding.Protection == nil {
		t.Fatal("missing composed binding")
	}
	if binding.Protection.RequestsPerSecond != 10 || binding.Protection.Burst != 30 || binding.Protection.SiteRequestsPerSecond != 500 || binding.Protection.SiteBurst != 1500 {
		t.Fatal("stacked flood budgets must be the most restrictive member's, got", binding.Protection.RequestsPerSecond, binding.Protection.Burst, binding.Protection.SiteRequestsPerSecond, binding.Protection.SiteBurst)
	}
}

// The combination digest dedupes identical merges: two sites composing the
// same set of policies share one compiled engine. Main compiles one engine
// per distinct policy configuration, so two differing members cost two.
func TestPolicyStackCombinationSharesEngineAcrossSites(t *testing.T) {
	a, api, site := compositionFixture(t)
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]any{"id": set.ID}, 200)
	second := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Second app", "hostnames": []string{"second.test"}, "upstream": "http://127.0.0.1:1", "enabled": true, "redirect_https": false, "protection": defaultProtection()}, 200))
	for _, target := range []int64{site, second} {
		paranoiaOne := compositionPolicy("Paranoia one", "block", nil, target, []string{"10.0.0.0/8"}, 10)
		paranoiaOne.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Paranoia: 1, Threshold: 10, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
		paranoiaTwo := compositionPolicy("Paranoia two", "block", nil, target, []string{"10.0.0.0/8"}, 20)
		paranoiaTwo.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Paranoia: 2, Threshold: 10, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
		mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback "+fmt.Sprint(target), "off", nil, target, nil, 10000), 200))
		mustID(t, api.call("POST", "/api/policies", paranoiaOne, 200))
		mustID(t, api.call("POST", "/api/policies", paranoiaTwo, 200))
	}
	if e = a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count := len(a.active.Load().managedWAFs); count != 1 {
		t.Fatal("two sites composing the same policy set must share one engine, got", count)
	}
}

// The same rule selected by two stacked policies composes once: the union
// de-duplicates curated and community selections across members.
func TestPolicyStackDeduplicatesSharedRules(t *testing.T) {
	a, api, site := compositionFixture(t)
	shared := mustID(t, api.call("POST", "/api/rules", probeRule("path", "", "equals", "/stack/shared"), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("First selector", "block", []int64{shared}, site, []string{"10.0.0.0/8"}, 10), 200))
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Second selector", "block", []int64{shared}, site, []string{"10.0.0.0/8"}, 20), 200))
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("10.8.8.8"), true)
	if binding == nil {
		t.Fatal("missing composed binding")
	}
	count := 0
	for _, rule := range binding.Rules {
		if rule.ID == shared {
			count++
		}
	}
	if count != 1 {
		t.Fatal("a rule shared by stacked policies must compose once, got", count)
	}
}

// Multiple default-scope assignments stack: a second default joins the
// scope instead of displacing the first (main reassigns and orphans it).
func TestPolicyStackDefaultsCompose(t *testing.T) {
	a, api, site := compositionFixture(t)
	ruleOne := mustID(t, api.call("POST", "/api/rules", probeRule("path", "", "equals", "/stack/one"), 200))
	ruleTwo := mustID(t, api.call("POST", "/api/rules", probeRule("path", "", "equals", "/stack/two"), 200))
	first := mustID(t, api.call("POST", "/api/policies", compositionPolicy("Default one", "block", []int64{ruleOne}, site, nil, 10000), 200))
	second := mustID(t, api.call("POST", "/api/policies", compositionPolicy("Default two", "block", []int64{ruleTwo}, site, nil, 10000), 200))
	var stored []policyView
	if e := json.Unmarshal(api.call("GET", "/api/policies", nil, 200), &stored); e != nil {
		t.Fatal(e)
	}
	assigned := map[int64]bool{}
	for _, p := range stored {
		for _, application := range p.Applications {
			if application.SiteID == site {
				assigned[p.ID] = true
			}
		}
	}
	if !assigned[first] || !assigned[second] {
		t.Fatal("both default policies must stay assigned to the application")
	}
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr("203.0.113.9"), true)
	if binding == nil {
		t.Fatal("missing composed default binding")
	}
	seen := map[int64]bool{}
	for _, rule := range binding.Rules {
		seen[rule.ID] = true
	}
	if !seen[ruleOne] || !seen[ruleTwo] {
		t.Fatal("stacked defaults must compose the union of their rules")
	}
	if code := compositionRequest(a, "/stack/two", "203.0.113.9:4000"); code != 403 {
		t.Fatal("stacked defaults must block either member's path, got", code)
	}
}

// A scope caps its contributors: the fifth policy in one scope is refused.
func TestPolicyStackRejectsFifthContributor(t *testing.T) {
	_, api, site := compositionFixture(t)
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	for n := 0; n < 4; n++ {
		mustID(t, api.call("POST", "/api/policies", compositionPolicy(fmt.Sprintf("Member %d", n+1), "block", nil, site, []string{"10.0.0.0/8"}, 10+n), 200))
	}
	api.call("POST", "/api/policies", compositionPolicy("Fifth member", "block", nil, site, []string{"10.0.0.0/8"}, 500), 409)
}

// Stacked managed selections must share one signature set: different rule
// universes cannot union at compile time. The rejection names the conflict.
func TestPolicyStackRejectsMixedSignatureSets(t *testing.T) {
	_, api, site := compositionFixture(t)
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]any{"id": set.ID}, 200)
	ids := make([]int, 0, 4)
	entries, e := inventoryForSignatures(set)
	if e != nil {
		t.Fatal(e)
	}
	eligible := make([]int, 0, len(entries))
	for _, entry := range entries {
		if selectableSignature(entry) {
			eligible = append(eligible, entry.ID)
		}
	}
	sort.Ints(eligible)
	if len(eligible) < 4 {
		t.Fatal("fixture set lacks enough selectable rule IDs")
	}
	ids = eligible[:4]
	curated := map[string]any{"name": "Curated subset", "source_set_id": set.ID, "selected_rule_ids": ids}
	var curatedView struct {
		ID string `json:"id"`
	}
	json.Unmarshal(api.call("POST", "/api/signature-sets", curated, 200), &curatedView)
	if curatedView.ID == "" || curatedView.ID == set.ID {
		t.Fatal("curated set fixture missing")
	}
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	first := compositionPolicy("Bundled set member", "block", nil, site, []string{"10.0.0.0/8"}, 10)
	first.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	second := compositionPolicy("Curated set member", "block", nil, site, []string{"10.0.0.0/8"}, 20)
	second.Spec.ManagedSignatures = managedSignatureOptions{SetID: curatedView.ID, Mode: "block", Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	mustID(t, api.call("POST", "/api/policies", first, 200))
	api.call("POST", "/api/policies", second, 409)
}

// The stacked exclusion surface is bounded by the engine's own cap: two
// policies excluding 60 disjoint rules each exceed the 100-rule bound.
func TestPolicyStackRejectsOversizedExclusionUnion(t *testing.T) {
	_, api, site := compositionFixture(t)
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]any{"id": set.ID}, 200)
	available := make([]int, 0, 130)
	for id := range signatureIDs(set.Files) {
		available = append(available, id)
		if len(available) == 130 {
			break
		}
	}
	if len(available) < 120 {
		t.Fatal("fixture set lacks enough rule IDs")
	}
	first := compositionPolicy("Sixty exclusions", "block", nil, site, []string{"10.0.0.0/8"}, 10)
	first.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Exclusions: available[:60], Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	second := compositionPolicy("Sixty more", "block", nil, site, []string{"10.0.0.0/8"}, 20)
	second.Spec.ManagedSignatures = managedSignatureOptions{SetID: set.ID, Mode: "block", Exclusions: available[60:120], Threshold: 10, Paranoia: 1, OutboundThreshold: 5, ResponseBodyLimit: 256 << 10}
	mustID(t, api.call("POST", "/api/policies", compositionPolicy("Fallback", "off", nil, site, nil, 10000), 200))
	mustID(t, api.call("POST", "/api/policies", first, 200))
	api.call("POST", "/api/policies", second, 409)
}

// The snapshot cache format bumps with composition: a cache from the
// previous format must be rejected and rebuilt from the database.
func TestSnapshotCacheRejectsPreviousFormat(t *testing.T) {
	now := time.Now()
	a := &App{cfg: Config{Key: make([]byte, 32), KeyID: "primary", DatabaseURL: "postgres://cache-test", SnapshotCacheFile: "unused", SnapshotCacheMaxAge: time.Hour}}
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	protection, e := compileProtection(defaultProtection())
	if e != nil {
		t.Fatal(e)
	}
	cache := cachedSnapshot{Format: 4, At: now, Version: 2, ManagedSets: map[string]signatureSet{set.ID: set}, Certificates: map[int64]cachedCertificate{}, Sites: []Site{}, Rules: map[int64][]cachedRule{}, Capture: map[int64]TrafficSettings{}, Protection: map[int64]ProtectionSettings{}, Bindings: map[int64][]cachedBinding{}}
	cache.Bindings[1] = append(cache.Bindings[1], cachedBinding{ManagedOptions: managedSignatureOptions{SetID: set.ID, Mode: "observe", Threshold: 15}, ID: 1, Revision: 1, Name: "stale-format", Priority: 10000, CIDRs: []string{}, Protection: protection.ProtectionSettings})
	raw, e := json.Marshal(cache)
	if e != nil {
		t.Fatal(e)
	}
	sealed, e := seal(a.cfg.Key, a.cacheAAD(), raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.decodeSnapshot(sealed, now); e == nil {
		t.Fatal("a cache from the previous format must be rejected")
	}
}

// Networks inside testdata/geolocation/GeoIP2-City-Test.mmdb: the fixture
// database resolves them to US and CN, so composition tests can exercise real
// geo decisions without a downloaded country database.
const (
	geoFixtureUSIP = "216.160.83.56"
	geoFixtureCNIP = "175.16.199.1"
)

// seedGeoFixture installs the vendored test MMDB as the workspace country
// database: enabling Geo on a policy requires a database at save time, and the
// request path resolves client countries from the loaded snapshot.
func seedGeoFixture(t *testing.T, a *App) {
	t.Helper()
	data, e := os.ReadFile("testdata/geolocation/GeoIP2-City-Test.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.db.Exec(context.Background(), "INSERT INTO geo_database(id,data) VALUES(true,$1) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=now()", data); e != nil {
		t.Fatal(e)
	}
}

func compositionGeoPolicy(name string, site int64, priority int, geoMode, strategy string, countries []string) policyInput {
	input := compositionPolicy(name, "block", nil, site, nil, priority)
	input.Spec.NetworkAccess = networkAccessSettings{GeoMode: geoMode, GeoStrategy: strategy, Countries: countries, UnknownCountry: "allow"}
	return input
}

// Country allow lists compose like CIDR allow lists: stacking an allow [US]
// member with an allow [US, CN] member must not admit a CN client the narrow
// member alone would block. Main unioned the composed country list, so the CN
// client was admitted through the stack.
func TestPolicyStackIntersectsAllowSelectedCountries(t *testing.T) {
	a, api, site := compositionFixture(t)
	seedGeoFixture(t, a)
	mustID(t, api.call("POST", "/api/policies", compositionGeoPolicy("Geo narrow", site, 10, "block", "allow_selected", []string{"US"}), 200))
	mustID(t, api.call("POST", "/api/policies", compositionGeoPolicy("Geo wide", site, 20, "block", "allow_selected", []string{"US", "CN"}), 200))
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr(geoFixtureCNIP), true)
	if binding == nil || binding.Protection == nil || binding.Protection.network == nil {
		t.Fatal("missing composed geo binding")
	}
	composed := binding.Protection.network.Settings.Countries
	if len(composed) != 1 || composed[0] != "US" {
		t.Fatal("stacked allow-selected countries must intersect to the narrowest member's list, got", composed)
	}
	if code := compositionRequest(a, "/", geoFixtureCNIP+":4000"); code != 403 {
		t.Fatal("a CN client must not be admitted by a stack whose narrow member allows only the US, got", code)
	}
	if code := compositionRequest(a, "/", geoFixtureUSIP+":4000"); code != 202 {
		t.Fatal("a US client must stay admitted by the stacked allow list, got", code)
	}
}

// A member that is not enforcing Geo contributes no countries to the composed
// allow list: its stale allow-selected settings are inert, so the stack keeps
// exactly the enforcing member's list instead of unioning stale residue in.
func TestPolicyStackIgnoresNonEnforcingMemberCountries(t *testing.T) {
	a, api, site := compositionFixture(t)
	seedGeoFixture(t, a)
	mustID(t, api.call("POST", "/api/policies", compositionGeoPolicy("Geo enforcing", site, 10, "block", "allow_selected", []string{"US"}), 200))
	inert := compositionGeoPolicy("Geo off", site, 20, "off", "allow_selected", []string{"CN"})
	mustID(t, api.call("POST", "/api/policies", inert, 200))
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr(geoFixtureCNIP), true)
	if binding == nil || binding.Protection == nil || binding.Protection.network == nil {
		t.Fatal("missing composed geo binding")
	}
	composed := binding.Protection.network.Settings.Countries
	if len(composed) != 1 || composed[0] != "US" {
		t.Fatal("a member not enforcing Geo must contribute no countries, got", composed)
	}
	if code := compositionRequest(a, "/", geoFixtureCNIP+":4000"); code != 403 {
		t.Fatal("a CN client must stay blocked when only the non-enforcing member would admit it, got", code)
	}
	if code := compositionRequest(a, "/", geoFixtureUSIP+":4000"); code != 202 {
		t.Fatal("a US client must stay admitted by the enforcing member's list, got", code)
	}
}

// Disjoint allow-selected country lists intersect to nothing, so the composed
// scope would admit no client at all: saving the second policy is rejected
// with 409 (the fourth composition rejection class) instead of silently
// composing a scope that blocks every country.
func TestPolicyStackDisjointAllowSelectedCountriesRejected(t *testing.T) {
	a, api, site := compositionFixture(t)
	seedGeoFixture(t, a)
	mustID(t, api.call("POST", "/api/policies", compositionGeoPolicy("Geo US", site, 10, "block", "allow_selected", []string{"US"}), 200))
	body := api.call("POST", "/api/policies", compositionGeoPolicy("Geo CN", site, 20, "block", "allow_selected", []string{"CN"}), 409)
	if !strings.Contains(string(body), "select at least one country") {
		t.Fatalf("disjoint allow-selected lists must be rejected naming the empty intersection, got %s", body)
	}
	// The rejection leaves the first policy protecting traffic untouched.
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	binding := selectPolicy(a.active.Load().policyBindings[site], netip.MustParseAddr(geoFixtureUSIP), true)
	if binding == nil || binding.Protection == nil || binding.Protection.network == nil {
		t.Fatal("missing binding after the rejected save")
	}
	if composed := binding.Protection.network.Settings.Countries; len(composed) != 1 || composed[0] != "US" {
		t.Fatal("the rejected policy must not widen or narrow the live scope, got", composed)
	}
}
