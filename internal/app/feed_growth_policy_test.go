package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Feed growth policy (#56): a rule-catalogue source must not be able to grow a
// deployment without bound. Per-source rule cap (RULE_FEED_SOURCE_LIMIT) and
// global community-rule budget (COMMUNITY_RULE_BUDGET) refuse growth at import
// time inside the catalogue transaction, so the previous catalogue stays
// applied, and both surfaces are visible per source.

func bundledCatalogueRules(t *testing.T) int {
	t.Helper()
	raw, e := os.ReadFile("../../rules/community/release.json")
	if e != nil {
		t.Fatal(e)
	}
	base, e := url.Parse(communityFeedURL)
	if e != nil {
		t.Fatal(e)
	}
	release, e := parseRuleManifest(raw, base)
	if e != nil {
		t.Fatal(e)
	}
	return release.Package.RuleCount
}

func growthRuleFile(id string, revision int) feedRuleFile {
	rule := probeRule("path", "", "equals", "/"+id)
	rule.Name = "Growth probe " + id
	return feedRuleFile{
		SchemaVersion: 1,
		ID:            id,
		catalogueMetadata: catalogueMetadata{
			Revision:          revision,
			Pack:              "Growth",
			Technology:        []string{"http"},
			Description:       "Synthetic feed growth policy rule " + id,
			AffectedVersions:  "all",
			Coverage:          "test fixture only",
			Limitations:       "none",
			FalsePositiveRisk: "low",
			References:        []string{"https://example.com/growth"},
		},
		Rule: rule,
		Tests: []catalogueRuleTest{
			{Name: "match", Method: "GET", Path: "/" + id, ExpectedMatch: true},
			{Name: "miss", Method: "GET", Path: "/other", ExpectedMatch: false},
		},
	}
}

func growthCatalogue(t *testing.T, revision, count int) (ruleManifest, []byte) {
	t.Helper()
	names := []string{}
	contents := [][]byte{}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("growth-%03d", i)
		raw, e := json.Marshal(growthRuleFile(id, revision))
		if e != nil {
			t.Fatal(e)
		}
		names = append(names, "rules/"+id+".json")
		contents = append(contents, raw)
	}
	archive := testArchive(t, names, contents, false)
	sum := sha256.Sum256(archive)
	manifest := ruleManifest{SchemaVersion: 3, Name: "Growth release", Revision: revision, Package: &cataloguePackage{Path: "growth.zip", SHA256: hex.EncodeToString(sum[:]), RuleCount: count, SizeBytes: int64(len(archive))}}
	return manifest, archive
}

func growthTransport(t *testing.T, a *App, manifest ruleManifest, archive []byte) {
	t.Helper()
	raw, e := json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		body := raw
		if strings.HasSuffix(r.URL.Path, "/growth.zip") {
			body = archive
		} else if !strings.HasSuffix(r.URL.Path, "/release.json") {
			return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
}

func growthAdmin(t *testing.T, cfg Config, a *App) testAPI {
	t.Helper()
	server := httptest.NewServer(a.Management())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "long password for growth test", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "long password for growth test"}, 200), &login)
	api.csrf = login["csrf"]
	return api
}

func TestFeedGrowthConfigValidation(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:secret@127.0.0.1:5432/aegis?sslmode=disable")
	t.Setenv("BOOTSTRAP_SECRET", strings.Repeat("s", 40))
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	for _, tc := range []struct{ name, key, value string }{
		{"per-source zero", "RULE_FEED_SOURCE_LIMIT", "0"},
		{"per-source negative", "RULE_FEED_SOURCE_LIMIT", "-1"},
		{"per-source over format bound", "RULE_FEED_SOURCE_LIMIT", "2001"},
		{"per-source not a number", "RULE_FEED_SOURCE_LIMIT", "many"},
		{"budget zero", "COMMUNITY_RULE_BUDGET", "0"},
		{"budget over max", "COMMUNITY_RULE_BUDGET", "20001"},
		{"budget not a number", "COMMUNITY_RULE_BUDGET", "lots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, e := LoadConfig(); e == nil || !strings.Contains(e.Error(), tc.key) {
				t.Fatalf("accepted %s=%s: %v", tc.key, tc.value, e)
			}
		})
	}
	t.Setenv("RULE_FEED_SOURCE_LIMIT", "1")
	t.Setenv("COMMUNITY_RULE_BUDGET", "20000")
	c, e := LoadConfig()
	if e != nil {
		t.Fatal(e)
	}
	if c.FeedSourceRuleLimit != 1 || c.CommunityRuleBudget != 20000 {
		t.Fatal("valid knob values not parsed", c.FeedSourceRuleLimit, c.CommunityRuleBudget)
	}
	// Bare configs (tests, zero values) resolve to the documented defaults.
	a := &App{}
	if a.feedSourceRuleLimit() != defaultFeedSourceRuleLimit || a.communityRuleBudget() != defaultCommunityRuleBudget {
		t.Fatal("default growth limits not applied for unset configuration")
	}
}

func TestFeedSourceRuleCapRefusesGrowth(t *testing.T) {
	cfg := testDB(t)
	cfg.FeedSourceRuleLimit = 3
	a := newTestReplica(t, cfg)
	api := growthAdmin(t, cfg, a)
	ctx := context.Background()
	manifest, archive := growthCatalogue(t, 1, 5)
	growthTransport(t, a, manifest, archive)
	id := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Runaway catalogue", "url": "https://example.com/growth/release.json"}, 201))
	body := api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", id), map[string]any{}, 400)
	for _, want := range []string{"per-source rule cap", "5 stored rules", "cap of 3", "RULE_FEED_SOURCE_LIMIT"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("refusal missing %q: %s", want, body)
		}
	}
	var stored, recorded int
	var failure string
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1", id).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	a.db.QueryRow(ctx, "SELECT count(*) FROM rule_feeds WHERE id=$1 AND error LIKE '%per-source rule cap%'", id).Scan(&recorded)
	a.db.QueryRow(ctx, "SELECT error FROM rule_feeds WHERE id=$1", id).Scan(&failure)
	if stored != 0 || recorded != 1 || failure == "" {
		t.Fatal("over-cap import applied rows or hid the failure", stored, recorded, failure)
	}
	// No partial application: the seeded official catalogue is untouched.
	var official int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog c JOIN rule_feeds f ON f.id=c.feed_id WHERE f.url=$1", communityFeedURL).Scan(&official); e != nil || official != bundledCatalogueRules(t) {
		t.Fatal("refused import damaged other sources", official, e)
	}
}

func TestFeedSourceRuleCapKeepsLastGoodAndAllowsNonGrowth(t *testing.T) {
	cfg := testDB(t)
	cfg.FeedSourceRuleLimit = 3
	a := newTestReplica(t, cfg)
	api := growthAdmin(t, cfg, a)
	ctx := context.Background()
	id := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Capped catalogue", "url": "https://example.com/growth/release.json"}, 201))
	apiSync := func(revision, count, want int) []byte {
		manifest, archive := growthCatalogue(t, revision, count)
		growthTransport(t, a, manifest, archive)
		return api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", id), map[string]any{}, want)
	}
	// Fitting release applies.
	apiSync(1, 3, 200)
	var stored int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1 AND available", id).Scan(&stored); e != nil || stored != 3 {
		t.Fatal("fitting catalogue not applied", stored, e)
	}
	// A same-size replacement (revision bump, no growth) still applies.
	apiSync(2, 3, 200)
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1 AND available", id).Scan(&stored); e != nil || stored != 3 {
		t.Fatal("non-growing replacement refused", stored, e)
	}
	// Growth past the cap is refused and keeps the last-good catalogue.
	body := apiSync(3, 4, 400)
	if !strings.Contains(string(body), "per-source rule cap") {
		t.Fatalf("growth refusal missing cap reason: %s", body)
	}
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1 AND available", id).Scan(&stored); e != nil || stored != 3 {
		t.Fatal("refused growth damaged last-good catalogue", stored, e)
	}
	var revision int
	if e := a.db.QueryRow(ctx, "SELECT manifest_revision FROM rule_feeds WHERE id=$1", id).Scan(&revision); e != nil || revision != 2 {
		t.Fatal("refused growth changed manifest revision", revision, e)
	}
}

func TestCommunityRuleBudgetRefusesGrowth(t *testing.T) {
	bundled := bundledCatalogueRules(t)
	cfg := testDB(t)
	cfg.CommunityRuleBudget = bundled + 2
	a := newTestReplica(t, cfg)
	api := growthAdmin(t, cfg, a)
	ctx := context.Background()
	first := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Budget fitting", "url": "https://example.com/growth/release.json"}, 201))
	manifest, archive := growthCatalogue(t, 1, 2)
	growthTransport(t, a, manifest, archive)
	api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", first), map[string]any{}, 200)
	second := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Budget exceeding", "url": "https://example.com/other/release.json"}, 201))
	other, otherArchive := growthCatalogue(t, 1, 1)
	otherRaw, _ := json.Marshal(other)
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		body := otherRaw
		if strings.HasSuffix(r.URL.Path, "/growth.zip") {
			body = otherArchive
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	body := api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", second), map[string]any{}, 400)
	for _, want := range []string{"community rule budget", fmt.Sprintf("budget of %d", bundled+2), "COMMUNITY_RULE_BUDGET"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("refusal missing %q: %s", want, body)
		}
	}
	var total, secondRows int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog").Scan(&total); e != nil || total != bundled+2 {
		t.Fatal("refused import changed the stored catalogue", total, e)
	}
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1", second).Scan(&secondRows); e != nil || secondRows != 0 {
		t.Fatal("over-budget source partially applied", secondRows, e)
	}
	// Growth of an already-present source past the budget is refused too.
	manifest, archive = growthCatalogue(t, 2, 3)
	growthTransport(t, a, manifest, archive)
	api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", first), map[string]any{}, 400)
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_catalog WHERE feed_id=$1 AND available", first).Scan(&secondRows); e != nil || secondRows != 2 {
		t.Fatal("over-budget growth damaged last-good catalogue", secondRows, e)
	}
}

func TestSiteFeedStagedRulesCapped(t *testing.T) {
	cfg := testDB(t)
	cfg.FeedSourceRuleLimit = 3
	a := newTestReplica(t, cfg)
	api := growthAdmin(t, cfg, a)
	ctx := context.Background()
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Growth app", "hostnames": []string{"growth.test"}, "upstream": "http://127.0.0.1:8000", "enabled": true, "redirect_https": false}, 200))
	id := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Rotating source", "url": "https://example.com/site.json", "site_id": site}, 201))
	feedDoc := func(prefix string, count int) []byte {
		rules := []feedCandidate{}
		for i := 0; i < count; i++ {
			spec := probeRule("path", "", "equals", "/"+prefix)
			spec.Name = "Probe " + prefix
			rules = append(rules, feedCandidate{fmt.Sprintf("%s-%d", prefix, i), spec})
		}
		raw, _ := json.Marshal(feedDocument{1, rules})
		return raw
	}
	serve := func(raw []byte) {
		a.feedHTTP = dnsTestTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		})
	}
	serve(feedDoc("first", 4))
	body := api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", id), map[string]any{}, 400)
	if !strings.Contains(string(body), "per-source rule cap") {
		t.Fatalf("first over-cap site feed accepted: %s", body)
	}
	var staged int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_feed_items WHERE feed_id=$1", id).Scan(&staged); e != nil || staged != 0 {
		t.Fatal("over-cap site feed staged candidates", staged, e)
	}
	serve(feedDoc("first", 3))
	api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", id), map[string]any{}, 200)
	// Rotating IDs grows staged storage even at the same document size; the
	// cap must refuse that growth and keep the last-good candidates.
	serve(feedDoc("second", 3))
	api.call("POST", fmt.Sprintf("/api/rule-feeds/%d/sync", id), map[string]any{}, 400)
	var available int
	if e := a.db.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE available) FROM rule_feed_items WHERE feed_id=$1", id).Scan(&staged, &available); e != nil {
		t.Fatal(e)
	}
	if staged != 3 || available != 3 {
		t.Fatal("refused rotation damaged last-good staged candidates", staged, available)
	}
}

func TestFeedGrowthSeedingBypassesCaps(t *testing.T) {
	// The bundled baseline is build-bounded and trusted; growth caps apply to
	// network syncs, so a replica with tight caps still boots and seeds.
	cfg := testDB(t)
	cfg.FeedSourceRuleLimit = 1
	cfg.CommunityRuleBudget = 1
	a := newTestReplica(t, cfg)
	var seeded int
	if e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM rule_catalog").Scan(&seeded); e != nil || seeded != bundledCatalogueRules(t) {
		t.Fatal("bundled catalogue not seeded under tight caps", seeded, e)
	}
}

func TestFeedGrowthVisibilitySurfaces(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	api := growthAdmin(t, cfg, a)
	bundled := bundledCatalogueRules(t)
	var sources []map[string]any
	json.Unmarshal(api.call("GET", "/api/rule-feeds", nil, 200), &sources)
	official := map[string]any{}
	for _, source := range sources {
		if source["url"] == communityFeedURL {
			official = source
		}
	}
	if official == nil || official["rule_count"] != float64(bundled) || official["rule_limit"] != float64(defaultFeedSourceRuleLimit) {
		t.Fatalf("rule-feeds list missing cap state: %+v", official)
	}
	var capacity struct {
		CommunityRules struct {
			Limit          int `json:"limit"`
			Stored         int `json:"stored"`
			Remaining      int `json:"remaining"`
			PerSourceLimit int `json:"per_source_limit"`
			Sources        int `json:"sources"`
		} `json:"community_rules"`
	}
	json.Unmarshal(api.call("GET", "/api/policy-capacity", nil, 200), &capacity)
	if capacity.CommunityRules.Limit != defaultCommunityRuleBudget || capacity.CommunityRules.Stored != bundled || capacity.CommunityRules.PerSourceLimit != defaultFeedSourceRuleLimit || capacity.CommunityRules.Sources < 1 || capacity.CommunityRules.Remaining != defaultCommunityRuleBudget-bundled {
		t.Fatalf("policy-capacity missing community rule budget: %+v", capacity.CommunityRules)
	}
	// A lowered cap is reported as the live limit on both surfaces.
	cfg2 := testDB(t)
	cfg2.FeedSourceRuleLimit = 5
	b := newTestReplica(t, cfg2)
	api2 := growthAdmin(t, cfg2, b)
	json.Unmarshal(api2.call("GET", "/api/rule-feeds", nil, 200), &sources)
	for _, source := range sources {
		if source["rule_limit"] != float64(5) {
			t.Fatalf("lowered per-source cap not surfaced: %+v", source)
		}
	}
}
