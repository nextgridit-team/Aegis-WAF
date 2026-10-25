package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestManagedSignaturesIntegration(t *testing.T) {
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("GET", "/api/signature-sets/catalogue", nil, 401)
	api.call("GET", "/api/signature-sets/unknown/rules", nil, 401)
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "long managed signature password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "long managed signature password"}, 200), &login)
	api.csrf = login["csrf"]
	var catalogue []struct {
		Set    signatureSet `json:"set"`
		Loaded bool         `json:"loaded"`
	}
	json.Unmarshal(api.call("GET", "/api/signature-sets/catalogue", nil, 200), &catalogue)
	if len(catalogue) != 1 || !catalogue[0].Loaded || len(catalogue[0].Set.Files) > 0 {
		t.Fatal("invalid public catalogue")
	}
	set := catalogue[0].Set
	inventoryPath := "/api/signature-sets/" + set.ID + "/rules"
	var inventory struct {
		Rules  []signatureEntry `json:"rules"`
		Loaded bool             `json:"loaded"`
	}
	rawInventory := api.call("GET", inventoryPath, nil, 200)
	if e := json.Unmarshal(rawInventory, &inventory); e != nil || len(inventory.Rules) != set.RuleCount || !inventory.Loaded || strings.Contains(string(rawInventory), "SecRule") {
		t.Fatal("invalid signature inventory", e)
	}
	api.call("GET", "/api/signature-sets/unknown/rules", nil, 404)
	csrf := api.csrf
	api.csrf = "wrong"
	api.call("POST", "/api/signature-sets", map[string]string{"id": set.ID}, 403)
	api.csrf = csrf
	for n := 0; n < 2; n++ {
		api.call("POST", "/api/signature-sets", map[string]string{"id": set.ID}, 200)
	}
	json.Unmarshal(api.call("GET", inventoryPath, nil, 200), &inventory)
	if !inventory.Loaded || len(inventory.Rules) != set.RuleCount {
		t.Fatal("loaded inventory unavailable")
	}
	var count int
	a.db.QueryRow(ctx, "SELECT count(*) FROM signature_sets").Scan(&count)
	if count != 1 {
		t.Fatal("signature load not idempotent")
	}
	if raw := api.call("GET", "/api/signature-sets", nil, 200); strings.Contains(string(raw), "SecRule") || strings.Contains(string(raw), "files") {
		t.Fatal("summary returned raw bundle")
	}
	var forwarded atomic.Int64
	var responseLeak atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if responseLeak.Load() {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, sqlLeak)
			return
		}
		w.WriteHeader(202)
		io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	protection := defaultProtection()
	protection.TrustedProxies = []string{"10.0.0.1"}
	protection.FloodExemptCIDRs = []string{"198.51.100.0/24"}
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Managed app", "hostnames": []string{"managed.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "protection": protection}, 200))
	input := policyInput{Spec: policySpecInput{Name: "External managed", Mode: "block", FloodEnabled: true, RequestsPerSecond: 10000, Burst: 10000, SiteRequestsPerSecond: 100000, SiteBurst: 100000, Groups: []policyGroupInput{}, ManagedSignatures: managedSignatureOptions{SetID: set.ID, Mode: "observe", ResponseMode: "block", ResponseBodyLimit: 128 << 10, BodyLimitAction: "process_partial"}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	id := mustID(t, api.call("POST", "/api/policies", input, 200))
	path := fmt.Sprintf("/api/policies/%d", id)
	input.Revision = 1
	refresh := func() {
		t.Helper()
		for _, replica := range []*App{a, b} {
			if e := replica.refresh(ctx); e != nil {
				t.Fatal(e)
			}
		}
	}
	refresh()
	attack := "/search?q=" + url.QueryEscape("1' UNION SELECT password FROM users --")
	request := func(replica *App, peer, xff string, want int, policy int64) accessEvent {
		t.Helper()
		r := httptest.NewRequest("GET", "http://managed.test"+attack, nil)
		r.RemoteAddr = peer + ":1234"
		r.Header.Set("User-Agent", "browser")
		r.Header.Set("Accept", "text/html")
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		replica.Public(w, r)
		if w.Code != want {
			t.Fatalf("HTTP %d want %d: %s", w.Code, want, w.Body.String())
		}
		event := <-replica.access
		if event.policyID != policy {
			t.Fatal("wrong selected policy", event.policyID, policy)
		}
		return event
	}
	events := []accessEvent{}
	for _, replica := range []*App{a, b} {
		event := request(replica, "203.0.113.4", "", 202, id)
		if event.managed.Mode != "observe" || len(event.managed.RuleIDs) == 0 || event.managed.SetID != set.ID {
			t.Fatal("missing managed attribution", event.managed)
		}
		events = append(events, event)
	}
	input.Spec.ManagedSignatures.Mode = "block"
	api.call("PUT", path, input, 200)
	input.Revision++
	refresh()
	before := forwarded.Load()
	for _, replica := range []*App{a, b} {
		events = append(events, request(replica, "203.0.113.4", "", 403, id))
	}
	if forwarded.Load() != before {
		t.Fatal("managed-blocked request reached upstream")
	}
	// Narrow component exceptions and forged identities cannot bypass managed signatures.
	events = append(events, request(a, "10.0.0.1", "198.51.100.4", 403, id))
	if len(events[len(events)-1].exemptions) == 0 {
		t.Fatal("flood exception not independently recorded")
	}
	internal := input
	internal.Spec.Name = "Internal managed policy"
	internal.Spec.Mode = "off"
	internal.Applications = []policyAssignment{{SiteID: site, SourceCIDRs: []string{"192.168.1.0/24"}, Priority: 100}}
	internal.Revision = 0
	internalID := mustID(t, api.call("POST", "/api/policies", internal, 200))
	refresh()
	request(a, "10.0.0.1", "192.168.1.4", 202, internalID)
	request(a, "203.0.113.4", "192.168.1.4", 403, id)
	request(a, "10.0.0.1", "invalid", 403, id)
	broken := input
	broken.Spec.ManagedSignatures.Exclusions = []int{999999}
	api.call("PUT", path, broken, 400)
	refresh()
	request(b, "203.0.113.4", "", 403, id)
	// Global Observe caps a configured blocking signature set.
	input.Spec.Mode = "observe"
	api.call("PUT", path, input, 200)
	input.Revision++
	refresh()
	event := request(a, "203.0.113.4", "", 202, id)
	if event.managed.Mode != "observe" {
		t.Fatal("policy Observe did not cap signatures")
	}
	input.Spec.Mode = "block"
	api.call("PUT", path, input, 200)
	input.Revision++
	refresh()
	// An unrelated policy edit reuses compiled immutable rules.
	previous := a.active.Load().policyBindings[site][1].Managed
	input.Spec.Description = "description only"
	api.call("PUT", path, input, 200)
	input.Revision++
	refresh()
	if a.active.Load().policyBindings[site][1].Managed != previous {
		t.Fatal("unchanged managed rules recompiled")
	}
	if e := a.storeAccessBatch(ctx, events); e != nil {
		t.Fatal(e)
	}
	raw := api.call("GET", "/api/access-logs", nil, 200)
	if strings.Contains(string(raw), "UNION") || strings.Contains(string(raw), "password FROM") {
		t.Fatal("matched payload leaked into metadata")
	}
	if !strings.Contains(string(raw), "managed_signatures") || !strings.Contains(string(raw), set.ID) {
		t.Fatal("managed result not persisted")
	}
	cached, e := New(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	cached.db.Close()
	if !cached.cacheRestored.Load() {
		t.Fatal("cache did not restore managed policy")
	}
	request(cached, "203.0.113.4", "", 403, id)
	responseLeak.Store(true)
	for _, replica := range []*App{a, b, cached} {
		r := httptest.NewRequest("GET", "http://managed.test/response", nil)
		r.RemoteAddr = "203.0.113.4:1234"
		r.Header.Set("User-Agent", "browser")
		w := httptest.NewRecorder()
		replica.Public(w, r)
		event := <-replica.access
		if w.Code != 502 || strings.Contains(w.Body.String(), sqlLeak) || event.managed.ResponseMode != "block" || event.managed.ResponseInspection != "match" {
			t.Fatalf("response policy not restored/enforced: %d %+v", w.Code, event.managed)
		}
		binding := replica.active.Load().policyBindings[site][1]
		if binding.Managed.Options.ResponseBodyLimit != 128<<10 || binding.Managed.Options.BodyLimitAction != "process_partial" {
			t.Fatal("body settings not preserved")
		}
		if e := a.storeAccessBatch(ctx, []accessEvent{event}); e != nil {
			t.Fatal(e)
		}
	}
	raw = api.call("GET", "/api/access-logs", nil, 200)
	if !strings.Contains(string(raw), "response_inspection") || !strings.Contains(string(raw), "951120") || strings.Contains(string(raw), "credentials") {
		t.Fatal("response telemetry missing or payload leaked")
	}
	// The enabled rules are persisted, not a mutable reference to a feed or catalogue.
	var digest string
	if e = a.db.QueryRow(ctx, "SELECT digest FROM signature_sets WHERE id=$1", set.ID).Scan(&digest); e != nil || digest != set.Digest {
		t.Fatal("signature bundle persistence mismatch", e)
	}
}
