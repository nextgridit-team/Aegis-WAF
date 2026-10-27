package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAPIPolicyControlsIntegration(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	upstream := a.active.Load().routes["bot.test"].site.Upstream
	api.call("PUT", fmt.Sprintf("/api/sites/%d", site), map[string]any{"name": "API", "hostnames": []string{"bot.test"}, "upstream": upstream, "enabled": true, "traffic_profile": "api", "stream_window_bytes": 8192}, 200)
	set, _ := bundledSignatureSet()
	input := policyInput{Spec: policySpecInput{Name: "API limits", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, ManagedSignatures: managedSignatureOptions{SetID: set.ID, Mode: "block", AllowedMethods: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, StreamWindowBytes: 4096}, ConnectionLimits: &connectionLimitSettings{Enabled: true, MaxConcurrent: 3, MaxPerClient: 2, MaxDurationSeconds: 90, IdleTimeoutSeconds: 30}, Groups: []policyGroupInput{}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	id := mustID(t, api.call("POST", "/api/policies", input, 200))
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		binding := selectPolicy(replica.active.Load().policyBindings[site], netip.MustParseAddr("198.51.100.2"), true)
		if binding == nil || binding.Protection.connectionLimits == nil || binding.Protection.connectionLimits.MaxConcurrent != 3 || binding.Protection.connectionMode != "block" || binding.Managed.Options.StreamWindowBytes != 4096 {
			t.Fatal("policy settings not loaded")
		}
		req := httptest.NewRequest("PATCH", "http://bot.test/api/items", strings.NewReader(`{"name":"chair"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "curl/8")
		rec := httptest.NewRecorder()
		replica.Public(rec, req)
		if rec.Code != 200 {
			t.Fatal("legitimate API method rejected", rec.Code, rec.Body)
		}
	}
	var stored []policyView
	if e := json.Unmarshal(api.call("GET", "/api/policies", nil, 200), &stored); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, p := range stored {
		if p.ID == id {
			found = true
			if p.Spec.ConnectionLimits == nil || p.Spec.ManagedSignatures.StreamWindowBytes != 4096 {
				t.Fatal("stored policy fields lost")
			}
		}
	}
	if !found {
		t.Fatal("policy missing")
	}
	// The sealed recovery snapshot retains policy authority, not legacy host settings.
	now := time.Now()
	sealed, e := a.archiveSnapshot(a.active.Load(), now)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := a.decodeSnapshot(sealed, now)
	if e != nil {
		t.Fatal(e)
	}
	binding := restored.policyBindings[site][0]
	if binding.Protection.connectionMode != "block" || binding.Protection.connectionLimits.MaxPerClient != 2 || binding.ManagedOptions.StreamWindowBytes != 4096 {
		t.Fatal("cached policy limits/window lost")
	}
	// Simulation accepts new fields, preserves current state, and warns about unreplayable live limits.
	obj := mustID(t, api.call("POST", "/api/address-objects", map[string]string{"name": "Agent", "value": "127.0.0.1"}, 200))
	var key struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(api.call("POST", "/api/agent-keys", map[string]any{"name": "API simulator", "allowed_addresses": addressSelection{ObjectIDs: []int64{obj}}, "scopes": []string{"read", "enforce", "configuration"}}, 201), &key)
	input.Revision = 1
	input.Spec.ConnectionLimits.MaxConcurrent = 4
	raw, _ := json.Marshal(input)
	mux := http.NewServeMux()
	policyAPI(a, mux)
	summary, e := a.simulateRuleImpact(ctx, agentPrincipal{ID: key.ID, Scopes: []string{"read", "enforce", "configuration"}}, mux, simulationInput{Method: "PUT", Path: fmt.Sprintf("/api/policies/%d", id), Input: raw, TestPayloads: []simulationPayload{{Host: "bot.test", Method: "PATCH", Path: "/api/items", ClientIP: "198.51.100.2", Headers: map[string]string{"User-Agent": "curl/8", "Accept": "application/json", "Content-Type": "application/json"}, Body: `{"name":"chair"}`, Expected: "allow"}}})
	if e != nil || !summary.Eligible {
		t.Fatal("API policy simulation failed", summary, e)
	}
	warnings := strings.Join(summary.Warnings, " ")
	if !strings.Contains(warnings, "connection counts") {
		t.Fatal("live limits simulation overclaim", warnings)
	}
	if a.active.Load().policyBindings[site][0].Protection.connectionLimits.MaxConcurrent != 3 {
		t.Fatal("simulation mutated live limits")
	}
	input.Spec.ConnectionLimits.MaxPerClient = 100
	api.call("PUT", fmt.Sprintf("/api/policies/%d", id), input, 400)
}
