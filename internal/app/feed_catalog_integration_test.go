package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceCatalogueIntegration(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	api.call("GET", "/api/rule-catalog", nil, 200)
	manifest, files := communityFixture(t)
	a.feedHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		raw := files[filepath.Base(r.URL.Path)]
		if strings.HasSuffix(r.URL.Path, "manifest.json") {
			raw, _ = json.Marshal(manifest)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	id := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Shared CVE catalogue", "url": "https://example.com/rules/manifest.json"}, 201))
	path := fmt.Sprintf("/api/rule-feeds/%d", id)
	api.call("POST", path+"/sync", map[string]any{}, 200)
	var catalogue []struct {
		ID    int64  `json:"id"`
		Entry string `json:"entry_id"`
	}
	json.Unmarshal(api.call("GET", "/api/rule-catalog", nil, 200), &catalogue)
	if len(catalogue) != 2 {
		t.Fatal("workspace catalogue not synced", catalogue)
	}
	var nativeCount int
	a.db.QueryRow(ctx, "SELECT count(*) FROM rules").Scan(&nativeCount)
	if nativeCount != 0 {
		t.Fatal("sync imported/activated native rules")
	}
	ruleID := catalogue[0].ID
	var fileName string
	for _, entry := range manifest.Rules {
		if entry.ID == catalogue[0].Entry {
			fileName = entry.Path
		}
	}
	p := policyInput{Spec: policySpecInput{Name: "Catalogue policy", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{{Name: "Chosen mitigation", RuleIDs: []int64{ruleID}}}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	policy := mustID(t, api.call("POST", "/api/policies", p, 200))
	policyPath := fmt.Sprintf("/api/policies/%d", policy)
	p.Revision = 1
	read := func() policyRule {
		t.Helper()
		var raw []byte
		if e := a.db.QueryRow(ctx, "SELECT spec FROM policies WHERE id=$1", policy).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		var spec policySpec
		json.Unmarshal(raw, &spec)
		return spec.Groups[0].Rules[0]
	}
	pinned := read()
	if pinned.Feed == nil || pinned.Feed.Revision != 1 || pinned.Feed.Digest == "" {
		t.Fatal("missing frozen feed provenance", pinned)
	}
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		bindings := replica.active.Load().policyBindings[site]
		if len(bindings) != 1 || len(bindings[0].Rules) != 1 || bindings[0].Rules[0].ID != ruleID {
			t.Fatal("catalogue not compiled into assigned policy")
		}
	}
	// Exercise the same policy operation through the MCP simulation guard.
	obj := mustID(t, api.call("POST", "/api/address-objects", map[string]string{"name": "Catalogue agent", "value": "127.0.0.1"}, 200))
	var key struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(api.call("POST", "/api/agent-keys", map[string]any{"name": "Catalogue simulator", "allowed_addresses": addressSelection{ObjectIDs: []int64{obj}}, "scopes": []string{"read", "enforce"}}, 201), &key)
	principal := agentPrincipal{ID: key.ID, Scopes: []string{"read", "enforce"}}
	mux := http.NewServeMux()
	policyAPI(a, mux)
	var vectorFile feedRuleFile
	json.Unmarshal(files[fileName], &vectorFile)
	vector := vectorFile.Tests[0]
	proposed := p
	proposed.RefreshRuleIDs = []int64{ruleID}
	payload, _ := json.Marshal(proposed)
	input := simulationInput{Method: "PUT", Path: policyPath, Input: payload, TestPayloads: []simulationPayload{{Host: "bot.test", Method: vector.Method, Path: vector.Path, Headers: vector.Headers, Expected: "block"}}}
	receipt, e := a.simulateRuleImpact(ctx, principal, mux, input)
	if e != nil || !receipt.Eligible || receipt.ID == "" || !receipt.Harness[0].Passed {
		t.Fatal("catalogue policy simulation failed", receipt, e)
	}
	apply := func(token string) int {
		digest, e := simulationCandidateHash(input.Method, input.Path, input.Input)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest(input.Method, input.Path, strings.NewReader(string(payload)))
		r.Header.Set("Content-Type", "application/json")
		_, pattern := mux.Handler(r)
		r = r.WithContext(context.WithValue(ctx, agentInvocationKey{}, agentInvocation{Principal: principal, Pattern: pattern, Scope: agentScopeFor(pattern), SimulationID: token, CandidateHash: digest}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	if got := apply(""); got != 428 {
		t.Fatal("catalogue policy allowed unsimulated MCP mutation", got)
	}
	var versionBefore int64
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&versionBefore)
	var file feedRuleFile
	json.Unmarshal(files[fileName], &file)
	file.Revision = 2
	file.Description += " Updated applicability."
	raw, _ := json.Marshal(file)
	files[fileName] = raw
	digest := sha256.Sum256(raw)
	for n := range manifest.Rules {
		if manifest.Rules[n].ID == file.ID {
			manifest.Rules[n].SHA256 = hex.EncodeToString(digest[:])
		}
	}
	manifest.Revision++
	api.call("POST", path+"/sync", map[string]any{}, 200)
	var versionAfter int64
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&versionAfter)
	if versionAfter <= versionBefore {
		t.Fatal("sync left old simulation receipts valid")
	}
	if read().Feed.Revision != 1 {
		t.Fatal("sync changed live pinned policy")
	}
	if got := apply(receipt.ID); got != 428 {
		t.Fatal("catalogue sync left an old MCP receipt usable", got)
	}
	if !strings.Contains(string(api.call("GET", path+"/items", nil, 200)), `"update_available":true`) {
		t.Fatal("missing per-policy update status")
	}
	api.call("PUT", policyPath, p, 200)
	p.Revision++
	if read().Feed.Revision != 1 {
		t.Fatal("ordinary save silently refreshed catalogue")
	}
	p.RefreshRuleIDs = []int64{ruleID}
	api.call("PUT", policyPath, p, 200)
	p.Revision++
	p.RefreshRuleIDs = nil
	if read().Feed.Revision != 2 {
		t.Fatal("explicit targeted refresh did not update pinned revision")
	}
	// Same revision with changed bytes is rejected atomically and visibly.
	file.Description += " Conflicting edit."
	raw, _ = json.Marshal(file)
	files[fileName] = raw
	digest = sha256.Sum256(raw)
	for n := range manifest.Rules {
		if manifest.Rules[n].ID == file.ID {
			manifest.Rules[n].SHA256 = hex.EncodeToString(digest[:])
		}
	}
	manifest.Revision++
	api.call("POST", path+"/sync", map[string]any{}, 400)
	var storedRevision int
	var failure string
	a.db.QueryRow(ctx, "SELECT revision FROM rule_catalog WHERE id=$1", ruleID).Scan(&storedRevision)
	a.db.QueryRow(ctx, "SELECT error FROM rule_feeds WHERE id=$1", id).Scan(&failure)
	if storedRevision != 2 || failure == "" {
		t.Fatal("conflicting revision damaged catalogue or hid failure", storedRevision, failure)
	}
	api.call("POST", path+"/import", map[string]any{}, 400)
	api.call("DELETE", path, nil, 200)
	if read().Feed.Revision != 2 {
		t.Fatal("removing feed removed active policy snapshot")
	}
	api.call("PUT", policyPath, p, 200)
	p.Revision++
	p.RefreshRuleIDs = []int64{ruleID}
	api.call("PUT", policyPath, p, 400)
	if e := b.refresh(ctx); e != nil {
		t.Fatal("frozen policy failed after feed removal", e)
	}
}

func TestCommunityFeedSeedOnce(t *testing.T) {
	a, b, api, _, _ := captchaFixture(t)
	ctx := context.Background()
	var id int64
	if e := a.db.QueryRow(ctx, "SELECT id FROM rule_feeds WHERE site_id IS NULL AND url=$1", communityFeedURL).Scan(&id); e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/rule-feeds", map[string]any{"name": "Duplicate", "url": communityFeedURL}, 409)
	api.call("DELETE", fmt.Sprintf("/api/rule-feeds/%d", id), nil, 200)
	if e := b.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	var count int
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM rule_feeds WHERE url=$1", communityFeedURL).Scan(&count); e != nil || count != 0 {
		t.Fatal("removed community subscription was recreated", count, e)
	}
}
