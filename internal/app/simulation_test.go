package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSimulationCandidateBinding(t *testing.T) {
	a, e := simulationCandidateHash("PUT", "/api/policies/1?b=2&a=1", json.RawMessage(`{"x":1,"y":2}`))
	b, f := simulationCandidateHash("PUT", "/api/policies/1?a=1&b=2", json.RawMessage(`{ "y":2, "x":1 }`))
	if e != nil || f != nil || a != b {
		t.Fatal("canonical candidate mismatch", e, f)
	}
	for _, body := range []string{`[]`, `null`, `{} {}`, `{"x":`} {
		if _, e := simulationCandidateHash("PUT", "/api/policies/1", json.RawMessage(body)); e == nil {
			t.Fatal("accepted invalid candidate", body)
		}
	}
	for _, path := range []string{"https://evil/api/sites", "/api/sites#fragment", "/api/\\sites"} {
		if _, e := simulationCandidateHash("PUT", path, json.RawMessage(`{}`)); e == nil {
			t.Fatal("accepted path", path)
		}
	}
	for _, pattern := range []string{"POST /api/rules/{id}/activate", "PUT /api/policies/{id}", "PUT /api/address-objects/{id}", "PUT /api/protection-settings/{id}", "DELETE /api/sites/{id}"} {
		if !requiresRuleSimulation(pattern) {
			t.Fatal("unguarded mutation", pattern)
		}
	}
}

func TestSimulationIntegration(t *testing.T) {
	a, _, api, site, forwarded := captchaFixture(t)
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), defaultProtection(), 200)
	rule := probeRule("path", "", "regex", `^/private`)
	rule.Scope.SiteID = site
	id := mustID(t, api.call("POST", "/api/rules", rule, 200))
	obj := mustID(t, api.call("POST", "/api/address-objects", map[string]string{"name": "Agent peer", "value": "127.0.0.1"}, 200))
	var key struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(api.call("POST", "/api/agent-keys", map[string]any{"name": "Simulator", "allowed_addresses": addressSelection{ObjectIDs: []int64{obj}}, "scopes": []string{"read", "enforce", "configuration", "evidence"}}, 201), &key)
	principal := agentPrincipal{ID: key.ID, Scopes: []string{"read", "enforce", "configuration", "evidence"}}
	mux := http.NewServeMux()
	ruleAPI(a, mux)
	dashboardAPI(a, mux)
	policyAPI(a, mux)
	addressAPI(a, mux)
	ctx := context.Background()
	if e := a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	before := a.active.Load()
	var version, audits int64
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&version)
	a.db.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&audits)
	input := simulationInput{Method: "POST", Path: fmt.Sprintf("/api/rules/%d/activate", id), Input: json.RawMessage(`{"action":"block","ttl_seconds":300}`), TestPayloads: []simulationPayload{{Host: "bot.test", Path: "/private/key", Expected: "block"}, {Host: "bot.test", Path: "/", Expected: "allow"}}}
	simulate := func(in simulationInput) simulationSummary {
		t.Helper()
		s, e := a.simulateRuleImpact(ctx, principal, mux, in)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	summary := simulate(input)
	if !summary.Eligible || summary.ID == "" || len(summary.Harness) != 2 || !summary.Harness[0].Passed || !summary.Harness[1].Passed {
		t.Fatalf("bad simulation %+v", summary)
	}
	var current, afterAudits int64
	var enabled bool
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&current)
	a.db.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&afterAudits)
	a.db.QueryRow(ctx, "SELECT enabled FROM rules WHERE id=$1", id).Scan(&enabled)
	if current != version || afterAudits != audits || enabled || a.active.Load() != before || forwarded.Load() != 0 {
		t.Fatal("simulation changed live state")
	}
	apply := func(p agentPrincipal, in simulationInput, receipt string) int {
		digest, e := simulationCandidateHash(in.Method, in.Path, in.Input)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest(in.Method, in.Path, strings.NewReader(string(in.Input)))
		r.Header.Set("Content-Type", "application/json")
		_, pattern := mux.Handler(r)
		r = r.WithContext(context.WithValue(ctx, agentInvocationKey{}, agentInvocation{Principal: p, Pattern: pattern, Scope: agentScopeFor(pattern), SimulationID: receipt, CandidateHash: digest}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	if got := apply(principal, input, ""); got != 428 {
		t.Fatal("missing receipt", got)
	}
	changed := input
	changed.Input = json.RawMessage(`{"action":"observe","ttl_seconds":300}`)
	if got := apply(principal, changed, summary.ID); got != 428 {
		t.Fatal("tampered candidate", got)
	}
	other := principal
	other.ID++
	if got := apply(other, input, summary.ID); got != 428 {
		t.Fatal("other key", got)
	}
	if got := apply(principal, input, summary.ID); got != 200 {
		t.Fatal("receipt enforcement", got)
	}
	if got := apply(principal, input, summary.ID); got != 428 {
		t.Fatal("receipt reused", got)
	}
	summary = simulate(input)
	if _, e := a.db.Exec(ctx, "UPDATE mcp_simulations SET expires_at=now()-interval '1 second' WHERE token_hash=$1", hash(summary.ID)); e != nil {
		t.Fatal(e)
	}
	if got := apply(principal, input, summary.ID); got != 428 {
		t.Fatal("expired receipt", got)
	}
	summary = simulate(input)
	api.call("PUT", fmt.Sprintf("/api/protection-settings/%d", site), defaultProtection(), 200)
	if got := apply(principal, input, summary.ID); got != 428 {
		t.Fatal("stale receipt", got)
	}
	// An expected outcome failure withholds an otherwise evaluable receipt.
	failed := input
	failed.TestPayloads = []simulationPayload{{Host: "bot.test", Path: "/private", Expected: "allow"}}
	if s := simulate(failed); s.ID != "" || s.Eligible {
		t.Fatal("failed expected outcome authorized", s)
	}
	empty := input
	empty.TestPayloads = nil
	if s := simulate(empty); s.ID != "" || s.Eligible {
		t.Fatal("empty simulation authorized", s)
	}
	// Metadata without a captured path cannot prove a regex match or non-match.
	if _, e := a.db.Exec(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,blocked) VALUES(now(),$1,'GET',200,0,'198.51.100.1',false)", site); e != nil {
		t.Fatal(e)
	}
	if s := simulate(empty); s.Unknown != 1 || s.ID != "" || s.NewlyBlocked != 0 {
		t.Fatal("unknown facts invented", s)
	}
	// Retained opted-in facts provide an offline match, with no forwarding.
	evidence := TrafficEvidence{SchemaVersion: 1, Facts: map[string]Fact{factKey("path", ""): {State: "present", Values: []string{"/private/key"}}}}
	raw, _ := json.Marshal(evidence)
	if _, e := a.db.Exec(ctx, "INSERT INTO traffic_evidence(id,at,site_id,expires_at,data) VALUES('simulation-test',now(),$1,now()+interval '1 hour',$2)", site, raw); e != nil {
		t.Fatal(e)
	}
	a.db.Exec(ctx, "UPDATE access_logs SET event_id='simulation-test' WHERE site_id=$1", site)
	if s := simulate(empty); s.NewlyBlocked != 1 || s.Unknown != 0 || s.ID == "" {
		t.Fatal("retained match missing", s)
	}
	// A single-use receipt remains single-use under concurrent mutation attempts.
	summary = simulate(input)
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if apply(principal, input, summary.ID) == 200 {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("concurrent receipt consumption", success.Load())
	}
	if forwarded.Load() != 0 {
		t.Fatal("simulation called upstream")
	}
}
