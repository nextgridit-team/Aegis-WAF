package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPolicyRuleActionCeiling(t *testing.T) {
	a, b, api, site, forwarded := captchaFixture(t)
	ctx := context.Background()
	ids := map[string]int64{}
	for _, action := range []string{"observe", "block"} {
		rule := probeRule("header", "X-"+action, "equals", "yes")
		rule.Scope.SiteID, rule.Action = site, action
		ids[action] = mustID(t, api.call("POST", "/api/rules", rule, 200))
	}
	input := policyInput{Spec: policySpecInput{Name: "Action ceiling", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{{Name: "Mixed rules", RuleIDs: []int64{ids["observe"], ids["block"]}}}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	id := mustID(t, api.call("POST", "/api/policies", input, 200))
	input.Revision = 1
	for _, mode := range []string{"block", "observe", "off"} {
		input.Spec.Mode = mode
		api.call("PUT", fmt.Sprintf("/api/policies/%d", id), input, 200)
		input.Revision++
		for replicaIndex, replica := range []*App{a, b} {
			if e := replica.refresh(ctx); e != nil {
				t.Fatal(e)
			}
			// A recovery snapshot must retain the same effective rule actions.
			sealed, e := replica.archiveSnapshot(replica.active.Load(), time.Now())
			if e != nil {
				t.Fatal(e)
			}
			restored, e := replica.decodeSnapshot(sealed, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			for _, recovery := range []bool{false, true} {
				if recovery {
					replica.active.Store(restored)
				}
				for _, matches := range [][]string{{"observe"}, {"block"}, {"observe", "block"}} {
					t.Run(fmt.Sprintf("%s/replica%d/cache%t/%v", mode, replicaIndex, recovery, matches), func(t *testing.T) {
						request := httptest.NewRequest("GET", "http://bot.test/action-probe", nil)
						request.Header.Set("User-Agent", "browser")
						wantBlocked := false
						for _, action := range matches {
							request.Header.Set("X-"+action, "yes")
							wantBlocked = wantBlocked || (mode == "block" && action == "block")
						}
						before := forwarded.Load()
						response := httptest.NewRecorder()
						replica.Public(response, request)
						event := <-replica.access
						wantStatus, wantForwarded := 200, int64(1)
						if wantBlocked {
							wantStatus, wantForwarded = 403, 0
						}
						if response.Code != wantStatus || event.blocked != wantBlocked || forwarded.Load()-before != wantForwarded {
							t.Fatalf("status=%d blocked=%t forwarded=%d, want %d/%t/%d", response.Code, event.blocked, forwarded.Load()-before, wantStatus, wantBlocked, wantForwarded)
						}
						wantResults := len(matches)
						if mode == "off" {
							wantResults = 0
						}
						if len(event.results) != wantResults {
							t.Fatalf("results=%+v", event.results)
						}
						for n, result := range event.results {
							wantAction := matches[n]
							if mode == "observe" {
								wantAction = "observe"
							}
							if result.RuleID != ids[matches[n]] || result.Result != "matched" || result.Action != wantAction || result.PolicyID != id || result.PolicyRevision != input.Revision || result.Group != "Mixed rules" {
								t.Fatalf("incorrect rule result: %+v", result)
							}
						}
						if mode == "block" && len(matches) == 1 && matches[0] == "observe" {
							if e := replica.storeAccessBatch(ctx, []accessEvent{event}); e != nil {
								t.Fatal(e)
							}
							var recorded bool
							if e := replica.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_logs WHERE site_id=$1 AND NOT blocked AND status=200 AND rule_results @> $2::jsonb)`, site, fmt.Sprintf(`[{"rule_id":%d,"action":"observe","result":"matched"}]`, ids["observe"])).Scan(&recorded); e != nil || !recorded {
								t.Fatal("observed rule result was not persisted", e)
							}
							var output bytes.Buffer
							if e := emitSecurityEvent(slog.New(slog.NewJSONHandler(&output, nil)), event); e != nil {
								t.Fatal(e)
							}
							var logged map[string]any
							if e := json.Unmarshal(output.Bytes(), &logged); e != nil || logged["action"] != "observed" {
								t.Fatal("observed event missing", output.String(), e)
							}
						}
					})
				}
			}
		}
	}
}

func TestPolicyActionFrozenRefreshRollbackAndSimulation(t *testing.T) {
	a, _, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	rule := probeRule("path", "", "equals", "/action-probe")
	rule.Scope.SiteID, rule.Action = site, "observe"
	ruleID := mustID(t, api.call("POST", "/api/rules", rule, 200))
	input := policyInput{Spec: policySpecInput{Name: "Frozen actions", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{{Name: "Custom", RuleIDs: []int64{ruleID}}}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	id := mustID(t, api.call("POST", "/api/policies", input, 200))
	path := fmt.Sprintf("/api/policies/%d", id)
	input.Revision = 1
	check := func(want int) {
		t.Helper()
		if e := a.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest("GET", "http://bot.test/action-probe", nil)
		r.Header.Set("User-Agent", "browser")
		w := httptest.NewRecorder()
		a.Public(w, r)
		<-a.access
		if w.Code != want {
			t.Fatalf("got %d, want %d", w.Code, want)
		}
	}
	check(200)
	rule.Action = "block"
	api.call("PUT", fmt.Sprintf("/api/rules/%d", ruleID), rule, 200)
	api.call("PUT", path, input, 200)
	input.Revision++
	check(200) // An ordinary save retains the frozen Observe action.
	input.RefreshRuleIDs = []int64{ruleID}
	api.call("PUT", path, input, 200)
	input.Revision++
	check(403)
	api.call("POST", path+"/rollback", map[string]int64{"revision": input.Revision, "target_revision": 1}, 200)
	input.Revision++
	input.RefreshRuleIDs = nil
	check(200)
	obj := mustID(t, api.call("POST", "/api/address-objects", map[string]string{"name": "Simulator", "value": "127.0.0.1"}, 200))
	var key struct {
		ID int64 `json:"id"`
	}
	if e := json.Unmarshal(api.call("POST", "/api/agent-keys", map[string]any{"name": "Action simulator", "allowed_addresses": addressSelection{ObjectIDs: []int64{obj}}, "scopes": []string{"read", "enforce", "configuration"}}, 201), &key); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	policyAPI(a, mux)
	before := a.active.Load()
	for _, refresh := range []bool{false, true} {
		input.RefreshRules = refresh
		expected := "allow"
		if refresh {
			expected = "block"
		}
		raw, _ := json.Marshal(input)
		summary, e := a.simulateRuleImpact(ctx, agentPrincipal{ID: key.ID, Scopes: []string{"read", "enforce", "configuration"}}, mux, simulationInput{Method: "PUT", Path: path, Input: raw, TestPayloads: []simulationPayload{{Host: "bot.test", Method: "GET", Path: "/action-probe", ClientIP: "198.51.100.2", Headers: map[string]string{"User-Agent": "browser"}, Expected: expected}}})
		if e != nil || !summary.Eligible || len(summary.Harness) != 1 || !summary.Harness[0].Passed || a.active.Load() != before {
			t.Fatalf("simulation refresh=%t: %+v, %v", refresh, summary, e)
		}
	}
	check(200)
}

func TestCommunityModeMigration(t *testing.T) {
	a, b, _, _, _ := captchaFixture(t)
	ctx := context.Background()
	// Recreate a pre-upgrade baseline, including its unchanged historical copy.
	if _, e := a.db.Exec(ctx, `UPDATE policies SET spec=spec #- '{community_mitigations,mode}'; UPDATE policy_revisions SET spec=spec #- '{community_mitigations,mode}'; DELETE FROM schema_version WHERE version=24`); e != nil {
		t.Fatal(e)
	}
	var before int64
	if e := a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&before); e != nil {
		t.Fatal(e)
	}
	for _, replica := range []*App{a, b} {
		if e := replica.initialize(ctx); e != nil {
			t.Fatal(e)
		}
	}
	var mode string
	var revision, version, migrations int64
	if e := a.db.QueryRow(ctx, "SELECT spec->'community_mitigations'->>'mode',revision FROM policies WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')").Scan(&mode, &revision); e != nil || mode != "inherit" || revision != 2 {
		t.Fatal("community inheritance migration", mode, revision, e)
	}
	if e := a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&version); e != nil || version != before+1 {
		t.Fatal("migration must publish exactly once", version, before, e)
	}
	if e := a.db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='policy.community_mode_migrated'").Scan(&migrations); e != nil || migrations != 1 {
		t.Fatal("migration audit missing or repeated", migrations, e)
	}
	var historical bool
	if e := a.db.QueryRow(ctx, "SELECT NOT (spec->'community_mitigations' ? 'mode') FROM policy_revisions WHERE policy_id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection') AND revision=1").Scan(&historical); e != nil || !historical {
		t.Fatal("migration rewrote policy history", e)
	}
}
