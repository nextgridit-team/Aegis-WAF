package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestPolicyCommunityEnableSelection(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	var ids []int64
	rows, e := a.db.Query(ctx, "SELECT id FROM rule_catalog ORDER BY id")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) < 2 {
		t.Fatal("bundled catalogue unavailable before network sync", ids)
	}
	var base []byte
	a.db.QueryRow(ctx, "SELECT spec FROM policies WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')").Scan(&base)
	var baseline policySpec
	json.Unmarshal(base, &baseline)
	if baseline.Community == nil || !baseline.Community.Enabled || len(baseline.Community.Rules) != len(ids) {
		t.Fatal("baseline does not enable all shipped mitigations")
	}
	var nodeID int64
	a.db.QueryRow(ctx, "SELECT id FROM rule_catalog WHERE entry_id='node-brotli-request-guard'").Scan(&nodeID)
	p := policyInput{Spec: policySpecInput{Name: "Community selection", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{}, Community: &policyCommunityInput{Enabled: true, RuleIDs: ids}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	id := mustID(t, api.call("POST", "/api/policies", p, 200))
	path := fmt.Sprintf("/api/policies/%d", id)
	p.Revision = 1
	check := func(node, php int) {
		t.Helper()
		for _, replica := range []*App{a, b} {
			if e := replica.refresh(ctx); e != nil {
				t.Fatal(e)
			}
			for _, test := range []struct {
				key, value string
				want       int
			}{{"Content-Encoding", "br", node}, {"Content-Type", "multipart/form-data; boundary=test", php}, {"Accept-Encoding", "br", 200}} {
				r := httptest.NewRequest("GET", "http://bot.test/", nil)
				r.Header.Set("User-Agent", "browser")
				r.Header.Set(test.key, test.value)
				w := httptest.NewRecorder()
				replica.Public(w, r)
				if w.Code != test.want {
					t.Fatalf("%s: got %d want %d", test.key, w.Code, test.want)
				}
			}
		}
	}
	check(403, 403)
	p.Spec.Community.Enabled = false
	api.call("PUT", path, p, 200)
	p.Revision++
	check(200, 200)
	if e := b.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	check(200, 200)
	p.Spec.Community.Enabled = true
	p.Spec.Community.RuleIDs = []int64{nodeID}
	api.call("PUT", path, p, 200)
	p.Revision++
	check(403, 200)
	p.Spec.Community.RuleIDs = []int64{}
	api.call("PUT", path, p, 400)
	p.Spec.Community.RuleIDs = []int64{nodeID, nodeID}
	api.call("PUT", path, p, 400)
	p.Spec.Community.RuleIDs = []int64{999999}
	api.call("PUT", path, p, 400)
	check(403, 200)
	// Legacy scoped groups retain their scope and obey the new global switch.
	p.Spec.Community.RuleIDs = []int64{nodeID}
	p.Spec.Groups = []policyGroupInput{{Name: "Scoped legacy", PathPrefix: "/private", RuleIDs: []int64{nodeID}}}
	api.call("PUT", path, p, 200)
	p.Revision++
	check(200, 200)
	p.Spec.Community.Enabled = false
	api.call("PUT", path, p, 200)
	check(200, 200)
}
func TestBaselineCommunityUpgradeOnce(t *testing.T) {
	a, _, _, _, _ := captchaFixture(t)
	ctx := context.Background()
	_, e := a.db.Exec(ctx, "UPDATE policies SET spec=(spec-'community_mitigations') || '{\"name\":\"Custom baseline\",\"mode\":\"observe\"}'::jsonb WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')")
	if e != nil {
		t.Fatal(e)
	}
	if e = a.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	var rev int64
	a.db.QueryRow(ctx, "SELECT spec,revision FROM policies WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')").Scan(&raw, &rev)
	var s policySpec
	json.Unmarshal(raw, &s)
	if s.Name != "Custom baseline" || s.Mode != "observe" || s.Community == nil || !s.Community.Enabled || len(s.Community.Rules) < 2 || rev != 2 {
		t.Fatal("baseline upgrade lost settings", s, rev)
	}
	_, e = a.db.Exec(ctx, "UPDATE policies SET spec=jsonb_set(spec,'{community_mitigations,enabled}','false') WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')")
	if e != nil {
		t.Fatal(e)
	}
	if e = a.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	var enabled bool
	a.db.QueryRow(ctx, "SELECT (spec->'community_mitigations'->>'enabled')::boolean FROM policies WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')").Scan(&enabled)
	if enabled {
		t.Fatal("restart re-enabled disabled mitigations")
	}
}

func TestBaselineCommunityUpgradeAtCapacity(t *testing.T) {
	a, _, _, site, _ := captchaFixture(t)
	ctx := context.Background()
	var raw []byte
	a.db.QueryRow(ctx, "SELECT spec FROM policies WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')").Scan(&raw)
	var spec policySpec
	json.Unmarshal(raw, &spec)
	spec.Community = nil
	group := policyGroup{Name: "Customized full library", Rules: []policyRule{}}
	rule := probeRule("path", "", "equals", "/private")
	rule.Scope.SiteID = site
	for n := int64(1); n <= 100; n++ {
		group.Rules = append(group.Rules, policyRule{RuleID: 1000 + n, Spec: rule})
	}
	spec.Groups = []policyGroup{group}
	raw, _ = json.Marshal(spec)
	if _, e := a.db.Exec(ctx, "UPDATE policies SET spec=$1 WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')", raw); e != nil {
		t.Fatal(e)
	}
	if e := a.initialize(ctx); e != nil {
		t.Fatal(e)
	}
	if e := a.refresh(ctx); e != nil {
		t.Fatal("upgrade damaged active configuration", e)
	}
	a.db.QueryRow(ctx, "SELECT spec FROM policies WHERE id=(SELECT policy_id FROM built_in_policies WHERE key='baseline-protection')").Scan(&raw)
	json.Unmarshal(raw, &spec)
	if spec.Community == nil || spec.Community.Enabled || len(spec.Groups[0].Rules) != 100 {
		t.Fatal("capacity upgrade changed working custom rules")
	}
}
