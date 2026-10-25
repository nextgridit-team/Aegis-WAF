package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestDetailsAllOutcomesAndRetention(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	api.call("GET", "/api/access-logs/1", nil, 401)
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "request detail password 123", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "request detail password 123"}, 200), &login)
	api.csrf = login["csrf"]
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Detail app", "hostnames": []string{"details.test"}, "upstream": "http://127.0.0.1:9999", "enabled": true}, 200))
	spec := probeRule("path", "", "prefix", "/admin")
	spec.Scope.SiteID = site
	spec.Name = "Original signature"
	rule := mustID(t, api.call("POST", "/api/rules", spec, 200))
	policy := mustID(t, api.call("POST", "/api/policies", policyInput{Spec: policySpecInput{Name: "Recorded policy", Mode: "observe", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{{Name: "Admin routes", RuleIDs: []int64{rule}}}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}, 200))
	spec.Name = "Edited current signature"
	api.call("PUT", fmt.Sprintf("/api/rules/%d", rule), spec, 200)
	for _, sample := range []struct {
		id     string
		expiry time.Time
		data   string
	}{{"live", time.Now().Add(time.Hour), `{"facts":{"path:":{"state":"redacted","values":["/admin/[redacted]"]}}}`}, {"expired", time.Now().Add(-time.Hour), `{"facts":{"path:":{"state":"present","values":["expired-secret-must-not-return"]}}}`}} {
		if _, e := a.db.Exec(ctx, "INSERT INTO traffic_evidence(id,at,site_id,expires_at,data) VALUES($1,now(),$2,$3,$4)", sample.id, site, sample.expiry, sample.data); e != nil {
			t.Fatal(e)
		}
	}
	set, _ := bundledSignatureSet()
	result, _ := json.Marshal([]RuleResult{{RuleID: rule, Action: "observe", Result: "matched", PolicyID: policy, PolicyRevision: 1, Group: "Admin routes"}})
	managed, _ := json.Marshal(managedSignatureResult{SetID: set.ID, Version: set.Version, Mode: "block", RuleIDs: []int{942100}, Inspection: "complete"})
	ids := []int64{}
	for n, kind := range []string{"allowed", "flagged", "blocked", "expired"} {
		evidence := ""
		rules := []byte("[]")
		matched := []byte("{}")
		status := 200
		if kind == "flagged" {
			evidence = "live"
			rules = result
		}
		if kind == "blocked" {
			matched = managed
			status = 403
		}
		if kind == "expired" {
			evidence = "expired"
		}
		var id int64
		if e := a.db.QueryRow(ctx, `INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,policy_id,policy_revision,policy_name,event_id,rule_results,managed_signatures,blocked) VALUES(now(),$1,'GET',$2,1,'198.51.100.3',$3,1,'Recorded policy',$4,$5,$6,$7) RETURNING id`, site, status, policy, evidence, rules, matched, kind == "blocked").Scan(&id); e != nil {
			t.Fatal(e)
		}
		ids = append(ids, id)
		data := api.call("GET", fmt.Sprintf("/api/access-logs/%d", id), nil, 200)
		if strings.Contains(string(data), "expired-secret-must-not-return") {
			t.Fatal("expired evidence disclosed")
		}
		var detail struct {
			EvidenceState string               `json:"evidence_state"`
			Custom        []detailedCustomRule `json:"custom_rules"`
			Managed       []signatureEntry     `json:"managed_rules"`
		}
		if e := json.Unmarshal(data, &detail); e != nil {
			t.Fatal(e)
		}
		if n == 0 && detail.EvidenceState != "not_captured" {
			t.Fatal("allowed request unavailable")
		}
		if kind == "flagged" && (detail.EvidenceState != "available" || len(detail.Custom) != 1 || detail.Custom[0].Name != "Original signature" || detail.Custom[0].DefinitionSource != "policy_snapshot") {
			t.Fatalf("historical signature lost: %+v", detail)
		}
		if kind == "blocked" && (len(detail.Managed) != 1 || detail.Managed[0].ID != 942100) {
			t.Fatal("managed match metadata lost")
		}
		if kind == "expired" && detail.EvidenceState != "expired" {
			t.Fatal("expired capture misrepresented")
		}
	}
	api.call("GET", "/api/access-logs/invalid", nil, 400)
	api.call("GET", "/api/access-logs/999999", nil, 404)
	api.call("DELETE", fmt.Sprintf("/api/policies/%d", policy), map[string]int64{"revision": 1}, 200)
	data := api.call("GET", fmt.Sprintf("/api/access-logs/%d", ids[1]), nil, 200)
	if !strings.Contains(string(data), "current_library") || !strings.Contains(string(data), "Edited current signature") {
		t.Fatal("missing history was not labeled as current metadata")
	}
	if _, e := a.db.Exec(ctx, "DELETE FROM traffic_evidence WHERE id='live'"); e != nil {
		t.Fatal(e)
	}
	data = api.call("GET", fmt.Sprintf("/api/access-logs/%d", ids[1]), nil, 200)
	if !strings.Contains(string(data), "expired_or_removed") {
		t.Fatal("removed capture misrepresented")
	}
}
