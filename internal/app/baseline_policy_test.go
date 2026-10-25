package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBaselinePolicyProvisioningAndAssignment(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	var id int64
	var raw []byte
	if e := a.db.QueryRow(ctx, "SELECT p.id,p.spec FROM policies p JOIN built_in_policies b ON b.policy_id=p.id WHERE b.key='baseline-protection'").Scan(&id, &raw); e != nil {
		t.Fatal(e)
	}
	var baseline policySpec
	if e := json.Unmarshal(raw, &baseline); e != nil {
		t.Fatal(e)
	}
	if baseline.Name != "Baseline protection" || baseline.Mode != "block" || baseline.ManagedSignatures.Mode != "block" || baseline.ManagedSignatures.Paranoia != 1 || baseline.ManagedSignatures.BodyLimit != 1<<20 || baseline.BotEnabled || baseline.FloodEnabled || baseline.ManagedSignatures.ResponseMode != "off" || baseline.ManagedSignatures.ResponseBodyLimit != 256<<10 || baseline.ManagedSignatures.BodyLimitAction != "reject" {
		t.Fatalf("unexpected baseline %+v", baseline)
	}
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "baseline test password 123", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "baseline test password 123"}, 200), &login)
	api.csrf = login["csrf"]
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer upstream.Close()
	input := map[string]any{"name": "Baseline app", "hostnames": []string{"baseline.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "initial_policy_id": id}
	site := mustID(t, api.call("POST", "/api/sites", input, 200))
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		for _, attack := range []bool{false, true} {
			target := "http://baseline.test/products"
			want := 202
			if attack {
				target += "?q=" + url.QueryEscape("1' UNION SELECT password FROM users --")
				want = 403
			}
			request := httptest.NewRequest("GET", target, nil)
			request.Header.Set("User-Agent", "browser")
			request.Header.Set("Accept", "text/html")
			response := httptest.NewRecorder()
			replica.Public(response, request)
			if response.Code != want {
				t.Fatalf("baseline HTTP %d want %d", response.Code, want)
			}
		}
	}
	input["initial_policy_id"] = 999999
	input["hostnames"] = []string{"missing-policy.test"}
	api.call("POST", "/api/sites", input, 400)
	var sites int
	a.db.QueryRow(ctx, "SELECT count(*) FROM sites").Scan(&sites)
	if sites != 1 {
		t.Fatal("failed policy assignment committed a site")
	}
	modified := policySpecInput{Name: "My baseline", Mode: "observe", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{}, ManagedSignatures: baseline.ManagedSignatures}
	api.call("PUT", fmt.Sprintf("/api/policies/%d", id), policyInput{Revision: 2, Spec: modified, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}, 200)
	// Simulate an existing installation before the provisioning marker existed.
	// The user's edited policy and its assignments must remain untouched.
	if _, e := a.db.Exec(ctx, "DELETE FROM built_in_policies"); e != nil {
		t.Fatal(e)
	}
	for _, replica := range []*App{a, b} {
		if e := replica.initialize(ctx); e != nil {
			t.Fatal(e)
		}
	}
	var oldName string
	var revision int64
	a.db.QueryRow(ctx, "SELECT spec->>'name',revision FROM policies WHERE id=$1", id).Scan(&oldName, &revision)
	if oldName != "My baseline" || revision != 3 {
		t.Fatal("provisioning changed existing policy")
	}
	var assigned int64
	a.db.QueryRow(ctx, "SELECT policy_id FROM policy_assignments WHERE site_id=$1", site).Scan(&assigned)
	if assigned != id {
		t.Fatal("provisioning reassigned existing application")
	}
	var newID int64
	a.db.QueryRow(ctx, "SELECT policy_id FROM built_in_policies WHERE key='baseline-protection'").Scan(&newID)
	if newID == id || newID == 0 {
		t.Fatal("baseline was not provisioned exactly once")
	}
	api.call("DELETE", fmt.Sprintf("/api/policies/%d", newID), map[string]int64{"revision": 1}, 200)
	for _, replica := range []*App{a, b} {
		if e := replica.initialize(ctx); e != nil {
			t.Fatal(e)
		}
	}
	var recreated bool
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM policies WHERE id=$1)", newID).Scan(&recreated)
	if recreated {
		t.Fatal("deleted baseline recreated on restart")
	}
	var name string
	a.db.QueryRow(ctx, "SELECT spec->>'name' FROM policies WHERE id=$1", id).Scan(&name)
	if !strings.Contains(name, "My baseline") {
		t.Fatal("existing policy lost")
	}
}
