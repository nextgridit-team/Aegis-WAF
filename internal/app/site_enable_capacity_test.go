package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

// saveSite PUT used to skip checkPolicyAssignments entirely (the check sat
// inside the initial-policy branch, unreachable on PUT), so enabling a site
// could activate a ninth distinct managed-signature configuration: the save
// returned 200 while load-time kept the previous snapshot, silently freezing
// the running configuration.
func TestSaveSiteEnableToggleEnforcesConfigBudget(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	management := httptest.NewServer(a.Management())
	t.Cleanup(management.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "site enable toggle password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "site enable toggle password"}, 200), &login)
	api.csrf = login["csrf"]
	var catalogue []struct {
		Set struct {
			ID string `json:"id"`
		} `json:"set"`
	}
	json.Unmarshal(api.call("GET", "/api/signature-sets/catalogue", nil, 200), &catalogue)
	if len(catalogue) != 1 || catalogue[0].Set.ID == "" {
		t.Fatal("bundled signature set unavailable")
	}
	api.call("POST", "/api/signature-sets", map[string]string{"id": catalogue[0].Set.ID}, 200)
	protection := defaultProtection()
	// Distinct managed shapes come from distinct inbound thresholds.
	managedPolicy := func(name string, threshold int, site int64) policyInput {
		return policyInput{Spec: policySpecInput{Name: name, Mode: "observe", FloodEnabled: true, RequestsPerSecond: 10000, Burst: 10000, SiteRequestsPerSecond: 100000, SiteBurst: 100000, Groups: []policyGroupInput{}, ManagedSignatures: managedSignatureOptions{SetID: catalogue[0].Set.ID, Mode: "observe", Threshold: threshold, ResponseBodyLimit: 256 << 10}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	}
	newSite := func(name, hostname string, enabled bool) int64 {
		return mustID(t, api.call("POST", "/api/sites", map[string]any{"name": name, "hostnames": []string{hostname}, "upstream": "http://127.0.0.1:1", "enabled": enabled, "redirect_https": false, "protection": protection}, 200))
	}
	// Fill all eight distinct active configuration slots.
	for n := 0; n < 8; n++ {
		site := newSite(fmt.Sprintf("App %d", n), fmt.Sprintf("app%d.test", n), true)
		api.call("POST", "/api/policies", managedPolicy(fmt.Sprintf("policy-%d", n), 10+n, site), 200)
	}
	// A disabled site whose policy would mint a ninth distinct shape.
	hidden := newSite("App hidden", "hidden.test", false)
	api.call("POST", "/api/policies", managedPolicy("policy-hidden", 50, hidden), 200)
	// Enabling it must be rejected with the invariant's 409, not accepted.
	api.call("PUT", fmt.Sprintf("/api/sites/%d", hidden), map[string]any{"name": "App hidden", "hostnames": []string{"hidden.test"}, "upstream": "http://127.0.0.1:1", "enabled": true, "redirect_https": false, "protection": protection}, 409)
	// Enabling a site whose shape duplicates an existing configuration is fine.
	duplicate := newSite("App duplicate", "duplicate.test", false)
	api.call("POST", "/api/policies", managedPolicy("policy-duplicate", 10, duplicate), 200)
	api.call("PUT", fmt.Sprintf("/api/sites/%d", duplicate), map[string]any{"name": "App duplicate", "hostnames": []string{"duplicate.test"}, "upstream": "http://127.0.0.1:1", "enabled": true, "redirect_https": false, "protection": protection}, 200)
	// A PUT that does not touch the invariant still succeeds.
	api.call("PUT", fmt.Sprintf("/api/sites/%d", duplicate), map[string]any{"name": "App duplicate renamed", "hostnames": []string{"duplicate.test"}, "upstream": "http://127.0.0.1:1", "enabled": true, "redirect_https": false, "protection": protection}, 200)
}
