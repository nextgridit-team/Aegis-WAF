package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPolicySelectionRequiresReliableIdentity(t *testing.T) {
	bindings := []compiledPolicyBinding{{ID: 1, CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, {ID: 2}}
	for _, test := range []struct {
		ip       string
		reliable bool
		want     int64
	}{{"10.1.2.3", true, 1}, {"10.1.2.3", false, 2}, {"203.0.113.5", true, 2}} {
		selected := selectPolicy(bindings, netip.MustParseAddr(test.ip), test.reliable)
		if selected == nil || selected.ID != test.want {
			t.Fatal("wrong policy for identity", test)
		}
	}
}
func TestPolicyIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	m := httptest.NewServer(a.Management())
	defer m.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, m.URL, ""}
	c.call("GET", "/api/policies", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "long policy integration password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "long policy integration password"}, 200), &login)
	c.csrf = login["csrf"]
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer up.Close()
	protection := defaultProtection()
	protection.TrustedProxies = []string{"10.0.0.1"}
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Policy app", "hostnames": []string{"policy.test"}, "upstream": up.URL, "enabled": true, "redirect_https": false, "protection": protection}, 200))
	ruleSpec := probeRule("path", "", "equals", "/api/.env")
	ruleSpec.Scope.SiteID = site
	rule := mustID(t, c.call("POST", "/api/rules", ruleSpec, 200))
	base := policySpecInput{Name: "External", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, Groups: []policyGroupInput{{Name: "Sensitive API", PathPrefix: "/api/", Methods: []string{"GET"}, RuleIDs: []int64{rule}}}}
	external := policyInput{Spec: base, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	extID := mustID(t, c.call("POST", "/api/policies", external, 200))
	extPath := fmt.Sprintf("/api/policies/%d", extID)
	external.Revision = 1
	internal := policyInput{Spec: base, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{"192.168.1.0/24"}, Priority: 100}}}
	internal.Spec.Name = "Internal"
	internal.Spec.Mode = "off"
	intID := mustID(t, c.call("POST", "/api/policies", internal, 200))
	intPath := fmt.Sprintf("/api/policies/%d", intID)
	refresh := func() {
		t.Helper()
		for _, r := range []*App{a, b} {
			if e := r.refresh(ctx); e != nil {
				t.Fatal(e)
			}
		}
	}
	refresh()
	request := func(replica *App, method, path, peer, xff string, want int, policy int64) {
		t.Helper()
		r := httptest.NewRequest(method, "http://policy.test"+path, nil)
		r.RemoteAddr = peer + ":1234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		replica.Public(w, r)
		if w.Code != want {
			t.Fatalf("%s: got %d want %d: %s", path, w.Code, want, w.Body.String())
		}
		event := <-replica.access
		if event.policyID != policy {
			t.Fatalf("selected policy %d, want %d", event.policyID, policy)
		}
	}
	for _, r := range []*App{a, b} {
		request(r, "GET", "/api/.env", "203.0.113.4", "192.168.1.20", 403, extID)
		request(r, "GET", "/api/.env", "10.0.0.1", "192.168.1.20", 202, intID)
		request(r, "GET", "/api/.env", "10.0.0.1", "", 403, extID)
		request(r, "POST", "/api/.env", "203.0.113.4", "", 202, extID)
	}
	// Library edits remain drafts; published policy snapshots keep protecting both replicas.
	ruleSpec.All[0].Value = json.RawMessage(`"/changed"`)
	c.call("PUT", fmt.Sprintf("/api/rules/%d", rule), ruleSpec, 200)
	external.Spec.Description = "Unrelated policy edit"
	c.call("PUT", extPath, external, 200)
	external.Revision = 2
	refresh()
	request(b, "GET", "/api/.env", "203.0.113.4", "", 403, extID)
	external.RefreshRules = true
	c.call("PUT", extPath, external, 200)
	external.Revision = 3
	refresh()
	request(a, "GET", "/api/.env", "203.0.113.4", "", 202, extID)
	c.call("POST", extPath+"/rollback", map[string]int64{"revision": 3, "target_revision": 1}, 200)
	external.Revision = 4
	refresh()
	request(b, "GET", "/api/.env", "203.0.113.4", "", 403, extID)
	c.call("PUT", extPath, policyInput{Spec: base, Revision: 1}, 409)
	c.call("DELETE", extPath, map[string]int64{"revision": 4}, 409) // A scoped assignment cannot lose its fallback.
	conflicting := internal
	conflicting.Spec.Name = "Conflict"
	c.call("POST", "/api/policies", conflicting, 409)
	invalid := internal
	invalid.Applications = []policyAssignment{{SiteID: site, SourceCIDRs: []string{"0.0.0.0/0"}, Priority: 101}}
	c.call("POST", "/api/policies", invalid, 400)
	// Moving the default invalidates the displaced policy's editor revision.
	replacement := external
	replacement.Spec.Name = "Replacement"
	replacement.Revision = 0
	replacement.RefreshRules = false
	replacementID := mustID(t, c.call("POST", "/api/policies", replacement, 200))
	c.call("PUT", extPath, external, 409)
	var revision int64
	if e := a.db.QueryRow(ctx, "SELECT revision FROM policies WHERE id=$1", extID).Scan(&revision); e != nil || revision != 5 {
		t.Fatal("displaced revision", revision, e)
	}
	c.call("DELETE", intPath, map[string]int64{"revision": 1}, 200)
	c.call("DELETE", fmt.Sprintf("/api/policies/%d", replacementID), map[string]int64{"revision": 1}, 200)
	refresh()
	request(a, "GET", "/api/.env", "203.0.113.4", "", 202, 0)
}
