package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type capacityPolicyRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type capacityConfiguration struct {
	ID       string                  `json:"id"`
	Options  managedSignatureOptions `json:"options"`
	Policies []capacityPolicyRef     `json:"policies"`
}
type capacityReport struct {
	Limit          int                     `json:"limit"`
	Distinct       int                     `json:"distinct"`
	Remaining      int                     `json:"remaining"`
	Configurations []capacityConfiguration `json:"configurations"`
}
type capacityCheckResult struct {
	Limit           int      `json:"limit"`
	Distinct        int      `json:"distinct"`
	DistinctAfter   int      `json:"distinct_after"`
	WouldCreateNew  bool     `json:"would_create_new"`
	Blocked         bool     `json:"blocked"`
	NearestPolicyID int64    `json:"nearest_policy_id"`
	NearestPolicy   string   `json:"nearest_policy"`
	DifferingFields []string `json:"differing_fields"`
}

func capacityFixture(t *testing.T) (testAPI, string, int64, *App) {
	t.Helper()
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	a := newTestReplica(t, cfg)
	management := httptest.NewServer(a.Management())
	t.Cleanup(management.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "capacity fixture password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "capacity fixture password"}, 200), &login)
	api.csrf = login["csrf"]
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]string{"id": set.ID}, 200)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	t.Cleanup(upstream.Close)
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Capacity app", "hostnames": []string{"capacity.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "protection": defaultProtection()}, 200))
	return api, set.ID, site, a
}

func capacityPolicy(name string, setID string, site int64, threshold int, defaultAssignment bool) policyInput {
	assignment := policyAssignment{SiteID: site, SourceCIDRs: []string{}, Priority: 10000}
	if !defaultAssignment {
		assignment = policyAssignment{SiteID: site, SourceCIDRs: []string{fmt.Sprintf("198.51.100.%d/32", threshold)}, Priority: threshold}
	}
	return policyInput{Spec: policySpecInput{Name: name, Mode: "observe", FloodEnabled: true, RequestsPerSecond: 100000, Burst: 100000, SiteRequestsPerSecond: 100000, SiteBurst: 100000, Groups: []policyGroupInput{}, ManagedSignatures: managedSignatureOptions{SetID: setID, Mode: "observe", Threshold: threshold}}, Applications: []policyAssignment{assignment}}
}

// The eight-distinct-managed-config budget must be visible before it 409s.
func TestPolicyCapacityReport(t *testing.T) {
	api, setID, site, a := capacityFixture(t)
	shared := capacityPolicy("Shared posture A", setID, site, 5, true)
	mustID(t, api.call("POST", "/api/policies", shared, 200))
	// Identical options on a second policy reuse the same engine.
	shared.Spec.Name = "Shared posture B"
	shared.Applications = []policyAssignment{{SiteID: site, SourceCIDRs: []string{"198.51.100.9/32"}, Priority: 9}}
	mustID(t, api.call("POST", "/api/policies", shared, 200))
	// A one-field difference compiles a second engine.
	distinct := capacityPolicy("Distinct posture", setID, site, 6, false)
	distinct.Spec.ManagedSignatures.StreamWindowBytes = 4096
	mustID(t, api.call("POST", "/api/policies", distinct, 200))
	var report capacityReport
	json.Unmarshal(api.call("GET", "/api/policy-capacity", nil, 200), &report)
	if report.Limit != 8 || report.Distinct != 2 || report.Remaining != 6 {
		t.Fatalf("wrong usage report: %+v", report)
	}
	sharedCount := 0
	for _, configuration := range report.Configurations {
		if len(configuration.Policies) == 2 {
			sharedCount++
			names := map[string]bool{}
			for _, policy := range configuration.Policies {
				names[policy.Name] = true
			}
			if !names["Shared posture A"] || !names["Shared posture B"] {
				t.Fatalf("shared engine policies mislabeled: %+v", configuration.Policies)
			}
		}
		if configuration.Options.StreamWindowBytes == 4096 && len(configuration.Policies) != 1 {
			t.Fatalf("distinct posture should stand alone: %+v", configuration)
		}
	}
	if sharedCount != 1 {
		t.Fatal("identical postures did not share one engine:", report.Configurations)
	}
	// The active set mirrors save-time semantics: only enabled sites count.
	if _, e := a.db.Exec(context.Background(), "UPDATE sites SET enabled=false WHERE id=$1", site); e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(api.call("GET", "/api/policy-capacity", nil, 200), &report)
	if report.Distinct != 0 {
		t.Fatal("disabled site still counted:", report)
	}
}

// A preflight check must warn before a save mints a new engine and predict
// the 409, while the save path itself still backstops.
func TestPolicyCapacityPreflight(t *testing.T) {
	api, setID, site, _ := capacityFixture(t)
	var first int64
	for n := 0; n < 8; n++ {
		input := capacityPolicy(fmt.Sprintf("Posture %d", n), setID, site, 5+n, n == 0)
		id := mustID(t, api.call("POST", "/api/policies", input, 200))
		if n == 0 {
			first = id
		}
	}
	// The ninth distinct configuration still 409s at save time (backstop).
	ninth := capacityPolicy("Posture nine", setID, site, 99, false)
	api.call("POST", "/api/policies", ninth, 409)
	// Preflight: a new shape is flagged, blocked, and the nearest reusable
	// posture is named with the fields that differ.
	check := func(policyID int64, options managedSignatureOptions) capacityCheckResult {
		t.Helper()
		var result capacityCheckResult
		json.Unmarshal(api.call("POST", "/api/policy-capacity/check", map[string]any{"policy_id": policyID, "mode": "observe", "options": options}, 200), &result)
		return result
	}
	options := managedSignatureOptions{SetID: setID, Mode: "observe", Threshold: 99}
	result := check(0, options)
	if !result.WouldCreateNew || !result.Blocked || result.Distinct != 8 || result.DistinctAfter != 9 {
		t.Fatalf("new shape not flagged: %+v", result)
	}
	if result.NearestPolicy == "" || len(result.DifferingFields) == 0 {
		t.Fatalf("nearest reusable posture missing: %+v", result)
	}
	foundThreshold := false
	for _, field := range result.DifferingFields {
		if field == "inbound_threshold" {
			foundThreshold = true
		}
	}
	if !foundThreshold {
		t.Fatal("differing fields miss the threshold:", result.DifferingFields)
	}
	// Reusing an existing shape needs no warning.
	reuse := managedSignatureOptions{SetID: setID, Mode: "observe", Threshold: 8}
	if result = check(0, reuse); result.WouldCreateNew || result.Blocked {
		t.Fatalf("reuse flagged as new: %+v", result)
	}
	// Editing an existing policy swaps its slot: a new shape on the first
	// policy stays within the limit because its old engine is released.
	if result = check(first, options); !result.WouldCreateNew || result.Blocked || result.DistinctAfter != 8 {
		t.Fatalf("slot swap mispredicted: %+v", result)
	}
	// Signatures off never mint an engine.
	off := managedSignatureOptions{SetID: setID, Mode: "off", Threshold: 99}
	if result = check(0, off); result.WouldCreateNew || result.Blocked {
		t.Fatalf("disabled signatures flagged: %+v", result)
	}
	// Invalid candidate options surface before the save attempt.
	api.call("POST", "/api/policy-capacity/check", map[string]any{"policy_id": 0, "mode": "observe", "options": managedSignatureOptions{SetID: setID, Mode: "observe", Exclusions: []int{999999}}}, 400)
}
