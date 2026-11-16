package app

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func exceptionsAPITest(t *testing.T) testAPI {
	t.Helper()
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar, Timeout: 10 * time.Second}, server.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "exceptions-admin", "password": "strong exceptions editor password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "exceptions-admin", "password": "strong exceptions editor password"}, 200), &login)
	api.csrf = login["csrf"]
	return api
}

// A scoped exclusion carrying a key outside the allowlist must be rejected at
// save time with a message naming the offending key and the exception index,
// so a misspelled scope cannot silently broaden the exclusion.
func TestPolicyRejectsUnknownScopedExclusionKeys(t *testing.T) {
	api := exceptionsAPITest(t)
	spec := func(exclusions any) map[string]any {
		return map[string]any{
			"spec": map[string]any{
				"name":                     "Exceptions policy",
				"mode":                     "observe",
				"requests_per_second":      100,
				"burst":                    200,
				"site_requests_per_second": 100,
				"site_burst":               200,
				"groups":                   []any{},
				"managed_signatures": map[string]any{
					"mode":              "off",
					"scoped_exclusions": exclusions,
				},
			},
			"applications": []any{},
		}
	}
	// Misspelled client scope alongside a valid one: on main the key is
	// silently dropped and the exclusion widens to every client.
	body := api.call("POST", "/api/policies", spec([]any{
		map[string]any{"rule_ids": []int{942100}, "path_prefix": "/search", "client_cidr": []string{"10.0.0.0/8"}},
	}), 400)
	if !strings.Contains(string(body), "client_cidr") || !strings.Contains(string(body), "exception 1") {
		t.Fatalf("rejection does not name the key and exception index: %s", body)
	}
	// The index is per exclusion, not a count of bad keys in the document.
	body = api.call("POST", "/api/policies", spec([]any{
		map[string]any{"rule_ids": []int{942100}, "path_prefix": "/search"},
		map[string]any{"rule_ids": []int{941100}, "paramaters": []string{"q"}},
	}), 400)
	if !strings.Contains(string(body), "paramaters") || !strings.Contains(string(body), "exception 2") {
		t.Fatalf("rejection does not name the second exception's key and index: %s", body)
	}
}

// Known keys survive a save and read-back unchanged: no silent drops on the
// round trip.
func TestScopedExclusionsRoundTrip(t *testing.T) {
	api := exceptionsAPITest(t)
	exclusions := []any{
		map[string]any{"rule_ids": []int{942100}, "path_prefix": "/search", "client_cidrs": []string{"10.0.0.0/8"}, "parameters": []string{"q"}},
		map[string]any{"rule_ids": []int{941100}, "path_prefix": "/api"},
	}
	id := mustID(t, api.call("POST", "/api/policies", map[string]any{
		"spec": map[string]any{
			"name":                     "Round trip policy",
			"mode":                     "observe",
			"requests_per_second":      100,
			"burst":                    200,
			"site_requests_per_second": 100,
			"site_burst":               200,
			"groups":                   []any{},
			"managed_signatures": map[string]any{
				"mode":              "off",
				"scoped_exclusions": exclusions,
			},
		},
		"applications": []any{},
	}, 200))
	var stored []policyView
	if e := json.Unmarshal(api.call("GET", "/api/policies", nil, 200), &stored); e != nil {
		t.Fatal(e)
	}
	for _, p := range stored {
		if p.ID != id {
			continue
		}
		saved := p.Spec.ManagedSignatures.ScopedExclusions
		if len(saved) != len(exclusions) {
			t.Fatalf("scoped exclusions lost on round trip: %+v", saved)
		}
		if saved[0].PathPrefix != "/search" || !reflect.DeepEqual(saved[0].ClientCIDRs, []string{"10.0.0.0/8"}) || !reflect.DeepEqual(saved[0].Parameters, []string{"q"}) || !reflect.DeepEqual(saved[0].RuleIDs, []int{942100}) {
			t.Fatalf("first exclusion changed on round trip: %+v", saved[0])
		}
		if saved[1].PathPrefix != "/api" || !reflect.DeepEqual(saved[1].RuleIDs, []int{941100}) || saved[1].ClientCIDRs != nil || saved[1].Parameters != nil {
			t.Fatalf("second exclusion changed on round trip: %+v", saved[1])
		}
		return
	}
	t.Fatal("saved policy not returned")
}
