package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// managedLimitConfig loads a Config through LoadConfig exactly like the
// container entrypoint, with the supplied MANAGED_ENGINE_LIMIT and the test
// database as backing store.
func managedLimitConfig(t *testing.T, dsn, secret, limit string) (Config, error) {
	t.Helper()
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("BOOTSTRAP_SECRET", secret)
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if limit != "" {
		t.Setenv("MANAGED_ENGINE_LIMIT", limit)
	} else {
		t.Setenv("MANAGED_ENGINE_LIMIT", "")
	}
	return LoadConfig()
}

func TestManagedEngineLimitConfigParsing(t *testing.T) {
	cases := []struct {
		name  string
		limit string
		want  int
	}{
		{"unset defaults to eight", "", managedConfigurationLimit},
		{"minimum", "1", 1},
		{"raised", "16", 16},
		{"maximum", "64", 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, e := managedLimitConfig(t, "postgres://configured", "bootstrap-secret-of-at-least-32-chars", tc.limit)
			if e != nil {
				t.Fatal(e)
			}
			if cfg.ManagedEngineLimit != tc.want {
				t.Fatalf("MANAGED_ENGINE_LIMIT=%q gave %d, want %d", tc.limit, cfg.ManagedEngineLimit, tc.want)
			}
		})
	}
	for _, raw := range []string{"0", "65", "-1", "eight", "2.5"} {
		t.Run("rejects "+raw, func(t *testing.T) {
			if _, e := managedLimitConfig(t, "postgres://configured", "bootstrap-secret-of-at-least-32-chars", raw); e == nil {
				t.Fatalf("MANAGED_ENGINE_LIMIT=%q accepted", raw)
			}
		})
	}
}

// The env-configured budget drives every surface: the save-time 409 fires at
// the third distinct configuration, the capacity surface reports it, and both
// the load-time compile guard and the snapshot-cache restore guard enforce it.
// On main the env var is ignored, so the third save succeeds and this fails.
func TestManagedEngineLimitEnforced(t *testing.T) {
	cfg, e := managedLimitConfig(t, testDB(t).DatabaseURL, strings.Repeat("b", 40), "2")
	if e != nil {
		t.Fatal(e)
	}
	cfg.Refresh = 25 * time.Millisecond
	api, setID, site, a := capacityFixtureWithConfig(t, cfg)
	api.call("POST", "/api/policies", capacityPolicy("Posture one", setID, site, 21, true), 200)
	api.call("POST", "/api/policies", capacityPolicy("Posture two", setID, site, 22, false), 200)
	// The third distinct configuration exceeds the configured budget.
	body := api.call("POST", "/api/policies", capacityPolicy("Posture three", setID, site, 23, false), 409)
	if !strings.Contains(string(body), "at most 2") {
		t.Fatalf("save-time capacity message does not name the configured limit: %s", body)
	}
	// The capacity surface reports the configured budget.
	data := api.call("GET", "/api/policy-capacity", nil, 200)
	var report capacityReport
	json.Unmarshal(data, &report)
	if report.Limit != 2 || report.Distinct != 2 || report.Remaining != 0 {
		t.Fatalf("capacity surface = %+v, want limit 2 distinct 2 remaining 0", report)
	}
	// The load-time compile guard enforces the same configured budget.
	protection, e := compileProtection(defaultProtection())
	if e != nil {
		t.Fatal(e)
	}
	next := &snapshot{policyBindings: map[int64][]compiledPolicyBinding{}}
	for n := 0; n <= 2; n++ {
		options, e := normalizeManagedSignatures(managedSignatureOptions{SetID: setID, Mode: "observe", Threshold: 30 + n})
		if e != nil {
			t.Fatal(e)
		}
		next.policyBindings[site] = append(next.policyBindings[site], compiledPolicyBinding{ManagedOptions: effectiveManagedOptions(options, "observe"), Priority: 10000 + n, Protection: protection})
	}
	tx, e := a.db.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if e = a.loadManagedSignatures(context.Background(), tx, next); e == nil {
		t.Fatal("third distinct configuration compiled at load time under limit 2")
	} else if !strings.Contains(e.Error(), "at most 2") {
		t.Fatalf("load-time capacity message does not name the configured limit: %s", e)
	}
	// The snapshot-cache restore guard uses the live limit: a sealed snapshot
	// carrying more engines than the current budget fails closed to
	// full-database startup.
	restore, e := managedLimitRestoreFixture(a, setID, site, protection, 3)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.decodeSnapshot(restore, time.Now()); e == nil {
		t.Fatal("oversized cached signature configuration restored under limit 2")
	} else if !strings.Contains(e.Error(), "at most 2") {
		t.Fatalf("restore capacity message does not name the configured limit: %s", e)
	}
}

// managedLimitRestoreFixture seals a cached snapshot with count distinct
// managed configurations bound to one site under the replica's own key and
// AAD, mirroring the format the restore path reads.
func managedLimitRestoreFixture(a *App, setID string, site int64, protection *protectionPolicy, count int) ([]byte, error) {
	set, e := bundledSignatureSet()
	if e != nil {
		return nil, e
	}
	cache := cachedSnapshot{Format: snapshotCacheFormat, At: time.Now(), Version: 2, ManagedSets: map[string]signatureSet{set.ID: set}, Certificates: map[int64]cachedCertificate{}, Sites: []Site{}, Rules: map[int64][]cachedRule{}, Capture: map[int64]TrafficSettings{}, Protection: map[int64]ProtectionSettings{}, Bindings: map[int64][]cachedBinding{}}
	for n := 0; n < count; n++ {
		priority := 10001 + n
		cidrs := []string{fmt.Sprintf("198.51.100.%d/32", n+1)}
		if n == 0 {
			priority = 10000
			cidrs = []string{}
		}
		cache.Bindings[site] = append(cache.Bindings[site], cachedBinding{ManagedOptions: managedSignatureOptions{SetID: setID, Mode: "observe", Threshold: 40 + n}, ID: int64(n + 1), Revision: 1, Name: fmt.Sprintf("cached-%d", n), Priority: priority, CIDRs: cidrs, Protection: protection.ProtectionSettings})
	}
	raw, e := json.Marshal(cache)
	if e != nil {
		return nil, e
	}
	return seal(a.cfg.Key, a.cacheAAD(), raw)
}
