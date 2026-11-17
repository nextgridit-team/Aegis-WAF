package app

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The managed-configuration budget has three enforcement sites: the save-time
// 409, the load-time compile guard and the snapshot-cache restore. Their
// limits and messages must derive from managedConfigurationLimit: a hardcoded
// 8 or "eight" prose desyncs the moment the constant changes, and a snapshot
// carrying more engines than a stale literal silently degrades the replica to
// full-database startup.
func TestManagedConfigurationBudgetDerivesFromConstant(t *testing.T) {
	api, setID, site, a := capacityFixture(t)
	for n := 0; n < managedConfigurationLimit; n++ {
		api.call("POST", "/api/policies", capacityPolicy(fmt.Sprintf("Posture %d", n), setID, site, 20+n, n == 0), 200)
	}
	// The save-time 409 must name the enforced limit, not a hardcoded word.
	overflow := capacityPolicy("Posture overflow", setID, site, 99, false)
	body := api.call("POST", "/api/policies", overflow, 409)
	if !strings.Contains(string(body), strconv.Itoa(managedConfigurationLimit)) {
		t.Fatalf("save-time capacity message does not carry the configured limit: %s", body)
	}
	// The load-time guard fires with the same derived limit when the database
	// somehow holds more distinct active configurations than the budget.
	protection, e := compileProtection(defaultProtection())
	if e != nil {
		t.Fatal(e)
	}
	next := &snapshot{policyBindings: map[int64][]compiledPolicyBinding{}}
	for n := 0; n <= managedConfigurationLimit; n++ {
		options, e := normalizeManagedSignatures(managedSignatureOptions{SetID: setID, Mode: "observe", Threshold: 20 + n})
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
		t.Fatal("overflowing distinct configuration compiled at load time")
	} else if !strings.Contains(e.Error(), strconv.Itoa(managedConfigurationLimit)) {
		t.Fatalf("load-time capacity message does not carry the configured limit: %s", e)
	}
}

// The snapshot-cache restore path enforces the same derived budget: a cached
// binding set referencing more distinct managed configurations than
// managedConfigurationLimit must be rejected with a message naming the limit.
func TestSnapshotCacheManagedCapacityDerivesFromConstant(t *testing.T) {
	now := time.Now()
	a := &App{cfg: Config{Key: make([]byte, 32), KeyID: "primary", DatabaseURL: "postgres://cache-test", SnapshotCacheFile: filepath.Join(t.TempDir(), "snapshot"), SnapshotCacheMaxAge: time.Hour}}
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	protection, e := compileProtection(defaultProtection())
	if e != nil {
		t.Fatal(e)
	}
	cache := cachedSnapshot{Format: snapshotCacheFormat, At: now, Version: 2, ManagedSets: map[string]signatureSet{set.ID: set}, Certificates: map[int64]cachedCertificate{}, Sites: []Site{}, Rules: map[int64][]cachedRule{}, Capture: map[int64]TrafficSettings{}, Protection: map[int64]ProtectionSettings{}, Bindings: map[int64][]cachedBinding{}}
	for n := 0; n <= managedConfigurationLimit; n++ {
		// The zero-CIDR binding is the site's default policy and must carry
		// priority 10000; scoped bindings follow with higher priorities.
		priority := 10001 + n
		cidrs := []string{fmt.Sprintf("198.51.100.%d/32", n+1)}
		if n == 0 {
			priority = 10000
			cidrs = []string{}
		}
		cache.Bindings[1] = append(cache.Bindings[1], cachedBinding{ManagedOptions: managedSignatureOptions{SetID: set.ID, Mode: "observe", Threshold: 30 + n}, ID: int64(n + 1), Revision: 1, Name: fmt.Sprintf("cached-%d", n), Priority: priority, CIDRs: cidrs, Protection: protection.ProtectionSettings})
	}
	raw, e := json.Marshal(cache)
	if e != nil {
		t.Fatal(e)
	}
	sealed, e := seal(a.cfg.Key, a.cacheAAD(), raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.decodeSnapshot(sealed, now); e == nil {
		t.Fatal("oversized cached signature configuration restored")
	} else if !strings.Contains(e.Error(), strconv.Itoa(managedConfigurationLimit)) {
		t.Fatalf("restore capacity message does not carry the configured limit: %s", e)
	}
}
