package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The flood-capacity trigger must validate like the existing kinds, reject a
// typo with the full kind list, and reject nothing on site scoping (a pinned
// map is per replica, but the affected traffic is site-addressable).
func TestFloodCapacityAlertKindValidation(t *testing.T) {
	rule := alertRule{Name: "Flood map exhausted", Enabled: true, Kind: "flood_capacity_exceeded", Threshold: 1, WindowMinutes: 5, CooldownMinutes: 10}
	if err := normalizeAlertRule(&rule); err != nil {
		t.Fatal("flood_capacity_exceeded kind rejected:", err)
	}
	typo := rule
	typo.Kind = "flood_capacity"
	err := normalizeAlertRule(&typo)
	if err == nil {
		t.Fatal("typo kind accepted")
	}
	if !strings.Contains(err.Error(), "flood_capacity_exceeded") {
		t.Fatal("rejection does not name the flood capacity kind:", err)
	}
}

// A pinned local flood map admits new clients unmetered — enforcement is
// degraded exactly when an operator needs a push alert. Without the kind,
// saturation is visible only via the dashboard signals panel or direct
// access-log queries.
func TestFloodCapacityAlert(t *testing.T) {
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "flood capacity password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "flood capacity password"}, 200), &login)
	api.csrf = login["csrf"]
	secret := strings.Repeat("secret", 8)
	var sends atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel := mustID(t, api.call("POST", "/api/notification-channels", map[string]any{"name": "Flood capacity receiver", "provider": "automation", "enabled": true, "config": notificationConfig{URL: receiver.URL, Secret: secret, AllowPrivate: true}}, 200))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer upstream.Close()
	protection := defaultProtection()
	protection.Mode = "observe"
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Sprayed app", "hostnames": []string{"sprayed.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "protection": protection}, 200))
	input := policyInput{Spec: policySpecInput{Name: "Sprayed policy", Mode: "observe", FloodEnabled: true, RequestsPerSecond: 100000, Burst: 100000, SiteRequestsPerSecond: 100000, SiteBurst: 100000, BotEnabled: true, BotChallenge: botChallengeSettings{Enabled: true, Threshold: 90, ClearanceMinutes: 30, RequestsPerSecond: 25, Burst: 50}, Groups: []policyGroupInput{}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	mustID(t, api.call("POST", "/api/policies", input, 200))
	if e := a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	rule := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: "Flood map exhausted", Enabled: true, Kind: "flood_capacity_exceeded", SiteID: site, Threshold: 1, WindowMinutes: 5, CooldownMinutes: 10, ChannelIDs: []int64{channel}}, 200))
	request := func(ip string) accessEvent {
		t.Helper()
		r := httptest.NewRequest("GET", "http://sprayed.test/probe", nil)
		r.RemoteAddr = ip + ":1234"
		r.Header.Set("User-Agent", "browser")
		w := httptest.NewRecorder()
		a.Public(w, r)
		return <-a.access
	}
	// Unpinned traffic must not fire the capacity trigger.
	quiet := request("203.0.113.4")
	if slices.Contains(quiet.signals, "flood_capacity_exceeded") || slices.Contains(quiet.signals, "bot_rate_capacity_exceeded") {
		t.Fatal("unsaturated request signalled capacity:", quiet.signals)
	}
	if e := a.storeAccessBatch(ctx, []accessEvent{quiet}); e != nil {
		t.Fatal(e)
	}
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	var fired int
	if err := a.db.QueryRow(ctx, "SELECT count(*) FROM alerts WHERE (data->>'rule_id')::bigint=$1", rule).Scan(&fired); err != nil {
		t.Fatal(err)
	}
	if fired != 0 {
		t.Fatal("unsaturated traffic fired the capacity alert")
	}
	// Pin the local flood and bot maps: the next first-time client is
	// admitted unmetered and signalled on both limiters.
	now := time.Now()
	for n := 0; n < 100000; n++ {
		key := fmt.Sprintf("198.18.%d.%d", n>>8, n&0xff)
		a.flood.allow(rateKey{site: site, ip: key}, 1, 1, now)
		a.botRates.allow(rateKey{site: site, ip: key}, 25, 50, now)
	}
	sprayed := request("203.0.113.5")
	if !slices.Contains(sprayed.signals, "flood_capacity_exceeded") {
		t.Fatal("saturated request not signalled:", sprayed.signals)
	}
	if !slices.Contains(sprayed.signals, "bot_rate_capacity_exceeded") {
		t.Fatal("bot capacity event not signalled:", sprayed.signals)
	}
	if e := a.storeAccessBatch(ctx, []accessEvent{sprayed}); e != nil {
		t.Fatal(e)
	}
	a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now() WHERE id=$1", rule)
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	var events []alertEvent
	json.Unmarshal(api.call("GET", "/api/alerts", nil, 200), &events)
	var match *alertEvent
	for n := range events {
		if events[n].RuleID == rule {
			match = &events[n]
		}
	}
	if match == nil {
		t.Fatal("capacity alert not generated")
	}
	if match.Kind != "flood_capacity_exceeded" || match.Count != 1 {
		t.Fatalf("wrong capacity alert: %+v", match)
	}
	var deliveries int
	a.db.QueryRow(ctx, "SELECT count(*) FROM alert_deliveries WHERE alert_id=$1", match.ID).Scan(&deliveries)
	if deliveries != 1 {
		t.Fatal("capacity alert not queued for delivery")
	}
	if found, err := a.deliverNotification(ctx); err != nil || !found {
		t.Fatal("capacity alert not deliverable:", err)
	}
	if sends.Load() != 1 {
		t.Fatal("notification not delivered")
	}
}
