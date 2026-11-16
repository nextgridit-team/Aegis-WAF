package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The saturation trigger must validate like the existing kinds, and a typo must
// be rejected with a message that names the accepted kinds.
func TestInspectionSaturationAlertKindValidation(t *testing.T) {
	rule := alertRule{Name: "Inspection pool exhausted", Enabled: true, Kind: "inspection_saturation", Threshold: 5, WindowMinutes: 5, CooldownMinutes: 10}
	if err := normalizeAlertRule(&rule); err != nil {
		t.Fatal("inspection_saturation kind rejected:", err)
	}
	typo := rule
	typo.Kind = "inspection_saturated"
	err := normalizeAlertRule(&typo)
	if err == nil {
		t.Fatal("typo kind accepted")
	}
	if !strings.Contains(err.Error(), "inspection_saturation") {
		t.Fatal("rejection does not name the saturation kind:", err)
	}
}

// Saturating every managedSlots token leaves observe-mode requests uninspected
// (fail-open) and block-mode requests rejected with 503. The alert rule engine
// must turn those busy inspections into a deliverable alert; without the kind
// nothing can express the condition at all.
func TestInspectionSaturationAlert(t *testing.T) {
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "inspection saturation password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "inspection saturation password"}, 200), &login)
	api.csrf = login["csrf"]
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	api.call("POST", "/api/signature-sets", map[string]string{"id": set.ID}, 200)
	secret := strings.Repeat("secret", 8)
	var sends atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel := mustID(t, api.call("POST", "/api/notification-channels", map[string]any{"name": "Saturation receiver", "provider": "automation", "enabled": true, "config": notificationConfig{URL: receiver.URL, Secret: secret, AllowPrivate: true}}, 200))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer upstream.Close()
	protection := defaultProtection()
	site := mustID(t, api.call("POST", "/api/sites", map[string]any{"name": "Saturated app", "hostnames": []string{"saturated.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "protection": protection}, 200))
	input := policyInput{Spec: policySpecInput{Name: "Saturated managed", Mode: "observe", FloodEnabled: true, RequestsPerSecond: 100000, Burst: 100000, SiteRequestsPerSecond: 100000, SiteBurst: 100000, Groups: []policyGroupInput{}, ManagedSignatures: managedSignatureOptions{SetID: set.ID, Mode: "observe", ResponseMode: "off", ResponseBodyLimit: 128 << 10, BodyLimitAction: "process_partial"}}, Applications: []policyAssignment{{SiteID: site, SourceCIDRs: []string{}}}}
	mustID(t, api.call("POST", "/api/policies", input, 200))
	if e := a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	// A misspelled trigger is rejected with the full kind list.
	api.call("POST", "/api/alert-rules", alertRule{Name: "Typo", Kind: "inspection_saturated", Threshold: 1, WindowMinutes: 5, CooldownMinutes: 10}, 400)
	rule := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: "Inspection pool exhausted", Enabled: true, Kind: "inspection_saturation", SiteID: site, Threshold: 1, WindowMinutes: 5, CooldownMinutes: 10, ChannelIDs: []int64{channel}}, 200))
	request := func() accessEvent {
		t.Helper()
		r := httptest.NewRequest("GET", "http://saturated.test/probe", nil)
		r.RemoteAddr = "203.0.113.4:1234"
		r.Header.Set("User-Agent", "browser")
		w := httptest.NewRecorder()
		a.Public(w, r)
		return <-a.access
	}
	// Inspected traffic must not fire the saturation trigger.
	complete := request()
	if complete.managed.Inspection != "complete" {
		t.Fatal("baseline request not inspected:", complete.managed.Inspection)
	}
	if e := a.storeAccessBatch(ctx, []accessEvent{complete}); e != nil {
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
		t.Fatal("inspected traffic fired the saturation alert")
	}
	// Fill every inspection slot so the next request cannot be inspected.
	for n := cap(a.managedSlots); n > 0; n-- {
		a.managedSlots <- struct{}{}
	}
	busy := request()
	if busy.managed.Inspection != "busy" {
		t.Fatal("saturated pool did not mark the request busy:", busy.managed.Inspection)
	}
	if e := a.storeAccessBatch(ctx, []accessEvent{busy}); e != nil {
		t.Fatal(e)
	}
	// The first evaluation pass moved next_eval ten seconds ahead; reset it so
	// the busy window is evaluated immediately.
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
		t.Fatal("saturation alert not generated")
	}
	if match.Kind != "inspection_saturation" || match.Count != 1 {
		t.Fatalf("wrong saturation alert: %+v", match)
	}
	var deliveries int
	a.db.QueryRow(ctx, "SELECT count(*) FROM alert_deliveries WHERE alert_id=$1", match.ID).Scan(&deliveries)
	if deliveries != 1 {
		t.Fatal("saturation alert not queued for delivery")
	}
	if found, err := a.deliverNotification(ctx); err != nil || !found {
		t.Fatal("saturation alert not deliverable:", err)
	}
	if sends.Load() != 1 {
		t.Fatal("notification not delivered")
	}
	// Cooldown suppresses an immediate re-notification of the same condition.
	a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now() WHERE id=$1", rule)
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(ctx, "SELECT count(*) FROM alerts WHERE (data->>'rule_id')::bigint=$1", rule).Scan(&fired); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		var dump []alertEvent
		json.Unmarshal(api.call("GET", "/api/alerts", nil, 200), &dump)
		t.Fatalf("cooldown ignored for saturation alert: fired=%d events=%+v", fired, dump)
	}
}
