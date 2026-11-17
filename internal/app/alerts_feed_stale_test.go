package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The feed-stale trigger must validate like the existing kinds, and a typo must
// be rejected with a message that names the accepted kinds. Thresholds are
// hours (day scale), bounded like certificate_expiry's days, and feeds are
// workspace-wide so application scoping is rejected rather than ignored.
func TestFeedStaleAlertKindValidation(t *testing.T) {
	rule := alertRule{Name: "Stale rule feeds", Enabled: true, Kind: "feed_stale", Threshold: 48, WindowMinutes: 5, CooldownMinutes: 60}
	if err := normalizeAlertRule(&rule); err != nil {
		t.Fatal("feed_stale kind rejected:", err)
	}
	typo := rule
	typo.Kind = "feed_staleness"
	err := normalizeAlertRule(&typo)
	if err == nil {
		t.Fatal("typo kind accepted")
	}
	if !strings.Contains(err.Error(), "feed_stale") {
		t.Fatal("rejection does not name the feed_stale kind:", err)
	}
	bound := rule
	bound.Threshold = 2161
	if err := normalizeAlertRule(&bound); err == nil || !strings.Contains(err.Error(), "hours") {
		t.Fatal("out-of-range feed staleness threshold accepted:", err)
	}
	scoped := rule
	scoped.SiteID = 3
	if err := normalizeAlertRule(&scoped); err == nil {
		t.Fatal("site-scoped feed_stale rule accepted")
	}
}

// A feed whose last success is older than the threshold (or that carries a
// sync error) must generate an alert event and deliver through the
// notification pipeline with the feed and reason visible to the operator.
// Healthy feeds stay quiet.
func TestFeedStaleAlert(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "feed-admin", "password": "feed stale alert password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "feed-admin", "password": "feed stale alert password"}, 200), &login)
	api.csrf = login["csrf"]
	secret := strings.Repeat("secret", 8)
	var sends atomic.Int64
	var bodies []string
	var delivered sync.Mutex
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		delivered.Lock()
		bodies = append(bodies, string(body))
		delivered.Unlock()
		sends.Add(1)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel := mustID(t, api.call("POST", "/api/notification-channels", map[string]any{"name": "Feed receiver", "provider": "automation", "enabled": true, "config": notificationConfig{URL: receiver.URL, Secret: secret, AllowPrivate: true}}, 200))
	feed := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Stale CRS feed", "url": "https://feeds.example.test/rules.json"}, 201))
	// A healthy feed (recent success, no error) must not fire.
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET last_success=now(),last_attempt=now(),error='' WHERE id=$1", feed); e != nil {
		t.Fatal(e)
	}
	rule := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: "Stale rule feeds", Enabled: true, Kind: "feed_stale", Threshold: 48, WindowMinutes: 5, CooldownMinutes: 10, ChannelIDs: []int64{channel}}, 200))
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	var fired int
	if err := a.db.QueryRow(ctx, "SELECT count(*) FROM alerts WHERE (data->>'rule_id')::bigint=$1", rule).Scan(&fired); err != nil {
		t.Fatal(err)
	}
	if fired != 0 {
		t.Fatal("healthy feed fired the stale-feed alert")
	}
	// Stale last_success with no error fires.
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET last_success=now()-interval '3 days' WHERE id=$1", feed); e != nil {
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
		t.Fatal("stale-feed alert not generated")
	}
	if match.Kind != "feed_stale" || match.Count != 1 {
		t.Fatalf("wrong stale-feed alert: %+v", match)
	}
	var deliveries int
	a.db.QueryRow(ctx, "SELECT count(*) FROM alert_deliveries WHERE alert_id=$1", match.ID).Scan(&deliveries)
	if deliveries != 1 {
		t.Fatal("stale-feed alert not queued for delivery")
	}
	if found, err := a.deliverNotification(ctx); err != nil || !found {
		t.Fatal("stale-feed alert not deliverable:", err)
	}
	if sends.Load() != 1 {
		t.Fatal("notification not delivered")
	}
	// The delivered notification tells the operator which feed and why.
	delivered.Lock()
	last := bodies[len(bodies)-1]
	delivered.Unlock()
	if !strings.Contains(last, "Stale CRS feed") || !strings.Contains(last, "3 days") {
		t.Fatalf("delivered notification does not name the feed and reason: %s", last)
	}
	// A recorded sync error fires even after a recent success, and carries the error.
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET last_success=now(),error='sync failed: HTTP 502' WHERE id=$1", feed); e != nil {
		t.Fatal(e)
	}
	a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now(),last_emitted=NULL WHERE id=$1", rule)
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if found, err := a.deliverNotification(ctx); err != nil || !found {
		t.Fatal("failed-sync alert not deliverable:", err)
	}
	delivered.Lock()
	last = bodies[len(bodies)-1]
	delivered.Unlock()
	if !strings.Contains(last, "Stale CRS feed") || !strings.Contains(last, "HTTP 502") {
		t.Fatalf("delivered notification does not name the failing feed and its error: %s", last)
	}
	if count := alertsFor(t, a, rule); count != 2 {
		t.Fatal("expected a second alert event for the failed sync, got", count)
	}
}
func alertsFor(t *testing.T, a *App, rule int64) int {
	t.Helper()
	var fired int
	if err := a.db.QueryRow(context.Background(), "SELECT count(*) FROM alerts WHERE (data->>'rule_id')::bigint=$1", rule).Scan(&fired); err != nil {
		t.Fatal(err)
	}
	return fired
}

// The reason string must be hours-accurate under a day: "0 days ago" hides
// hour-scale staleness from the operator reading the alert.
func TestFeedStaleReasonHoursAccurate(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "feed-admin", "password": "feed hours password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "feed-admin", "password": "feed hours password"}, 200), &login)
	api.csrf = login["csrf"]
	feed := mustID(t, api.call("POST", "/api/rule-feeds", map[string]any{"name": "Hourly CRS feed", "url": "https://feeds.example.test/rules.json"}, 201))
	rule := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: "Hourly staleness", Enabled: true, Kind: "feed_stale", Threshold: 1, WindowMinutes: 5, CooldownMinutes: 10}, 200))
	reason := func() string {
		t.Helper()
		a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now(),last_emitted=NULL WHERE id=$1", rule)
		a.db.Exec(ctx, "DELETE FROM alerts WHERE (data->>'rule_id')::bigint=$1", rule)
		if err := a.evaluateAlerts(ctx); err != nil {
			t.Fatal(err)
		}
		var events []alertEvent
		json.Unmarshal(api.call("GET", "/api/alerts", nil, 200), &events)
		for n := range events {
			if events[n].RuleID == rule {
				return events[n].Details
			}
		}
		return ""
	}
	// Two hours stale against a one-hour threshold names the hours.
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET last_success=now()-interval '2 hours',last_attempt=now(),error='' WHERE id=$1", feed); e != nil {
		t.Fatal(e)
	}
	details := reason()
	if !strings.Contains(details, "2 hours ago") || strings.Contains(details, "0 days ago") {
		t.Fatalf("hour-scale staleness floored to days: %s", details)
	}
	// Three days stale keeps the day-scale wording.
	if _, e := a.db.Exec(ctx, "UPDATE rule_feeds SET last_success=now()-interval '3 days' WHERE id=$1", feed); e != nil {
		t.Fatal(e)
	}
	if details = reason(); !strings.Contains(details, "3 days ago") {
		t.Fatalf("day-scale staleness lost its wording: %s", details)
	}
}
