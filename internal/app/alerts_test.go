package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotificationDestinationValidation(t *testing.T) {
	for _, raw := range []string{"http://public.example/path", "https://user:pass@example.com/", "https://169.254.169.254/latest/meta-data", "https://[::1]/", "file:///tmp/test", "https://0.0.0.0/"} {
		if validateNotificationConfig(notificationConfig{URL: raw}) == nil {
			t.Fatal("accepted unsafe URL", raw)
		}
	}
	for _, ip := range []string{"169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:169.254.169.254"} {
		if notificationIPAllowed(netip.MustParseAddr(ip), true, false) {
			t.Fatal("private override allowed metadata/multicast", ip)
		}
	}
	if notificationIPAllowed(netip.MustParseAddr("1.1.1.1"), true, true) {
		t.Fatal("public HTTP allowed")
	}
	if validateNotificationConfig(notificationConfig{URL: "http://127.0.0.1:1234/", AllowPrivate: true}) != nil {
		t.Fatal("explicit private receiver rejected")
	}
}
func TestNotificationProvidersAndSignatures(t *testing.T) {
	secret := strings.Repeat("s", 32)
	for _, provider := range []string{"automation", "webhook", "slack", "discord", "gotify", "ntfy", "apprise"} {
		t.Run(provider, func(t *testing.T) {
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get("X-Aegis-Alert-ID") != "42" {
					t.Error("missing stable alert ID")
				}
				if provider == "automation" || provider == "webhook" {
					mac := hmac.New(sha256.New, []byte(secret))
					mac.Write([]byte(r.Header.Get("X-Aegis-Timestamp") + "."))
					mac.Write(body)
					if r.Header.Get("X-Aegis-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
						t.Error("bad HMAC")
					}
				}
				if provider == "gotify" && r.Header.Get("X-Gotify-Key") != secret {
					t.Error("missing Gotify token")
				}
				if (provider == "ntfy" || provider == "apprise") && r.Header.Get("Authorization") != "Bearer "+secret {
					t.Error("missing Bearer token")
				}
				if strings.Contains(string(body), secret) {
					t.Error("secret in payload")
				}
				if provider != "ntfy" && !json.Valid(body) {
					t.Error("invalid provider payload")
				}
				w.WriteHeader(204)
			}))
			defer receiver.Close()
			if err := sendNotification(context.Background(), provider, notificationConfig{URL: receiver.URL, Secret: secret, AllowPrivate: true}, alertEvent{ID: 42, Title: "Blocked traffic"}); err != nil {
				t.Fatal(err)
			}
		})
	}
	var redirected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	if sendNotification(context.Background(), "webhook", notificationConfig{URL: redirect.URL, AllowPrivate: true}, alertEvent{}) == nil || redirected.Load() != 0 {
		t.Fatal("followed notification redirect")
	}
}
func TestAlertingIntegration(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	var initialVersion int64
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&initialVersion)
	secret := strings.Repeat("secret", 8)
	var sends atomic.Int64
	var fail atomic.Bool
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		if fail.Load() {
			w.WriteHeader(500)
			io.WriteString(w, secret)
			return
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel := mustID(t, api.call("POST", "/api/notification-channels", map[string]any{"name": "Agent receiver", "provider": "automation", "enabled": true, "config": notificationConfig{URL: receiver.URL, Secret: secret, AllowPrivate: true}}, 200))
	read := api.call("GET", "/api/notification-channels", nil, 200)
	if strings.Contains(string(read), secret) || strings.Contains(string(read), receiver.URL) {
		t.Fatal("destination secret returned")
	}
	var cipher []byte
	if err := a.db.QueryRow(ctx, "SELECT config_cipher FROM notification_channels WHERE id=$1", channel).Scan(&cipher); err != nil || strings.Contains(string(cipher), secret) {
		t.Fatal("destination not encrypted", err)
	}
	api.call("PUT", fmt.Sprintf("/api/notification-channels/%d", channel), map[string]any{"name": "Agent receiver", "provider": "automation", "enabled": true, "revision": 0}, 409)
	api.call("POST", fmt.Sprintf("/api/notification-channels/%d/test", channel), map[string]any{}, 200)
	if sends.Load() != 1 {
		t.Fatal("test notification not sent")
	}
	rule := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: "Investigate blocks", Enabled: true, Kind: "blocked_volume", SiteID: site, Threshold: 2, WindowMinutes: 5, CooldownMinutes: 15, ChannelIDs: []int64{channel}}, 200))
	if _, err := a.db.Exec(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,blocked) SELECT now(),$1,'GET',403,0,'198.51.100.1',true FROM generate_series(1,2)", site); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, replica := range []*App{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := replica.evaluateAlerts(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var alerts, deliveries int
	a.db.QueryRow(ctx, "SELECT count(*) FROM alerts").Scan(&alerts)
	a.db.QueryRow(ctx, "SELECT count(*) FROM alert_deliveries").Scan(&deliveries)
	if alerts != 1 || deliveries != 1 {
		t.Fatal("replica duplicate or missing alert", alerts, deliveries)
	}
	for _, replica := range []*App{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := replica.deliverNotification(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if sends.Load() != 2 {
		t.Fatal("duplicate delivery claim", sends.Load())
	}
	var inbox []alertEvent
	json.Unmarshal(api.call("GET", "/api/alerts?after_id=0", nil, 200), &inbox)
	if len(inbox) != 1 || inbox[0].ID == 0 || inbox[0].RuleID != rule || inbox[0].Count != 2 {
		t.Fatal("missing alert metadata", inbox)
	}
	api.call("POST", fmt.Sprintf("/api/alerts/%d/acknowledge", inbox[0].ID), map[string]any{}, 200)
	var remaining []alertEvent
	json.Unmarshal(api.call("GET", "/api/alerts?unacknowledged=true", nil, 200), &remaining)
	if len(remaining) != 0 {
		t.Fatal("ack not persisted")
	}
	if _, err := a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now() WHERE id=$1", rule); err != nil {
		t.Fatal(err)
	}
	if err := b.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	a.db.QueryRow(ctx, "SELECT count(*) FROM alerts").Scan(&alerts)
	if alerts != 1 {
		t.Fatal("cooldown ignored")
	}
	var finalVersion int64
	a.db.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&finalVersion)
	if finalVersion != initialVersion {
		t.Fatal("alert administration invalidated protection simulations", initialVersion, finalVersion)
	}
	// A new queued delivery retries with backoff and never stores receiver bodies.
	fail.Store(true)
	a.db.Exec(ctx, "UPDATE alert_deliveries SET status='pending',attempts=0,next_attempt=now()")
	if found, err := a.deliverNotification(ctx); err != nil || !found {
		t.Fatal("missing retry", err)
	}
	var status, message string
	var next time.Time
	a.db.QueryRow(ctx, "SELECT status,error,next_attempt FROM alert_deliveries").Scan(&status, &message, &next)
	if status != "pending" || !next.After(time.Now()) || strings.Contains(message, secret) {
		t.Fatal("bad retry/redaction", status, message)
	}
	a.db.Exec(ctx, "UPDATE alert_deliveries SET attempts=4,next_attempt=now()")
	if _, err := a.deliverNotification(ctx); err != nil {
		t.Fatal(err)
	}
	a.db.QueryRow(ctx, "SELECT status FROM alert_deliveries").Scan(&status)
	if status != "failed" {
		t.Fatal("retry limit ignored")
	}
	api.call("DELETE", fmt.Sprintf("/api/notification-channels/%d", channel), nil, 400)
	// Alert read access is available through MCP; acknowledgement/config stays scoped.
	for _, op := range agentOperations() {
		if strings.HasPrefix(op.Pattern, "GET /api/alert") && op.Scope != "read" {
			t.Fatal("wrong alert read scope")
		}
	}
	if agentScopeFor("POST /api/alerts/{id}/acknowledge") != "configuration" {
		t.Fatal("ack has wrong mutation scope")
	}
}

func TestAlertCertificateAndFailureTriggers(t *testing.T) {
	a, _, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	var cert int64
	if err := a.db.QueryRow(ctx, "INSERT INTO certificates(name,origin,domains,chain_pem,not_after) VALUES('Alert fixture','upload',ARRAY['bot.test'],'isolated-metadata-fixture',now()+interval '2 days') RETURNING id").Scan(&cert); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(ctx, "UPDATE sites SET certificate_id=$2 WHERE id=$1", site, cert); err != nil {
		t.Fatal(err)
	}
	// These tests exercise alert metadata queries, not certificate parsing/activation.
	if _, err := a.db.Exec(ctx, "INSERT INTO jobs(certificate_id,status,attempts) VALUES($1,'retry',1)", cert); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"certificate_expiry", "acme_failure", "upstream_errors"} {
		threshold := 1
		if kind == "certificate_expiry" {
			threshold = 7
		}
		id := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: kind, Kind: kind, Enabled: true, SiteID: site, Threshold: threshold, WindowMinutes: 5, CooldownMinutes: 10}, 200))
		if kind == "upstream_errors" {
			if _, err := a.db.Exec(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,response_source) VALUES(now(),$1,'GET',500,0,'127.0.0.1','upstream'),(now(),$1,'GET',502,0,'127.0.0.1','waf')", site); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.evaluateAlerts(ctx); err != nil {
			t.Fatal(err)
		}
		var events []alertEvent
		json.Unmarshal(api.call("GET", "/api/alerts", nil, 200), &events)
		found := false
		for _, event := range events {
			if event.RuleID == id {
				found = true
				if event.Count != 1 {
					t.Fatalf("%s included wrong records: %+v", kind, event)
				}
			}
		}
		if !found {
			t.Fatal("trigger did not fire", kind)
		}
	}
	// Ascending cursor pages must not skip backlog when more than 200 arrive.
	if _, err := a.db.Exec(ctx, `INSERT INTO alerts(data) SELECT '{"title":"cursor"}'::jsonb FROM generate_series(1,205)`); err != nil {
		t.Fatal(err)
	}
	var first, second []alertEvent
	json.Unmarshal(api.call("GET", "/api/alerts?after_id=0", nil, 200), &first)
	if len(first) != 200 {
		t.Fatal("cursor page limit", len(first))
	}
	cursor := first[len(first)-1].ID
	json.Unmarshal(api.call("GET", "/api/alerts?after_id="+itoa(cursor), nil, 200), &second)
	if len(second) != 8 || second[0].ID <= cursor {
		t.Fatal("cursor lost backlog", len(second))
	}
}
