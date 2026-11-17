package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The management-plaintext trigger must validate like the existing kinds,
// reject a typo with the full kind list, and refuse application scoping: the
// condition describes this replica's listener, not one application's traffic.
func TestManagementPlaintextAlertKindValidation(t *testing.T) {
	rule := alertRule{Name: "Plaintext management", Enabled: true, Kind: "management_plaintext_non_loopback", Threshold: 1, WindowMinutes: 5, CooldownMinutes: 60}
	if err := normalizeAlertRule(&rule); err != nil {
		t.Fatal("management_plaintext_non_loopback kind rejected:", err)
	}
	typo := rule
	typo.Kind = "management_plaintext"
	err := normalizeAlertRule(&typo)
	if err == nil {
		t.Fatal("typo kind accepted")
	}
	if !strings.Contains(err.Error(), "management_plaintext_non_loopback") {
		t.Fatal("rejection does not name the management plaintext kind:", err)
	}
	scoped := rule
	scoped.SiteID = 3
	if err = normalizeAlertRule(&scoped); err == nil {
		t.Fatal("site-scoped management plaintext rule accepted")
	}
}

// Surfacing is otherwise a startup log line, a status field and a dashboard
// banner: an operator centralizing alerts sees one line per boot. The kind
// turns the config-derived condition into a durable, deliverable alert.
func TestManagementPlaintextAlert(t *testing.T) {
	cfg := testDB(t)
	cfg.SnapshotCacheFile = filepath.Join(t.TempDir(), "snapshot")
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	management := httptest.NewServer(a.Management())
	defer management.Close()
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "management plaintext password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "management plaintext password"}, 200), &login)
	api.csrf = login["csrf"]
	rule := mustID(t, api.call("POST", "/api/alert-rules", alertRule{Name: "Plaintext management", Enabled: true, Kind: "management_plaintext_non_loopback", Threshold: 1, WindowMinutes: 5, CooldownMinutes: 60}, 200))
	alerted := func() *alertEvent {
		t.Helper()
		var events []alertEvent
		json.Unmarshal(api.call("GET", "/api/alerts", nil, 200), &events)
		for n := range events {
			if events[n].RuleID == rule {
				return &events[n]
			}
		}
		return nil
	}
	// A loopback plaintext bind does not fire.
	a.cfg.ManagementAddr = "127.0.0.1:9090"
	a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now() WHERE id=$1", rule)
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if alerted() != nil {
		t.Fatal("loopback bind fired the plaintext alert")
	}
	// A non-loopback plaintext bind fires once with the bind address named.
	a.cfg.ManagementAddr = "192.0.2.10:9090"
	a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now() WHERE id=$1", rule)
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	match := alerted()
	if match == nil {
		t.Fatal("non-loopback bind did not fire the plaintext alert")
	}
	if match.Kind != "management_plaintext_non_loopback" || match.Count != 1 {
		t.Fatalf("wrong plaintext alert: %+v", match)
	}
	if !strings.Contains(match.Details, "192.0.2.10:9090") || !strings.Contains(match.Details, "plaintext") {
		t.Fatalf("plaintext alert lost the cause and bind address: %s", match.Details)
	}
	// Native TLS clears it even on a non-loopback bind.
	a.cfg.ManagementTLS = true
	a.db.Exec(ctx, "UPDATE alert_rules SET next_eval=now() WHERE id=$1", rule)
	if err := a.evaluateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if match = alerted(); match == nil || match.Count != 1 {
		t.Fatal("TLS state re-fired or lost the earlier alert")
	}
	var fired int
	a.db.QueryRow(ctx, "SELECT count(*) FROM alerts WHERE (data->>'rule_id')::bigint=$1", rule).Scan(&fired)
	if fired != 1 {
		t.Fatal("TLS state fired a second plaintext alert:", fired)
	}
}
