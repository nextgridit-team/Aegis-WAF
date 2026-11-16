package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func auditRetentionFixture(t *testing.T) (*App, testAPI, int64) {
	t.Helper()
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	management := httptest.NewServer(a.Management())
	t.Cleanup(management.Close)
	jar, _ := cookiejar.New(nil)
	api := testAPI{t, &http.Client{Jar: jar}, management.URL, ""}
	api.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "audit retention password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(api.call("POST", "/api/login", map[string]string{"username": "admin", "password": "audit retention password"}, 200), &login)
	api.csrf = login["csrf"]
	var site int64
	if err := a.db.QueryRow(context.Background(), "INSERT INTO sites(name,hostnames,upstream) VALUES('Audit app',ARRAY['audit.test'],'http://127.0.0.1:1') RETURNING id").Scan(&site); err != nil {
		t.Fatal(err)
	}
	return a, api, site
}

func storedRowExists(t *testing.T, a *App, query string, args ...any) bool {
	t.Helper()
	var exists bool
	if err := a.db.QueryRow(context.Background(), query, args...).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func runLogMaintenanceWorker(t *testing.T, a *App, duration time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.LogMaintenanceWorker(ctx)
	}()
	time.Sleep(duration)
	cancel()
	<-done
}

// A separate audit retention window keeps administrative audit events past the
// traffic-log window, and cannot be set below it.
func TestAuditRetentionSeparateWindow(t *testing.T) {
	a, api, _ := auditRetentionFixture(t)
	ctx := context.Background()
	api.call("PUT", "/api/log-settings", map[string]any{"retention_hours": 1, "audit_retention_hours": 8760, "revision": 1}, 200)
	var status map[string]any
	json.Unmarshal(api.call("GET", "/api/log-settings", nil, 200), &status)
	if status["audit_retention_hours"] != float64(8760) {
		t.Fatal("audit retention not surfaced:", status)
	}
	// Row-scoped checks: the fixture itself audits setup and login, so
	// table-wide EXISTS would conflate fixture rows with the probe rows.
	var oldAudit, oldAccess int64
	if err := a.db.QueryRow(ctx, "INSERT INTO audit_events(at,actor,action,resource,stdout_emitted) VALUES(now()-interval '2 hours','admin','test.audit.window','1',true) RETURNING id").Scan(&oldAudit); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,stdout_emitted) VALUES(now()-interval '2 hours',1,'GET',200,0,'198.51.100.1',true) RETURNING id").Scan(&oldAccess); err != nil {
		t.Fatal(err)
	}
	if err := a.cleanupLogs(ctx); err != nil {
		t.Fatal(err)
	}
	if storedRowExists(t, a, "SELECT EXISTS(SELECT 1 FROM access_logs WHERE id=$1)", oldAccess) {
		t.Fatal("expired access log retained")
	}
	if !storedRowExists(t, a, "SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1)", oldAudit) {
		t.Fatal("audit event deleted on the traffic-log window")
	}
	// The audit window is a floor over the traffic window, not a knob below it.
	api.call("PUT", "/api/log-settings", map[string]any{"retention_hours": 4, "audit_retention_hours": 2, "revision": 2}, 400)
	// Once the audit window itself passes, the event is removed.
	api.call("PUT", "/api/log-settings", map[string]any{"retention_hours": 1, "audit_retention_hours": 1, "revision": 2}, 200)
	if _, err := a.db.Exec(ctx, "UPDATE log_maintenance SET last_cleanup_at=NULL WHERE id"); err != nil {
		t.Fatal(err)
	}
	if err := a.cleanupLogs(ctx); err != nil {
		t.Fatal(err)
	}
	if storedRowExists(t, a, "SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1)", oldAudit) {
		t.Fatal("expired audit event retained")
	}
}

// A persistent stdout-export failure must surface its error class and a
// queryable backlog gauge instead of a constant message and silent growth.
func TestExportFailureSurfacesClassAndBacklog(t *testing.T) {
	a, _, _ := auditRetentionFixture(t)
	ctx := context.Background()
	// slog.SetDefault(broken) reroutes the log package through the broken
	// handler, which also poisons the pristine default logger. Anchor on a
	// real buffer-backed logger instead so restoring works (the same pattern
	// TestLogRetentionShutdownFlush uses).
	pristine := slog.Default()
	defer slog.SetDefault(pristine)
	var out logTestBuffer
	healthy := slog.New(slog.NewJSONHandler(&out, nil))
	slog.SetDefault(healthy)
	// Drain fixture-audited rows (setup, login) with a healthy sink first so
	// the backlog assertions below count only the probe rows.
	runLogMaintenanceWorker(t, a, 1200*time.Millisecond)
	for n := 0; n < 3; n++ {
		if _, err := a.db.Exec(ctx, "INSERT INTO audit_events(at,actor,action,resource) VALUES(now(),'admin','test.backlog.audit','1')"); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 2; n++ {
		if _, err := a.db.Exec(ctx, "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer) VALUES(now(),1,'GET',200,0,'198.51.100.1')"); err != nil {
			t.Fatal(err)
		}
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(failedLogWriter{}, nil)))
	runLogMaintenanceWorker(t, a, 1500*time.Millisecond)
	var exportError string
	if err := a.db.QueryRow(ctx, "SELECT export_error FROM log_maintenance WHERE id").Scan(&exportError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exportError, "sink unavailable") {
		t.Fatal("error class discarded:", exportError)
	}
	if !strings.Contains(exportError, "retained") {
		t.Fatal("retention guidance lost:", exportError)
	}
	if value := unexportedGauge(t, a.prom, "audit_events"); value != 3 {
		t.Fatal("audit backlog gauge wrong:", value)
	}
	if value := unexportedGauge(t, a.prom, "access_logs"); value != 2 {
		t.Fatal("access backlog gauge wrong:", value)
	}
	// A healthy pass clears the backlog and the error.
	slog.SetDefault(healthy)
	runLogMaintenanceWorker(t, a, 1500*time.Millisecond)
	if value := unexportedGauge(t, a.prom, "audit_events"); value != 0 {
		t.Fatal("backlog not cleared:", value)
	}
	if err := a.db.QueryRow(ctx, "SELECT export_error FROM log_maintenance WHERE id").Scan(&exportError); err != nil || exportError != "" {
		t.Fatal("export error not cleared:", exportError, err)
	}
	if !strings.Contains(out.String(), "test.backlog.audit") {
		t.Fatal("probe rows not exported on recovery")
	}
}

func unexportedGauge(t *testing.T, p *gatewayTelemetry, table string) float64 {
	t.Helper()
	families, err := p.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "aegis_stored_logs_unexported" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "table" && label.GetValue() == table {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatal("missing unexported backlog gauge for", table)
	return 0
}

// The evidence ceiling is the documented decision: captured samples are
// removed at the global window even when a site's capture expiry is later.
func TestEvidenceCeilingIsExplicit(t *testing.T) {
	a, _, site := auditRetentionFixture(t)
	ctx := context.Background()
	if _, err := a.db.Exec(ctx, "INSERT INTO traffic_evidence(id,at,site_id,expires_at,data) VALUES('ceiling',now()-interval '10 hours',$1,now()+interval '100 hours','{}'::jsonb)", site); err != nil {
		t.Fatal(err)
	}
	if err := a.cleanupLogs(ctx); err != nil {
		t.Fatal(err)
	}
	if storedRowExists(t, a, "SELECT EXISTS(SELECT 1 FROM traffic_evidence WHERE id='ceiling')") {
		t.Fatal("global evidence ceiling not enforced")
	}
}
