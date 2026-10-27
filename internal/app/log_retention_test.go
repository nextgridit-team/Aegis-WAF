package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type logTestBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *logTestBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *logTestBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type failedLogWriter struct{}

func (failedLogWriter) Write([]byte) (int, error) { return 0, errors.New("sink unavailable") }

func TestAllRequestStdoutCoverage(t *testing.T) {
	for name, event := range map[string]accessEvent{
		"normal": {status: 200, responseSource: "upstream"}, "upstream_error": {status: 503, responseSource: "upstream"},
		"redirect": {status: 308, responseSource: "waf"}, "observe": {status: 200, signals: []string{"automation_user_agent"}},
		"blocked": {status: 403, blocked: true}, "bypass": {status: 200, network: networkAccessResult{BypassWAF: true}},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			event.at = time.Now()
			event.requestID = "correlation"
			event.host = "app.test"
			event.siteName = "App"
			event.securityDisabled = true
			if err := emitSecurityEvent(slog.New(slog.NewJSONHandler(&out, nil)), event); err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["request_id"] != "correlation" || record["site_name"] != "App" || record["host"] != "app.test" {
				t.Fatal(record)
			}
			if event.blocked && record["event"] != "waf_block" {
				t.Fatal(record)
			}
			if name == "upstream_error" && record["event"] != "http_access" {
				t.Fatal(record)
			}
		})
	}
	if err := emitSecurityEvent(slog.New(slog.NewJSONHandler(failedLogWriter{}, nil)), accessEvent{}); err == nil {
		t.Fatal("lost sink failure")
	}
}
func TestEarlyGatewayRequestsAreLogged(t *testing.T) {
	a := &App{access: make(chan accessEvent, 8)}
	r := httptest.NewRequest("GET", "http://unknown.test/private?token=secret", nil)
	w := httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	event := <-a.access
	if event.status != 503 || event.host != "unknown.test" || len(event.signals) != 1 {
		t.Fatal(event)
	}
	a.active.Store(&snapshot{routes: map[string]*route{}})
	w = httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != 421 {
		t.Fatal(w.Code)
	}
	event = <-a.access
	var out bytes.Buffer
	emitSecurityEvent(slog.New(slog.NewJSONHandler(&out, nil)), event)
	if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "private") {
		t.Fatal("URL leaked", out.String())
	}
}
func TestSlowDatabaseDoesNotStallStdout(t *testing.T) {
	var out logTestBuffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	defer slog.SetDefault(prior)
	a := &App{access: make(chan accessEvent, 4000)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	var once sync.Once
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runAccessLogger(ctx, func(ctx context.Context, batch []accessEvent) error {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	for range 1000 {
		a.access <- accessEvent{at: time.Now(), status: 200}
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("database writer never started")
	}
	for range 1000 {
		a.access <- accessEvent{at: time.Now(), status: 200}
	}
	deadline := time.Now().Add(time.Second)
	for strings.Count(out.String(), `"event":"http_access"`) < 2000 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond * 5)
	}
	if strings.Count(out.String(), `"event":"http_access"`) != 2000 {
		t.Fatal("stdout waited for blocked DB")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("shutdown did not bound DB drain")
	}
	if a.stdoutDropped.Load() != 0 {
		t.Fatal("stdout dropped valid events")
	}
}

func TestLogRetentionExportAndCoordination(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	ctx := context.Background()
	var settings logSettingsInput
	if err := json.Unmarshal(api.call("GET", "/api/log-settings", nil, 200), &settings); err != nil || settings.RetentionHours != 6 {
		t.Fatal(settings, err)
	}
	api.call("PUT", "/api/log-settings", logSettingsInput{RetentionHours: 0, Revision: settings.Revision}, 400)
	api.call("PUT", "/api/log-settings", logSettingsInput{RetentionHours: 12, Revision: settings.Revision}, 200)
	api.call("PUT", "/api/log-settings", logSettingsInput{RetentionHours: 24, Revision: settings.Revision}, 409)
	api.call("PUT", "/api/log-settings", logSettingsInput{RetentionHours: 6, Revision: settings.Revision + 1}, 200)
	anonymous, err := http.Get(api.base + "/api/log-settings")
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != 401 {
		t.Fatal("unauthenticated settings")
	}
	savedCSRF := api.csrf
	api.csrf = "wrong"
	api.call("PUT", "/api/log-settings", logSettingsInput{RetentionHours: 1, Revision: 3}, 403)
	api.csrf = savedCSRF
	// Stored events from older releases have no stdout flag. Retention must wait.
	var oldAccess, oldAudit, recent int64
	for _, q := range []struct {
		sql string
		id  *int64
	}{
		{"INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer) VALUES(now()-interval '7 hours',0,'GET',200,1,'192.0.2.1') RETURNING id", &oldAccess},
		{"INSERT INTO audit_events(at,actor,action,resource) VALUES(now()-interval '7 hours','admin','test.retained','safe') RETURNING id", &oldAudit},
		{"INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer) VALUES(now(),0,'GET',502,1,'192.0.2.1') RETURNING id", &recent},
	} {
		if err = a.db.QueryRow(ctx, q.sql).Scan(q.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = a.db.Exec(ctx, "INSERT INTO traffic_evidence(id,at,site_id,expires_at,data) VALUES('old',now()-interval '7 hours',$1,now()+interval '1 day','{}'),('recent',now(),$1,now()+interval '1 day','{}')", site); err != nil {
		t.Fatal(err)
	}
	if err = a.cleanupLogs(ctx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_logs WHERE id=$1)", oldAccess).Scan(&exists)
	if !exists {
		t.Fatal("deleted unexported access")
	}
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1)", oldAudit).Scan(&exists)
	if !exists {
		t.Fatal("deleted unexported audit")
	}
	if err = a.exportStoredLogs(ctx, slog.New(slog.NewJSONHandler(failedLogWriter{}, nil))); err == nil {
		t.Fatal("sink failure not reported")
	}
	var pending bool
	a.db.QueryRow(ctx, "SELECT NOT stdout_emitted FROM audit_events WHERE id=$1", oldAudit).Scan(&pending)
	if !pending {
		t.Fatal("failed export acknowledged")
	}
	// An uncommitted audit must never be reported as a completed change.
	tx, err := a.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = audit(ctx, tx, "admin", "test.uncommitted", "safe"); err != nil {
		t.Fatal(err)
	}
	var out logTestBuffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	errs := make(chan error, 2)
	go func() { errs <- a.exportStoredLogs(ctx, logger) }()
	go func() { errs <- b.exportStoredLogs(ctx, logger) }()
	for range 2 {
		if err = <-errs; err != nil {
			t.Fatal(err)
		}
	}
	tx.Rollback(ctx)
	if strings.Contains(out.String(), "test.uncommitted") {
		t.Fatal("rolled-back audit exported")
	}
	if strings.Count(out.String(), `"action":"test.retained"`) != 1 {
		t.Fatal("audit missing/duplicated by replicas", out.String())
	}
	a.db.QueryRow(ctx, "SELECT stdout_emitted FROM access_logs WHERE id=$1", oldAccess).Scan(&exists)
	if !exists {
		t.Fatal("access export unacknowledged")
	}
	// Reset only test scheduling, then parallel cleanups should perform one pass.
	a.db.Exec(ctx, "UPDATE log_maintenance SET last_cleanup_at=NULL WHERE id")
	go func() { errs <- a.cleanupLogs(ctx) }()
	go func() { errs <- b.cleanupLogs(ctx) }()
	for range 2 {
		if err = <-errs; err != nil {
			t.Fatal(err)
		}
	}
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_logs WHERE id=$1)", oldAccess).Scan(&exists)
	if exists {
		t.Fatal("old exported access retained")
	}
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1)", oldAudit).Scan(&exists)
	if exists {
		t.Fatal("old exported audit retained")
	}
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_logs WHERE id=$1)", recent).Scan(&exists)
	if !exists {
		t.Fatal("recent access deleted")
	}
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM traffic_evidence WHERE id='old')").Scan(&exists)
	if exists {
		t.Fatal("system evidence ceiling ignored")
	}
	a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM traffic_evidence WHERE id='recent')").Scan(&exists)
	if !exists {
		t.Fatal("recent evidence deleted")
	}
	var count int64
	a.db.QueryRow(ctx, "SELECT access_deleted FROM log_maintenance WHERE id").Scan(&count)
	if count != 1 {
		t.Fatal("cleanup duplicated", count)
	}
	// Whole management route remains discoverable with explicit configuration scope.
	if agentScopeFor("PUT /api/log-settings") != "configuration" {
		t.Fatal("wrong agent scope")
	}
}

func TestLogRetentionShutdownFlush(t *testing.T) {
	for _, sinkFails := range []bool{false, true} {
		name := "final_commits"
		if sinkFails {
			name = "sink_failure_retains_records"
		}
		t.Run(name, func(t *testing.T) {
			a := newTestReplica(t, testDB(t))
			ctx := context.Background()
			tx, err := a.db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			const audits = storedLogBatchSize + 1
			if _, err = tx.Exec(ctx, "INSERT INTO audit_events(at,actor,action,resource) SELECT now()-interval '7 hours','admin','test.shutdown','safe' FROM generate_series(1,$1)", audits); err != nil {
				t.Fatal(err)
			}
			var out logTestBuffer
			logger := slog.New(slog.NewJSONHandler(&out, nil))
			// The last scheduled export cannot see the transaction still in flight.
			if err = a.exportStoredLogs(ctx, logger); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), `"action":"test.shutdown"`) {
				t.Fatal("exported an uncommitted final audit")
			}
			prior := slog.Default()
			defer slog.SetDefault(prior)
			slog.SetDefault(slog.New(slog.NewJSONHandler(failedLogWriter{}, nil)))
			workerCtx, stopWorkers := context.WithCancel(ctx)
			defer stopWorkers()
			done := make(chan struct{})
			a.access <- accessEvent{at: time.Now().Add(-7 * time.Hour), method: "GET", status: 200, requestID: "shutdown-access"}
			go func() { defer close(done); a.logWorker(workerCtx) }()
			stopWorkers()
			// As in main, wait for access persistence and the last audit producer.
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("access persistence did not finish")
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = a.FlushStoredLogs(workerCtx); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled worker context accepted: %v", err)
			}
			if sinkFails {
				flush, cancel := context.WithTimeout(ctx, 5*time.Second)
				err = a.FlushStoredLogs(flush)
				cancel()
				if err == nil {
					t.Fatal("final sink failure not reported")
				}
				if err = a.cleanupLogs(ctx); err != nil {
					t.Fatal(err)
				}
				var pending int
				if err = a.db.QueryRow(ctx, "SELECT (SELECT count(*) FROM audit_events WHERE NOT stdout_emitted)+(SELECT count(*) FROM access_logs WHERE NOT stdout_emitted)").Scan(&pending); err != nil || pending != audits+1 {
					t.Fatalf("failed final export lost records: pending=%d err=%v", pending, err)
				}
			}
			slog.SetDefault(logger)
			flush, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = a.FlushStoredLogs(flush)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(out.String(), `"action":"test.shutdown"`); got != audits {
				t.Fatalf("final audits exported: got %d want %d", got, audits)
			}
			if got := strings.Count(out.String(), `"request_id":"shutdown-access"`); got != 1 {
				t.Fatalf("final persisted access exported %d times", got)
			}
			var pending int
			if err = a.db.QueryRow(ctx, "SELECT (SELECT count(*) FROM audit_events WHERE NOT stdout_emitted)+(SELECT count(*) FROM access_logs WHERE NOT stdout_emitted)").Scan(&pending); err != nil || pending != 0 {
				t.Fatalf("final export did not drain all batches: pending=%d err=%v", pending, err)
			}
		})
	}
}

func TestLogRetentionCleanupCatchup(t *testing.T) {
	for _, tc := range []struct {
		name, insert, count, deleted string
		perPass                      int
	}{
		{"access", "INSERT INTO access_logs(at,site_id,method,status,duration_ms,peer,stdout_emitted) SELECT now()-interval '7 hours',0,'GET',200,1,'192.0.2.1',true FROM generate_series(1,$1)", "SELECT count(*) FROM access_logs", "access_deleted", cleanupBatchSize * cleanupAccessBatches},
		{"audit", "INSERT INTO audit_events(at,actor,action,resource,stdout_emitted) SELECT now()-interval '7 hours','admin','test.backlog','safe',true FROM generate_series(1,$1)", "SELECT count(*) FROM audit_events WHERE action='test.backlog'", "audit_deleted", cleanupBatchSize},
		{"evidence", "INSERT INTO traffic_evidence(id,at,site_id,expires_at,data) SELECT n::text,now()-interval '7 hours',1,now()+interval '1 day','{}' FROM generate_series(1,$1) n", "SELECT count(*) FROM traffic_evidence", "evidence_deleted", cleanupBatchSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testDB(t)
			a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
			ctx := context.Background()
			if _, err := a.db.Exec(ctx, "INSERT INTO sites(id,name,hostnames,upstream) VALUES(1,'test','{test.invalid}','http://127.0.0.1')"); err != nil {
				t.Fatal(err)
			}
			total := tc.perPass*(cleanupCatchupPasses+1) + 1
			if _, err := a.db.Exec(ctx, tc.insert, total); err != nil {
				t.Fatal(err)
			}
			if err := a.cleanupLogs(ctx); err != nil {
				t.Fatal(err)
			}
			var remaining int
			if err := a.db.QueryRow(ctx, tc.count).Scan(&remaining); err != nil || remaining != tc.perPass+1 {
				t.Fatalf("catch-up was not bounded or stopped after one pass: remaining=%d err=%v", remaining, err)
			}
			var due bool
			if err := a.db.QueryRow(ctx, "SELECT last_cleanup_at IS NULL OR last_cleanup_at<now()-interval '5 seconds' FROM log_maintenance WHERE id").Scan(&due); err != nil || !due {
				t.Fatalf("backlog incorrectly entered cooldown: due=%v err=%v", due, err)
			}
			// A second replica must continue immediately without resetting state.
			if err := b.cleanupLogs(ctx); err != nil {
				t.Fatal(err)
			}
			if err := a.db.QueryRow(ctx, tc.count).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatalf("replica failed to finish catch-up: remaining=%d err=%v", remaining, err)
			}
			var deleted int
			if err := a.db.QueryRow(ctx, "SELECT "+tc.deleted+" FROM log_maintenance WHERE id").Scan(&deleted); err != nil || deleted != total {
				t.Fatalf("cleanup count: got %d want %d err=%v", deleted, total, err)
			}
			if _, err := a.db.Exec(ctx, tc.insert, 1); err != nil {
				t.Fatal(err)
			}
			if err := a.cleanupLogs(ctx); err != nil {
				t.Fatal(err)
			}
			if err := a.db.QueryRow(ctx, tc.count).Scan(&remaining); err != nil || remaining != 1 {
				t.Fatalf("cleared backlog did not enter normal cooldown: remaining=%d err=%v", remaining, err)
			}
		})
	}
}
