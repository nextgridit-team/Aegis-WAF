package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"time"
)

// Schema-backed delivery flags also cover committed audits created outside the
// management handlers. Emit before marking; crash/commit failure can duplicate
// delivery, so collectors deduplicate by deployment + event_id/request_id.
const storedLogBatchSize = 250

func (a *App) exportStoredLogs(ctx context.Context, logger *slog.Logger) error {
	_, err := a.exportStoredLogBatch(ctx, logger)
	return err
}

func (a *App) exportStoredLogBatch(ctx context.Context, logger *slog.Logger) (bool, error) {
	audits, err := a.exportAuditBatch(ctx, logger)
	if err != nil {
		return false, err
	}
	access, err := a.exportAccessBatch(ctx, logger)
	return audits == storedLogBatchSize || access == storedLogBatchSize, err
}

// FlushStoredLogs drains committed records after handlers and background log
// producers have stopped. The caller supplies a fresh shutdown deadline. It
// bounds database work and checks between records; a blocked stdout Write itself
// cannot be interrupted by context cancellation.
func (a *App) FlushStoredLogs(ctx context.Context) error {
	if !a.initialized.Load() {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, err := a.exportStoredLogBatch(ctx, slog.Default())
		if err != nil || !more {
			return err
		}
	}
}
func (a *App) exportAuditBatch(ctx context.Context, logger *slog.Logger) (int, error) {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	rows, err := tx.Query(ctx, "SELECT id,at,actor,action,resource FROM audit_events WHERE NOT stdout_emitted ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1", storedLogBatchSize)
	if err != nil {
		return 0, err
	}
	type item struct {
		id                      int64
		at                      time.Time
		actor, action, resource string
	}
	events := []item{}
	for rows.Next() {
		var e item
		if err = rows.Scan(&e.id, &e.at, &e.actor, &e.action, &e.resource); err != nil {
			rows.Close()
			return 0, err
		}
		events = append(events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	ids := make([]int64, 0, len(events))
	for _, e := range events {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		record := slog.NewRecord(time.Now(), slog.LevelInfo, "administrative audit", 0)
		record.AddAttrs(slog.Int("schema_version", 1), slog.String("event", "admin_audit"), slog.String("event_id", "audit:"+strconv.FormatInt(e.id, 10)), slog.Time("timestamp", e.at.UTC()), slog.Int64("audit_id", e.id), slog.String("actor", e.actor), slog.String("action", e.action), slog.String("resource", e.resource))
		if err = logger.Handler().Handle(ctx, record); err != nil {
			return 0, err
		}
		ids = append(ids, e.id)
	}
	if len(ids) > 0 {
		if _, err = tx.Exec(ctx, "UPDATE audit_events SET stdout_emitted=true WHERE id=ANY($1)", ids); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(ids), nil
}

type storedAccessRecord struct {
	ID             int64                  `json:"id"`
	RequestID      string                 `json:"request_id"`
	Host           string                 `json:"host"`
	SiteName       string                 `json:"site_name"`
	At             time.Time              `json:"at"`
	SiteID         int64                  `json:"site_id"`
	Method         string                 `json:"method"`
	Status         int                    `json:"status"`
	Duration       int64                  `json:"duration_ms"`
	Peer           string                 `json:"peer"`
	Results        []RuleResult           `json:"rule_results"`
	Country        string                 `json:"country"`
	RegionCode     string                 `json:"region_code"`
	RegionName     string                 `json:"region_name"`
	Blocked        bool                   `json:"blocked"`
	Signals        []string               `json:"signals"`
	PolicyID       int64                  `json:"policy_id"`
	PolicyRevision int64                  `json:"policy_revision"`
	PolicyName     string                 `json:"policy_name"`
	Managed        managedSignatureResult `json:"managed_signatures"`
	Network        networkAccessResult    `json:"network_access"`
	Bot            botResult              `json:"bot"`
	ResponseSource string                 `json:"response_source"`
}

func (a *App) exportAccessBatch(ctx context.Context, logger *slog.Logger) (int, error) {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	rows, err := tx.Query(ctx, "SELECT to_jsonb(l) FROM access_logs l WHERE NOT stdout_emitted ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1", storedLogBatchSize)
	if err != nil {
		return 0, err
	}
	events := []storedAccessRecord{}
	for rows.Next() {
		var raw []byte
		var e storedAccessRecord
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return 0, err
		}
		if err = json.Unmarshal(raw, &e); err != nil {
			rows.Close()
			return 0, err
		}
		events = append(events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	ids := make([]int64, 0, len(events))
	for _, e := range events {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		requestID := e.RequestID
		if requestID == "" {
			requestID = "access:" + strconv.FormatInt(e.ID, 10)
		}
		event := accessEvent{requestID: requestID, host: e.Host, siteName: e.SiteName, at: e.At, site: e.SiteID, method: e.Method, status: e.Status, duration: e.Duration, peer: e.Peer, results: e.Results, country: e.Country, regionCode: e.RegionCode, regionName: e.RegionName, blocked: e.Blocked, signals: e.Signals, policyID: e.PolicyID, policyRevision: e.PolicyRevision, policyName: e.PolicyName, managed: e.Managed, network: e.Network, bot: e.Bot, responseSource: e.ResponseSource}
		// Historical exports are metadata only. Never infer past sample consent.
		if err = emitSecurityEvent(logger, event); err != nil {
			return 0, err
		}
		ids = append(ids, e.ID)
	}
	if len(ids) > 0 {
		if _, err = tx.Exec(ctx, "UPDATE access_logs SET stdout_emitted=true,request_id=CASE WHEN request_id='' THEN 'access:'||id::text ELSE request_id END WHERE id=ANY($1)", ids); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(ids), nil
}

const (
	cleanupBatchSize     = 1000
	cleanupAccessBatches = 10
	cleanupCatchupPasses = 8
)

func (a *App) cleanupLogs(ctx context.Context) error {
	// Commit between bounded passes so a large backlog makes progress even if
	// the worker's time budget expires. Stop immediately on an idle pass or an
	// error; a saturated sweep remains due for the next worker tick or replica.
	for range cleanupCatchupPasses {
		more, err := a.cleanupLogPass(ctx)
		if err != nil || !more {
			return err
		}
	}
	return nil
}

func (a *App) cleanupLogPass(ctx context.Context) (bool, error) {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background())
	var locked bool
	if err = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(700071)").Scan(&locked); err != nil || !locked {
		return false, err
	}
	var due bool
	if err = tx.QueryRow(ctx, "SELECT last_cleanup_at IS NULL OR last_cleanup_at<now()-interval '5 seconds' FROM log_maintenance WHERE id").Scan(&due); err != nil || !due {
		return false, err
	}
	var hours int
	if err = tx.QueryRow(ctx, "SELECT retention_hours FROM log_settings WHERE id FOR SHARE").Scan(&hours); err != nil {
		return false, err
	}
	var access, auditCount, evidence int64
	// Bounded statements and total transaction deadline avoid an unbounded delete
	// during upgrades or a short-retention change. Export failures retain records.
	for range cleanupAccessBatches {
		tag, err := tx.Exec(ctx, `DELETE FROM access_logs WHERE id IN (SELECT id FROM access_logs WHERE at<now()-make_interval(hours=>$1) AND stdout_emitted ORDER BY at FOR UPDATE SKIP LOCKED LIMIT $2)`, hours, cleanupBatchSize)
		if err != nil {
			return false, err
		}
		access += tag.RowsAffected()
		if tag.RowsAffected() < cleanupBatchSize {
			break
		}
	}
	tag, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE at<now()-make_interval(hours=>$1) AND stdout_emitted ORDER BY at FOR UPDATE SKIP LOCKED LIMIT $2)`, hours, cleanupBatchSize)
	if err != nil {
		return false, err
	}
	auditCount = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `DELETE FROM traffic_evidence WHERE id IN (SELECT id FROM traffic_evidence WHERE expires_at<=now() OR at<now()-make_interval(hours=>$1) ORDER BY at FOR UPDATE SKIP LOCKED LIMIT $2)`, hours, cleanupBatchSize)
	if err != nil {
		return false, err
	}
	evidence = tag.RowsAffected()
	more := access == cleanupBatchSize*cleanupAccessBatches || auditCount == cleanupBatchSize || evidence == cleanupBatchSize
	// Keep the sweep due across replicas while any table exhausts its limit.
	// The five-second cooldown begins only after a pass clears the backlog.
	if _, err = tx.Exec(ctx, "UPDATE log_maintenance SET last_cleanup_at=CASE WHEN $4 THEN last_cleanup_at ELSE now() END,cleanup_error='',access_deleted=access_deleted+$1,audit_deleted=audit_deleted+$2,evidence_deleted=evidence_deleted+$3 WHERE id", access, auditCount, evidence, more); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return more, nil
}
func (a *App) LogMaintenanceWorker(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if a.initialized.Load() {
			work, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := a.exportStoredLogs(work, slog.Default())
			cancel()
			status, statusCancel := context.WithTimeout(ctx, time.Second)
			if err != nil {
				_, _ = a.db.Exec(status, "UPDATE log_maintenance SET export_error='Stdout export unavailable; stored records retained' WHERE id")
			} else {
				_, _ = a.db.Exec(status, "UPDATE log_maintenance SET last_export_at=now(),export_error='' WHERE id")
			}
			statusCancel()
			work, cancel = context.WithTimeout(ctx, 3*time.Second)
			err = a.cleanupLogs(work)
			cancel()
			if err != nil {
				status, statusCancel = context.WithTimeout(ctx, time.Second)
				_, _ = a.db.Exec(status, "UPDATE log_maintenance SET cleanup_error='Log cleanup unavailable; records retained' WHERE id")
				statusCancel()
			}
			a.publishMetrics(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
