package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (a *App) AlertWorker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 8*time.Second)
		if err := a.evaluateAlerts(work); err != nil && ctx.Err() == nil {
			slog.Warn("alert evaluation unavailable; forwarding unaffected")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (a *App) evaluateAlerts(ctx context.Context) error {
	for range 64 {
		found, err := a.evaluateAlertRule(ctx)
		if err != nil {
			return err
		}
		if !found {
			break
		}
	}
	// The inbox and associated deliveries retain 30 days, capped to the newest
	// 1000 alerts. Cleanup is bounded and does not affect access-log retention.
	_, err := a.db.Exec(ctx, "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE at<now()-interval '30 days' ORDER BY id LIMIT 1000) OR id IN (SELECT id FROM alerts ORDER BY id DESC OFFSET 1000 LIMIT 1000)")
	return err
}
func (a *App) evaluateAlertRule(ctx context.Context) (bool, error) {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id int64
	var raw []byte
	var last *time.Time
	var created, now time.Time
	err = tx.QueryRow(ctx, "SELECT id,spec,last_emitted,created_at,now() FROM alert_rules WHERE next_eval<=now() ORDER BY next_eval,id FOR UPDATE SKIP LOCKED LIMIT 1").Scan(&id, &raw, &last, &created, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE alert_rules SET next_eval=now()+interval '10 seconds' WHERE id=$1", id); err != nil {
		return false, err
	}
	var rule alertRule
	if err = json.Unmarshal(raw, &rule); err != nil {
		return false, err
	}
	if !rule.Enabled || (last != nil && now.Sub(*last) < time.Duration(rule.CooldownMinutes)*time.Minute) {
		return true, tx.Commit(ctx)
	}
	start := now.Add(-time.Duration(rule.WindowMinutes) * time.Minute)
	if created.After(start) {
		start = created
	}
	if last != nil && last.After(start) {
		start = *last
	}
	var count int64
	var details string
	switch rule.Kind {
	case "blocked_volume":
		err = tx.QueryRow(ctx, "SELECT count(*) FROM access_logs WHERE at>$1 AND at<=$2 AND ($3=0 OR site_id=$3) AND blocked", start, now, rule.SiteID).Scan(&count)
	case "upstream_errors":
		err = tx.QueryRow(ctx, "SELECT count(*) FROM access_logs WHERE at>$1 AND at<=$2 AND ($3=0 OR site_id=$3) AND status>=500 AND response_source IN ('upstream','gateway_error')", start, now, rule.SiteID).Scan(&count)
	case "certificate_expiry":
		err = tx.QueryRow(ctx, "SELECT count(*) FROM certificates c WHERE c.chain_pem<>'' AND c.not_after<=now()+make_interval(days=>$1) AND ($2=0 OR EXISTS(SELECT 1 FROM sites s WHERE s.id=$2 AND s.certificate_id=c.id))", rule.Threshold, rule.SiteID).Scan(&count)
	case "acme_failure":
		err = tx.QueryRow(ctx, "SELECT count(*) FROM jobs j WHERE j.status='retry' AND j.attempts>0 AND ($1=0 OR EXISTS(SELECT 1 FROM sites s WHERE s.id=$1 AND s.certificate_id=j.certificate_id))", rule.SiteID).Scan(&count)
	case "inspection_saturation":
		// A busy inspection means the request bypassed signature inspection:
		// observe policies fail open, block policies answer 503.
		err = tx.QueryRow(ctx, "SELECT count(*) FROM access_logs WHERE at>$1 AND at<=$2 AND ($3=0 OR site_id=$3) AND managed_signatures->>'inspection'='busy'", start, now, rule.SiteID).Scan(&count)
	case "flood_capacity_exceeded":
		// The local limiter's bucket map is pinned: new clients are admitted
		// unmetered during an IP-spray, so flood enforcement is degraded, not
		// enforced — exactly when an operator needs a push alert.
		err = tx.QueryRow(ctx, "SELECT count(*) FROM access_logs WHERE at>$1 AND at<=$2 AND ($3=0 OR site_id=$3) AND signals @> '[\"flood_capacity_exceeded\"]'::jsonb", start, now, rule.SiteID).Scan(&count)
	case "management_plaintext_non_loopback":
		// Config-derived, not traffic-derived: this replica serves the
		// management listener over plaintext HTTP on a non-loopback bind, so
		// credentials, session tokens and MCP keys cross the network in the
		// clear. Centralized alerting makes the startup warning durable.
		if a.cfg.ManagementPlaintextNonLoopback() {
			count = 1
			details = "management listener serves plaintext HTTP on a non-loopback bind (" + a.cfg.ManagementAddr + "); administrator credentials, session tokens and MCP agent keys cross the network unencrypted"
		}
	case "feed_stale":
		// Failed feed syncs retry silently every 12 hours; staleness is
		// day-scale, not traffic-window scale. A feed counts when it carries a
		// sync error or its last success is older than the threshold hours.
		count, details, err = staleFeedMatches(ctx, tx, rule.Threshold)
	default:
		return true, invalid("unsupported alert trigger")
	}
	if err != nil {
		return false, err
	}
	threshold := int64(rule.Threshold)
	if rule.Kind == "certificate_expiry" || rule.Kind == "feed_stale" || rule.Kind == "management_plaintext_non_loopback" {
		threshold = 1
	}
	if count < threshold {
		return true, tx.Commit(ctx)
	}
	event := alertEvent{RuleID: id, At: now, Kind: rule.Kind, SiteID: rule.SiteID, Title: rule.Name, Details: details, Count: count, WindowStart: start, WindowEnd: now}
	data, _ := json.Marshal(event)
	if err = tx.QueryRow(ctx, "INSERT INTO alerts(data) VALUES($1) RETURNING id", data).Scan(&event.ID); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO alert_deliveries(alert_id,channel_id) SELECT $1,id FROM notification_channels WHERE id=ANY($2) AND enabled", event.ID, rule.ChannelIDs); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE alert_rules SET last_emitted=now() WHERE id=$1", id); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// staleFeedMatches returns the rule feeds that failed their last sync or have
// not succeeded within thresholdHours, with one human-readable reason per feed
// naming the feed and why it counts as stale. Feeds that have not yet attempted
// their first sync (no error, no success) stay quiet to avoid new-feed noise.
func staleFeedMatches(ctx context.Context, tx pgx.Tx, thresholdHours int) (int64, string, error) {
	rows, e := tx.Query(ctx, "SELECT name,coalesce(error,''),last_success FROM rule_feeds WHERE error<>'' OR (last_success IS NOT NULL AND last_success<now()-make_interval(hours=>$1)) ORDER BY id", thresholdHours)
	if e != nil {
		return 0, "", e
	}
	defer rows.Close()
	var parts []string
	var count int64
	for rows.Next() {
		var name, syncError string
		var last *time.Time
		if e = rows.Scan(&name, &syncError, &last); e != nil {
			return 0, "", e
		}
		count++
		reason := "never synced"
		if last != nil {
			// Hours-accurate under a day: flooring hour-scale staleness to
			// "0 days ago" hides it from the operator reading the alert.
			elapsed := time.Since(*last)
			switch {
			case elapsed < time.Hour:
				reason = "last success less than an hour ago"
			case elapsed < 24*time.Hour:
				reason = fmt.Sprintf("last success %d hours ago", int(elapsed.Hours()))
			default:
				reason = fmt.Sprintf("last success %d days ago", int(elapsed.Hours()/24))
			}
		}
		if syncError != "" {
			reason += " · " + syncError
		}
		parts = append(parts, fmt.Sprintf("%s: %s", name, reason))
	}
	if e = rows.Err(); e != nil {
		return 0, "", e
	}
	return count, strings.Join(parts, "; "), nil
}
func (a *App) NotificationWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 12*time.Second)
		found, err := a.deliverNotification(work)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("notification worker unavailable; delivery remains queued")
		}
		if found && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (a *App) deliverNotification(ctx context.Context) (bool, error) {
	var id, alertID, channelID int64
	var attempts int
	owner := a.replicaID + ":" + token()
	err := a.db.QueryRow(ctx, `UPDATE alert_deliveries d SET lease_until=now()+interval '30 seconds',lease_owner=$1,attempts=d.attempts+1
 WHERE d.id=(SELECT q.id FROM alert_deliveries q JOIN notification_channels c ON c.id=q.channel_id WHERE q.status='pending' AND q.next_attempt<=now() AND (q.lease_until IS NULL OR q.lease_until<now()) AND c.enabled ORDER BY q.next_attempt,q.id FOR UPDATE OF q SKIP LOCKED LIMIT 1)
 RETURNING d.id,d.alert_id,d.channel_id,d.attempts`, owner).Scan(&id, &alertID, &channelID, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var raw []byte
	if err = a.db.QueryRow(ctx, "SELECT data FROM alerts WHERE id=$1", alertID).Scan(&raw); err != nil {
		return true, err
	}
	var event alertEvent
	if err = json.Unmarshal(raw, &event); err != nil {
		return true, err
	}
	event.ID = alertID
	channel, config, sendErr := a.loadNotificationChannel(ctx, channelID)
	if sendErr == nil {
		sendErr = sendNotification(ctx, channel.Provider, config, event)
	}
	status, message := "sent", ""
	if sendErr != nil {
		status = "pending"
		message = "delivery failed; check destination credentials and connectivity"
		if attempts >= 5 {
			status = "failed"
		}
	}
	delay := 30 * (1 << min(attempts-1, 4))
	_, err = a.db.Exec(ctx, "UPDATE alert_deliveries SET status=$3,error=$4,next_attempt=now()+make_interval(secs=>$5),lease_until=NULL,lease_owner='' WHERE id=$1 AND lease_owner=$2", id, owner, status, message, delay)
	return true, err
}
