package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type notificationConfig struct {
	URL          string `json:"url"`
	Secret       string `json:"secret"`
	AllowPrivate bool   `json:"allow_private"`
}
type notificationChannel struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Enabled   bool   `json:"enabled"`
	Revision  int64  `json:"revision"`
	HasConfig bool   `json:"has_config"`
}
type channelInput struct {
	notificationChannel
	Config *notificationConfig `json:"config,omitempty"`
}
type alertRule struct {
	ID              int64   `json:"id"`
	Revision        int64   `json:"revision"`
	Name            string  `json:"name"`
	Enabled         bool    `json:"enabled"`
	Kind            string  `json:"kind"`
	SiteID          int64   `json:"site_id"`
	Threshold       int     `json:"threshold"`
	WindowMinutes   int     `json:"window_minutes"`
	CooldownMinutes int     `json:"cooldown_minutes"`
	ChannelIDs      []int64 `json:"channel_ids"`
}
type alertEvent struct {
	ID             int64      `json:"id"`
	RuleID         int64      `json:"rule_id"`
	At             time.Time  `json:"at"`
	Kind           string     `json:"kind"`
	SiteID         int64      `json:"site_id"`
	Title          string     `json:"title"`
	Count          int64      `json:"count"`
	WindowStart    time.Time  `json:"window_start"`
	WindowEnd      time.Time  `json:"window_end"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
	AcknowledgedBy string     `json:"acknowledged_by"`
}

func alertAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/notification-channels", a.wrap(true, a.listNotificationChannels))
	m.HandleFunc("POST /api/notification-channels", a.wrap(true, a.saveNotificationChannel))
	m.HandleFunc("PUT /api/notification-channels/{id}", a.wrap(true, a.saveNotificationChannel))
	m.HandleFunc("DELETE /api/notification-channels/{id}", a.wrap(true, a.deleteNotificationChannel))
	m.HandleFunc("POST /api/notification-channels/{id}/test", a.wrap(true, a.testNotificationChannel))
	m.HandleFunc("GET /api/alert-rules", a.wrap(true, a.listAlertRules))
	m.HandleFunc("POST /api/alert-rules", a.wrap(true, a.saveAlertRule))
	m.HandleFunc("PUT /api/alert-rules/{id}", a.wrap(true, a.saveAlertRule))
	m.HandleFunc("DELETE /api/alert-rules/{id}", a.wrap(true, a.deleteAlertRule))
	m.HandleFunc("GET /api/alerts/{id}", a.wrap(true, a.getAlert))
	m.HandleFunc("GET /api/alerts", a.wrap(true, a.listAlerts))
	m.HandleFunc("POST /api/alerts/{id}/acknowledge", a.wrap(true, a.acknowledgeAlert))
	m.HandleFunc("GET /api/alert-deliveries", a.wrap(true, a.listAlertDeliveries))
}
func (a *App) listNotificationChannels(w http.ResponseWriter, r *http.Request, _ identity) error {
	rows, err := a.db.Query(r.Context(), "SELECT id,name,provider,enabled,revision FROM notification_channels ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	result := []notificationChannel{}
	for rows.Next() {
		var c notificationChannel
		if err = rows.Scan(&c.ID, &c.Name, &c.Provider, &c.Enabled, &c.Revision); err != nil {
			return err
		}
		c.HasConfig = true
		result = append(result, c)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	respond(w, 200, result)
	return nil
}
func notificationProvider(p string) bool {
	switch p {
	case "webhook", "automation", "slack", "discord", "gotify", "ntfy", "apprise":
		return true
	}
	return false
}
func (a *App) saveNotificationChannel(w http.ResponseWriter, r *http.Request, who identity) error {
	var in channelInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 120 || !notificationProvider(in.Provider) {
		return invalid("provide a name and supported notification provider")
	}
	var id int64
	var err error
	if r.Method == "PUT" {
		id, err = pathID(r)
		if err != nil {
			return err
		}
	}
	err = a.alertChange(r.Context(), func(tx pgx.Tx) error {
		var cipher []byte
		keyID := ""
		revision := int64(0)
		previousProvider := ""
		if id != 0 {
			if e := tx.QueryRow(r.Context(), "SELECT config_cipher,key_id,revision,provider FROM notification_channels WHERE id=$1 FOR UPDATE", id).Scan(&cipher, &keyID, &revision, &previousProvider); e != nil {
				return e
			}
			if in.Revision != revision {
				return apiError{409, "destination changed; reload before saving"}
			}
		}
		if in.Config != nil {
			if e := validateNotificationConfig(*in.Config); e != nil {
				return e
			}
			if in.Provider == "automation" && len(in.Config.Secret) < 32 {
				return invalid("automation signing secret must contain at least 32 bytes")
			}
			raw, _ := json.Marshal(in.Config)
			cipher, err = seal(a.cfg.Key, a.cfg.KeyID+":notification-channel-v1", raw)
			if err != nil {
				return err
			}
			keyID = a.cfg.KeyID
		} else if id == 0 || previousProvider != in.Provider {
			return invalid("provide destination settings when creating or changing provider")
		}
		if id == 0 {
			var count int
			if e := tx.QueryRow(r.Context(), "SELECT count(*) FROM notification_channels").Scan(&count); e != nil {
				return e
			}
			if count >= 32 {
				return invalid("notification destination limit reached (32)")
			}
			if e := tx.QueryRow(r.Context(), "INSERT INTO notification_channels(name,provider,enabled,config_cipher,key_id) VALUES($1,$2,$3,$4,$5) RETURNING id", in.Name, in.Provider, in.Enabled, cipher, keyID).Scan(&id); e != nil {
				return e
			}
		} else if _, e := tx.Exec(r.Context(), "UPDATE notification_channels SET name=$2,provider=$3,enabled=$4,config_cipher=$5,key_id=$6,revision=revision+1 WHERE id=$1", id, in.Name, in.Provider, in.Enabled, cipher, keyID); e != nil {
			return e
		}
		return audit(r.Context(), tx, who.Username, "notification_channel.saved", itoa(id))
	})
	if err != nil {
		return err
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) deleteNotificationChannel(w http.ResponseWriter, r *http.Request, who identity) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	err = a.alertChange(r.Context(), func(tx pgx.Tx) error {
		var used bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM alert_rules WHERE $1=ANY(channel_ids))", id).Scan(&used); e != nil {
			return e
		}
		if used {
			return invalid("remove this destination from alert rules first")
		}
		tag, e := tx.Exec(r.Context(), "DELETE FROM notification_channels WHERE id=$1", id)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return apiError{404, "destination not found"}
		}
		return audit(r.Context(), tx, who.Username, "notification_channel.deleted", itoa(id))
	})
	if err != nil {
		return err
	}
	respond(w, 200, map[string]bool{"deleted": true})
	return nil
}
func (a *App) loadNotificationChannel(ctx context.Context, id int64) (notificationChannel, notificationConfig, error) {
	var c notificationChannel
	var config notificationConfig
	var cipher []byte
	var keyID string
	err := a.db.QueryRow(ctx, "SELECT id,name,provider,enabled,revision,config_cipher,key_id FROM notification_channels WHERE id=$1", id).Scan(&c.ID, &c.Name, &c.Provider, &c.Enabled, &c.Revision, &cipher, &keyID)
	if err != nil {
		return c, config, err
	}
	if keyID != a.cfg.KeyID {
		return c, config, invalid("notification encryption key unavailable")
	}
	raw, err := open(a.cfg.Key, keyID+":notification-channel-v1", cipher)
	if err != nil {
		return c, config, err
	}
	defer clear(raw)
	err = json.Unmarshal(raw, &config)
	return c, config, err
}
func (a *App) testNotificationChannel(w http.ResponseWriter, r *http.Request, who identity) error {
	if a.notificationTests != nil {
		select {
		case a.notificationTests <- struct{}{}:
			defer func() { <-a.notificationTests }()
		default:
			return apiError{429, "notification test busy; retry shortly"}
		}
	}

	id, err := pathID(r)
	if err != nil {
		return err
	}
	c, config, err := a.loadNotificationChannel(r.Context(), id)
	if err != nil {
		return err
	}
	// A test is an explicit external send, audited before its network side effect.
	if _, err = a.db.Exec(r.Context(), "INSERT INTO audit_events(actor,action,resource) VALUES($1,'notification_channel.tested',$2)", who.Username, itoa(id)); err != nil {
		return err
	}
	now := time.Now().UTC()
	event := alertEvent{At: now, Kind: "test", Title: "Aegis notification test", WindowStart: now, WindowEnd: now}
	if err = sendNotification(r.Context(), c.Provider, config, event); err != nil {
		return apiError{502, "notification delivery failed; check destination, credentials and network access"}
	}
	respond(w, 200, map[string]bool{"delivered": true})
	return nil
}
func normalizeAlertRule(in *alertRule) error {
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 120 || in.SiteID < 0 || in.Threshold < 1 || in.Threshold > 1000000 || in.WindowMinutes < 1 || in.WindowMinutes > 60 || in.CooldownMinutes < 1 || in.CooldownMinutes > 10080 || len(in.ChannelIDs) > 32 {
		return invalid("provide name, threshold 1–1000000, window 1–60 minutes and cooldown 1–10080 minutes")
	}
	switch in.Kind {
	case "blocked_volume", "upstream_errors", "certificate_expiry", "acme_failure":
	default:
		return invalid("unsupported alert trigger")
	}
	if in.Kind == "certificate_expiry" && in.Threshold > 90 {
		return invalid("certificate expiry threshold is days (1–90)")
	}
	seen := map[int64]bool{}
	for _, id := range in.ChannelIDs {
		if id <= 0 || seen[id] {
			return invalid("destination IDs must be positive and unique")
		}
		seen[id] = true
	}
	if in.ChannelIDs == nil {
		in.ChannelIDs = []int64{}
	}
	return nil
}
func (a *App) listAlertRules(w http.ResponseWriter, r *http.Request, _ identity) error {
	rows, err := a.db.Query(r.Context(), "SELECT id,revision,spec FROM alert_rules ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	result := []alertRule{}
	for rows.Next() {
		var rule alertRule
		var raw []byte
		var id, rev int64
		if err = rows.Scan(&id, &rev, &raw); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &rule); err != nil {
			return err
		}
		rule.ID = id
		rule.Revision = rev
		result = append(result, rule)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	respond(w, 200, result)
	return nil
}
func (a *App) saveAlertRule(w http.ResponseWriter, r *http.Request, who identity) error {
	var in alertRule
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := normalizeAlertRule(&in); err != nil {
		return err
	}
	var id int64
	var err error
	if r.Method == "PUT" {
		id, err = pathID(r)
		if err != nil {
			return err
		}
	}
	err = a.alertChange(r.Context(), func(tx pgx.Tx) error {
		if in.SiteID != 0 {
			var exists bool
			if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1)", in.SiteID).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				return invalid("application not found")
			}
		}
		var channels int
		if e := tx.QueryRow(r.Context(), "SELECT count(*) FROM notification_channels WHERE id=ANY($1)", in.ChannelIDs).Scan(&channels); e != nil {
			return e
		}
		if channels != len(in.ChannelIDs) {
			return invalid("destination not found")
		}
		raw, _ := json.Marshal(in)
		if id == 0 {
			var count int
			if e := tx.QueryRow(r.Context(), "SELECT count(*) FROM alert_rules").Scan(&count); e != nil {
				return e
			}
			if count >= 64 {
				return invalid("alert rule limit reached (64)")
			}
			if e := tx.QueryRow(r.Context(), "INSERT INTO alert_rules(spec,channel_ids) VALUES($1,$2) RETURNING id", raw, in.ChannelIDs).Scan(&id); e != nil {
				return e
			}
		} else {
			tag, e := tx.Exec(r.Context(), "UPDATE alert_rules SET spec=$2,channel_ids=$3,revision=revision+1,created_at=now(),last_emitted=NULL,next_eval=now() WHERE id=$1 AND revision=$4", id, raw, in.ChannelIDs, in.Revision)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return apiError{409, "alert rule changed; reload before saving"}
			}
		}
		return audit(r.Context(), tx, who.Username, "alert_rule.saved", itoa(id))
	})
	if err != nil {
		return err
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) deleteAlertRule(w http.ResponseWriter, r *http.Request, who identity) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	err = a.alertChange(r.Context(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(r.Context(), "DELETE FROM alert_rules WHERE id=$1", id)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return apiError{404, "alert rule not found"}
		}
		return audit(r.Context(), tx, who.Username, "alert_rule.deleted", itoa(id))
	})
	if err != nil {
		return err
	}
	respond(w, 200, map[string]bool{"deleted": true})
	return nil
}
func (a *App) listAlerts(w http.ResponseWriter, r *http.Request, _ identity) error {
	after := int64(0)
	if raw := r.URL.Query().Get("after_id"); raw != "" {
		var err error
		if raw != "0" {
			after, err = parseAlertCursor(raw)
		}
		if err != nil {
			return err
		}
	}
	rows, err := a.db.Query(r.Context(), "SELECT id,data,acknowledged_at,acknowledged_by FROM alerts WHERE id>$1 AND ($2=false OR acknowledged_at IS NULL) ORDER BY CASE WHEN $3 THEN id END ASC,id DESC LIMIT 200", after, r.URL.Query().Get("unacknowledged") == "true", r.URL.Query().Has("after_id"))
	if err != nil {
		return err
	}
	defer rows.Close()
	result := []alertEvent{}
	for rows.Next() {
		var event alertEvent
		var raw []byte
		var id int64
		var ack *time.Time
		var by string
		if err = rows.Scan(&id, &raw, &ack, &by); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &event); err != nil {
			return err
		}
		event.ID = id
		event.AcknowledgedAt = ack
		event.AcknowledgedBy = by
		result = append(result, event)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	respond(w, 200, result)
	return nil
}
func (a *App) acknowledgeAlert(w http.ResponseWriter, r *http.Request, who identity) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	err = a.alertChange(r.Context(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(r.Context(), "UPDATE alerts SET acknowledged_at=coalesce(acknowledged_at,now()),acknowledged_by=CASE WHEN acknowledged_at IS NULL THEN $2 ELSE acknowledged_by END WHERE id=$1", id, who.Username)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return apiError{404, "alert not found"}
		}
		return audit(r.Context(), tx, who.Username, "alert.acknowledged", itoa(id))
	})
	if err != nil {
		return err
	}
	respond(w, 200, map[string]bool{"acknowledged": true})
	return nil
}
func (a *App) listAlertDeliveries(w http.ResponseWriter, r *http.Request, _ identity) error {
	rows, err := a.db.Query(r.Context(), "SELECT id,alert_id,channel_id,status,attempts,error,next_attempt FROM alert_deliveries ORDER BY id DESC LIMIT 200")
	if err != nil {
		return err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var id, alert, channel int64
		var status, message string
		var attempts int
		var next time.Time
		if err = rows.Scan(&id, &alert, &channel, &status, &attempts, &message, &next); err != nil {
			return err
		}
		result = append(result, map[string]any{"id": id, "alert_id": alert, "channel_id": channel, "status": status, "attempts": attempts, "error": message, "next_attempt": next})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	respond(w, 200, result)
	return nil
}

func (a *App) getAlert(w http.ResponseWriter, r *http.Request, _ identity) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var event alertEvent
	var raw []byte
	var ack *time.Time
	var by string
	err = a.db.QueryRow(r.Context(), "SELECT data,acknowledged_at,acknowledged_by FROM alerts WHERE id=$1", id).Scan(&raw, &ack, &by)
	if err == pgx.ErrNoRows {
		return apiError{404, "alert not found"}
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &event); err != nil {
		return err
	}
	event.ID = id
	event.AcknowledgedAt = ack
	event.AcknowledgedBy = by
	respond(w, 200, event)
	return nil
}

// Notification administration is independent of live WAF configuration. Reading
// or acknowledging an alert must not invalidate an agent's simulation receipt.
func (a *App) alertChange(ctx context.Context, fn func(pgx.Tx) error) error {
	if ctx.Value(simulationTransactionKey{}) != nil {
		return invalid("notification administration is not a protection simulation")
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x4145474953414c52)); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
