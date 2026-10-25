package app

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed rule-schema.json
var ruleSchema []byte

type ruleRecord struct {
	ID        int64      `json:"id"`
	Spec      RuleSpec   `json:"spec"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at"`
	Revision  int64      `json:"revision"`
}
type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readRule(ctx context.Context, q rowQuerier, id int64, lock bool) (ruleRecord, error) {
	var record ruleRecord
	var data []byte
	query := "SELECT id,spec,enabled,expires_at,revision FROM rules WHERE id=$1"
	if lock {
		query += " FOR UPDATE"
	}
	e := q.QueryRow(ctx, query, id).Scan(&record.ID, &data, &record.Enabled, &record.ExpiresAt, &record.Revision)
	if errors.Is(e, pgx.ErrNoRows) {
		return record, apiError{404, "rule not found"}
	}
	if e != nil {
		return record, e
	}
	e = json.Unmarshal(data, &record.Spec)
	return record, e
}
func ruleHistory(ctx context.Context, tx pgx.Tx, id int64, actor string) error {
	_, e := tx.Exec(ctx, "INSERT INTO rule_revisions(rule_id,spec,enabled,expires_at,actor) SELECT id,spec,enabled,expires_at,$2 FROM rules WHERE id=$1", id, actor)
	return e
}
func checkRuleSite(ctx context.Context, tx pgx.Tx, site, id int64) error {
	var exists bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1)", site).Scan(&exists); e != nil {
		return e
	}
	if !exists {
		return invalid("scope.site_id does not identify an existing site")
	}
	var count, total int
	if e := tx.QueryRow(ctx, "SELECT count(*) FILTER(WHERE site_id=$1 AND id<>$2),count(*) FILTER(WHERE id<>$2) FROM rules", site, id).Scan(&count, &total); e != nil {
		return e
	}
	if count >= maxRulesPerSite || total >= maxRulesTotal {
		return apiError{409, "rule capacity reached (100 per site, 1000 total)"}
	}
	return nil
}
func (a *App) listRules(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, `SELECT id,site_id,spec,enabled,expires_at,revision,created_at,updated_at,CASE WHEN NOT enabled THEN CASE WHEN expires_at IS NULL THEN 'draft' ELSE 'disabled' END WHEN expires_at<=now() THEN 'expired' ELSE spec->>'action' END AS status FROM rules ORDER BY id`)
}
func (a *App) saveRule(w http.ResponseWriter, r *http.Request, i identity) error {
	var spec RuleSpec
	if e := decode(w, r, &spec); e != nil {
		return e
	}
	if _, e := compileRule(spec); e != nil {
		return invalid(e.Error())
	}
	var id int64
	var e error
	if r.Method == "PUT" {
		id, e = resourceID(r)
		if e != nil {
			return e
		}
	}
	data, _ := json.Marshal(spec)
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		if e := checkRuleSite(ctx, tx, spec.Scope.SiteID, id); e != nil {
			return e
		}
		if len(spec.EvidenceIDs) > 0 {
			var n int
			if e := tx.QueryRow(ctx, "SELECT count(*) FROM traffic_evidence WHERE site_id=$1 AND id=ANY($2) AND expires_at>now()", spec.Scope.SiteID, spec.EvidenceIDs).Scan(&n); e != nil {
				return e
			}
			seen := map[string]bool{}
			for _, id := range spec.EvidenceIDs {
				seen[id] = true
			}
			if n != len(seen) {
				return invalid("one or more evidence IDs are unavailable for this site")
			}
		}
		action := "rule.created"
		if id == 0 {
			if e := tx.QueryRow(ctx, "INSERT INTO rules(site_id,spec) VALUES($1,$2) RETURNING id", spec.Scope.SiteID, data).Scan(&id); e != nil {
				return e
			}
		} else {
			if _, e := readRule(ctx, tx, id, true); e != nil {
				return e
			}
			if e := ruleHistory(ctx, tx, id, i.Username); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, "UPDATE rules SET site_id=$2,spec=$3,enabled=false,expires_at=NULL,revision=revision+1,updated_at=now() WHERE id=$1", id, spec.Scope.SiteID, data); e != nil {
				return e
			}
			action = "rule.updated"
		}
		return audit(ctx, tx, i.Username, action, strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) activateRule(w http.ResponseWriter, r *http.Request, i identity) error {
	var body struct {
		Action     string `json:"action"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		record, e := readRule(ctx, tx, id, true)
		if e != nil {
			return e
		}
		record.Spec.Action = body.Action
		record.Spec.TTLSeconds = body.TTLSeconds
		if _, e = compileRule(record.Spec); e != nil {
			return invalid(e.Error())
		}
		if e = ruleHistory(ctx, tx, id, i.Username); e != nil {
			return e
		}
		data, _ := json.Marshal(record.Spec)
		if _, e = tx.Exec(ctx, "UPDATE rules SET spec=$2,enabled=true,expires_at=now()+$3::integer*interval '1 second',revision=revision+1,updated_at=now() WHERE id=$1", id, data, body.TTLSeconds); e != nil {
			return e
		}
		return audit(ctx, tx, i.Username, "rule.activated."+body.Action, strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"activated": true})
	return nil
}
func (a *App) disableRule(w http.ResponseWriter, r *http.Request, i identity) error {
	var body struct{}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		if _, e := readRule(ctx, tx, id, true); e != nil {
			return e
		}
		if e := ruleHistory(ctx, tx, id, i.Username); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE rules SET enabled=false,revision=revision+1,updated_at=now() WHERE id=$1", id); e != nil {
			return e
		}
		return audit(ctx, tx, i.Username, "rule.disabled", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"disabled": true})
	return nil
}
func (a *App) rollbackRule(w http.ResponseWriter, r *http.Request, i identity) error {
	var body struct{}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		if _, e := readRule(ctx, tx, id, true); e != nil {
			return e
		}
		var data []byte
		var enabled bool
		var expires *time.Time
		e := tx.QueryRow(ctx, "SELECT spec,enabled,expires_at FROM rule_revisions WHERE rule_id=$1 ORDER BY id DESC LIMIT 1", id).Scan(&data, &enabled, &expires)
		if errors.Is(e, pgx.ErrNoRows) {
			return apiError{409, "no previous rule revision exists"}
		}
		if e != nil {
			return e
		}
		var spec RuleSpec
		if e = json.Unmarshal(data, &spec); e != nil {
			return e
		}
		if _, e = compileRule(spec); e != nil {
			return invalid("previous revision is not valid")
		}
		if e = checkRuleSite(ctx, tx, spec.Scope.SiteID, id); e != nil {
			return e
		}
		enabled = enabled && expires != nil && time.Now().Before(*expires)
		if e = ruleHistory(ctx, tx, id, i.Username); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE rules SET site_id=$2,spec=$3,enabled=$4,expires_at=$5,revision=revision+1,updated_at=now() WHERE id=$1", id, spec.Scope.SiteID, data, enabled, expires); e != nil {
			return e
		}
		return audit(ctx, tx, i.Username, "rule.rolled_back", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"rolled_back": true})
	return nil
}
func (a *App) deleteRule(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(r.Context(), "DELETE FROM rules WHERE id=$1", id)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return apiError{404, "rule not found"}
		}
		return audit(r.Context(), tx, i.Username, "rule.deleted", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"deleted": true})
	return nil
}
func (a *App) listRuleHistory(w http.ResponseWriter, r *http.Request, _ identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	var data []byte
	e = a.db.QueryRow(r.Context(), "SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM (SELECT id,spec,enabled,expires_at,at,actor FROM rule_revisions WHERE rule_id=$1 ORDER BY id DESC LIMIT 20) x", id).Scan(&data)
	if e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(data))
	return nil
}
func (a *App) listTrafficSettings(w http.ResponseWriter, r *http.Request, _ identity) error {
	return a.list(w, r, "SELECT site_id,settings FROM traffic_settings ORDER BY site_id")
}
func (a *App) saveTrafficSettings(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	var settings TrafficSettings
	if e = decode(w, r, &settings); e != nil {
		return e
	}
	if e = validateTrafficSettings(settings); e != nil {
		return invalid(e.Error())
	}
	data, _ := json.Marshal(settings)
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1)", id).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return apiError{404, "site not found"}
		}
		if _, e := tx.Exec(r.Context(), "INSERT INTO traffic_settings(site_id,settings) VALUES($1,$2) ON CONFLICT(site_id) DO UPDATE SET settings=excluded.settings", id, data); e != nil {
			return e
		}
		return audit(r.Context(), tx, i.Username, "traffic.settings.saved", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, settings)
	return nil
}
func (a *App) listTrafficEvents(w http.ResponseWriter, r *http.Request, _ identity) error {
	var site int64
	if raw := r.URL.Query().Get("site_id"); raw != "" {
		var e error
		site, e = strconv.ParseInt(raw, 10, 64)
		if e != nil || site < 1 {
			return invalid("invalid site_id")
		}
	}
	var data []byte
	e := a.db.QueryRow(r.Context(), "SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM (SELECT id,at,site_id,expires_at,data FROM traffic_evidence WHERE expires_at>now() AND ($1::bigint=0 OR site_id=$1) ORDER BY at DESC LIMIT 100) x", site).Scan(&data)
	if e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(data))
	return nil
}
func (a *App) replayRule(w http.ResponseWriter, r *http.Request, _ identity) error {
	var body struct {
		Rule     RuleSpec `json:"rule"`
		EventIDs []string `json:"event_ids"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	compiled, e := compileRule(body.Rule)
	if e != nil {
		return invalid(e.Error())
	}
	if len(body.EventIDs) < 1 || len(body.EventIDs) > 200 {
		return invalid("select 1–200 event IDs")
	}
	seen := map[string]bool{}
	for _, id := range body.EventIDs {
		if len(id) < 1 || len(id) > 128 {
			return invalid("invalid event ID")
		}
		seen[id] = true
	}
	rows, e := a.db.Query(r.Context(), "SELECT id,data FROM traffic_evidence WHERE site_id=$1 AND id=ANY($2) AND expires_at>now() ORDER BY at", body.Rule.Scope.SiteID, body.EventIDs)
	if e != nil {
		return e
	}
	defer rows.Close()
	type result struct {
		EventID string `json:"event_id"`
		Result  string `json:"result"`
	}
	results := []result{}
	counts := map[string]int{"matched": 0, "not_matched": 0, "unknown": 0}
	for rows.Next() {
		var id string
		var data []byte
		if e = rows.Scan(&id, &data); e != nil {
			return e
		}
		var evidence TrafficEvidence
		outcome := "unknown"
		if json.Unmarshal(data, &evidence) == nil && evidence.SchemaVersion == 1 {
			outcome = compiled.evaluate(func(field, key string) Fact { return evidenceFact(evidence, field, key) })
		}
		counts[outcome]++
		results = append(results, result{id, outcome})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if len(results) != len(seen) {
		return invalid("one or more events are expired, unavailable, or outside this site")
	}
	respond(w, 200, map[string]any{"counts": counts, "results": results, "live_requests_sent": 0})
	return nil
}

func (a *App) loadPolicies(ctx context.Context, tx pgx.Tx, next *snapshot) error {
	next.rules = map[int64][]compiledRule{}
	next.capture = map[int64]*capturePolicy{}
	rows, e := tx.Query(ctx, "SELECT id,site_id,spec,expires_at FROM rules WHERE enabled AND expires_at>now() ORDER BY id LIMIT 1001")
	if e != nil {
		return e
	}
	total := 0
	for rows.Next() {
		var id, site int64
		var data []byte
		var expires time.Time
		if e = rows.Scan(&id, &site, &data, &expires); e != nil {
			rows.Close()
			return e
		}
		var spec RuleSpec
		if e = json.Unmarshal(data, &spec); e != nil {
			rows.Close()
			return e
		}
		compiled, e := compileRule(spec)
		if e != nil || spec.Scope.SiteID != site {
			rows.Close()
			return errors.New("invalid stored rule")
		}
		compiled.ID = id
		compiled.Expires = expires
		next.rules[site] = append(next.rules[site], compiled)
		total++
		if total > maxRulesTotal || len(next.rules[site]) > maxRulesPerSite {
			rows.Close()
			return errors.New("stored rule capacity exceeded")
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = tx.Query(ctx, "SELECT site_id,settings FROM traffic_settings")
	if e != nil {
		return e
	}
	old := a.active.Load()
	for rows.Next() {
		var site int64
		var data []byte
		if e = rows.Scan(&site, &data); e != nil {
			rows.Close()
			return e
		}
		var settings TrafficSettings
		if e = json.Unmarshal(data, &settings); e != nil {
			rows.Close()
			return e
		}
		if e = validateTrafficSettings(settings); e != nil {
			rows.Close()
			return e
		}
		budget := &captureBudget{}
		if old != nil && old.capture[site] != nil {
			budget = old.capture[site].budget
		}
		next.capture[site] = &capturePolicy{Settings: settings, budget: budget, redactors: evidenceRedactors(settings)}
	}
	e = rows.Err()
	rows.Close()
	return e
}
func ruleAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/rules", a.wrap(true, a.listRules))
	m.HandleFunc("POST /api/rules", a.wrap(true, a.saveRule))
	m.HandleFunc("PUT /api/rules/{id}", a.wrap(true, a.saveRule))
	m.HandleFunc("DELETE /api/rules/{id}", a.wrap(true, a.deleteRule))
	m.HandleFunc("POST /api/rules/{id}/activate", a.wrap(true, a.activateRule))
	m.HandleFunc("POST /api/rules/{id}/disable", a.wrap(true, a.disableRule))
	m.HandleFunc("POST /api/rules/{id}/rollback", a.wrap(true, a.rollbackRule))
	m.HandleFunc("GET /api/rules/{id}/history", a.wrap(true, a.listRuleHistory))
	m.HandleFunc("POST /api/rules/replay", a.wrap(true, a.replayRule))
	m.HandleFunc("GET /api/rules/schema", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		respond(w, 200, json.RawMessage(ruleSchema))
		return nil
	}))
	m.HandleFunc("GET /api/traffic-settings", a.wrap(true, a.listTrafficSettings))
	m.HandleFunc("PUT /api/traffic-settings/{id}", a.wrap(true, a.saveTrafficSettings))
	m.HandleFunc("GET /api/traffic-events", a.wrap(true, a.listTrafficEvents))
}
