package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"mime"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Capture is disabled by default. Field values require a per-site allowlist.
type TrafficSettings struct {
	Enabled        bool     `json:"enabled"`
	CapturePath    bool     `json:"capture_path"`
	QueryKeys      []string `json:"query_keys"`
	HeaderKeys     []string `json:"header_keys"`
	JSONBodyKeys   []string `json:"json_body_keys"`
	SampleEvery    int      `json:"sample_every"`
	MaxPerMinute   int      `json:"max_per_minute"`
	RetentionHours int      `json:"retention_hours"`
}
type captureBudget struct {
	mu          sync.Mutex
	window      int64
	seen, count int
}
type capturePolicy struct {
	Settings TrafficSettings
	budget   *captureBudget
}
type TrafficEvidence struct {
	SchemaVersion int             `json:"schema_version"`
	Facts         map[string]Fact `json:"facts"`
	ContentType   string          `json:"content_type,omitempty"`
	BodyLength    int64           `json:"body_length"`
	Results       []RuleResult    `json:"rule_results"`
}
type evidenceEvent struct {
	id          string
	at, expires time.Time
	site        int64
	data        []byte
}

func defaultTrafficSettings() TrafficSettings {
	return TrafficSettings{QueryKeys: []string{}, HeaderKeys: []string{}, JSONBodyKeys: []string{}, SampleEvery: 1, MaxPerMinute: 60, RetentionHours: 24}
}
func validateTrafficSettings(s TrafficSettings) error {
	if s.QueryKeys == nil || s.HeaderKeys == nil || s.JSONBodyKeys == nil {
		return errors.New("capture allowlists must be arrays; use [] for empty lists")
	}
	if s.SampleEvery < 1 || s.SampleEvery > 10000 {
		return errors.New("sample_every must be 1–10000")
	}
	if s.MaxPerMinute < 1 || s.MaxPerMinute > 600 {
		return errors.New("max_per_minute must be 1–600 per replica")
	}
	if s.RetentionHours < 1 || s.RetentionHours > 168 {
		return errors.New("retention_hours must be 1–168")
	}
	for _, set := range []struct {
		field string
		keys  []string
	}{{"query", s.QueryKeys}, {"header", s.HeaderKeys}, {"json_body", s.JSONBodyKeys}} {
		if len(set.keys) > 4 {
			return errors.New("at most four keys per field type may be captured")
		}
		seen := map[string]bool{}
		for _, key := range set.keys {
			if e := validSelector(set.field, key); e != nil {
				return e
			}
			id := factKey(set.field, key)
			if seen[id] {
				return errors.New("duplicate capture key")
			}
			seen[id] = true
		}
	}
	return nil
}
func (p *capturePolicy) permit(now time.Time) bool {
	if p == nil || !p.Settings.Enabled {
		return false
	}
	b := p.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	minute := now.Unix() / 60
	if b.window != minute {
		b.window = minute
		b.seen = 0
		b.count = 0
	}
	b.seen++
	if b.seen%p.Settings.SampleEvery != 0 || b.count >= p.Settings.MaxPerMinute {
		return false
	}
	b.count++
	return true
}

var valueSecrets = regexp.MustCompile(`(?i)(?:bearer|basic)[ \t]+[a-z0-9._~+/=-]+|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|(?:AKIA|ASIA)[A-Z0-9]{16}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}`)
var opaqueSegment = regexp.MustCompile(`^[A-Za-z0-9_=-]{24,}$|^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$|^[0-9]{4,}$`)
var pathEmail = regexp.MustCompile(`^[^ /@]+@[^ /@]+\.[^ /@]+$`)

func redactPath(path string) (string, bool) {
	parts := strings.Split(path, "/")
	redacted := false
	previousSensitive := false
	for i, part := range parts {
		if previousSensitive || opaqueSegment.MatchString(part) || pathEmail.MatchString(part) {
			parts[i] = "[redacted]"
			redacted = true
		}
		previousSensitive = sensitiveKey(part) || strings.EqualFold(part, "reset") || strings.EqualFold(part, "verify") || strings.EqualFold(part, "verification")
	}
	joined := strings.Join(parts, "/")
	if len(joined) > 1024 {
		joined = truncateUTF8(joined, 1024)
		redacted = true
	}
	return joined, redacted
}
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}
func capturedFact(field string, f Fact) Fact {
	if f.State != "present" {
		return f
	}
	out := Fact{State: "present", Values: []string{}}
	if len(f.Values) > 2 {
		out.State = "truncated"
	}
	for i, v := range f.Values {
		if i == 2 {
			break
		}
		clean := valueSecrets.ReplaceAllString(v, "[redacted]")
		if clean != v {
			out.State = "redacted"
		}
		if field == "path" {
			var redacted bool
			clean, redacted = redactPath(clean)
			if redacted {
				out.State = "redacted"
			}
		}
		if len(clean) > 192 {
			clean = truncateUTF8(clean, 192)
			if out.State != "redacted" {
				out.State = "truncated"
			}
		}
		out.Values = append(out.Values, clean)
	}
	return out
}
func (p *capturePolicy) capture(f *requestFacts, results []RuleResult, now time.Time) *evidenceEvent {
	if !p.permit(now) {
		return nil
	}
	return p.captureAllowed(f, results, now)
}
func (p *capturePolicy) captureAllowed(f *requestFacts, results []RuleResult, now time.Time) *evidenceEvent {
	s := p.Settings
	e := TrafficEvidence{SchemaVersion: 1, Facts: map[string]Fact{}, Results: results, BodyLength: f.request.ContentLength}
	e.ContentType, _, _ = mime.ParseMediaType(f.request.Header.Get("Content-Type"))
	if len(e.ContentType) > 128 {
		e.ContentType = "[truncated]"
	}
	for _, field := range []string{"method", "client_ip"} {
		e.Facts[factKey(field, "")] = capturedFact(field, f.get(field, ""))
	}
	if s.CapturePath {
		e.Facts[factKey("path", "")] = capturedFact("path", f.get("path", ""))
	}
	for _, set := range []struct {
		field string
		keys  []string
	}{{"query", s.QueryKeys}, {"header", s.HeaderKeys}, {"json_body", s.JSONBodyKeys}} {
		for _, key := range set.keys {
			e.Facts[factKey(set.field, key)] = capturedFact(set.field, f.get(set.field, key))
		}
	}
	data, err := json.Marshal(e)
	if err != nil || len(data) > 16384 {
		return nil
	}
	return &evidenceEvent{id: token(), at: now, expires: now.Add(time.Duration(s.RetentionHours) * time.Hour), site: 0, data: data}
}
func evidenceFact(e TrafficEvidence, field, key string) Fact {
	if v, ok := e.Facts[factKey(field, key)]; ok {
		return v
	}
	return Fact{State: "unavailable"}
}

// Lock existing parent sites for this short batch so deletion cannot invalidate
// evidence inserts. Requests from a recently deleted cached route still get
// metadata access logs, but their content samples are discarded.
func (a *App) storeAccessBatch(ctx context.Context, batch []accessEvent) error {
	for n := range batch {
		batch[n].enrich()
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	sites := []int64{}
	seen := map[int64]bool{}
	for _, event := range batch {
		if event.evidence != nil && !seen[event.site] {
			seen[event.site] = true
			sites = append(sites, event.site)
		}
	}
	existing := map[int64]bool{}
	if len(sites) > 0 {
		rows, e := tx.Query(ctx, "SELECT id FROM sites WHERE id=ANY($1) ORDER BY id FOR KEY SHARE", sites)
		if e != nil {
			return e
		}
		for rows.Next() {
			var id int64
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			existing[id] = true
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	items := make([][]any, len(batch))
	evidenceRows := [][]any{}
	for i, event := range batch {
		results := event.results
		if results == nil {
			results = []RuleResult{}
		}
		resultJSON, _ := json.Marshal(results)
		id := ""
		if event.evidence != nil && existing[event.site] {
			ev := event.evidence
			id = ev.id
			evidenceRows = append(evidenceRows, []any{ev.id, ev.at, ev.site, ev.expires, ev.data})
		}
		signalJSON, _ := json.Marshal(event.signals)
		if event.signals == nil {
			signalJSON = []byte("[]")
		}
		exemptJSON, _ := json.Marshal(event.exemptions)
		if event.exemptions == nil {
			exemptJSON = []byte("[]")
		}
		items[i] = []any{event.at, event.site, event.method, event.status, event.duration, event.peer, resultJSON, id, event.country, event.blocked, signalJSON, exemptJSON, event.policyID, event.policyRevision, event.policyName}
	}
	if _, e = tx.CopyFrom(ctx, pgx.Identifier{"access_logs"}, []string{"at", "site_id", "method", "status", "duration_ms", "peer", "rule_results", "event_id", "country", "blocked", "signals", "protection_exemptions", "policy_id", "policy_revision", "policy_name"}, pgx.CopyFromRows(items)); e != nil {
		return e
	}
	if len(evidenceRows) > 0 {
		if _, e = tx.CopyFrom(ctx, pgx.Identifier{"traffic_evidence"}, []string{"id", "at", "site_id", "expires_at", "data"}, pgx.CopyFromRows(evidenceRows)); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
