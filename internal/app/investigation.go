package app

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Investigation history: filtered, cursor-paginated reads over access_logs and
// audit_events. Every path is bounded — a capped page size, a keyset cursor
// that cannot skip or repeat rows, and an export whose window must fit an
// explicit row cap (over-cap windows are rejected, never silently truncated).
// Query parameters are validated strictly: an unrecognized or malformed filter
// fails with 400 instead of silently returning the unfiltered view.

const (
	accessPageSizeMax      = 200
	auditPageSizeMax       = 200
	accessExportRowCap     = 10000
	accessFilterTextMax    = 512
	investigationCursorMax = 256
	peerShapePattern       = `^[0-9A-Fa-f:.]+$`
)

// accessLogQuery is the validated filter set shared by the listing and export
// endpoints. The zero value means "no filters".
type accessLogQuery struct {
	from, to     time.Time
	siteID       int64
	clientPrefix netip.Prefix
	blocked      *bool
	status       int
	ruleID       int64
	requestID    string
	host         string
	policyID     int64
	pathClass    string
}

// parseTimestamp reads one RFC3339 timestamp parameter.
func parseTimestamp(name, value string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339, value)
	if e != nil {
		return time.Time{}, invalid(name + " must be an RFC3339 timestamp")
	}
	return t, nil
}

// parseAccessLogQuery validates every recognized query parameter. Unknown
// parameters are rejected so a mistyped filter cannot silently widen the view.
func parseAccessLogQuery(r *http.Request) (accessLogQuery, error) {
	var q accessLogQuery
	query := r.URL.Query()
	for name := range query {
		switch name {
		case "from", "to", "site_id", "client_ip", "blocked", "status", "rule_id", "request_id", "host", "policy_id", "path_class", "limit", "cursor", "format":
		default:
			return q, invalid("unknown filter " + name)
		}
	}
	if v := query.Get("from"); v != "" {
		t, e := parseTimestamp("from", v)
		if e != nil {
			return q, e
		}
		q.from = t
	}
	if v := query.Get("to"); v != "" {
		t, e := parseTimestamp("to", v)
		if e != nil {
			return q, e
		}
		q.to = t
	}
	if !q.from.IsZero() && !q.to.IsZero() && q.to.Before(q.from) {
		return q, invalid("to must not be before from")
	}
	if v := query.Get("site_id"); v != "" {
		id, e := strconv.ParseInt(v, 10, 64)
		if e != nil || id < 1 {
			return q, invalid("site_id must be a positive integer")
		}
		q.siteID = id
	}
	if v := query.Get("client_ip"); v != "" {
		if len(v) > accessFilterTextMax {
			return q, invalid("client_ip is too long")
		}
		prefix, e := parseClientFilter(v)
		if e != nil {
			return q, e
		}
		q.clientPrefix = prefix
	}
	if v := query.Get("blocked"); v != "" {
		if v != "true" && v != "false" {
			return q, invalid("blocked must be true or false")
		}
		blocked := v == "true"
		q.blocked = &blocked
	}
	if v := query.Get("status"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 100 || n > 599 {
			return q, invalid("status must be an HTTP status between 100 and 599")
		}
		q.status = n
	}
	if v := query.Get("rule_id"); v != "" {
		id, e := strconv.ParseInt(v, 10, 64)
		if e != nil || id < 1 {
			return q, invalid("rule_id must be a positive integer")
		}
		q.ruleID = id
	}
	if v := query.Get("policy_id"); v != "" {
		id, e := strconv.ParseInt(v, 10, 64)
		if e != nil || id < 1 {
			return q, invalid("policy_id must be a positive integer")
		}
		q.policyID = id
	}
	for name, target := range map[string]*string{"request_id": &q.requestID, "host": &q.host, "path_class": &q.pathClass} {
		v := strings.TrimSpace(query.Get(name))
		if len(v) > accessFilterTextMax {
			return q, invalid(name + " is too long")
		}
		*target = v
	}
	return q, nil
}

// parseClientFilter accepts one IP address or CIDR and returns its canonical
// masked prefix. The full-length prefix makes an exact address a containment
// check, so both forms share one SQL predicate.
func parseClientFilter(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, e := netip.ParsePrefix(value)
		if e != nil {
			return netip.Prefix{}, invalid("client_ip must be an IP address or CIDR")
		}
		return prefix.Masked(), nil
	}
	addr, e := netip.ParseAddr(value)
	if e != nil {
		return netip.Prefix{}, invalid("client_ip must be an IP address or CIDR")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// where builds the parameterized WHERE fragment for the filter set. The caller
// supplies the argument slice so listing and export share identical semantics.
func (q accessLogQuery) where(args []any) (string, []any) {
	conds := []string{"true"}
	add := func(fragment string, value any) {
		args = append(args, value)
		conds = append(conds, fmt.Sprintf(fragment, len(args)))
	}
	if !q.from.IsZero() {
		add("at >= $%d", q.from)
	}
	if !q.to.IsZero() {
		add("at <= $%d", q.to)
	}
	if q.siteID != 0 {
		add("site_id = $%d", q.siteID)
	}
	if q.clientPrefix.IsValid() {
		// The CASE guard keeps rows with a malformed peer text out of the
		// result instead of failing the whole query on the inet cast.
		args = append(args, peerShapePattern, q.clientPrefix.String())
		conds = append(conds, fmt.Sprintf("(CASE WHEN peer ~ $%d THEN peer::inet END) <<= $%d::inet", len(args)-1, len(args)))
	}
	if q.blocked != nil {
		add("blocked = $%d", *q.blocked)
	}
	if q.status != 0 {
		add("status = $%d", q.status)
	}
	if q.ruleID != 0 {
		add("rule_results @> $%d::jsonb", fmt.Sprintf(`[{"rule_id":%d}]`, q.ruleID))
	}
	if q.requestID != "" {
		add("request_id = $%d", q.requestID)
	}
	if q.host != "" {
		add("host = $%d", q.host)
	}
	if q.policyID != 0 {
		add("policy_id = $%d", q.policyID)
	}
	if q.pathClass != "" {
		add("path_class = $%d", q.pathClass)
	}
	return strings.Join(conds, " AND "), args
}

// pageCursor is the opaque keyset position: rows strictly before (at,id) in
// the (at DESC, id DESC) ordering. New inserts sort ahead of the cursor, so
// paging through a window never shifts, duplicates or skips it.
type pageCursor struct {
	at time.Time
	id int64
}

func encodePageCursor(c pageCursor) string {
	payload, _ := json.Marshal(struct {
		AT string `json:"at"`
		ID int64  `json:"id"`
	}{c.at.UTC().Format(time.RFC3339Nano), c.id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodePageCursor(value string) (pageCursor, error) {
	var c pageCursor
	if len(value) == 0 || len(value) > investigationCursorMax {
		return c, invalid("invalid cursor")
	}
	payload, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil {
		return c, invalid("invalid cursor")
	}
	var decoded struct {
		AT string `json:"at"`
		ID int64  `json:"id"`
	}
	if e := json.Unmarshal(payload, &decoded); e != nil || decoded.ID < 1 || decoded.AT == "" {
		return c, invalid("invalid cursor")
	}
	at, e := time.Parse(time.RFC3339Nano, decoded.AT)
	if e != nil {
		return c, invalid("invalid cursor")
	}
	return pageCursor{at: at, id: decoded.ID}, nil
}

func parseLimit(r *http.Request, maximum int) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return maximum, nil
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > maximum {
		return 0, invalid(fmt.Sprintf("limit must be between 1 and %d", maximum))
	}
	return n, nil
}

func parseCursorParam(r *http.Request) (pageCursor, bool, error) {
	v := r.URL.Query().Get("cursor")
	if v == "" {
		return pageCursor{}, false, nil
	}
	c, e := decodePageCursor(v)
	if e != nil {
		return pageCursor{}, false, e
	}
	return c, true, nil
}

// trimPage drops the lookahead row and returns the next-page cursor encoded
// from the last returned row.
func trimPage(rows []json.RawMessage, limit int) ([]json.RawMessage, string, error) {
	if len(rows) <= limit {
		return rows, "", nil
	}
	rows = rows[:limit]
	var last struct {
		ID int64     `json:"id"`
		AT time.Time `json:"at"`
	}
	if e := json.Unmarshal(rows[limit-1], &last); e != nil || last.ID < 1 {
		return rows, "", invalid("invalid cursor")
	}
	return rows, encodePageCursor(pageCursor{at: last.AT, id: last.ID}), nil
}

// listAccess serves the filtered, cursor-paginated access-log view.
func (a *App) listAccess(w http.ResponseWriter, r *http.Request, _ identity) error {
	q, e := parseAccessLogQuery(r)
	if e != nil {
		return e
	}
	limit, e := parseLimit(r, accessPageSizeMax)
	if e != nil {
		return e
	}
	cursor, hasCursor, e := parseCursorParam(r)
	if e != nil {
		return e
	}
	where, args := q.where(nil)
	if hasCursor {
		args = append(args, cursor.at, cursor.id)
		where += fmt.Sprintf(" AND (at,id) < ($%d,$%d)", len(args)-1, len(args))
	}
	args = append(args, limit+1)
	sql := "SELECT coalesce(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM access_logs WHERE " + where + " ORDER BY at DESC, id DESC LIMIT $%d) t"
	var raw []byte
	if e := a.db.QueryRow(r.Context(), fmt.Sprintf(sql, len(args)), args...).Scan(&raw); e != nil {
		return e
	}
	var rows []json.RawMessage
	if e := json.Unmarshal(raw, &rows); e != nil {
		return e
	}
	rows, next, e := trimPage(rows, limit)
	if e != nil {
		return e
	}
	names, e := loadAddressNames(r.Context(), a.db)
	if e != nil {
		return e
	}
	for n := range rows {
		annotated, e := names.annotate(rows[n])
		if e != nil {
			return e
		}
		rows[n] = annotated
	}
	payload, e := json.Marshal(struct {
		Rows       []json.RawMessage `json:"rows"`
		NextCursor string            `json:"next_cursor"`
	}{rows, next})
	if e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(payload))
	return nil
}

// listAudit serves the filtered, cursor-paginated administrative audit view.
func (a *App) listAudit(w http.ResponseWriter, r *http.Request, _ identity) error {
	query := r.URL.Query()
	for name := range query {
		switch name {
		case "from", "to", "actor", "action", "limit", "cursor":
		default:
			return invalid("unknown filter " + name)
		}
	}
	var from, to time.Time
	if v := query.Get("from"); v != "" {
		t, e := parseTimestamp("from", v)
		if e != nil {
			return e
		}
		from = t
	}
	if v := query.Get("to"); v != "" {
		t, e := parseTimestamp("to", v)
		if e != nil {
			return e
		}
		to = t
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		return invalid("to must not be before from")
	}
	actor := strings.TrimSpace(query.Get("actor"))
	action := strings.TrimSpace(query.Get("action"))
	if len(actor) > accessFilterTextMax || len(action) > accessFilterTextMax {
		return invalid("filter value is too long")
	}
	limit, e := parseLimit(r, auditPageSizeMax)
	if e != nil {
		return e
	}
	cursor, hasCursor, e := parseCursorParam(r)
	if e != nil {
		return e
	}
	conds := []string{"true"}
	args := []any{}
	add := func(fragment string, value any) {
		args = append(args, value)
		conds = append(conds, fmt.Sprintf(fragment, len(args)))
	}
	if !from.IsZero() {
		add("at >= $%d", from)
	}
	if !to.IsZero() {
		add("at <= $%d", to)
	}
	if actor != "" {
		add("actor = $%d", actor)
	}
	if action != "" {
		add("action = $%d", action)
	}
	where := strings.Join(conds, " AND ")
	if hasCursor {
		args = append(args, cursor.at, cursor.id)
		where += fmt.Sprintf(" AND (at,id) < ($%d,$%d)", len(args)-1, len(args))
	}
	args = append(args, limit+1)
	sql := "SELECT coalesce(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM audit_events WHERE " + where + " ORDER BY at DESC, id DESC LIMIT $%d) t"
	var raw []byte
	if e := a.db.QueryRow(r.Context(), fmt.Sprintf(sql, len(args)), args...).Scan(&raw); e != nil {
		return e
	}
	var rows []json.RawMessage
	if e := json.Unmarshal(raw, &rows); e != nil {
		return e
	}
	rows, next, e := trimPage(rows, limit)
	if e != nil {
		return e
	}
	payload, e := json.Marshal(struct {
		Rows       []json.RawMessage `json:"rows"`
		NextCursor string            `json:"next_cursor"`
	}{rows, next})
	if e != nil {
		return e
	}
	respond(w, 200, json.RawMessage(payload))
	return nil
}

// accessLogExportColumns is the explicit export column set: the same metadata
// the listing shows, and nothing from retained request evidence.
const accessLogExportColumns = "id,at,site_id,site_name,host,method,path_class,status,blocked,response_source,peer,request_id,policy_id,policy_revision,policy_name,duration_ms,upstream_us,observed_country,region_code,rule_results,signals"

const accessExportHeader = "id,at,site_id,site_name,host,method,path_class,status,blocked,response_source,client_ip,request_id,policy_id,policy_revision,policy_name,duration_ms,upstream_us,observed_country,region_code,rule_ids,signals"

// exportAccessLogs serves a bounded CSV or JSON export of one filtered window.
// The window is counted first; anything over the row cap is rejected so an
// export is never silently truncated.
func (a *App) exportAccessLogs(w http.ResponseWriter, r *http.Request, _ identity) error {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		return invalid("format must be csv or json")
	}
	if r.URL.Query().Get("cursor") != "" {
		return invalid("export does not accept a cursor; it returns the whole filtered window")
	}
	if r.URL.Query().Get("limit") != "" {
		return invalid("export does not accept a limit; the window is bounded by the row cap")
	}
	q, e := parseAccessLogQuery(r)
	if e != nil {
		return e
	}
	where, args := q.where(nil)
	var count int64
	if e := a.db.QueryRow(r.Context(), "SELECT count(*) FROM access_logs WHERE "+where, args...).Scan(&count); e != nil {
		return e
	}
	if count > accessExportRowCap {
		return apiError{409, fmt.Sprintf("export window has %d rows, over the %d-row cap; narrow the filters (from/to, site, client IP) and retry", count, accessExportRowCap)}
	}
	if format == "json" {
		sql := "SELECT coalesce(jsonb_agg(t),'[]'::jsonb) FROM (SELECT " + accessLogExportColumns + " FROM access_logs WHERE " + where + " ORDER BY at DESC, id DESC) t"
		var raw []byte
		if e := a.db.QueryRow(r.Context(), sql, args...).Scan(&raw); e != nil {
			return e
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="access-logs.json"`)
		w.WriteHeader(200)
		w.Write(raw)
		return nil
	}
	rows, e := a.db.Query(r.Context(), "SELECT "+accessLogExportColumns+" FROM access_logs WHERE "+where+" ORDER BY at DESC, id DESC", args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="access-logs.csv"`)
	w.WriteHeader(200)
	csvOut := csv.NewWriter(w)
	if e := csvOut.Write(strings.Split(accessExportHeader, ",")); e != nil {
		return e
	}
	for rows.Next() {
		var id, siteID, policyID, policyRevision, duration, upstream int64
		var at time.Time
		var status int
		var blocked bool
		var siteName, host, method, pathClass, source, peer, requestID, policyName, country, region string
		var ruleResults, signalsJSON []byte
		if e := rows.Scan(&id, &at, &siteID, &siteName, &host, &method, &pathClass, &status, &blocked, &source, &peer, &requestID, &policyID, &policyRevision, &policyName, &duration, &upstream, &country, &region, &ruleResults, &signalsJSON); e != nil {
			return e
		}
		ruleIDs := []string{}
		var results []RuleResult
		if json.Unmarshal(ruleResults, &results) == nil {
			for _, result := range results {
				ruleIDs = append(ruleIDs, strconv.FormatInt(result.RuleID, 10))
			}
		}
		signals := []string{}
		var parsed []string
		if json.Unmarshal(signalsJSON, &parsed) == nil {
			signals = parsed
		}
		record := []string{
			strconv.FormatInt(id, 10), at.UTC().Format(time.RFC3339Nano), strconv.FormatInt(siteID, 10), siteName, host, method, pathClass,
			strconv.Itoa(status), strconv.FormatBool(blocked), source, peer, requestID, strconv.FormatInt(policyID, 10), strconv.FormatInt(policyRevision, 10), policyName,
			strconv.FormatInt(duration, 10), strconv.FormatInt(upstream, 10), country, region, strings.Join(ruleIDs, ";"), strings.Join(signals, ";"),
		}
		if e := csvOut.Write(record); e != nil {
			return e
		}
	}
	if e := rows.Err(); e != nil {
		return e
	}
	csvOut.Flush()
	return csvOut.Error()
}

// accessLogQueryFromInput translates an agent tool input object into the query
// string for GET /api/access-logs. Only the documented filter keys are
// accepted; the endpoint re-validates every value.
func accessLogQueryFromInput(input json.RawMessage) (string, error) {
	if len(input) == 0 {
		return "", nil
	}
	var filters map[string]any
	if e := json.Unmarshal(input, &filters); e != nil {
		return "", e
	}
	allowed := map[string]bool{"site_id": true, "blocked": true, "status": true, "rule_id": true, "request_id": true, "host": true, "client_ip": true, "policy_id": true, "path_class": true, "from": true, "to": true, "limit": true, "cursor": true}
	values := url.Values{}
	for key, value := range filters {
		if !allowed[key] {
			return "", fmt.Errorf("unknown filter %q", key)
		}
		switch typed := value.(type) {
		case string:
			values.Set(key, typed)
		case bool:
			values.Set(key, strconv.FormatBool(typed))
		case float64:
			values.Set(key, strconv.FormatInt(int64(typed), 10))
		default:
			return "", fmt.Errorf("filter %q must be a string, number or boolean", key)
		}
	}
	if len(values) == 0 {
		return "", nil
	}
	return "?" + values.Encode(), nil
}
