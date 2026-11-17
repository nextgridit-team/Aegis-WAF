package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The export row cap documented for GET /api/access-logs/export.
const investigationExportRowCap = 10000

// raw performs a request without asserting the status, for endpoints that
// return non-JSON bodies.
func (c *testAPI) raw(method, path string, body any) *http.Response {
	c.t.Helper()
	b, _ := json.Marshal(body)
	r, e := http.NewRequest(method, c.base+path, bytes.NewReader(b))
	if e != nil {
		c.t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Requested-With", "aegis-waf")
	r.Header.Set("X-CSRF-Token", c.csrf)
	res, e := c.client.Do(r)
	if e != nil {
		c.t.Fatal(e)
	}
	return res
}

// Investigation history: the filtered, cursor-paginated views over access_logs
// and audit_events. The decoders below accept both the legacy bare-array body
// and the {rows,next_cursor} envelope so assertions fail on unfiltered
// behavior rather than on response shape.

type accessPage struct {
	Rows       []map[string]any `json:"rows"`
	NextCursor string           `json:"next_cursor"`
}

func decodeAccessRows(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var rows []map[string]any
		if e := json.Unmarshal(data, &rows); e != nil {
			t.Fatalf("invalid legacy array body: %v (%s)", e, data)
		}
		return rows
	}
	var page accessPage
	if e := json.Unmarshal(data, &page); e != nil {
		t.Fatalf("invalid page body: %v (%s)", e, data)
	}
	return page.Rows
}

func decodePageEnvelope(t *testing.T, data []byte) accessPage {
	t.Helper()
	var page accessPage
	if e := json.Unmarshal(data, &page); e != nil {
		t.Fatalf("invalid page body: %v (%s)", e, data)
	}
	return page
}

func investigationReplica(t *testing.T) (*App, *testAPI) {
	t.Helper()
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	server := httptest.NewServer(a.Management())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	c := &testAPI{t, client, server.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "correct horse battery gateway", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery gateway"}, 200), &login)
	c.csrf = login["csrf"]
	return a, c
}

func investigationSite(t *testing.T, c *testAPI, name, hostname string) int64 {
	t.Helper()
	return mustID(t, c.call("POST", "/api/sites", map[string]any{"name": name, "hostnames": []string{hostname}, "upstream": "http://127.0.0.1:1", "enabled": false}, 200))
}

// The headline red case: on main the query parameters are ignored and the
// global latest 200 rows come back, so a row from the other application (or
// an allowed request) is present in a site+blocked filtered response.
func TestAccessLogsFilterBySiteAndBlocked(t *testing.T) {
	a, c := investigationReplica(t)
	siteA := investigationSite(t, c, "Investigation A", "a.example.com")
	siteB := investigationSite(t, c, "Investigation B", "b.example.com")
	base := time.Now().Add(-time.Hour).UTC()
	events := []accessEvent{
		{at: base, site: siteA, method: "POST", status: 403, duration: 4, peer: "198.51.100.7", blocked: true, responseSource: "waf", host: "a.example.com", requestID: "req-a-1", pathClass: "/login", policyID: 5, policyName: "P", results: []RuleResult{{RuleID: 942100, Action: "block", Result: "matched"}}},
		{at: base.Add(time.Second), site: siteA, method: "GET", status: 200, duration: 5, peer: "198.51.100.8", blocked: false, responseSource: "upstream", host: "a.example.com", requestID: "req-a-2", pathClass: "/api/items/{id}", policyID: 5, policyName: "P"},
		{at: base.Add(2 * time.Second), site: siteB, method: "POST", status: 403, duration: 6, peer: "203.0.113.9", blocked: true, responseSource: "waf", host: "b.example.com", requestID: "req-b-1", pathClass: "/login", policyID: 6, policyName: "Q"},
		{at: base.Add(3 * time.Second), site: siteB, method: "GET", status: 200, duration: 7, peer: "203.0.113.10", blocked: false, responseSource: "upstream", host: "b.example.com", requestID: "req-b-2", pathClass: "/health", policyID: 6, policyName: "Q"},
	}
	if e := a.storeAccessBatch(context.Background(), events); e != nil {
		t.Fatal(e)
	}
	rows := decodeAccessRows(t, c.call("GET", "/api/access-logs?site_id="+itoa(siteA)+"&blocked=true", nil, 200))
	if len(rows) != 1 {
		t.Fatalf("site+blocked filter: got %d rows, want 1 (rows %v)", len(rows), rows)
	}
	for _, row := range rows {
		if row["site_id"] != float64(siteA) || row["blocked"] != true {
			t.Fatalf("unfiltered row returned for site+blocked: %v", row)
		}
	}
}

func TestAccessLogsEachFilter(t *testing.T) {
	a, c := investigationReplica(t)
	siteA := investigationSite(t, c, "Investigation A", "a.example.com")
	siteB := investigationSite(t, c, "Investigation B", "b.example.com")
	base := time.Now().Add(-time.Hour).UTC()
	blocked := accessEvent{at: base, site: siteA, method: "POST", status: 403, duration: 4, peer: "198.51.100.7", blocked: true, responseSource: "waf", host: "a.example.com", requestID: "req-a-1", pathClass: "/login", policyID: 5, policyName: "P", results: []RuleResult{{RuleID: 942100, Action: "block", Result: "matched"}}}
	allowed := accessEvent{at: base.Add(time.Second), site: siteA, method: "GET", status: 200, duration: 5, peer: "198.51.100.8", blocked: false, responseSource: "upstream", host: "a.example.com", requestID: "req-a-2", pathClass: "/api/items/{id}", policyID: 5, policyName: "P"}
	other := accessEvent{at: base.Add(2 * time.Second), site: siteB, method: "POST", status: 403, duration: 6, peer: "203.0.113.9", blocked: true, responseSource: "waf", host: "b.example.com", requestID: "req-b-1", pathClass: "/login", policyID: 6, policyName: "Q"}
	if e := a.storeAccessBatch(context.Background(), []accessEvent{blocked, allowed, other}); e != nil {
		t.Fatal(e)
	}
	matching := func(t *testing.T, query string, want ...string) {
		t.Helper()
		rows := decodeAccessRows(t, c.call("GET", "/api/access-logs?"+query, nil, 200))
		got := map[string]bool{}
		for _, row := range rows {
			id, _ := row["request_id"].(string)
			got[id] = true
		}
		if len(rows) != len(want) {
			t.Fatalf("%s: got %d rows (%v), want %d (%v)", query, len(rows), got, len(want), want)
		}
		for _, id := range want {
			if !got[id] {
				t.Fatalf("%s: missing row %s (got %v)", query, id, got)
			}
		}
	}
	matching(t, "client_ip=198.51.100.7", "req-a-1")
	matching(t, "client_ip=198.51.100.0/25", "req-a-1", "req-a-2")
	matching(t, "client_ip=203.0.113.0/24", "req-b-1")
	matching(t, "status=200", "req-a-2")
	matching(t, "rule_id=942100", "req-a-1")
	matching(t, "request_id=req-a-2", "req-a-2")
	matching(t, "host=a.example.com", "req-a-1", "req-a-2")
	matching(t, "policy_id=6", "req-b-1")
	matching(t, "path_class=/login", "req-a-1", "req-b-1")
	matching(t, "from="+base.Add(time.Second).Format(time.RFC3339Nano), "req-a-2", "req-b-1")
	matching(t, "to="+base.Add(time.Second).Format(time.RFC3339Nano), "req-a-1", "req-a-2")
	matching(t, "from="+base.Format(time.RFC3339Nano)+"&to="+base.Add(2*time.Second).Format(time.RFC3339Nano), "req-a-1", "req-a-2", "req-b-1")
	// Combined filters AND together, never widen.
	matching(t, "site_id="+itoa(siteA)+"&blocked=false&status=200", "req-a-2")
	matching(t, "site_id="+itoa(siteA)+"&client_ip=198.51.100.0/24&blocked=true", "req-a-1")
}

// Keyset pagination over (at,id): pages are stable while new rows arrive, with
// no duplicates and no skips for the captured window.
func TestAccessLogsCursorStableAcrossInserts(t *testing.T) {
	a, c := investigationReplica(t)
	site := investigationSite(t, c, "Investigation", "cursor.example.com")
	base := time.Now().Add(-2 * time.Hour).UTC()
	seed := make([]accessEvent, 25)
	for n := range seed {
		seed[n] = accessEvent{at: base.Add(time.Duration(n) * time.Second), site: site, method: "GET", status: 200, duration: int64(n + 1), peer: "198.51.100.20", requestID: fmt.Sprintf("cur-%02d", n+1), responseSource: "upstream"}
	}
	if e := a.storeAccessBatch(context.Background(), seed); e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		query := "/api/access-logs?site_id=" + itoa(site) + "&limit=10"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		body := c.call("GET", query, nil, 200)
		if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
			t.Fatal("legacy unpaginated body: no next_cursor envelope")
		}
		page := decodePageEnvelope(t, body)
		if len(page.Rows) == 0 || len(page.Rows) > 10 {
			t.Fatalf("page size %d out of bounds", len(page.Rows))
		}
		for _, row := range page.Rows {
			id, _ := row["request_id"].(string)
			if seen[id] {
				t.Fatalf("duplicate row across pages: %s", id)
			}
			seen[id] = true
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
		// Newer traffic lands while the operator pages: the captured window
		// must not shift, duplicate or skip.
		if pages == 1 {
			newer := []accessEvent{{at: base.Add(time.Minute), site: site, method: "GET", status: 200, duration: 99, peer: "198.51.100.21", requestID: "cur-new", responseSource: "upstream"}}
			if e := a.storeAccessBatch(context.Background(), newer); e != nil {
				t.Fatal(e)
			}
		}
	}
	if pages != 3 {
		t.Fatalf("expected 3 pages of 10/10/5, got %d", pages)
	}
	if len(seen) != 25 {
		t.Fatalf("expected the 25 seeded rows exactly, got %d (%v)", len(seen), seen)
	}
	if seen["cur-new"] {
		t.Fatal("row inserted after the first page leaked into the captured window")
	}
}

func TestAccessLogsValidation(t *testing.T) {
	_, c := investigationReplica(t)
	for _, query := range []string{
		"limit=0", "limit=201", "limit=-5", "limit=abc",
		"client_ip=not-an-ip", "client_ip=198.51.100.0/99",
		"from=banana", "to=banana",
		"site_id=abc", "site_id=-1",
		"status=99", "status=600", "status=abc",
		"rule_id=abc", "policy_id=abc",
		"cursor=AAAA", "cursor=not-a-cursor",
		"mystery_filter=1",
	} {
		c.call("GET", "/api/access-logs?"+query, nil, 400)
	}
	c.call("GET", "/api/access-logs?limit=200", nil, 200)
	c.call("GET", "/api/access-logs", nil, 200)
}

func TestAccessLogsExport(t *testing.T) {
	a, c := investigationReplica(t)
	site := investigationSite(t, c, "Export", "export.example.com")
	base := time.Now().Add(-time.Hour).UTC()
	events := []accessEvent{
		{at: base, site: site, method: "POST", status: 403, duration: 4, peer: "198.51.100.7", blocked: true, responseSource: "waf", host: "export.example.com", requestID: "exp-1", pathClass: "/login", policyID: 5, policyName: "P", results: []RuleResult{{RuleID: 942100, Action: "block", Result: "matched"}}},
		{at: base.Add(time.Second), site: site, method: "GET", status: 200, duration: 5, peer: "198.51.100.8", blocked: false, responseSource: "upstream", host: "export.example.com", requestID: "exp-2", pathClass: "/health"},
	}
	if e := a.storeAccessBatch(context.Background(), events); e != nil {
		t.Fatal(e)
	}
	res := c.raw("GET", "/api/access-logs/export?site_id="+itoa(site)+"&format=csv", nil)
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("csv export status %d: %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Fatalf("csv content type %q", ct)
	}
	csvBody, _ := io.ReadAll(res.Body)
	lines := strings.Split(strings.TrimSpace(string(csvBody)), "\n")
	if len(lines) != 3 {
		t.Fatalf("csv export: got %d lines, want header + 2 rows: %q", len(lines), csvBody)
	}
	if !strings.Contains(lines[0], "request_id") || !strings.Contains(lines[0], "rule_ids") {
		t.Fatalf("csv header missing expected columns: %q", lines[0])
	}
	if !strings.Contains(string(csvBody), "exp-1") || !strings.Contains(string(csvBody), "942100") {
		t.Fatalf("csv export missing filtered rows: %q", csvBody)
	}
	// JSON export returns the same bounded window as row objects.
	data := c.call("GET", "/api/access-logs/export?site_id="+itoa(site)+"&format=json", nil, 200)
	var exported []map[string]any
	if e := json.Unmarshal(data, &exported); e != nil || len(exported) != 2 {
		t.Fatalf("json export: %v rows=%d (%s)", e, len(exported), data)
	}
	// A window over the export row cap is rejected, never silently truncated.
	over := make([]accessEvent, investigationExportRowCap+1)
	for n := range over {
		over[n] = accessEvent{at: base.Add(time.Duration(n) * time.Millisecond), site: site, method: "GET", status: 200, duration: 1, peer: "198.51.100.9", requestID: fmt.Sprintf("over-%d", n), responseSource: "upstream"}
	}
	if e := a.storeAccessBatch(context.Background(), over); e != nil {
		t.Fatal(e)
	}
	body := c.call("GET", "/api/access-logs/export?site_id="+itoa(site)+"&format=csv", nil, 409)
	if !strings.Contains(string(body), "cap") {
		t.Fatalf("over-cap export error does not explain the cap: %s", body)
	}
	// Narrowing the window brings the export back under the cap.
	narrow := c.call("GET", "/api/access-logs/export?site_id="+itoa(site)+"&request_id=exp-1&format=csv", nil, 200)
	if !strings.Contains(string(narrow), "exp-1") || strings.Contains(string(narrow), "exp-2") {
		t.Fatalf("narrowed export wrong rows: %s", narrow)
	}
	c.call("GET", "/api/access-logs/export?format=xml", nil, 400)
	c.call("GET", "/api/access-logs/export?client_ip=bogus", nil, 400)
}

func TestAuditFiltersAndCursor(t *testing.T) {
	a, c := investigationReplica(t)
	base := time.Now().Add(-time.Hour).UTC()
	// Distinctive actors/actions: the replica's own setup, login and site
	// creation also write admin audit rows, which the filters must exclude.
	rows := [][4]any{
		{base, "inv-admin", "inv.one", "inv:1"},
		{base.Add(time.Second), "inv-agent", "inv.two", "inv:2"},
		{base.Add(2 * time.Second), "inv-admin", "inv.three", "inv:3"},
		{base.Add(3 * time.Second), "inv-auditor", "inv.four", "inv:4"},
	}
	for _, row := range rows {
		if _, e := a.db.Exec(context.Background(), "INSERT INTO audit_events(at,actor,action,resource) VALUES($1,$2,$3,$4)", row[0], row[1], row[2], row[3]); e != nil {
			t.Fatal(e)
		}
	}
	resources := func(filtered []map[string]any) []string {
		out := []string{}
		for _, row := range filtered {
			out = append(out, fmt.Sprintf("%v", row["resource"]))
		}
		return out
	}
	filtered := decodeAccessRows(t, c.call("GET", "/api/audit?actor=inv-admin", nil, 200))
	if fmt.Sprint(resources(filtered)) != "[inv:3 inv:1]" {
		t.Fatalf("actor filter wrong rows: %v", resources(filtered))
	}
	for _, row := range filtered {
		if row["actor"] != "inv-admin" {
			t.Fatalf("unfiltered audit row returned: %v", row)
		}
	}
	filtered = decodeAccessRows(t, c.call("GET", "/api/audit?action=inv.two", nil, 200))
	if fmt.Sprint(resources(filtered)) != "[inv:2]" {
		t.Fatalf("action filter wrong rows: %v", resources(filtered))
	}
	filtered = decodeAccessRows(t, c.call("GET", "/api/audit?actor=inv-admin&from="+base.Add(time.Second).Format(time.RFC3339Nano), nil, 200))
	if fmt.Sprint(resources(filtered)) != "[inv:3]" {
		t.Fatalf("actor+from filter wrong rows: %v", resources(filtered))
	}
	filtered = decodeAccessRows(t, c.call("GET", "/api/audit?actor=inv-admin&to="+base.Add(time.Second).Format(time.RFC3339Nano), nil, 200))
	if fmt.Sprint(resources(filtered)) != "[inv:1]" {
		t.Fatalf("actor+to filter wrong rows: %v", resources(filtered))
	}
	// Cursor pagination over the whole audit trail: every seeded row appears
	// exactly once and the pages never repeat.
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		query := "/api/audit?limit=2"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		page := decodePageEnvelope(t, c.call("GET", query, nil, 200))
		if len(page.Rows) == 0 || len(page.Rows) > 2 {
			t.Fatalf("audit page size %d out of bounds", len(page.Rows))
		}
		for _, row := range page.Rows {
			resource := fmt.Sprintf("%v", row["resource"])
			if strings.HasPrefix(resource, "inv:") {
				if seen[resource] {
					t.Fatalf("duplicate audit row across pages: %s", resource)
				}
				seen[resource] = true
			}
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 20 {
			t.Fatal("audit pagination did not terminate")
		}
	}
	if len(seen) != 4 {
		t.Fatalf("expected the 4 seeded audit rows, got %v", seen)
	}
	for _, query := range []string{"limit=0", "limit=501", "from=banana", "mystery=1"} {
		c.call("GET", "/api/audit?"+query, nil, 400)
	}
}

// A read-only key must not enumerate traffic metadata: the access-log listing
// and its export are evidence-scoped, while an evidence key can use both.
func TestInvestigationAgentScopes(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	srv := httptest.NewTLSServer(a.Management())
	t.Cleanup(srv.Close)
	client := srv.Client()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	c := &testAPI{t, client, srv.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "investigation scope long password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "investigation scope long password"}, 200), &login)
	c.csrf = login["csrf"]
	obj := mustID(t, c.call("POST", "/api/address-objects", map[string]string{"name": "Investigation peer", "value": "127.0.0.1"}, 200))
	mkkey := func(name string, scopes []string) string {
		var key struct {
			Secret string `json:"api_key"`
		}
		json.Unmarshal(c.call("POST", "/api/agent-keys", map[string]any{"name": name, "allowed_addresses": addressSelection{ObjectIDs: []int64{obj}}, "scopes": scopes}, 201), &key)
		if key.Secret == "" {
			t.Fatalf("missing one-time key for %s", name)
		}
		return key.Secret
	}
	readKey := mkkey("Read investigator", []string{"read"})
	evidenceKey := mkkey("Evidence investigator", []string{"read", "evidence"})
	c.call("PUT", "/api/agent-access", map[string]bool{"enabled": true}, 200)
	site := investigationSite(t, c, "Scope", "scope.example.com")
	base := time.Now().Add(-time.Hour).UTC()
	if e := a.storeAccessBatch(context.Background(), []accessEvent{
		{at: base, site: site, method: "POST", status: 403, duration: 4, peer: "198.51.100.7", blocked: true, responseSource: "waf", requestID: "scope-1"},
		{at: base.Add(time.Second), site: site, method: "GET", status: 200, duration: 5, peer: "198.51.100.8", blocked: false, responseSource: "upstream", requestID: "scope-2"},
	}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connect := func(secret string) *mcp.ClientSession {
		t.Helper()
		mc := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
		session, e := mc.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: agentTestTransport{srv.Client().Transport, secret}}}, nil)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { session.Close() })
		return session
	}
	evidence := connect(evidenceKey)
	result, e := evidence.CallTool(ctx, &mcp.CallToolParams{Name: "list_access_logs", Arguments: map[string]any{"input": map[string]any{"site_id": site, "blocked": true}}})
	if e != nil || result.IsError {
		t.Fatalf("evidence key filtered listing failed: %v %+v", e, result)
	}
	text, _ := result.Content[0].(*mcp.TextContent)
	if text == nil || !strings.Contains(text.Text, "scope-1") || strings.Contains(text.Text, "scope-2") {
		t.Fatalf("evidence key filtered listing wrong rows: %+v", text)
	}
	// The read-only key cannot enumerate traffic metadata at all.
	read := connect(readKey)
	result, e = read.CallTool(ctx, &mcp.CallToolParams{Name: "list_access_logs", Arguments: map[string]any{"input": map[string]any{}}})
	if e == nil && (result == nil || !result.IsError) {
		t.Fatal("read-only key listed traffic metadata")
	}
	result, e = read.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "GET", "path": "/api/access-logs?site_id=" + itoa(site)}})
	if e == nil && (result == nil || !result.IsError) {
		t.Fatal("read-only key listed access logs through management_operation")
	}
	// The evidence key can use the filtered listing and the bounded export.
	result, e = evidence.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "GET", "path": "/api/access-logs?site_id=" + itoa(site) + "&blocked=true"}})
	if e != nil || result.IsError {
		t.Fatalf("evidence key filtered management_operation failed: %v %+v", e, result)
	}
	result, e = evidence.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "GET", "path": "/api/access-logs/export?site_id=" + itoa(site) + "&request_id=scope-1&format=csv"}})
	if e != nil || result.IsError {
		t.Fatalf("evidence key export failed: %v %+v", e, result)
	}
}
