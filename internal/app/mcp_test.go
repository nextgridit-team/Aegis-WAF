package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type agentTestTransport struct {
	base http.RoundTripper
	key  string
}

func (tr agentTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	r.Header.Set("Authorization", "Bearer "+tr.key)
	return tr.base.RoundTrip(r)
}
func TestAgentIntegration(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	srv := httptest.NewTLSServer(a.Management())
	defer srv.Close()
	client := srv.Client()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	c := testAPI{t, client, srv.URL, ""}
	c.call("GET", "/api/agent-access/skill", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "agent access long test password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "agent access long test password"}, 200), &login)
	c.csrf = login["csrf"]
	c.call("GET", "/mcp", nil, 404)
	c.call("GET", "/api/agent-access/skill", nil, 200)
	obj := mustID(t, c.call("POST", "/api/address-objects", map[string]string{"name": "Agent peer", "value": "127.0.0.1"}, 200))
	keyInput := map[string]any{"name": "Review agent", "allowed_addresses": addressSelection{ObjectIDs: []int64{obj}}, "scopes": []string{"read"}}
	var key struct {
		ID     int64  `json:"id"`
		Secret string `json:"api_key"`
	}
	json.Unmarshal(c.call("POST", "/api/agent-keys", keyInput, 201), &key)
	if key.Secret == "" {
		t.Fatal("missing one-time key")
	}
	if strings.Contains(string(c.call("GET", "/api/agent-keys", nil, 200)), key.Secret) {
		t.Fatal("key leaked through read API")
	}
	c.call("POST", "/api/agent-keys", map[string]any{"name": "No sources"}, 400)
	c.call("PUT", "/api/agent-access", map[string]bool{"enabled": true}, 200)
	c.call("GET", "/mcp", nil, 401)
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
	session := connect(key.Secret)
	list, e := session.ListTools(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	if !names["list_rules"] || names["activate_rule"] || names["get_request_details"] || names["propose_rule"] {
		t.Fatalf("bad read-only tools: %v", names)
	}

	skill, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_agent_skill", Arguments: map[string]any{}})
	if e != nil || skill.IsError {
		t.Fatalf("skill retrieval %v %+v", e, skill)
	}
	result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_applications", Arguments: map[string]any{}})
	if e != nil || result.IsError {
		t.Fatalf("read failed: %v %+v", e, result)
	}
	result, e = session.CallTool(ctx, &mcp.CallToolParams{Name: "activate_rule", Arguments: map[string]any{"id": 1, "input": map[string]any{"action": "block", "ttl_seconds": 60}}})
	if e == nil && (result == nil || !result.IsError) {
		t.Fatal("read key activated rule")
	}
	c.call("DELETE", fmt.Sprintf("/api/address-objects/%d", obj), nil, 409)
	// Address restrictions use the socket peer; group edits take effect immediately.
	c.call("PUT", fmt.Sprintf("/api/address-objects/%d", obj), map[string]string{"name": "Agent peer", "value": "192.0.2.1"}, 200)
	if _, e = session.ListTools(ctx, nil); e == nil {
		t.Fatal("address update did not revoke source access")
	}
	c.call("PUT", fmt.Sprintf("/api/address-objects/%d", obj), map[string]string{"name": "Agent peer", "value": "127.0.0.1"}, 200)
	session = connect(key.Secret) // A denied request closes the SDK client session.
	// Wrong Origin is rejected even with a valid key.
	req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+key.Secret)
	req.Header.Set("Origin", "https://evil.test")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("origin status %d", res.StatusCode)
	}

	result, e = session.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "POST", "path": "/api/sites", "input": map[string]any{}}})
	if e != nil || !result.IsError {
		t.Fatalf("read-only generic mutation %v %+v", e, result)
	}
	result, e = session.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "GET", "path": "/api/policies"}})
	if e != nil || result.IsError {
		t.Fatalf("generic read %v %+v", e, result)
	}
	keyInput["scopes"] = []string{"read", "evidence", "draft", "enforce", "configuration", "certificates", "agent_admin"}
	var fullKey struct {
		Secret string `json:"api_key"`
	}
	json.Unmarshal(c.call("POST", "/api/agent-keys", keyInput, 201), &fullKey)
	fullSession := connect(fullKey.Secret)
	result, e = fullSession.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "POST", "path": "/api/address-objects", "input": map[string]any{"name": "Agent-created subnet", "value": "10.20.30.45/24"}}})
	if e != nil || result.IsError {
		t.Fatalf("full management creation %v %+v content=%+v", e, result, result.Content[0].(*mcp.TextContent).Text)
	}
	for _, path := range []string{"/api/setup", "/api/login", "/api/acme/accounts", "/api/agent-keys", "/api/%61gent-keys", "/mcp", "https://example.com/api/sites"} {
		result, e = fullSession.CallTool(ctx, &mcp.CallToolParams{Name: "management_operation", Arguments: map[string]any{"method": "POST", "path": path, "input": map[string]any{}}})
		if e != nil || !result.IsError {
			t.Fatalf("forbidden management route %s %v %+v", path, e, result)
		}
	}
	// A draft-capable key can create a proposal, but it remains disabled.
	keyInput["scopes"] = []string{"read", "draft"}
	var draftKey struct {
		Secret string `json:"api_key"`
	}
	json.Unmarshal(c.call("POST", "/api/agent-keys", keyInput, 201), &draftKey)
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Agent test", "hostnames": []string{"agent.test"}, "upstream": "http://127.0.0.1:18080", "enabled": true}, 200))
	rule := probeRule("path", "", "equals", "/.env")
	rule.Scope.SiteID = site
	draftSession := connect(draftKey.Secret)
	result, e = draftSession.CallTool(ctx, &mcp.CallToolParams{Name: "propose_rule", Arguments: map[string]any{"input": rule}})
	if e != nil || result.IsError {
		t.Fatalf("proposal failed %v %+v", e, result)
	}
	var enabled bool
	if e = a.db.QueryRow(ctx, "SELECT enabled FROM rules ORDER BY id DESC LIMIT 1").Scan(&enabled); e != nil || enabled {
		t.Fatalf("draft enabled %v %v", enabled, e)
	}

	keyInput["scopes"] = []string{"read", "enforce"}
	var enforceKey struct {
		Secret string `json:"api_key"`
	}
	json.Unmarshal(c.call("POST", "/api/agent-keys", keyInput, 201), &enforceKey)
	enforceSession := connect(enforceKey.Secret)
	var ruleID int64
	if e = a.db.QueryRow(ctx, "SELECT id FROM rules ORDER BY id DESC LIMIT 1").Scan(&ruleID); e != nil {
		t.Fatal(e)
	}
	result, e = enforceSession.CallTool(ctx, &mcp.CallToolParams{Name: "activate_rule", Arguments: map[string]any{"id": ruleID, "input": map[string]any{"action": "observe", "ttl_seconds": 60}}})
	if e != nil || result.IsError {
		t.Fatalf("activation %v %+v", e, result)
	}
	result, e = enforceSession.CallTool(ctx, &mcp.CallToolParams{Name: "disable_rule", Arguments: map[string]any{"id": ruleID}})
	if e != nil || result.IsError {
		t.Fatalf("disable %v %+v", e, result)
	}
	var calls int
	if e = a.db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE actor LIKE 'agent-key:%' AND action='agent.tool_called'").Scan(&calls); e != nil || calls < 4 {
		t.Fatalf("missing agent audit %d %v", calls, e)
	}
	c.call("DELETE", fmt.Sprintf("/api/agent-keys/%d", key.ID), nil, 200)
	if _, e = session.ListTools(ctx, nil); e == nil {
		t.Fatal("revoked key accepted")
	}
	c.call("PUT", "/api/agent-access", map[string]bool{"enabled": false}, 200)
	if _, e = draftSession.ListTools(ctx, nil); e == nil {
		t.Fatal("disabled endpoint accepted")
	}
}
