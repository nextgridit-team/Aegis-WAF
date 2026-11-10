package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestApplicationAccessMCPWorkflow(t *testing.T) {
	a, _, api, site, _ := captchaFixture(t)
	server := httptest.NewTLSServer(a.Management())
	defer server.Close()
	object := mustID(t, api.call("POST", "/api/address-objects", map[string]string{"name": "Auth agent", "value": "127.0.0.1"}, 200))
	var key struct {
		Secret string `json:"api_key"`
	}
	api.call("PUT", "/api/agent-access", map[string]bool{"enabled": true}, 200)
	json.Unmarshal(api.call("POST", "/api/agent-keys", map[string]any{"name": "Auth agent", "allowed_addresses": addressSelection{ObjectIDs: []int64{object}}, "scopes": []string{"read", "configuration", "enforce"}}, 201), &key)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "auth-test", Version: "1"}, nil)
	session, e := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: agentTestTransport{server.Client().Transport, key.Secret}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	call := func(tool string, args map[string]any, wantError bool) string {
		t.Helper()
		result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if e != nil || result.IsError != wantError {
			t.Fatalf("%s error=%v result=%+v", tool, e, result)
		}
		return result.Content[0].(*mcp.TextContent).Text
	}
	catalog := call("list_management_operations", map[string]any{}, false)
	for _, path := range []string{"/api/identity-providers/{id}/groups", "/api/identity-providers/presets", "/api/application-access/{id}", "/api/application-sessions/{id}"} {
		if !strings.Contains(catalog, path) {
			t.Fatal("missing operation", path)
		}
	}
	input := identityProviderInput{identityProviderSettings: identityProviderSettings{Name: "Agent configured", Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: "https://identity.example.test", ClientID: "aegis"}}, Secret: "agent-supplied-secret"}
	call("management_operation", map[string]any{"method": "POST", "path": "/api/identity-providers", "input": input}, false)
	var provider int64
	if e = a.db.QueryRow(ctx, "SELECT id FROM identity_providers").Scan(&provider); e != nil {
		t.Fatal(e)
	}
	if read := call("management_operation", map[string]any{"method": "GET", "path": fmt.Sprintf("/api/identity-providers/%d", provider)}, false); strings.Contains(read, input.Secret) {
		t.Fatal("provider secret leaked through MCP")
	}
	access := applicationAccessInput{applicationAccessSettings: applicationAccessSettings{Enabled: true, ProviderID: provider, PublicOrigin: "https://bot.test", AllowedGroups: []string{"finance"}, SessionMinutes: 30}}
	path := fmt.Sprintf("/api/application-access/%d", site)
	call("management_operation", map[string]any{"method": "PUT", "path": path, "input": access}, true)
	tests := []simulationPayload{
		{Host: "bot.test", Path: "/", Expected: "block"},
		{Host: "bot.test", Path: "/", Identity: &applicationIdentity{Subject: "wrong-user", Groups: []string{"engineering"}}, Expected: "block"},
		{Host: "bot.test", Path: "/", Identity: &applicationIdentity{Subject: "allowed-user", Groups: []string{"finance"}}, Expected: "allow"},
	}
	raw := call("simulate_rule_impact", map[string]any{"method": "PUT", "path": path, "input": access, "test_payloads": tests}, false)
	var summary simulationSummary
	if e = json.Unmarshal([]byte(raw), &summary); e != nil || summary.ID == "" || !summary.Eligible {
		t.Fatal("simulation not meaningful", e, raw)
	}
	for _, test := range summary.Harness {
		if !test.Passed {
			t.Fatal("group authorization mismatch", raw)
		}
	}
	current, e := readApplicationAccess(ctx, a.db, site)
	if e != nil || current.Settings.Enabled {
		t.Fatal("simulation mutated live access", e)
	}
	changed := access
	changed.AllowAnyAuthenticated = true
	changed.AllowedGroups = []string{}
	call("management_operation", map[string]any{"method": "PUT", "path": path, "input": changed, "simulation_id": summary.ID}, true)
	call("management_operation", map[string]any{"method": "PUT", "path": path, "input": access, "simulation_id": summary.ID}, false)
	current, e = readApplicationAccess(ctx, a.db, site)
	if e != nil || !current.Settings.Enabled {
		t.Fatal("agent failed to configure application", e)
	}
	call("management_operation", map[string]any{"method": "POST", "path": path + "/revoke", "input": map[string]any{}}, false)
	if agentScopeFor("PUT /api/identity-providers/{id}") != "enforce" || agentScopeFor("POST /api/identity-providers/{id}/test") != "configuration" {
		t.Fatal("identity permission boundaries changed")
	}
}
