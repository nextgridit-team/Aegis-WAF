package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func prometheusCounter(t *testing.T, p *gatewayTelemetry, name string, labels map[string]string) float64 {
	t.Helper()
	families, e := p.registry.Gather()
	if e != nil {
		t.Fatal(e)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			match := true
			for key, value := range labels {
				found := false
				for _, label := range metric.Label {
					if label.GetName() == key && label.GetValue() == value {
						found = true
					}
				}
				match = match && found
			}
			if match {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}
func TestPrometheusCountersAndBounds(t *testing.T) {
	a := &App{}
	p := newGatewayTelemetry(a)
	a.prom = p
	p.observeEvent(accessEvent{status: 200, results: []RuleResult{{RuleID: 9, Result: "matched"}, {RuleID: 3, Result: "matched"}}, peer: "198.51.100.99"})
	p.observeEvent(accessEvent{status: 200, blocked: true, managed: managedSignatureResult{RuleIDs: []int{951120, 951110}}})
	if prometheusCounter(t, p, "aegis_requests_total", map[string]string{"status": "200", "rule_id": "custom:3"}) != 1 || prometheusCounter(t, p, "aegis_requests_total", map[string]string{"rule_id": "crs:951110"}) != 1 || prometheusCounter(t, p, "aegis_decisions_total", map[string]string{"action": "blocked"}) != 1 {
		t.Fatal("wrong request attribution")
	}
	p.observeInspection("request", time.Millisecond)
	w := httptest.NewRecorder()
	p.handler.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "198.51.100.99") || !strings.Contains(w.Body.String(), "aegis_inspection_duration_seconds_bucket") {
		t.Fatal("invalid or unsafe exposition", w.Code)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	if _, e := parser.TextToMetricFamilies(strings.NewReader(w.Body.String())); e != nil {
		t.Fatal("invalid Prometheus format", e)
	}
	for i := range 6000 {
		p.recordHTTP(403, fmt.Sprintf("custom:%d", i), "blocked")
	}
	if len(p.pairs) > maxRequestMetricPairs+501 || prometheusCounter(t, p, "aegis_requests_total", map[string]string{"status": "403", "rule_id": "other"}) == 0 {
		t.Fatal("unbounded label series", len(p.pairs))
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				p.recordHTTP(200, "none", "allowed")
			}
		}()
	}
	wg.Wait()
	if prometheusCounter(t, p, "aegis_requests_total", map[string]string{"status": "200", "rule_id": "none"}) != 1600 {
		t.Fatal("concurrent requests were lost")
	}
}
func TestPrometheusManagementAuthorization(t *testing.T) {
	a, _, api, _, _ := captchaFixture(t)
	server := httptest.NewTLSServer(a.Management())
	defer server.Close()
	client := server.Client()
	get := func(key string, want int) string {
		t.Helper()
		r, _ := http.NewRequest("GET", server.URL+"/metrics", nil)
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("metrics status got %d want %d: %s", response.StatusCode, want, raw)
		}
		return string(raw)
	}
	get("", 401)
	object := mustID(t, api.call("POST", "/api/address-objects", map[string]string{"name": "Metrics peer", "value": "127.0.0.1"}, 200))
	var key struct {
		ID     int64  `json:"id"`
		Secret string `json:"api_key"`
	}
	json.Unmarshal(api.call("POST", "/api/agent-keys", map[string]any{"name": "Metrics read", "allowed_addresses": addressSelection{ObjectIDs: []int64{object}}, "scopes": []string{"read"}}, 201), &key)
	raw := get(key.Secret, 200)
	if !strings.Contains(raw, "aegis_requests_total") || strings.Contains(raw, key.Secret) {
		t.Fatal("missing metrics or leaked credential")
	}
	get("invalid", 401)
	client.Jar = api.client.Jar
	get("", 200)
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.RemoteAddr = "198.51.100.1:1234"
	r.Header.Set("Authorization", "Bearer "+key.Secret)
	w := httptest.NewRecorder()
	a.metricsHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("remote HTTP bearer accepted", w.Code)
	}
	api.call("DELETE", fmt.Sprintf("/api/agent-keys/%d", key.ID), nil, 200)
	get(key.Secret, 401)
	// /metrics belongs to management; a protected host forwards that path.
	request := httptest.NewRequest("GET", "http://bot.test/metrics", nil)
	request.Header.Set("User-Agent", "browser")
	a.access = make(chan accessEvent, 1)
	a.access <- accessEvent{}
	output := httptest.NewRecorder()
	a.Public(output, request)
	if a.dropped.Load() != 1 || prometheusCounter(t, a.prom, "aegis_requests_total", map[string]string{"status": "200", "rule_id": "none"}) != 1 {
		t.Fatal("request metrics depended on logging queue")
	}
	if strings.Contains(output.Body.String(), "aegis_requests_total") || output.Body.String() != "application" {
		t.Fatal("metrics exposed through protected listener", output.Code)
	}
}
func TestPrometheusAgentMiddlewarePrivacy(t *testing.T) {
	a := &App{}
	a.prom = newGatewayTelemetry(a)
	var output bytes.Buffer
	logger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(logger)
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "get_dashboard"}, func(ctx context.Context, r *mcp.CallToolRequest, input struct {
		Secret string `json:"secret"`
	}) (*mcp.CallToolResult, any, error) {
		if input.Secret == "panic" {
			panic("must-not-be-logged")
		}
		if input.Secret != "" {
			return agentError("test denial"), nil, nil
		}
		return &mcp.CallToolResult{}, nil, nil
	})
	a.instrumentAgent(server)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ss, e := server.Connect(context.Background(), serverTransport, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, e := client.Connect(context.Background(), clientTransport, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer cs.Close()
	result, e := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_dashboard", Arguments: map[string]any{"secret": "must-not-be-logged"}})
	if e != nil || !result.IsError {
		t.Fatal("test tool failed", e)
	}
	if prometheusCounter(t, a.prom, "aegis_mcp_actions_total", map[string]string{"tool": "get_dashboard", "status": "error"}) != 1 {
		t.Fatal("missing MCP error metric")
	}
	_, e = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_dashboard", Arguments: map[string]any{"secret": ""}})
	if e != nil || prometheusCounter(t, a.prom, "aegis_mcp_actions_total", map[string]string{"tool": "get_dashboard", "status": "success"}) != 1 {
		t.Fatal("missing MCP success metric", e)
	}
	result, e = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_dashboard", Arguments: map[string]any{"secret": "panic"}})
	if e != nil || !result.IsError || prometheusCounter(t, a.prom, "aegis_mcp_actions_total", map[string]string{"tool": "get_dashboard", "status": "panic"}) != 1 {
		t.Fatal("tool panic was not contained", e)
	}
	var logged map[string]any
	if e = json.NewDecoder(bytes.NewReader(output.Bytes())).Decode(&logged); e != nil || logged["event"] != "mcp_action" || logged["tool"] != "get_dashboard" || bytes.Contains(output.Bytes(), []byte("must-not-be-logged")) {
		t.Fatal("unstructured or unsafe MCP log", e)
	}
}
