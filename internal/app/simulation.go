package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type simulationTransactionKey struct{}
type simulationResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}
type simulationPayload struct {
	Host     string              `json:"host"`
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	ClientIP string              `json:"client_ip"`
	Headers  map[string]string   `json:"headers,omitempty"`
	Body     string              `json:"body,omitempty"`
	Response *simulationResponse `json:"response,omitempty"`
	Expected string              `json:"expected,omitempty"`
}
type simulationInput struct {
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	Input           json.RawMessage     `json:"input"`
	LookbackMinutes int                 `json:"lookback_minutes,omitempty"`
	MaxEvents       int                 `json:"max_events,omitempty"`
	TestPayloads    []simulationPayload `json:"test_payloads,omitempty"`
}
type simulationSummary struct {
	ID                string                    `json:"simulation_id,omitempty"`
	Version           int64                     `json:"config_version"`
	Expires           time.Time                 `json:"expires_at,omitempty"`
	Eligible          bool                      `json:"eligible_for_enforcement"`
	Sampled           int                       `json:"sampled_requests"`
	Truncated         bool                      `json:"sample_truncated"`
	PreviouslyAllowed int                       `json:"previously_allowed"`
	NewlyBlocked      int                       `json:"newly_blocked"`
	NewlyUnblocked    int                       `json:"newly_unblocked"`
	Unknown           int                       `json:"unknown"`
	Harness           []simulationHarnessResult `json:"test_results"`
	Warnings          []string                  `json:"warnings"`
}
type simulationHarnessResult struct {
	Evaluable bool    `json:"evaluable"`
	Index     int     `json:"index"`
	Outcome   string  `json:"outcome"`
	Passed    bool    `json:"passed"`
	RuleIDs   []int64 `json:"rule_ids,omitempty"`
}

func requiresRuleSimulation(pattern string) bool {
	method, path, _ := strings.Cut(pattern, " ")
	if method == "GET" {
		return false
	}
	if strings.HasPrefix(path, "/api/policies") || strings.HasPrefix(path, "/api/sites") || strings.HasPrefix(path, "/api/protection-settings") || pattern == "PUT /api/rate-state" {
		return true
	}
	if strings.HasPrefix(path, "/api/rules/") && path != "/api/rules/replay" {
		return true
	}
	if (method == "PUT" || method == "DELETE") && (strings.HasPrefix(path, "/api/address-objects/") || strings.HasPrefix(path, "/api/address-groups/")) {
		return true
	}
	return strings.HasPrefix(path, "/api/rule-feeds/") && strings.HasSuffix(path, "/import")
}
func simulationCandidateHash(method, path string, payload json.RawMessage) (string, error) {
	u, e := url.Parse(path)
	if e != nil || !strings.HasPrefix(path, "/api/") || u.IsAbs() || u.Host != "" || u.Fragment != "" || u.User != nil || strings.Contains(path, "\\") || len(path) > 2048 {
		return "", invalid("invalid simulation path")
	}
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if e = decoder.Decode(&data); e != nil || data == nil {
		return "", invalid("provide a candidate input object")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", invalid("provide one candidate input object")
	}
	canonical, e := json.Marshal(data)
	if e != nil {
		return "", e
	}
	return hash(method + "\n" + u.EscapedPath() + "?" + u.Query().Encode() + "\n" + string(canonical)), nil
}
func (a *App) consumeSimulation(ctx context.Context, tx pgx.Tx, invocation agentInvocation) error {
	if invocation.SimulationID == "" || len(invocation.SimulationID) > 128 || invocation.CandidateHash == "" {
		return apiError{428, "run simulate_rule_impact on this exact operation first and provide simulation_id"}
	}
	tag, e := tx.Exec(ctx, "UPDATE mcp_simulations SET used=true WHERE token_hash=$1 AND agent_id=$2 AND candidate_hash=$3 AND config_version=(SELECT version FROM config_version WHERE id) AND expires_at>now() AND NOT used", hash(invocation.SimulationID), invocation.Principal.ID, invocation.CandidateHash)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return apiError{428, "simulation is stale, expired, used or does not match this key and operation; simulate again"}
	}
	return nil
}
func (a *App) addAgentSimulation(server *mcp.Server, principal agentPrincipal, mux *http.ServeMux) {
	schema := map[string]any{"type": "object", "properties": map[string]any{"method": map[string]any{"type": "string", "enum": []string{"POST", "PUT", "DELETE"}}, "path": map[string]any{"type": "string", "maxLength": 2048}, "input": map[string]any{"type": "object"}, "lookback_minutes": map[string]any{"type": "integer", "minimum": 1, "maximum": 1440}, "max_events": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}, "test_payloads": map[string]any{"type": "array", "maxItems": 20, "items": map[string]any{"type": "object"}}}, "required": []string{"method", "path", "input"}, "additionalProperties": false}
	server.AddTool(&mcp.Tool{Name: "simulate_rule_impact", Description: "Validate an exact proposed live protection mutation in a rolled-back transaction, compile its prospective configuration, and test recent access metadata/authorized retained facts plus optional synthetic requests. Never sends requests upstream. Allowed does not mean legitimate; uncaptured data yields unknown. Successful meaningful simulation issues a 2-minute, single-use simulation_id bound to this key, candidate and configuration version. Provide it to the live mutation. Expected test assertions must pass.", InputSchema: schema, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		current, ok := ctx.Value(agentContextKey{}).(agentPrincipal)
		if !ok || current.ID != principal.ID {
			return agentError("permission denied"), nil
		}
		var input simulationInput
		d := json.NewDecoder(bytes.NewReader(req.Params.Arguments))
		d.DisallowUnknownFields()
		if e := d.Decode(&input); e != nil {
			return agentError("invalid simulation input"), nil
		}
		summary, e := a.simulateRuleImpact(ctx, current, mux, input)
		if e != nil {
			var api apiError
			if errors.As(e, &api) {
				return agentError(api.message), nil
			}
			return agentError("simulation unavailable; no live changes were applied"), nil
		}
		raw, _ := json.Marshal(summary)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}, nil
	})
}
func (a *App) simulateRuleImpact(parent context.Context, principal agentPrincipal, mux *http.ServeMux, input simulationInput) (simulationSummary, error) {
	result := simulationSummary{Harness: []simulationHarnessResult{}, Warnings: []string{"Recorded allowed requests are not verified legitimate traffic. Uncaptured/redacted facts remain unknown.", "Rate state, browser clearance, upstream behavior and uncaptured CRS payloads cannot be reconstructed from access metadata."}}
	if input.LookbackMinutes == 0 {
		input.LookbackMinutes = 60
	}
	if input.MaxEvents == 0 {
		input.MaxEvents = 200
	}
	if input.LookbackMinutes < 1 || input.LookbackMinutes > 1440 || input.MaxEvents < 1 || input.MaxEvents > 500 || len(input.TestPayloads) > 20 || len(input.Input) > 1<<20 {
		return result, invalid("use lookback 1–1440 minutes, at most 500 log rows, 20 tests and 1 MiB input")
	}
	digest, e := simulationCandidateHash(input.Method, input.Path, input.Input)
	if e != nil {
		return result, e
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	select {
	case a.simulationWork <- struct{}{}:
		defer func() { <-a.simulationWork }()
	default:
		return result, apiError{429, "simulation capacity busy; retry"}
	}
	request, e := http.NewRequestWithContext(ctx, input.Method, "http://internal"+input.Path, bytes.NewReader(input.Input))
	if e != nil {
		return result, invalid("invalid candidate request")
	}
	request.Header.Set("Content-Type", "application/json")
	_, pattern := mux.Handler(request)
	allowed := false
	scope := ""
	for _, operation := range agentOperations() {
		if operation.Pattern == pattern && principal.has(operation.Scope) {
			allowed = true
			scope = operation.Scope
			break
		}
	}
	if !allowed || !requiresRuleSimulation(pattern) {
		return result, invalid("select a permitted live rule, policy, host, protection or existing-address mutation")
	}
	tx, e := a.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return result, e
	}
	defer tx.Rollback(ctx)
	if e = tx.QueryRow(ctx, "SELECT version FROM config_version WHERE id").Scan(&result.Version); e != nil {
		return result, e
	}
	originalHosts := map[string]bool{}
	originalSites := map[int64]bool{}
	originalRows, e := tx.Query(ctx, "SELECT id,hostnames FROM sites WHERE enabled")
	if e != nil {
		return result, e
	}
	for originalRows.Next() {
		var id int64
		var hosts []string
		if e = originalRows.Scan(&id, &hosts); e != nil {
			originalRows.Close()
			return result, e
		}
		originalSites[id] = true
		for _, host := range hosts {
			originalHosts[host] = true
		}
	}
	e = originalRows.Err()
	originalRows.Close()
	if e != nil {
		return result, e
	}
	invocation := agentInvocation{Principal: principal, Pattern: pattern, Scope: scope, CandidateHash: digest}
	simulated := context.WithValue(ctx, simulationTransactionKey{}, tx)
	request = request.WithContext(context.WithValue(simulated, agentInvocationKey{}, invocation))
	output := &agentOutput{header: http.Header{}, status: 200}
	mux.ServeHTTP(output, request)
	if output.status >= 400 {
		return result, invalid("candidate validation failed: " + output.String())
	}
	candidate, e := a.buildSnapshot(ctx, tx, result.Version+1)
	if e != nil {
		return result, e
	}
	rows, e := tx.Query(ctx, `SELECT l.id,l.site_id,l.method,l.peer,l.country,l.blocked,CASE WHEN $3 THEN coalesce(t.data,'{}'::jsonb) ELSE '{}'::jsonb END FROM access_logs l LEFT JOIN traffic_evidence t ON t.id=l.event_id AND t.expires_at>now() WHERE l.at>now()-$1::integer*interval '1 minute' ORDER BY l.id DESC LIMIT $2`, input.LookbackMinutes, input.MaxEvents+1, principal.has("evidence"))
	if e != nil {
		return result, e
	}
	known := 0
	for rows.Next() {
		if e = ctx.Err(); e != nil {
			rows.Close()
			return result, e
		}
		var id, site int64
		var method, peer, country string
		var blocked bool
		var raw []byte
		if e = rows.Scan(&id, &site, &method, &peer, &country, &blocked, &raw); e != nil {
			rows.Close()
			return result, e
		}
		if result.Sampled == input.MaxEvents {
			result.Truncated = true
			break
		}
		result.Sampled++
		if !blocked {
			result.PreviouslyAllowed++
		}
		var evidence TrafficEvidence
		_ = json.Unmarshal(raw, &evidence)
		get := func(field, key string) Fact {
			if field == "method" {
				return Fact{State: "present", Values: []string{method}}
			}
			if field == "client_ip" {
				return Fact{State: "present", Values: []string{peer}}
			}
			if evidence.SchemaVersion == 1 {
				return evidenceFact(evidence, field, key)
			}
			return Fact{State: "unknown"}
		}
		outcome, _ := simulationMetadata(candidate, site, peer, country, get)
		if outcome == "unroutable" && !originalSites[site] {
			outcome = "unknown"
		}
		if outcome == "unknown" {
			result.Unknown++
		} else {
			known++
			if !blocked && (outcome == "block" || outcome == "unroutable") {
				result.NewlyBlocked++
			}
			if blocked && outcome == "allow" {
				result.NewlyUnblocked++
			}
		}
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return result, e
	}
	rows.Close()
	allPassed := true
	harnessApp := &App{managedSlots: make(chan struct{}, 8)}
	for i, payload := range input.TestPayloads {
		if e = ctx.Err(); e != nil {
			return result, e
		}
		outcome, ids, e := simulatePayload(ctx, harnessApp, candidate, payload)
		if e != nil {
			return result, e
		}
		if payload.Expected != "" && payload.Expected != "allow" && payload.Expected != "block" && payload.Expected != "challenge" && payload.Expected != "unroutable" {
			return result, invalid("test expected must be allow, block, challenge or unroutable")
		}
		evaluable := outcome != "unknown" && (candidate.routes[requestHost(payload.Host)] != nil || originalHosts[requestHost(payload.Host)])
		pass := evaluable && (payload.Expected == "" || payload.Expected == outcome)
		allPassed = allPassed && pass
		result.Harness = append(result.Harness, simulationHarnessResult{Index: i, Outcome: outcome, Passed: pass, RuleIDs: ids, Evaluable: evaluable})
		if evaluable {
			known++
		}
	}
	// Roll back every candidate configuration and audit write before persisting
	// only the opaque receipt and aggregate summary. No active pointer is swapped.
	if e = tx.Rollback(ctx); e != nil {
		return result, e
	}
	result.Eligible = known > 0 && allPassed
	if !result.Eligible {
		result.Warnings = append(result.Warnings, "No receipt issued: provide evaluable traffic/test payloads and resolve failed expected outcomes.")
		return result, nil
	}
	result.ID = token()
	result.Expires = time.Now().Add(2 * time.Minute)
	saved := result
	saved.ID = "" // Store only the receipt hash, never its bearer value.
	summary, _ := json.Marshal(saved)
	receiptTx, e := a.db.Begin(ctx)
	if e != nil {
		return result, e
	}
	defer receiptTx.Rollback(ctx)
	// Serialize each principal's quota across replicas. No config lock is held
	// while the offline harness runs.
	var active bool
	if e = receiptTx.QueryRow(ctx, "SELECT revoked_at IS NULL AND expires_at>now() FROM agent_keys WHERE id=$1 FOR UPDATE", principal.ID).Scan(&active); e != nil {
		return result, e
	}
	if !active {
		return result, apiError{403, "agent key is no longer active"}
	}
	if _, e = receiptTx.Exec(ctx, "DELETE FROM mcp_simulations WHERE expires_at<=now()"); e != nil {
		return result, e
	}
	tag, e := receiptTx.Exec(ctx, `INSERT INTO mcp_simulations(token_hash,agent_id,candidate_hash,config_version,expires_at,summary) SELECT $1,$2,$3,$4,$5,$6 WHERE (SELECT version FROM config_version WHERE id)=$4 AND (SELECT count(*) FROM mcp_simulations WHERE agent_id=$2)<100`, hash(result.ID), principal.ID, digest, result.Version, result.Expires, summary)
	if e != nil {
		return result, e
	}
	if tag.RowsAffected() != 1 {
		return result, apiError{409, "configuration changed or simulation quota reached; simulate again later"}
	}
	if e = receiptTx.Commit(ctx); e != nil {
		return result, e
	}
	return result, nil
}
func simulationMetadata(snapshot *snapshot, site int64, peer, country string, get func(string, string) Fact) (string, []int64) {
	var route *route
	for _, r := range snapshot.routes {
		if r.site.ID == site {
			route = r
			break
		}
	}
	if route == nil {
		return "unroutable", nil
	}
	ip, e := netip.ParseAddr(peer)
	if e != nil {
		return "unknown", nil
	}
	policy := snapshot.protection[site]
	rules := snapshot.rules[site]
	selected := selectPolicy(snapshot.policyBindings[site], ip, true)
	if selected != nil {
		policy = selected.Protection
		rules = selected.Rules
	}
	if policy != nil {
		network := policy.network.evaluate(ip, true, func() string { return country })
		if network.Blocked {
			return "block", nil
		}
		if network.BypassWAF {
			return "allow", nil
		}
	}
	unknown := false
	ids := []int64{}
	for _, rule := range rules {
		if rule.PolicyID == 0 && !time.Now().Before(rule.Expires) {
			continue
		}
		match := rule.evaluate(get)
		if match == "unknown" {
			unknown = true
		}
		if match == "matched" {
			ids = append(ids, rule.ID)
			if rule.Spec.Action == "block" {
				return "block", ids
			}
		}
	}
	if selected != nil && selected.Managed != nil {
		unknown = true
	}
	if policy != nil && (policy.Mode == "block" || policy.BotMode == "block") {
		unknown = true
	}
	if unknown {
		return "unknown", ids
	}
	return "allow", ids
}
func simulatePayload(ctx context.Context, app *App, snapshot *snapshot, payload simulationPayload) (string, []int64, error) {
	if payload.Method == "" {
		payload.Method = "GET"
	}
	if payload.Path == "" {
		payload.Path = "/"
	}
	if payload.ClientIP == "" {
		payload.ClientIP = "198.51.100.1"
	}
	if len(payload.Body) > maxInspectionBytes || len(payload.Path) > 2048 || len(payload.Headers) > 32 {
		return "", nil, invalid("bound test bodies to 64 KiB, paths to 2048 bytes and headers to 32")
	}
	parsed, e := url.ParseRequestURI(payload.Path)
	if e != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(payload.Path, "/") {
		return "", nil, invalid("provide a relative test request path")
	}
	route := snapshot.routes[requestHost(payload.Host)]
	if route == nil {
		return "unroutable", nil, nil
	}
	ip, e := netip.ParseAddr(payload.ClientIP)
	if e != nil {
		return "", nil, invalid("invalid test client IP")
	}
	request, e := http.NewRequestWithContext(ctx, payload.Method, "https://"+payload.Host+payload.Path, strings.NewReader(payload.Body))
	if e != nil {
		return "", nil, invalid("invalid test request")
	}
	for k, v := range payload.Headers {
		if len(k) > 128 || len(v) > 4096 {
			return "", nil, invalid("test header too large")
		}
		request.Header.Set(k, v)
	}
	defer func() {
		if request.Body != nil {
			request.Body.Close()
		}
	}()
	site := route.site.ID
	policy := snapshot.protection[site]
	rules := snapshot.rules[site]
	var managed *managedSignatureRuntime
	selected := selectPolicy(snapshot.policyBindings[site], ip, true)
	if selected != nil {
		policy = selected.Protection
		rules = selected.Rules
		managed = selected.Managed
	}
	if policy != nil {
		network := policy.network.evaluate(ip, true, func() string { return countryFor(snapshot.geo, ip) })
		if network.Blocked {
			return "block", nil, nil
		}
		if network.BypassWAF {
			return "allow", nil, nil
		}
	}
	_, blocked, _ := app.protectResolved(policy, site, request, ip, time.Now(), true)
	if blocked {
		return "block", nil, nil
	}
	facts := newRequestFacts(request)
	facts.facts[factKey("client_ip", "")] = Fact{State: "present", Values: []string{ip.String()}}
	results, blocked := evaluateRules(rules, facts, time.Now())
	ids := []int64{}
	for _, r := range results {
		if r.Result == "matched" {
			ids = append(ids, r.RuleID)
		}
	}
	if blocked {
		return "block", ids, nil
	}
	if managed != nil {
		result := managedSignatureResult{}
		managedBlocked := false
		state := &managedResponseState{runtime: managed, result: &result, blocked: &managedBlocked, cancel: func() {}, app: app, site: route.site, clientIP: ip, reliable: true}
		if managed.Options.ResponseMode != "off" && payload.Response != nil {
			request = request.WithContext(context.WithValue(request.Context(), managedResponseKey{}, state))
			defer state.Close()
		}
		result, blocked, _ = app.inspectManaged(managed, request, ip, true)
		if blocked {
			return "block", ids, nil
		}
		if payload.Response != nil && managed.Options.ResponseMode != "off" {
			response := payload.Response
			if len(response.Body) > maxInspectionBytes || len(response.Headers) > 32 {
				return "", nil, invalid("bound synthetic response body to 64 KiB and headers to 32")
			}
			status := response.Status
			if status == 0 {
				status = 200
			}
			if status < 200 || status > 599 {
				return "", nil, invalid("invalid synthetic response status")
			}
			headers := http.Header{}
			for k, v := range response.Headers {
				if len(k) > 128 || len(v) > 4096 {
					return "", nil, invalid("response header too large")
				}
				headers.Set(k, v)
			}
			upstream := &http.Response{StatusCode: status, Proto: "HTTP/1.1", Header: headers, Body: io.NopCloser(strings.NewReader(response.Body)), ContentLength: int64(len(response.Body)), Request: request}
			defer upstream.Body.Close()
			if e = state.inspect(upstream); e != nil {
				return "block", ids, nil
			}
			if _, e = io.Copy(io.Discard, upstream.Body); e != nil {
				return "block", ids, nil
			}
			upstream.Body.Close()
		}
	}
	if policy != nil && policy.BotChallenge.Enabled && policy.BotMode == "block" {
		score := app.botScore(policy, site, request, ip, time.Now())
		if score.Score >= score.Threshold {
			return "challenge", ids, nil
		}
	}
	return "allow", ids, nil
}
