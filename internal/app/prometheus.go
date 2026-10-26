package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxRequestMetricPairs = 4096

type requestMetricPair struct {
	status int
	rule   string
}
type gatewayTelemetry struct {
	registry   *prometheus.Registry
	handler    http.Handler
	requests   *prometheus.CounterVec
	decisions  *prometheus.CounterVec
	inspection *prometheus.HistogramVec
	actions    *prometheus.CounterVec
	mu         sync.Mutex
	pairs      map[requestMetricPair]prometheus.Counter
}

func newGatewayTelemetry(a *App) *gatewayTelemetry {
	registry := prometheus.NewRegistry()
	p := &gatewayTelemetry{registry: registry, pairs: map[requestMetricPair]prometheus.Counter{}, requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegis_requests_total", Help: "Completed public HTTP requests, counted once with one primary rule attribution; overflow IDs use other."}, []string{"status", "rule_id"}), decisions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegis_decisions_total", Help: "Completed public request decisions: allowed, blocked or challenged."}, []string{"action"}), inspection: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "aegis_inspection_duration_seconds", Help: "Inspection phase duration including bounded body reads and counter checks; excludes the upstream round trip. Streaming windows are separate samples.", Buckets: []float64{.00001, .00005, .0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}}, []string{"phase"}), actions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegis_mcp_actions_total", Help: "Dispatched MCP tool calls by bounded tool name and completion status."}, []string{"tool", "status"})}
	registry.MustRegister(p.requests, p.decisions, p.inspection, p.actions, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "aegis_access_logs_dropped", Help: "Requests whose access logging was dropped since process startup."}, func() float64 { return float64(a.dropped.Load()) }), prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "aegis_configuration_version", Help: "This replica's active configuration version."}, func() float64 {
		if s := a.active.Load(); s != nil {
			return float64(s.version)
		}
		return 0
	}))
	for _, phase := range []string{"request", "response", "stream_window"} {
		p.inspection.WithLabelValues(phase)
	}
	for _, action := range []string{"allowed", "blocked", "challenged"} {
		p.decisions.WithLabelValues(action)
	}
	p.actions.WithLabelValues("unknown", "error")
	p.pairs[requestMetricPair{200, "none"}] = p.requests.WithLabelValues("200", "none")
	p.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{DisableCompression: true, MaxRequestsInFlight: 4, Timeout: 5 * time.Second})
	return p
}
func (p *gatewayTelemetry) observeInspection(phase string, duration time.Duration) {
	if p != nil {
		p.inspection.WithLabelValues(phase).Observe(duration.Seconds())
	}
}
func (p *gatewayTelemetry) recordHTTP(status int, rule, action string) {
	if p == nil {
		return
	}
	if status < 100 || status > 599 {
		status = 0
	}
	key := requestMetricPair{status, rule}
	p.mu.Lock()
	counter := p.pairs[key]
	if counter == nil {
		if len(p.pairs) >= maxRequestMetricPairs {
			key.rule = "other"
			counter = p.pairs[key]
		}
		if counter == nil {
			counter = p.requests.WithLabelValues(strconv.Itoa(key.status), key.rule)
			p.pairs[key] = counter
		}
	}
	p.mu.Unlock()
	counter.Inc()
	p.decisions.WithLabelValues(action).Inc()
}
func (p *gatewayTelemetry) observeEvent(event accessEvent) {
	if p == nil {
		return
	}
	rule := "none"
	var native int64
	for _, match := range event.results {
		if match.Result == "matched" && match.RuleID > 0 && (native == 0 || match.RuleID < native) {
			native = match.RuleID
		}
	}
	if native > 0 {
		rule = "custom:" + strconv.FormatInt(native, 10)
	} else {
		var signature int
		for _, id := range event.managed.RuleIDs {
			if id > 0 && (signature == 0 || id < signature) {
				signature = id
			}
		}
		if signature > 0 {
			rule = "crs:" + strconv.Itoa(signature)
		} else if event.network.Blocked || event.network.WouldBlock {
			rule = "network"
		} else if event.bot.Decision != "" && event.bot.Decision != "allow" {
			rule = "bot"
		} else if len(event.signals) > 0 {
			rule = "signal"
		}
	}
	action := "allowed"
	if event.blocked {
		action = "blocked"
	}
	if event.bot.Decision == "challenge" {
		action = "challenged"
	}
	p.recordHTTP(event.status, rule, action)
}
func boundedAgentTool(name string) string {
	switch name {
	case "list_signature_sets", "get_dashboard", "list_applications", "list_policies", "list_rules", "get_rule_schema", "list_access_logs", "get_request_details", "list_evidence", "replay_rule", "propose_rule", "activate_rule", "disable_rule", "save_policy", "list_management_operations", "management_operation", "get_management_contract", "get_agent_skill", "simulate_rule_impact":
		return name
	}
	return "unknown"
}
func (a *App) instrumentAgent(server *mcp.Server) {
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (result mcp.Result, err error) {
			if method != "tools/call" {
				return next(ctx, method, request)
			}
			tool := "unknown"
			if args, ok := request.GetParams().(*mcp.CallToolParamsRaw); ok && args != nil {
				tool = boundedAgentTool(args.Name)
			}
			start := time.Now()
			status := "panic"
			defer func() {
				if recover() != nil {
					result = agentError("tool failed; refresh state before retrying")
					err = nil
					status = "panic"
				}
				if a.prom != nil {
					a.prom.actions.WithLabelValues(tool, status).Inc()
				}
				principal, _ := ctx.Value(agentContextKey{}).(agentPrincipal)
				slog.InfoContext(ctx, "agent action completed", "schema_version", 1, "event", "mcp_action", "timestamp", time.Now().UTC(), "tool", tool, "status", status, "agent_key_id", principal.ID, "duration_ms", time.Since(start).Milliseconds())
			}()
			result, err = next(ctx, method, request)
			status = "success"
			if err != nil {
				status = "error"
			}
			if called, ok := result.(*mcp.CallToolResult); ok && called != nil && called.IsError {
				status = "error"
			}
			return result, err
		}
	})
}
func (a *App) serveMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.prom == nil {
		http.Error(w, "metrics unavailable", 503)
		return
	}
	a.prom.handler.ServeHTTP(w, r)
}
func (a *App) metricsHandler() http.Handler {
	session := a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error { a.serveMetrics(w, r); return nil })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			session.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if _, e := a.authenticateAgent(r, false); e != nil {
			var api apiError
			if errors.As(e, &api) {
				respond(w, api.status, map[string]string{"error": api.message})
			} else {
				respond(w, 503, map[string]string{"error": "metrics authorization unavailable"})
			}
			return
		}
		a.serveMetrics(w, r)
	})
}
