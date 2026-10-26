package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Called from the bounded logging worker after the request action. Never write
// stdout or wait for a log sink from the forwarding goroutine.
func emitSecurityEvent(logger *slog.Logger, e accessEvent) {
	if e.securityDisabled {
		return
	}
	ids := []int64{}
	triggers := []string{}
	seen := map[string]bool{}
	add := func(value string) {
		if !seen[value] {
			seen[value] = true
			triggers = append(triggers, value)
		}
	}
	for _, r := range e.results {
		if r.Result == "matched" {
			ids = append(ids, r.RuleID)
			add(fmt.Sprintf("custom:%d", r.RuleID))
		}
	}
	signatureIDs := e.managed.RuleIDs
	if signatureIDs == nil {
		signatureIDs = []int{}
	}
	for _, id := range signatureIDs {
		add(fmt.Sprintf("crs:%d", id))
	}
	signals := e.signals
	if signals == nil {
		signals = []string{}
	}
	for _, signal := range signals {
		add("signal:" + signal)
	}
	if !e.blocked && len(signals) == 0 && len(ids) == 0 && len(signatureIDs) == 0 && !e.network.BypassWAF {
		return
	}
	kind, action := "waf_observe", "observed"
	if e.blocked {
		kind, action = "waf_block", "blocked"
	} else if e.network.BypassWAF {
		kind, action = "waf_allow", "allowed"
	}
	if e.network.Decision != "" && (e.network.Blocked || e.network.WouldBlock || e.network.BypassWAF) {
		add("network:" + e.network.Decision)
	}
	if e.managed.Inspection != "" && e.managed.Inspection != "complete" {
		add("inspection:" + e.managed.Inspection)
	}
	if e.blocked && len(triggers) == 0 {
		add("waf:unspecified")
	}
	var payload *string
	source := "disabled"
	truncated := false
	if e.securitySamples {
		source = "unavailable"
		if e.evidence != nil {
			var sample TrafficEvidence
			if json.Unmarshal(e.evidence.data, &sample) == nil && len(sample.Facts) > 0 {
				raw, _ := json.Marshal(sample.Facts)
				text := truncateUTF8(string(raw), 2048)
				payload = &text
				truncated = len(raw) > len(text)
				source = "redacted_request_context"
			}
		}
	}
	responseSource := e.responseSource
	if responseSource == "" {
		if e.blocked {
			responseSource = "waf"
		} else {
			responseSource = "unknown"
		}
	}
	attrs := []slog.Attr{
		slog.Int("schema_version", 1), slog.String("event", kind), slog.String("action", action), slog.Time("timestamp", e.at.UTC()), slog.Time("request_at", e.at),
		slog.Int64("site_id", e.site), slog.Int64("policy_id", e.policyID), slog.Int64("policy_revision", e.policyRevision), slog.String("client_ip", e.peer), slog.String("method", e.method), slog.Int("status", e.status), slog.String("response_source", responseSource), slog.Int64("duration_ms", e.duration),
		slog.Any("rule_triggered", triggers), slog.Any("matched_payload", payload), slog.String("matched_payload_source", source), slog.Bool("payload_truncated", truncated),
		slog.Any("rule_ids", ids), slog.Any("signature_ids", signatureIDs), slog.Any("signals", signals), slog.Any("network_access", e.network), slog.Any("bot", e.bot),
	}
	if e.evidence != nil {
		attrs = append(attrs, slog.String("evidence_id", e.evidence.id))
	}
	if payload != nil {
		attrs = append(attrs, slog.String("request_sample", *payload))
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "security decision", attrs...)
}
