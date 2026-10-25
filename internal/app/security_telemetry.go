package app

import (
	"context"
	"encoding/json"
	"log/slog"
)

// Called from the bounded logging worker after the request action. Never write
// stdout or wait for a log sink from the forwarding goroutine.
func emitSecurityEvent(logger *slog.Logger, e accessEvent) {
	if e.securityDisabled {
		return
	}
	ids := []int64{}
	for _, r := range e.results {
		if r.Result == "matched" {
			ids = append(ids, r.RuleID)
		}
	}
	if !e.blocked && len(e.signals) == 0 && len(ids) == 0 && !e.network.BypassWAF {
		return
	}
	kind := "waf_observe"
	if e.blocked {
		kind = "waf_block"
	} else if e.network.BypassWAF {
		kind = "waf_allow"
	}
	attrs := []slog.Attr{slog.String("event", kind), slog.Time("request_at", e.at), slog.Int64("site_id", e.site), slog.Int64("policy_id", e.policyID), slog.Int64("policy_revision", e.policyRevision), slog.String("client_ip", e.peer), slog.String("method", e.method), slog.Int("status", e.status), slog.Any("rule_ids", ids), slog.Any("signature_ids", e.managed.RuleIDs), slog.Any("signals", e.signals), slog.Any("network_access", e.network)}
	if e.evidence != nil {
		attrs = append(attrs, slog.String("evidence_id", e.evidence.id))
		if e.securitySamples {
			var sample TrafficEvidence
			if json.Unmarshal(e.evidence.data, &sample) == nil {
				raw, _ := json.Marshal(sample.Facts)
				attrs = append(attrs, slog.String("request_sample", truncateUTF8(string(raw), 2048)))
			}
		}
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "security decision", attrs...)
}
