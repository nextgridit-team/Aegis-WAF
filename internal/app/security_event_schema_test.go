package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestBlockEventSchema(t *testing.T) {
	for name, event := range map[string]accessEvent{
		"custom":     {results: []RuleResult{{RuleID: 7, Result: "matched", Action: "block"}}},
		"managed":    {managed: managedSignatureResult{RuleIDs: []int{942100}, Inspection: "complete"}},
		"flood":      {signals: []string{"client_rate_limit"}},
		"network":    {network: networkAccessResult{Decision: "cidr_block", Blocked: true}},
		"inspection": {managed: managedSignatureResult{Inspection: "body_limit"}},
		"fallback":   {},
	} {
		t.Run(name, func(t *testing.T) {
			event.blocked = true
			event.peer = "198.51.100.1"
			event.at = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
			event.status = 403
			var output bytes.Buffer
			emitSecurityEvent(slog.New(slog.NewJSONHandler(&output, nil)), event)
			var record map[string]any
			if e := json.Unmarshal(output.Bytes(), &record); e != nil {
				t.Fatal(e)
			}
			for _, key := range []string{"schema_version", "timestamp", "client_ip", "rule_triggered", "matched_payload", "matched_payload_source", "payload_truncated", "action"} {
				if _, ok := record[key]; !ok {
					t.Fatalf("missing %s: %s", key, output.String())
				}
			}
			if record["schema_version"] != float64(1) || record["action"] != "blocked" || record["event"] != "waf_block" || record["matched_payload"] != nil || record["matched_payload_source"] != "disabled" {
				t.Fatalf("invalid block schema: %s", output.String())
			}
			if _, e := time.Parse(time.RFC3339Nano, record["timestamp"].(string)); e != nil {
				t.Fatal(e)
			}
			if len(record["rule_triggered"].([]any)) == 0 {
				t.Fatal("block reason missing")
			}
			for _, key := range []string{"rule_ids", "signature_ids", "signals"} {
				if _, ok := record[key].([]any); !ok {
					t.Fatalf("%s is not a stable array", key)
				}
			}
		})
	}
}
func TestSecuritySampleSchema(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	event := accessEvent{blocked: true, securitySamples: true}
	emitSecurityEvent(logger, event)
	if !strings.Contains(output.String(), `"matched_payload":null`) || !strings.Contains(output.String(), `"matched_payload_source":"unavailable"`) {
		t.Fatal(output.String())
	}
	facts := TrafficEvidence{Facts: map[string]Fact{"query:q": {State: "present", Values: []string{strings.Repeat("x", 4096)}}}}
	raw, _ := json.Marshal(facts)
	event.evidence = &evidenceEvent{id: "evidence", data: raw}
	output.Reset()
	emitSecurityEvent(logger, event)
	var record map[string]any
	json.Unmarshal(output.Bytes(), &record)
	if len(record["matched_payload"].(string)) > 2048 || record["payload_truncated"] != true || record["matched_payload_source"] != "redacted_request_context" || record["matched_payload"] != record["request_sample"] {
		t.Fatal(output.String())
	}
	output.Reset()
	event = accessEvent{managed: managedSignatureResult{RuleIDs: []int{942100}}}
	emitSecurityEvent(logger, event)
	if !strings.Contains(output.String(), `"action":"observed"`) {
		t.Fatal("managed observe matches were not emitted")
	}
	output.Reset()
	emitSecurityEvent(logger, accessEvent{status: 403, responseSource: "upstream"})
	if !strings.Contains(output.String(), `"event":"http_access"`) || !strings.Contains(output.String(), `"action":"allowed"`) {
		t.Fatal("upstream 403 was mislabeled as a WAF block")
	}
}
