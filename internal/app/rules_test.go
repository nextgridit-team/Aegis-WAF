package app

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func probeRule(field, key, op string, value any) RuleSpec {
	v, _ := json.Marshal(value)
	return RuleSpec{SchemaVersion: 1, Name: "Probe", Scope: RuleScope{SiteID: 1}, All: []RuleCondition{{Field: field, Key: key, Op: op, Value: v}}, Action: "block", TTLSeconds: 60}
}
func mustCompileRule(t *testing.T, s RuleSpec) compiledRule {
	t.Helper()
	r, e := compileRule(s)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestRuleValidation(t *testing.T) {
	for _, s := range []RuleSpec{probeRule("path", "", "regex", `(?=evil)`), probeRule("path", "", "regex", `(x)\1`), probeRule("header", "Authorization", "equals", "x"), probeRule("query", "access_token", "equals", "x"), probeRule("json_body", "/password", "equals", "x"), probeRule("header", "X-Forwarded-For", "equals", "x"), probeRule("method", "", "contains", "GET"), probeRule("path", "", "cidr", "127.0.0.0/8"), probeRule("client_ip", "", "equals", "127.0.0.1"), probeRule("path", "", "in", []any{"x", 2}), probeRule("path", "", "exec", "x"), probeRule("json_body", "/a~2b", "equals", "x")} {
		if _, e := compileRule(s); e == nil {
			t.Errorf("accepted invalid spec: %+v", s)
		}
	}
	for _, mutate := range []func(*RuleSpec){func(s *RuleSpec) { s.All = nil }, func(s *RuleSpec) { s.TTLSeconds = 59 }, func(s *RuleSpec) { s.TTLSeconds = 86401 }, func(s *RuleSpec) { s.Scope.SiteID = 0 }, func(s *RuleSpec) { s.Action = "execute" }, func(s *RuleSpec) { s.SchemaVersion = 2 }} {
		s := probeRule("path", "", "equals", "/.env")
		mutate(&s)
		if _, e := compileRule(s); e == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}
func TestRuleFactsAndMatching(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.test/%252eenv?q=safe&q=evil+value", nil)
	r.RemoteAddr = "[::ffff:192.0.2.4]:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	r.Header.Set("User-Agent", "scanner")
	f := newRequestFacts(r)
	for _, tc := range []struct {
		s    RuleSpec
		want string
	}{{probeRule("path", "", "equals", "/%2eenv"), "matched"}, {probeRule("path", "", "equals", "/.env"), "not_matched"}, {probeRule("query", "q", "contains", "evil value"), "matched"}, {probeRule("header", "user-agent", "regex", "^scan"), "matched"}, {probeRule("client_ip", "", "cidr", "192.0.2.0/24"), "matched"}, {probeRule("client_ip", "", "cidr", "::ffff:192.0.2.0/120"), "matched"}, {probeRule("client_ip", "", "cidr", "203.0.113.0/24"), "not_matched"}, {probeRule("method", "", "in", []string{"POST", "GET"}), "matched"}} {
		c := mustCompileRule(t, tc.s)
		if got := c.evaluate(f.get); got != tc.want {
			t.Errorf("%+v: got %s", tc.s, got)
		}
	}
	invalid := httptest.NewRequest("GET", "http://app.test/?q=%zz", nil)
	if got := newRequestFacts(invalid).get("query", "q"); got.State != "invalid" {
		t.Fatal(got)
	}
	c := mustCompileRule(t, probeRule("path", "", "equals", "/.env"))
	if got := c.evaluate(func(string, string) Fact { return Fact{State: "unavailable"} }); got != "unknown" {
		t.Fatal(got)
	}
	c.Spec.Scope.PathPrefix = "/api/"
	if got := c.evaluate(f.get); got != "not_matched" {
		t.Fatal(got)
	}
	s := probeRule("query", "q", "equals", "x")
	s.All = append(s.All, probeRule("method", "", "equals", "POST").All...)
	c = mustCompileRule(t, s)
	if got := c.evaluate(func(field, key string) Fact {
		if field == "method" {
			return Fact{State: "present", Values: []string{"GET"}}
		}
		return Fact{State: "unavailable"}
	}); got != "not_matched" {
		t.Fatal(got)
	}
}
func TestInspectionPreservesRequestBody(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		chunked          bool
	}{{"valid", `{"file":"evil","items":[{"name":"ok"}]}`, "present", false}, {"duplicate", `{"file":"safe","file":"evil"}`, "invalid", false}, {"trailing", `{"file":"x"} {}`, "invalid", false}, {"malformed", `{"file":`, "invalid", false}, {"large", `{"file":"` + strings.Repeat("x", maxInspectionBytes) + `"}`, "truncated", false}, {"chunked-large", strings.Repeat("x", maxInspectionBytes+100), "truncated", true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://app.test", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.chunked {
				r.ContentLength = -1
			}
			f := newRequestFacts(r)
			fact := f.get("json_body", "/file")
			if fact.State != tc.want {
				t.Fatal(fact)
			}
			if tc.name == "valid" && f.get("json_body", "/items/0/name").Values[0] != "ok" {
				t.Fatal("array pointer failed")
			}
			body, e := io.ReadAll(r.Body)
			if e != nil || string(body) != tc.body {
				t.Fatal("inspection altered upstream body")
			}
		})
	}
	r := httptest.NewRequest("POST", "http://app.test", strings.NewReader(`{"file":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	f := newRequestFacts(r)
	mustCompileRule(t, probeRule("method", "", "equals", "POST")).evaluate(f.get)
	if f.bodyDone {
		t.Fatal("unnecessary body read")
	}
}
func TestRuleExpiryAndUnknownNeverBlock(t *testing.T) {
	now := time.Now()
	r := httptest.NewRequest("GET", "http://app.test/.env", nil)
	c := mustCompileRule(t, probeRule("path", "", "equals", "/.env"))
	c.ID = 1
	c.Expires = now.Add(time.Second)
	if _, blocked := evaluateRules([]compiledRule{c}, newRequestFacts(r), now); !blocked {
		t.Fatal("matching block ignored")
	}
	if results, blocked := evaluateRules([]compiledRule{c}, newRequestFacts(r), now.Add(time.Second)); blocked || len(results) > 0 {
		t.Fatal("expired rule enforced")
	}
	c = mustCompileRule(t, probeRule("json_body", "/file", "equals", "x"))
	c.Expires = now.Add(time.Second)
	results, blocked := evaluateRules([]compiledRule{c}, newRequestFacts(r), now)
	if blocked || len(results) != 1 || results[0].Result != "unknown" {
		t.Fatal(results, blocked)
	}
}
func TestEvidencePrivacyAndBudgets(t *testing.T) {
	now := time.Now()
	r := httptest.NewRequest("GET", "http://app.test/reset/123456789012345678901234?q=Bearer+abc123&password=never-store", nil)
	r.Header.Set("Authorization", "Bearer private")
	r.Header.Set("Cookie", "session=private")
	f := newRequestFacts(r)
	var off *capturePolicy
	if off.capture(f, nil, now) != nil {
		t.Fatal("nil capture enabled")
	}
	s := defaultTrafficSettings()
	s.Enabled = true
	s.CapturePath = true
	s.QueryKeys = []string{"q"}
	s.MaxPerMinute = 1
	p := &capturePolicy{s, &captureBudget{}}
	ev := p.capture(f, nil, now)
	if ev == nil {
		t.Fatal("missing evidence")
	}
	if strings.Contains(string(ev.data), "abc123") || strings.Contains(string(ev.data), "never-store") || strings.Contains(string(ev.data), "123456789012345678901234") {
		t.Fatal(string(ev.data))
	}
	var evidence TrafficEvidence
	json.Unmarshal(ev.data, &evidence)
	if evidence.Facts["query:q"].State != "redacted" || evidence.Facts["path:"].State != "redacted" {
		t.Fatal(evidence)
	}
	if evidenceFact(evidence, "query", "not_selected").State != "unavailable" {
		t.Fatal("uncaptured fact treated as missing")
	}
	if p.capture(f, nil, now) != nil {
		t.Fatal("sampling cap exceeded")
	}
	if p.capture(f, nil, now.Add(time.Minute)) == nil {
		t.Fatal("budget not reset")
	}
	s.HeaderKeys = []string{"authorization"}
	if validateTrafficSettings(s) == nil {
		t.Fatal("sensitive capture accepted")
	}
	truncated := capturedFact("query", Fact{State: "present", Values: []string{strings.Repeat("é", 200)}})
	if truncated.State != "truncated" || len(truncated.Values[0]) > 192 {
		t.Fatal(truncated)
	}
}

func TestCaptureRequiresExplicitAllowlists(t *testing.T) {
	s := defaultTrafficSettings()
	s.QueryKeys = nil
	if validateTrafficSettings(s) == nil {
		t.Fatal("accepted null allowlist that cannot round-trip through the dashboard")
	}
}
