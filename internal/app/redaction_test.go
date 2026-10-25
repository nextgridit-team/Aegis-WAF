package app

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCustomEvidenceRedactionBeforePersistence(t *testing.T) {
	settings := defaultTrafficSettings()
	settings.Enabled = true
	settings.CapturePath = true
	settings.HeaderKeys = []string{"x-customer"}
	settings.QueryKeys = []string{"q"}
	settings.RedactPatterns = []string{`(?i)customer-[0-9]+`, `[^\s@]+@[^\s@]+\.[^\s@]+`}
	if e := validateTrafficSettings(settings); e != nil {
		t.Fatal(e)
	}
	p := &capturePolicy{Settings: settings, budget: &captureBudget{}, redactors: evidenceRedactors(settings)}
	r := httptest.NewRequest("GET", "http://app.test/customer-123?q=person%40example.test", nil)
	r.Header.Set("X-Customer", "customer-123")
	event := p.capture(newRequestFacts(r), nil, time.Now())
	if event == nil {
		t.Fatal("missing sample")
	}
	if strings.Contains(string(event.data), "customer-123") || strings.Contains(string(event.data), "person@") {
		t.Fatal("PII retained in stored sample")
	}
	var evidence TrafficEvidence
	if e := json.Unmarshal(event.data, &evidence); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"path:", "header:x-customer", "query:q"} {
		if evidence.Facts[key].State != "redacted" {
			t.Fatal("redaction not reflected in replay facts", key, evidence.Facts[key])
		}
	}
	settings.RedactPatterns = []string{"["}
	if validateTrafficSettings(settings) == nil {
		t.Fatal("invalid regex accepted")
	}
}
