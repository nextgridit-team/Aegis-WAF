package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestAttackRegressionMatrix(t *testing.T) {
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block", BodyLimit: 4096})
	if e != nil {
		t.Fatal(e)
	}
	if closer, ok := runtime.WAF.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	a := &App{managedSlots: make(chan struct{}, 64)}
	for _, test := range []struct {
		name, query string
		attack      bool
	}{{"sqli", "1' OR '1'='1' --", true}, {"sqli_union", "1 UNION SELECT username,password FROM users--", true}, {"xss", "<script>alert(1)</script>", true}, {"xss_attribute", "<img src=x onerror=alert(1)>", true}, {"traversal", "../../../../etc/passwd", true}, {"encoded_traversal", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", true}, {"normal_search", "office address", false}, {"normal_quote", "O'Reilly books", false}, {"normal_json_text", "monthly revenue 2026", false}} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://regression.test/?q="+url.QueryEscape(test.query), nil)
			r.Header.Set("User-Agent", "Regression client")
			_, blocked, _ := a.inspectManaged(runtime, r, netip.MustParseAddr("198.51.100.1"))
			if blocked != test.attack {
				t.Fatalf("blocked=%v want=%v", blocked, test.attack)
			}
			r.Body.Close()
		})
	}
	// Prompt injection has no general CRS detector. This tests only an explicitly
	// configured native literal rule, not semantic or model-based protection.
	rule := probeRule("query", "q", "contains", "ignore previous instructions")
	compiled, e := compileRule(rule)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "http://regression.test/?q=ignore+previous+instructions", nil)
	if got := compiled.evaluate(newRequestFacts(r).get); got != "matched" {
		t.Fatal(got)
	}
}
func TestScopedSignatureExceptions(t *testing.T) {
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	options := managedSignatureOptions{SetID: set.ID, Mode: "observe", ScopedExclusions: []signatureException{{RuleIDs: []int{942100}, PathPrefix: "/search", Parameters: []string{"q"}, ClientCIDRs: []string{"198.51.100.0/24"}}}}
	runtime, e := compileManagedSignatures(set, options)
	if e != nil {
		t.Fatal(e)
	}
	if closer, ok := runtime.WAF.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	a := &App{managedSlots: make(chan struct{}, 64)}
	for _, test := range []struct {
		path, param, ip    string
		reliable, excluded bool
	}{{"/search", "q", "198.51.100.1", true, true}, {"/other", "q", "198.51.100.1", true, false}, {"/search", "other", "198.51.100.1", true, false}, {"/search", "q", "203.0.113.1", true, false}, {"/search", "q", "198.51.100.1", false, false}} {
		r := httptest.NewRequest("GET", "http://regression.test"+test.path+"?"+test.param+"="+url.QueryEscape("1' OR '1'='1' --"), nil)
		r.Header.Set("User-Agent", "Regression client")
		result, _, _ := a.inspectManaged(runtime, r, netip.MustParseAddr(test.ip), test.reliable)
		found := false
		for _, id := range result.RuleIDs {
			found = found || id == 942100
		}
		if found == test.excluded {
			t.Fatalf("%+v result %+v", test, result)
		}
		r.Body.Close()
	}
	for _, bad := range []signatureException{{RuleIDs: []int{942100}}, {RuleIDs: []int{949110}, PathPrefix: "/"}, {RuleIDs: []int{942100}, Parameters: []string{"q;ctl:ruleEngine=Off"}}} {
		if _, e = normalizeSignatureExceptions([]signatureException{bad}); e == nil {
			t.Fatal("unsafe exception accepted")
		}
	}
}

type chunkReader struct {
	data  []byte
	read  int
	chunk int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.chunk, len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	r.read += n
	return n, nil
}
func TestBodyInspectionBoundsAndReplay(t *testing.T) {
	set, _ := bundledSignatureSet()
	runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "observe", BodyLimit: 4096})
	if e != nil {
		t.Fatal(e)
	}
	if closer, ok := runtime.WAF.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	a := &App{managedSlots: make(chan struct{}, 64)}
	original := []byte("q=" + url.QueryEscape("<script>alert(1)</script>") + strings.Repeat("x", 10000))
	reader := &chunkReader{data: append([]byte{}, original...), chunk: 3}
	r := httptest.NewRequest("POST", "http://regression.test/", io.NopCloser(reader))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Regression client")
	result, blocked, _ := a.inspectManaged(runtime, r, netip.MustParseAddr("198.51.100.1"))
	if blocked || reader.read > 4097 || result.Inspection != "partial" {
		t.Fatalf("read=%d result=%+v", reader.read, result)
	}
	forwarded, e := io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil || !bytes.Equal(original, forwarded) || len(a.managedSlots) != 0 {
		t.Fatal("body changed or inspection slot leaked")
	}
	// A signature crossing tiny transport chunks still matches.
	reader = &chunkReader{data: []byte("q=" + url.QueryEscape("<script>alert(1)</script>")), chunk: 1}
	r = httptest.NewRequest("POST", "http://regression.test/", io.NopCloser(reader))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Regression client")
	result, _, _ = a.inspectManaged(runtime, r, netip.MustParseAddr("198.51.100.1"))
	r.Body.Close()
	if len(result.RuleIDs) == 0 {
		t.Fatal("chunk boundary bypass")
	}
}
func TestSecurityTelemetryPrivacy(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	event := accessEvent{blocked: true, peer: "198.51.100.1", status: 403, managed: managedSignatureResult{RuleIDs: []int{942100}}, evidence: &evidenceEvent{id: "sample", data: []byte(`{"facts":{"query:q":{"state":"present","values":["private sample"]}}}`)}}
	emitSecurityEvent(logger, event)
	var record map[string]any
	if e := json.Unmarshal(output.Bytes(), &record); e != nil || record["event"] != "waf_block" || strings.Contains(output.String(), "private sample") {
		t.Fatalf("metadata privacy %s %v", output.String(), e)
	}
	output.Reset()
	event.securitySamples = true
	emitSecurityEvent(logger, event)
	if !strings.Contains(output.String(), "private sample") {
		t.Fatal("explicit sample omitted")
	}
	output.Reset()
	event.securityDisabled = true
	emitSecurityEvent(logger, event)
	if !strings.Contains(output.String(), `"event":"waf_block"`) || strings.Contains(output.String(), "private sample") {
		t.Fatal("legacy disable setting must retain metadata but suppress payload context")
	}
}
func FuzzRequestBodyReplay(f *testing.F) {
	for _, seed := range []string{`{"q":"hello"}`, `{"q":"<script>"}`, strings.Repeat("x", 65540), `{"q":[[[[1]]]]}`, `{"q":"ignore previous instructions"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 131072 {
			t.Skip()
		}
		reader := &chunkReader{data: append([]byte{}, data...), chunk: 7}
		r := httptest.NewRequest("POST", "http://fuzz.test/", io.NopCloser(reader))
		r.ContentLength = -1
		r.Header.Set("Content-Type", "application/json")
		facts := newRequestFacts(r)
		facts.get("json_body", "/q")
		if reader.read > maxInspectionBytes+1 {
			t.Fatal("read bound exceeded")
		}
		forwarded, e := io.ReadAll(r.Body)
		r.Body.Close()
		if e != nil || !bytes.Equal(forwarded, data) {
			t.Fatal("body changed")
		}
	})
}
