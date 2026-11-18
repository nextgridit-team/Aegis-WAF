package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Regression for #81: opt-in evidence capture copies raw request bytes into
// TrafficEvidence.Facts. json.Marshal escapes NUL as \u0000 and PostgreSQL jsonb
// rejects that escape (SQLSTATE 22P05), so a %00 path on a capture-enabled site
// failed the traffic_evidence CopyFrom inside storeAccessBatch's transaction
// and rolled back the WHOLE batch — including the already-copied access_logs
// rows of a valid sibling. Captured fact values must be NUL-free, mirroring
// the #75 path_class strip: the %00 event and its valid sibling must both
// store, and the evidence row must carry the path with the NUL stripped.
func TestEvidenceNULPathFactStoresThroughBatch(t *testing.T) {
	cfg := testDB(t)
	aDB := newTestReplica(t, cfg)
	ctx := context.Background()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	// Evidence rows are only stored for sites that exist: storeAccessBatch
	// locks the parent site FOR KEY SHARE before copying traffic_evidence.
	var site int64
	if e := aDB.db.QueryRow(ctx, "INSERT INTO sites(name, hostnames, upstream) VALUES('capture app', '{app.example.com}', $1) RETURNING id", up.URL).Scan(&site); e != nil {
		t.Fatal(e)
	}
	settings := defaultTrafficSettings()
	settings.Enabled = true
	settings.CapturePath = true
	aPub := &App{access: make(chan accessEvent, 10), captureSlots: make(chan struct{}, 4)}
	aPub.active.Store(&snapshot{version: 1,
		routes:  map[string]*route{"app.example.com": {site: Site{ID: site, Name: "capture app"}, proxy: newProxy(u, true)}},
		capture: map[int64]*capturePolicy{site: {Settings: settings, budget: &captureBudget{}}}})
	// A valid sibling rides the same storeAccessBatch as the %00-path event:
	// while the traffic_evidence CopyFrom can be poisoned, this sibling's
	// already-copied access row dies in the same transaction rollback.
	sib := httptest.NewRequest("GET", "http://app.example.com/api/items/42", nil)
	sib.RemoteAddr = "192.0.2.10:1234"
	aPub.Public(httptest.NewRecorder(), sib)
	sibling := <-aPub.access

	r := httptest.NewRequest("GET", "http://app.example.com/secret%00data", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	aPub.Public(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	event := <-aPub.access
	batch := []accessEvent{sibling, event}
	if e := aDB.storeAccessBatch(ctx, batch); e != nil {
		t.Fatalf("batch store failed: %v", e)
	}
	// Both access rows persisted: the %00-path event and the valid sibling
	// that shared its batch.
	for _, ev := range batch {
		var count int
		if e := aDB.db.QueryRow(ctx, "SELECT count(*) FROM access_logs WHERE request_id=$1", ev.requestID).Scan(&count); e != nil || count != 1 {
			t.Fatalf("access row for %q not stored (count %d, err %v)", ev.requestID, count, e)
		}
	}
	// The evidence sample for the %00 request stored, with the NUL stripped
	// from the captured path fact rather than dropped with the batch.
	if batch[1].evidence == nil {
		t.Fatal("evidence event not prepared")
	}
	var data []byte
	if e := aDB.db.QueryRow(ctx, "SELECT data FROM traffic_evidence WHERE id=$1", batch[1].evidence.id).Scan(&data); e != nil {
		t.Fatalf("evidence row not stored: %v", e)
	}
	if i := strings.IndexByte(string(data), 0); i >= 0 {
		t.Fatalf("stored evidence still carries a NUL byte at %d: %s", i, data)
	}
	var evidence TrafficEvidence
	if e := json.Unmarshal(data, &evidence); e != nil {
		t.Fatal(e)
	}
	if got := evidence.Facts[factKey("path", "")]; got.State != "present" || len(got.Values) != 1 || got.Values[0] != "/secretdata" {
		t.Fatalf("captured path fact = %+v, want present values [\"/secretdata\"]", got)
	}
	// The clean-path control from the issue's reproduction: the sibling's own
	// evidence sample stores through the same batch.
	if batch[0].evidence == nil {
		t.Fatal("sibling evidence event not prepared")
	}
	var control int
	if e := aDB.db.QueryRow(ctx, "SELECT count(*) FROM traffic_evidence WHERE id=$1", batch[0].evidence.id).Scan(&control); e != nil || control != 1 {
		t.Fatalf("clean-path control evidence not stored (count %d, err %v)", control, e)
	}
}

// The strip must hold on every captured fact family, not just the path: query
// values, JSON body values and header values arrive percent- or JSON-decoded
// and can carry NUL just like a %00 path, and every one of them reaches the
// same jsonb column.
func TestCapturedFactStripsNULFromEveryField(t *testing.T) {
	for _, field := range []string{"method", "client_ip", "client_fingerprint", "path", "query", "header", "json_body"} {
		fact := capturedFact(field, Fact{State: "present", Values: []string{"a\x00b", "\x00"}})
		if fact.State != "present" || len(fact.Values) != 2 {
			t.Fatalf("%s: fact = %+v", field, fact)
		}
		for i, value := range fact.Values {
			if strings.IndexByte(value, 0) >= 0 {
				t.Fatalf("%s: value %d %q still carries a NUL byte", field, i, value)
			}
		}
		if fact.Values[0] != "ab" || fact.Values[1] != "" {
			t.Fatalf("%s: values = %q, want [\"ab\" \"\"]", field, fact.Values)
		}
	}
	// The custom-redaction path funnels through the same strip: a redactor
	// that does not match must not leave the NUL in place either.
	settings := defaultTrafficSettings()
	settings.RedactPatterns = []string{`secret-[0-9]+`}
	p := &capturePolicy{Settings: settings, redactors: evidenceRedactors(settings)}
	fact := p.captureFact("query", Fact{State: "present", Values: []string{"keep\x00me"}})
	if len(fact.Values) != 1 || fact.Values[0] != "keepme" {
		t.Fatalf("redactor path value = %q, want \"keepme\"", fact.Values)
	}
}
