package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestFullAccessQueueNeverBlocksAction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "forwarded") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	for _, blocking := range []bool{false, true} {
		a := &App{access: make(chan accessEvent, 1)}
		a.access <- accessEvent{}
		snapshot := &snapshot{routes: map[string]*route{"queue.test": {site: Site{ID: 1}, proxy: newProxy(target, true)}}}
		if blocking {
			s := defaultProtection()
			s.BotMode = "block"
			p, _ := compileProtection(s)
			snapshot.protection = map[int64]*protectionPolicy{1: p}
		}
		a.active.Store(snapshot)
		done := make(chan int, 1)
		go func() {
			r := httptest.NewRequest("GET", "http://queue.test/", nil)
			r.Header.Set("User-Agent", "sqlmap")
			w := httptest.NewRecorder()
			a.Public(w, r)
			done <- w.Code
		}()
		select {
		case status := <-done:
			want := 200
			if blocking {
				want = 403
			}
			if status != want || a.dropped.Load() != 1 {
				t.Fatal("action/log saturation mismatch", status, a.dropped.Load())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("full logging queue blocked traffic action")
		}
	}
}

type unreadableLogBody struct{}

func (unreadableLogBody) Read([]byte) (int, error) {
	panic("logging read the request body before forwarding")
}
func (unreadableLogBody) Close() error { return nil }
func TestEvidenceDoesNotReadAheadAndEnrichesAfterAction(t *testing.T) {
	settings := defaultTrafficSettings()
	settings.Enabled = true
	settings.JSONBodyKeys = []string{"/name"}
	p := &capturePolicy{Settings: settings, budget: &captureBudget{}}
	a := &App{captureSlots: make(chan struct{}, 1)}
	r := httptest.NewRequest("POST", "http://app.test/", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Body = unreadableLogBody{}
	facts := newRequestFacts(r)
	work := a.deferEvidence(p, facts, nil, time.Now(), 1)
	if work == nil {
		t.Fatal("missing capture reservation")
	}
	prepared := work.finish()
	if prepared == nil {
		t.Fatal("missing deferred preparation")
	}
	event := accessEvent{prepareEvidence: prepared}
	if event.evidence != nil {
		t.Fatal("evidence prepared on forwarding path")
	}
	event.enrich()
	if event.evidence == nil || len(a.captureSlots) != 0 {
		t.Fatal("background evidence preparation/release failed")
	}
	r = httptest.NewRequest("POST", "http://app.test/", strings.NewReader(`{"name":"sample"}`))
	r.Header.Set("Content-Type", "application/json")
	facts = newRequestFacts(r)
	work = a.deferEvidence(p, facts, nil, time.Now(), 1)
	if work == nil {
		t.Fatal("missing second capture")
	}
	raw, e := io.ReadAll(r.Body)
	if e != nil || string(raw) != `{"name":"sample"}` {
		t.Fatal("tap changed bytes")
	}
	event = accessEvent{prepareEvidence: work.finish()}
	event.enrich()
	if event.evidence == nil || !strings.Contains(string(event.evidence.data), "sample") {
		t.Fatal("consumed body not captured in background")
	}
}
