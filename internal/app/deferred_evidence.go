package app

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A tap copies at most the inspection limit while the upstream consumes the
// request. It never reads ahead to prepare a log. A response before EOF yields
// unavailable evidence rather than waiting on the remaining client body.
type evidenceTap struct {
	io.ReadCloser
	mu          sync.Mutex
	data        []byte
	total       int64
	eof, sealed bool
}

func (t *evidenceTap) Read(p []byte) (int, error) {
	n, e := t.ReadCloser.Read(p)
	t.mu.Lock()
	if !t.sealed {
		t.total += int64(n)
		space := maxInspectionBytes + 1 - len(t.data)
		if space > 0 {
			t.data = append(t.data, p[:min(n, space)]...)
		}
		if e == io.EOF {
			t.eof = true
		}
	}
	t.mu.Unlock()
	return n, e
}
func (t *evidenceTap) finish(length int64) ([]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sealed = true
	data := t.data
	t.data = nil
	return data, t.eof || (length >= 0 && t.total == length)
}

type deferredEvidence struct {
	redactors []*regexp.Regexp
	settings  TrafficSettings
	facts     *requestFacts
	tap       *evidenceTap
	results   []RuleResult
	at        time.Time
	site      int64
	slots     chan struct{}
	once      sync.Once
}

func (a *App) deferEvidence(p *capturePolicy, f *requestFacts, results []RuleResult, now time.Time, site int64) *deferredEvidence {
	if !p.permit(now) {
		return nil
	}
	if a.captureSlots == nil {
		a.evidenceDropped.Add(1)
		return nil
	}
	select {
	case a.captureSlots <- struct{}{}:
	default:
		a.evidenceDropped.Add(1)
		return nil
	}
	work := &deferredEvidence{redactors: p.redactors, settings: p.Settings, facts: f, results: results, at: now, site: site, slots: a.captureSlots}
	if len(p.Settings.JSONBodyKeys) > 0 && !f.bodyDone && f.request.Body != nil {
		work.tap = &evidenceTap{ReadCloser: f.request.Body}
		f.request.Body = work.tap
	}
	return work
}
func (w *deferredEvidence) release() {
	if w != nil {
		w.once.Do(func() { <-w.slots })
	}
}
func (w *deferredEvidence) discard() {
	if w == nil {
		return
	}
	if w.tap != nil {
		w.tap.finish(-1)
	}
	w.release()
}
func (w *deferredEvidence) finish() func() *evidenceEvent {
	if w == nil {
		return nil
	}
	original := w.facts
	request := original.request
	snapshot := &http.Request{Method: request.Method, ContentLength: request.ContentLength, Header: http.Header{}, URL: &url.URL{}}
	snapshot.Header.Set("Content-Type", truncateUTF8(request.Header.Get("Content-Type"), 128))
	facts := newRequestFacts(snapshot)
	facts.facts[factKey("client_ip", "")] = original.get("client_ip", "")
	if len(request.URL.Path) <= 1024 {
		snapshot.URL.Path = strings.Clone(request.URL.Path)
	} else {
		facts.facts[factKey("path", "")] = Fact{State: "unavailable"}
	}
	if len(request.URL.RawQuery) <= maxInspectionBytes {
		snapshot.URL.RawQuery = strings.Clone(request.URL.RawQuery)
	} else {
		facts.queryDone = true
		facts.queryErr = true
	}
	for _, key := range w.settings.HeaderKeys {
		values, ok := request.Header[http.CanonicalHeaderKey(key)]
		if !ok {
			continue
		}
		if len(values) > 32 {
			facts.facts[factKey("header", key)] = Fact{State: "truncated"}
			continue
		}
		snapshot.Header.Del(key)
		for n, value := range values {
			if n == 3 {
				break
			}
			snapshot.Header.Add(key, strings.Clone(value[:min(len(value), maxFieldBytes+1)]))
		}
	}
	if original.bodyDone {
		facts.bodyDone = true
		facts.body = original.body
		facts.bodyState = original.bodyState
	} else if w.tap != nil {
		body, complete := w.tap.finish(request.ContentLength)
		if complete {
			snapshot.Body = io.NopCloser(bytes.NewReader(body))
		} else {
			facts.bodyDone = true
			facts.bodyState = "unavailable"
		}
	} else {
		facts.bodyDone = true
		facts.bodyState = "unavailable"
	}
	w.facts = nil
	w.tap = nil
	return func() *evidenceEvent {
		defer w.release()
		p := capturePolicy{Settings: w.settings, redactors: w.redactors}
		evidence := p.captureAllowed(facts, w.results, w.at)
		if evidence != nil {
			evidence.site = w.site
		}
		return evidence
	}
}
func (e *accessEvent) enrich() {
	if release := e.releaseEvidence; release != nil {
		e.releaseEvidence = nil
		defer release()
	}
	if e.prepareEvidence != nil {
		e.evidence = e.prepareEvidence()
		e.prepareEvidence = nil
	}
	if e.regions != nil {
		location := regionFor(e.regions.db, e.clientIP)
		if !e.network.GeoChecked && location.Country != "" {
			e.country = location.Country
			e.geo = nil
		}
		if location.Country == e.country {
			e.regionCode = location.Code
			e.regionName = location.Name
		}
		e.regions = nil
	}
	if e.geo != nil {
		e.country = countryFor(e.geo, e.clientIP)
		e.geo = nil
	}
}
