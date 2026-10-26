package app

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

func normalizeSiteTraffic(site *Site) error {
	if site.TrafficProfile == "" {
		site.TrafficProfile = "web"
	}
	if site.TrafficProfile != "web" && site.TrafficProfile != "streaming" {
		return invalid("traffic_profile must be web or streaming")
	}
	if site.StreamWindowBytes == 0 {
		site.StreamWindowBytes = 8192
	}
	if site.StreamWindowBytes < 4096 || site.StreamWindowBytes > 65536 {
		return invalid("stream_window_bytes must be 4096–65536")
	}
	return nil
}
func newSiteProxy(target *url.URL, site Site, headers HeaderSettings) *httputil.ReverseProxy {
	proxy := newProxyWithHeaders(target, site.PreserveHost, headers)
	if site.TrafficProfile == "streaming" {
		proxy.FlushInterval = -1
		proxy.Transport.(*http.Transport).ResponseHeaderTimeout = 2 * time.Minute
	}
	return proxy
}

func (s *managedResponseState) stream(response *http.Response, mediaType string) error {
	eligible := false
	switch mediaType {
	case "text/event-stream", "application/x-ndjson", "text/plain", "text/html", "text/xml", "application/json", "application/xml", "application/xhtml+xml":
		eligible = true
	}
	if !eligible {
		s.result.ResponseInspection = "skipped_content_type"
		return nil
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		s.result.ResponseInspection = "unsupported_encoding"
		if s.runtime.Options.ResponseMode == "block" {
			return s.reject("unsupported_encoding")
		}
		return nil
	}
	if s.app == nil || s.runtime.StreamWAF == nil {
		s.result.ResponseInspection = "stream_unavailable"
		if s.runtime.Options.ResponseMode == "block" {
			return s.reject("stream_unavailable")
		}
		return nil
	}
	window := s.site.StreamWindowBytes
	if window == 0 {
		window = 8192
	}
	window = min(window, s.runtime.Options.ResponseBodyLimit)
	s.result.ResponseInspection = "stream_windows"
	response.Body = &streamSignatureBody{original: response.Body, state: s, response: response, window: make([]byte, 0, window), limit: window}
	// The request transaction is closed by inspect's defer. The stream retains
	// only bounded metadata/window bytes and reserves a slot per inspection.
	return nil
}

type streamSignatureBody struct {
	original   io.ReadCloser
	state      *managedResponseState
	response   *http.Response
	window     []byte
	limit      int
	dirty      bool
	readErr    error
	stopped    bool
	closeOnce  sync.Once
	closeError error
}

func (b *streamSignatureBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.stopped {
		return 0, managedResponseError{}
	}
	// ReverseProxy has written/flushed the previous read before asking for more.
	// Thus inspection never delays the first chunk or buffers to EOF.
	if b.dirty {
		b.dirty = false
		if e := b.inspectWindow(); e != nil {
			b.stopped = true
			return 0, e
		}
	}
	if b.readErr != nil {
		return 0, b.readErr
	}
	n, e := b.original.Read(p[:min(len(p), b.limit/2)])
	if n > 0 {
		if excess := len(b.window) + n - b.limit; excess > 0 {
			copy(b.window, b.window[excess:])
			b.window = b.window[:len(b.window)-excess]
		}
		b.window = append(b.window, p[:n]...)
		b.dirty = true
		b.state.result.StreamBytes += int64(n)
		// Defer EOF until the next read so the final delivered bytes are inspected.
		b.readErr = e
		return n, nil
	}
	return n, e
}
func (b *streamSignatureBody) Close() error {
	b.closeOnce.Do(func() { b.closeError = b.original.Close() })
	return b.closeError
}
func (b *streamSignatureBody) failure(reason string) error {
	b.state.result.ResponseInspection = reason
	if b.state.runtime.Options.ResponseMode == "block" {
		*b.state.blocked = true
		return managedResponseError{}
	}
	return nil
}
func (b *streamSignatureBody) inspectWindow() (err error) {
	s := b.state
	started := time.Now()
	defer func() { s.app.prom.observeInspection("stream_window", time.Since(started)) }()
	defer func() {
		if recover() != nil {
			err = b.failure("stream_error")
		}
	}()
	select {
	case s.app.managedSlots <- struct{}{}:
		defer func() { <-s.app.managedSlots }()
	default:
		return b.failure("stream_busy")
	}
	waf := s.runtime.StreamWAF
	var tx types.Transaction
	if options, ok := waf.(experimental.WAFWithOptions); ok {
		tx = options.NewTransactionWithOptions(experimental.Options{Context: b.response.Request.Context()})
	} else {
		tx = waf.NewTransaction()
	}
	defer tx.Close()
	defer collectManagedMatches(tx, s.runtime, s.result)
	request := b.response.Request
	tx.ProcessConnection(s.clientIP.String(), 0, "", 0)
	tx.ProcessURI(request.URL.RequestURI(), request.Method, request.Proto)
	tx.SetServerName(requestHost(request.Host))
	if e := applySignatureExceptions(tx, s.runtime.Options.ScopedExclusions, request, s.clientIP, s.reliable); e != nil {
		return b.failure("stream_error")
	}
	// This engine contains CRS initialization and response rules only. Windows
	// have independent anomaly scores; request-body state is not reconstructed.
	tx.AddRequestHeader("Host", request.Host)
	for name, values := range request.Header {
		if name == "Content-Type" || name == "Content-Length" || name == "Transfer-Encoding" {
			continue
		}
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}
	if reject, _ := managedInterruption(tx.ProcessRequestHeaders()); reject {
		return b.failure("stream_error")
	}
	if interruption, e := tx.ProcessRequestBody(); e != nil || interruption != nil {
		return b.failure("stream_error")
	}
	for name, values := range b.response.Header {
		for _, value := range values {
			tx.AddResponseHeader(name, value)
		}
	}
	interruption := tx.ProcessResponseHeaders(b.response.StatusCode, b.response.Proto)
	if !tx.IsResponseBodyAccessible() || !tx.IsResponseBodyProcessable() {
		return b.failure("stream_unavailable")
	}
	blocked, _ := managedInterruption(interruption)
	if !blocked {
		interruption, _, err = tx.WriteResponseBody(b.window)
		if err != nil {
			return b.failure("stream_error")
		}
		blocked, _ = managedInterruption(interruption)
	}
	if !blocked {
		interruption, err = tx.ProcessResponseBody()
		if err != nil {
			return b.failure("stream_error")
		}
		blocked, _ = managedInterruption(interruption)
	}
	s.result.StreamWindows++
	if blocked && s.runtime.Options.ResponseMode == "block" {
		return b.failure("stream_match")
	}
	// Observe engines do not interrupt; record actual response detection matches.
	if s.runtime.Options.ResponseMode == "observe" {
		for _, match := range tx.MatchedRules() {
			if match.Rule().ID() >= 950000 && match.Rule().ID() < 959000 && s.runtime.Reportable[match.Rule().ID()] {
				if s.result.ResponseInspection == "stream_windows" {
					s.result.ResponseInspection = "stream_observed_match"
				}
				break
			}
		}
	}
	return nil
}
