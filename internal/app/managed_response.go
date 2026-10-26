package app

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

type managedResponseKey struct{}

// The transaction is used sequentially by request inspection and ModifyResponse.
// A bounded reservation spans the two phases only when responses are enabled.
type managedResponseState struct {
	app      *App
	site     Site
	clientIP netip.Addr
	reliable bool
	runtime  *managedSignatureRuntime
	result   *managedSignatureResult
	blocked  *bool
	tx       types.Transaction
	release  func()
	cancel   context.CancelFunc
	once     sync.Once
}

func (s *managedResponseState) Close() {
	if s.tx != nil {
		s.tx.Close()
		s.tx = nil
	}
	s.once.Do(func() {
		if s.release != nil {
			s.release()
		}
	})
}
func collectManagedMatches(tx types.Transaction, runtime *managedSignatureRuntime, result *managedSignatureResult) {
	ids := map[int]bool{}
	for _, id := range result.RuleIDs {
		ids[id] = true
	}
	for _, match := range tx.MatchedRules() {
		id := match.Rule().ID()
		if runtime.Reportable[id] {
			ids[id] = true
		}
	}
	result.RuleIDs = result.RuleIDs[:0]
	for id := range ids {
		result.RuleIDs = append(result.RuleIDs, id)
	}
	sort.Ints(result.RuleIDs)
	result.Matches = len(result.RuleIDs)
	if len(result.RuleIDs) > 128 {
		result.RuleIDs = result.RuleIDs[:128]
	}
}

type managedResponseError struct{}

func (managedResponseError) Error() string {
	return "upstream response rejected by managed signature protection"
}

func (s *managedResponseState) reject(reason string) error {
	s.result.ResponseInspection = reason
	*s.blocked = true
	return managedResponseError{}
}

func inspectManagedResponse(response *http.Response) error {
	s, _ := response.Request.Context().Value(managedResponseKey{}).(*managedResponseState)
	if s == nil || s.tx == nil {
		return nil
	}
	return s.inspect(response)
}

func (s *managedResponseState) inspect(response *http.Response) (err error) {
	started := time.Now()
	if s.app != nil {
		defer func() { s.app.prom.observeInspection("response", time.Since(started)) }()
	}
	tx := s.tx
	buffered := false
	defer func() {
		if recover() != nil {
			err = s.reject("error")
		}
		collectManagedMatches(tx, s.runtime, s.result)
		tx.Close()
		s.tx = nil
		if !buffered {
			s.Close()
		}
	}()
	options := s.runtime.Options
	enforce := options.ResponseMode == "block"
	for key, values := range response.Header {
		for _, value := range values {
			tx.AddResponseHeader(key, value)
		}
	}
	interruption := tx.ProcessResponseHeaders(response.StatusCode, response.Proto)
	if reject, _ := managedInterruption(interruption); reject && enforce {
		return s.reject("headers")
	}
	switch {
	case response.StatusCode == http.StatusSwitchingProtocols:
		s.result.ResponseInspection = "skipped_upgrade"
		return nil
	case response.Request.Method == "HEAD" || response.StatusCode == 204 || response.StatusCode == 304 || response.Body == nil || response.Body == http.NoBody:
		s.result.ResponseInspection = "no_body"
		return nil
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType == "text/event-stream" || s.site.TrafficProfile == "streaming" {
		return s.stream(response, mediaType)
	}
	if !tx.IsResponseBodyAccessible() || !tx.IsResponseBodyProcessable() {
		s.result.ResponseInspection = "skipped_content_type"
		return nil
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		s.result.ResponseInspection = "unsupported_encoding"
		if enforce {
			return s.reject("unsupported_encoding")
		}
		return nil
	}
	if enforce && options.ResponseBodyLimitAction == "reject" && response.ContentLength > int64(options.ResponseBodyLimit) {
		return s.reject("body_limit")
	}
	// Cancel the upstream request if an eligible body stalls while being buffered.
	// No timer is applied to exempt streams or after the bounded prefix is read.
	timer := time.AfterFunc(5*time.Second, s.cancel)
	prefix, readErr := io.ReadAll(io.LimitReader(response.Body, int64(options.ResponseBodyLimit)+1))
	stopped := timer.Stop()
	if readErr != nil || !stopped {
		return s.reject("read_error_or_timeout")
	}
	inspected := prefix
	s.result.ResponseInspection = "complete"
	if len(prefix) > options.ResponseBodyLimit {
		s.result.ResponseInspection = "partial"
		if enforce && options.ResponseBodyLimitAction == "reject" {
			return s.reject("body_limit")
		}
		inspected = prefix[:options.ResponseBodyLimit]
	}
	interruption, _, e := tx.WriteResponseBody(inspected)
	if e != nil {
		return s.reject("error")
	}
	if reject, _ := managedInterruption(interruption); reject && enforce {
		return s.reject("match")
	}
	interruption, e = tx.ProcessResponseBody()
	if e != nil {
		return s.reject("error")
	}
	if reject, _ := managedInterruption(interruption); reject && enforce {
		return s.reject("match")
	}
	// Replay exactly the consumed bytes, including the sentinel byte. The body
	// owns the reservation until the prefix has been forwarded or closed.
	response.Body = &bufferedSignatureBody{prefix: bytes.NewReader(prefix), original: response.Body, release: s.Close}
	buffered = true
	return nil
}
