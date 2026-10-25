package app

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"

	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

// bufferedSignatureBody releases the bounded inspection reservation as soon as
// its inspected prefix is forwarded, or when the request is closed. WebSocket
// lifetime and response streaming never hold an inspection slot.
type bufferedSignatureBody struct {
	mu         sync.Mutex
	prefix     *bytes.Reader
	original   io.ReadCloser
	release    func()
	closeOnce  sync.Once
	closeError error
}

func (b *bufferedSignatureBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.prefix != nil {
		n, e := b.prefix.Read(p)
		empty := b.prefix.Len() == 0
		if empty {
			b.prefix = nil
		}
		b.mu.Unlock()
		if empty {
			b.release()
		}
		if n > 0 {
			return n, nil
		}
		if e != io.EOF {
			return n, e
		}
	} else {
		b.mu.Unlock()
	}
	return b.original.Read(p)
}
func (b *bufferedSignatureBody) Close() error {
	b.closeOnce.Do(func() { b.mu.Lock(); b.prefix = nil; b.mu.Unlock(); b.release(); b.closeError = b.original.Close() })
	return b.closeError
}

func managedInterruption(interruption *types.Interruption) (bool, int) {
	if interruption == nil || interruption.Action == "allow" || interruption.Action == "pass" {
		return false, 0
	}
	status := interruption.Status
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	return true, status
}
func (a *App) inspectManaged(runtime *managedSignatureRuntime, r *http.Request, ip netip.Addr) (result managedSignatureResult, blocked bool, status int) {
	result = managedSignatureResult{SetID: runtime.Set.ID, Version: runtime.Set.Version, Mode: runtime.Options.Mode, Inspection: "complete", RuleIDs: []int{}}
	select {
	case a.managedSlots <- struct{}{}:
	default:
		result.Inspection = "busy"
		if runtime.Options.Mode == "observe" {
			return result, false, 0
		}
		return result, true, http.StatusServiceUnavailable
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { <-a.managedSlots }) }
	retained := false
	originalBody := r.Body
	defer func() {
		if recover() != nil {
			result.Inspection = "error"
			blocked = true
			status = http.StatusServiceUnavailable
		}
		if blocked && retained {
			r.Body = originalBody
			retained = false
		}
		if !retained {
			release()
		}
	}()

	var transaction types.Transaction
	if withOptions, ok := runtime.WAF.(experimental.WAFWithOptions); ok {
		transaction = withOptions.NewTransactionWithOptions(experimental.Options{Context: r.Context()})
	} else {
		transaction = runtime.WAF.NewTransaction()
	}
	defer transaction.Close()
	defer func() {
		ids := map[int]bool{}
		for _, match := range transaction.MatchedRules() {
			id := match.Rule().ID()
			if runtime.Reportable[id] {
				ids[id] = true
			}
		}
		for id := range ids {
			result.RuleIDs = append(result.RuleIDs, id)
		}
		sort.Ints(result.RuleIDs)
		result.Matches = len(result.RuleIDs)
		if len(result.RuleIDs) > 128 {
			result.RuleIDs = result.RuleIDs[:128]
		}
	}()
	_, port, _ := net.SplitHostPort(r.RemoteAddr)
	clientPort, _ := strconv.Atoi(port)
	transaction.ProcessConnection(ip.String(), clientPort, "", 0)
	transaction.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	transaction.SetServerName(requestHost(r.Host))
	for key, values := range r.Header {
		for _, value := range values {
			transaction.AddRequestHeader(key, value)
		}
	}
	transaction.AddRequestHeader("Host", r.Host)
	for _, encoding := range r.TransferEncoding {
		transaction.AddRequestHeader("Transfer-Encoding", encoding)
	}
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength >= 0 && r.Header.Get("Content-Length") == "" {
		transaction.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	interruption := transaction.ProcessRequestHeaders()
	if reject, code := managedInterruption(interruption); reject {
		result.Inspection = "headers"
		return result, true, code
	}
	if runtime.Options.Mode == "block" && r.ContentLength > int64(runtime.Options.BodyLimit) {
		result.Inspection = "body_limit"
		return result, true, http.StatusRequestEntityTooLarge
	}
	inspectedBody := false
	if transaction.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		interruption, consumed, e := transaction.ReadRequestBodyFrom(r.Body)
		if e != nil {
			result.Inspection = "invalid_request"
			return result, true, http.StatusBadRequest
		}
		if reject, code := managedInterruption(interruption); reject {
			result.Inspection = "body_limit_or_match"
			return result, true, code
		}
		inspectedBody = true
		if r.ContentLength > int64(runtime.Options.BodyLimit) || (r.ContentLength < 0 && consumed >= runtime.Options.BodyLimit) {
			result.Inspection = "partial"
		}
	}
	interruption, e := transaction.ProcessRequestBody()
	if e != nil {
		if result.Inspection != "partial" {
			result.Inspection = "invalid_request"
		}
		if runtime.Options.Mode == "block" {
			return result, true, http.StatusBadRequest
		}
	}
	if reject, code := managedInterruption(interruption); reject {
		return result, true, code
	}
	if inspectedBody {
		buffered, e := transaction.RequestBodyReader()
		if e != nil {
			result.Inspection = "error"
			return result, true, http.StatusServiceUnavailable
		}
		prefix, e := io.ReadAll(io.LimitReader(buffered, int64(runtime.Options.BodyLimit)+1))
		if e != nil || len(prefix) > runtime.Options.BodyLimit {
			result.Inspection = "error"
			return result, true, http.StatusServiceUnavailable
		}
		// The bounded copy outlives transaction.Close, without retaining raw WAF
		// collections or temporary files during streaming or a WebSocket lifetime.
		if len(prefix) > 0 {
			r.Body = &bufferedSignatureBody{prefix: bytes.NewReader(prefix), original: originalBody, release: release}
			retained = true
		}
	}

	return result, false, 0
}
