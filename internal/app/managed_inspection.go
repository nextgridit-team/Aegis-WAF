package app

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/netip"
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
func (a *App) inspectManaged(runtime *managedSignatureRuntime, r *http.Request, ip netip.Addr, resolved ...bool) (result managedSignatureResult, blocked bool, status int) {
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
	responseState, _ := r.Context().Value(managedResponseKey{}).(*managedResponseState)
	defer func() {
		if responseState == nil || responseState.tx != transaction {
			transaction.Close()
		}
	}()
	defer func() { collectManagedMatches(transaction, runtime, &result) }()
	_, port, _ := net.SplitHostPort(r.RemoteAddr)
	clientPort, _ := strconv.Atoi(port)
	transaction.ProcessConnection(ip.String(), clientPort, "", 0)
	reliable := len(resolved) > 0 && resolved[0]
	if e := applySignatureExceptions(transaction, runtime.Options.ScopedExclusions, r, ip, reliable); e != nil {
		result.Inspection = "error"
		return result, true, http.StatusServiceUnavailable
	}
	profile, _ := r.Context().Value(endpointProfileKey{}).(string)
	if err := applyManagedMethods(transaction, profile, runtime.Options.AllowedMethods, r.Method); err != nil {
		result.Inspection = "error"
		return result, true, http.StatusServiceUnavailable
	}
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
	if runtime.Options.Mode == "block" && runtime.Options.BodyLimitAction == "reject" && r.ContentLength > int64(runtime.Options.BodyLimit) {
		result.Inspection = "body_limit"
		return result, true, http.StatusRequestEntityTooLarge
	}
	var prefix []byte
	if transaction.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		var e error
		prefix, e = io.ReadAll(io.LimitReader(r.Body, int64(runtime.Options.BodyLimit)+1))
		if e != nil {
			result.Inspection = "invalid_request"
			return result, true, http.StatusBadRequest
		}
		inspected := prefix
		if len(prefix) > runtime.Options.BodyLimit {
			result.Inspection = "partial"
			if runtime.Options.Mode == "block" && runtime.Options.BodyLimitAction == "reject" {
				result.Inspection = "body_limit"
				return result, true, http.StatusRequestEntityTooLarge
			}
			inspected = prefix[:runtime.Options.BodyLimit]
		}
		interruption, _, e = transaction.WriteRequestBody(inspected)
		if e != nil {
			result.Inspection = "invalid_request"
			return result, true, http.StatusBadRequest
		}
		if reject, code := managedInterruption(interruption); reject {
			return result, true, code
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
	if len(prefix) > 0 {
		bodyRelease := release
		if responseState != nil {
			bodyRelease = func() {}
		}
		r.Body = &bufferedSignatureBody{prefix: bytes.NewReader(prefix), original: originalBody, release: bodyRelease}
		retained = true
	}
	if responseState != nil {
		responseState.tx = transaction
		responseState.release = release
		result.ResponseInspection = "not_reached"
		result.ResponseMode = runtime.Options.ResponseMode
		retained = true
	}

	return result, false, 0
}
