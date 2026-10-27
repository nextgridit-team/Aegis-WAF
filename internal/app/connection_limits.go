package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// These limits bound admitted upstream requests per application/policy/replica.
// Existing policies omit them. They are independent of optional distributed rate counters.
type connectionLimitSettings struct {
	Enabled            bool `json:"enabled"`
	MaxConcurrent      int  `json:"max_concurrent"`
	MaxPerClient       int  `json:"max_per_client"`
	MaxDurationSeconds int  `json:"max_duration_seconds"`
	IdleTimeoutSeconds int  `json:"idle_timeout_seconds"`
}

func normalizeConnectionLimits(input *connectionLimitSettings) (*connectionLimitSettings, error) {
	if input == nil {
		return nil, nil
	}
	v := *input
	if v.MaxConcurrent == 0 {
		v.MaxConcurrent = 100
	}
	if v.MaxPerClient == 0 {
		v.MaxPerClient = 10
	}
	if v.MaxDurationSeconds == 0 {
		v.MaxDurationSeconds = 900
	}
	if v.IdleTimeoutSeconds == 0 {
		v.IdleTimeoutSeconds = 60
	}
	if v.MaxConcurrent < 1 || v.MaxConcurrent > 10000 || v.MaxPerClient < 1 || v.MaxPerClient > v.MaxConcurrent || v.MaxDurationSeconds < 1 || v.MaxDurationSeconds > 86400 || v.IdleTimeoutSeconds < 1 || v.IdleTimeoutSeconds > 3600 {
		return nil, invalid("connection limits require 1–10000 concurrent requests, a client cap no larger than total, duration 1–86400s and idle timeout 1–3600s")
	}
	return &v, nil
}

type connectionBucketKey struct{ site, policy int64 }
type connectionBucket struct {
	total   int
	clients map[netip.Addr]int
}
type connectionLimiter struct {
	mu      sync.Mutex
	buckets map[connectionBucketKey]*connectionBucket
}

func (l *connectionLimiter) acquire(key connectionBucketKey, client netip.Addr, settings connectionLimitSettings, enforce bool) (release func(), over bool) {
	l.mu.Lock()
	if l.buckets == nil {
		l.buckets = map[connectionBucketKey]*connectionBucket{}
	}
	b := l.buckets[key]
	if b == nil {
		b = &connectionBucket{clients: map[netip.Addr]int{}}
		l.buckets[key] = b
	}
	over = b.total >= settings.MaxConcurrent || b.clients[client] >= settings.MaxPerClient
	if over && enforce {
		l.mu.Unlock()
		return nil, true
	}
	b.total++
	b.clients[client]++
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			b.total--
			b.clients[client]--
			if b.clients[client] == 0 {
				delete(b.clients, client)
			}
			if b.total == 0 {
				delete(l.buckets, key)
			}
		})
	}, over
}

var errConnectionDuration = errors.New("upstream duration limit")
var errConnectionIdle = errors.New("upstream idle limit")

type connectionRequestKey struct{}
type connectionRequestState struct {
	responseStarted                atomic.Bool
	writer                         http.ResponseWriter
	idleDisabled                   bool
	enforce                        bool
	overCapacity                   bool
	durationExceeded, idleExceeded atomic.Bool
	closed                         atomic.Bool
	cancel                         context.CancelCauseFunc
	release                        func()
	durationTimer                  *time.Timer
	idleTimer                      *time.Timer
	idle                           time.Duration
	mu                             sync.Mutex
	lastProgress                   time.Time
	gatewayErrorDeadline           time.Time
}

func (s *connectionRequestState) progress() {
	if s == nil || s.closed.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || s.idleDisabled {
		return
	}
	s.lastProgress = time.Now()
	if s.idleTimer != nil {
		s.idleTimer.Reset(s.idle)
	}
}
func (s *connectionRequestState) expireIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || s.idleDisabled {
		return
	}
	remaining := s.idle - time.Since(s.lastProgress)
	if remaining > 0 {
		s.idleTimer.Reset(remaining)
		return
	}
	s.idleExceeded.Store(true)
	if s.enforce {
		s.cancel(errConnectionIdle)
		if s.responseStarted.Load() {
			_ = http.NewResponseController(s.writer).SetWriteDeadline(s.expiredWriteDeadline(time.Now()))
		}
	}
}
func (s *connectionRequestState) finish(w http.ResponseWriter) {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.mu.Unlock()
	if s.durationTimer != nil {
		s.durationTimer.Stop()
	}
	if s.enforce {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	}
	s.cancel(nil)
	s.release()
}

// expiredWriteDeadline is called with mu held. The gateway error grace is fixed
// once, so subsequent writes cannot extend an expired upstream request.
func (s *connectionRequestState) expiredWriteDeadline(now time.Time) time.Time {
	if !s.gatewayErrorDeadline.IsZero() {
		return s.gatewayErrorDeadline
	}
	return now
}

func (s *connectionRequestState) allowGatewayTimeoutResponse() {
	if s == nil || !s.enforce {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.responseStarted.Load() && s.gatewayErrorDeadline.IsZero() && (s.durationExceeded.Load() || s.idleExceeded.Load()) {
		s.gatewayErrorDeadline = time.Now().Add(time.Second)
	}
}

func (s *connectionRequestState) writeDeadline(w http.ResponseWriter, _ int) {
	if s == nil || !s.enforce {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idleDisabled {
		return
	}
	now := time.Now()
	deadline := now.Add(s.idle)
	if s.durationExceeded.Load() || s.idleExceeded.Load() {
		deadline = s.expiredWriteDeadline(now)
	}
	_ = http.NewResponseController(w).SetWriteDeadline(deadline)
}
func (s *connectionRequestState) disableIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idleDisabled = true
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
}
func (a *App) beginConnectionLimits(r *http.Request, p *protectionPolicy, site int64, client netip.Addr, w http.ResponseWriter) (*http.Request, *connectionRequestState, bool) {
	if p == nil || p.connectionLimits == nil || !p.connectionLimits.Enabled || p.connectionMode == "off" || p.connectionMode == "" {
		return r, nil, true
	}
	cfg := *p.connectionLimits
	enforce := p.connectionMode == "block"
	release, over := a.connections.acquire(connectionBucketKey{site, p.budgetScope}, client, cfg, enforce)
	if release == nil {
		return r, nil, false
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	s := &connectionRequestState{writer: w, enforce: enforce, overCapacity: over, cancel: cancel, release: release, idle: time.Duration(cfg.IdleTimeoutSeconds) * time.Second, lastProgress: time.Now()}
	s.idleTimer = time.AfterFunc(s.idle, s.expireIdle)
	s.durationTimer = time.AfterFunc(time.Duration(cfg.MaxDurationSeconds)*time.Second, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.closed.Load() {
			s.durationExceeded.Store(true)
			if s.enforce {
				s.cancel(errConnectionDuration)
				if s.responseStarted.Load() {
					_ = http.NewResponseController(s.writer).SetWriteDeadline(s.expiredWriteDeadline(time.Now()))
				}
			}
		}
	})
	r = r.WithContext(context.WithValue(ctx, connectionRequestKey{}, s))
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &progressUpstreamBody{r.Body, s}
	}
	if getBody := r.GetBody; getBody != nil {
		r.GetBody = func() (io.ReadCloser, error) {
			body, err := getBody()
			if err != nil || body == nil || body == http.NoBody {
				return body, err
			}
			return &progressUpstreamBody{body, s}, nil
		}
	}
	return r, s, true
}

type progressUpstreamBody struct {
	io.ReadCloser
	state *connectionRequestState
}

func (b *progressUpstreamBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if n > 0 {
		b.state.progress()
	}
	return n, e
}
func prepareLimitedResponse(response *http.Response) {
	s, _ := response.Request.Context().Value(connectionRequestKey{}).(*connectionRequestState)
	if s == nil {
		return
	}
	s.progress()
	if response.StatusCode == 101 {
		s.disableIdle()
		return
	}
	if response.StatusCode != 101 && response.Body != nil && response.Body != http.NoBody {
		response.Body = &progressUpstreamBody{response.Body, s}
	}
}
func connectionFailure(ctx context.Context) (string, bool) {
	switch {
	case errors.Is(context.Cause(ctx), errConnectionIdle):
		return "upstream_idle_timeout", true
	case errors.Is(context.Cause(ctx), errConnectionDuration):
		return "upstream_duration_exceeded", true
	}
	return "", false
}
