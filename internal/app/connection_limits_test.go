package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionLeaseBoundsAndPolicyIsolation(t *testing.T) {
	var limiter connectionLimiter
	cfg := connectionLimitSettings{MaxConcurrent: 2, MaxPerClient: 1}
	key := connectionBucketKey{1, 7}
	first := netip.MustParseAddr("198.51.100.1")
	second := netip.MustParseAddr("198.51.100.2")
	release, over := limiter.acquire(key, first, cfg, true)
	if release == nil || over {
		t.Fatal("first lease rejected")
	}
	if next, _ := limiter.acquire(key, first, cfg, true); next != nil {
		next()
		t.Fatal("client cap bypassed")
	}
	r2, _ := limiter.acquire(key, second, cfg, true)
	if r2 == nil {
		t.Fatal("other client incorrectly limited")
	}
	if next, _ := limiter.acquire(key, netip.MustParseAddr("198.51.100.3"), cfg, true); next != nil {
		next()
		t.Fatal("host cap bypassed")
	}
	other, _ := limiter.acquire(connectionBucketKey{1, 8}, first, cfg, true)
	if other == nil {
		t.Fatal("policies share budgets")
	}
	other()
	release()
	release()
	r2()
	if len(limiter.buckets) != 0 {
		t.Fatal("lease entries leaked")
	}
	cfg.MaxConcurrent = 1
	var count atomic.Int32
	var wg sync.WaitGroup
	hold := make(chan struct{})
	attempted := make(chan struct{}, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := limiter.acquire(key, first, cfg, true)
			if r != nil {
				count.Add(1)
			}
			attempted <- struct{}{}
			if r != nil {
				<-hold
				r()
			}
		}()
	}
	for range 32 {
		<-attempted
	}
	if count.Load() != 1 {
		t.Fatal("non-atomic admission", count.Load())
	}
	close(hold)
	wg.Wait()
}
func limitFixture(t *testing.T, upstream string, mode string, cfg connectionLimitSettings) *App {
	a := managedPublicFixture(t, upstream)
	route := a.active.Load().routes["managed.test"]
	route.site.TrafficProfile = "streaming"
	target, _ := url.Parse(upstream)
	route.proxy = newSiteProxy(target, route.site, HeaderSettings{})
	p := a.active.Load().policyBindings[1][0].Protection
	p.connectionMode = mode
	p.connectionLimits = &cfg
	p.budgetScope = 1
	return a
}
func limitRequest(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest("GET", url, nil)
	r.Host = "managed.test"
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("Accept", "text/event-stream")
	response, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	return response
}
func TestConnectionCapsReleaseAndReload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: ready\n\n")
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	a := limitFixture(t, upstream.URL, "block", connectionLimitSettings{Enabled: true, MaxConcurrent: 1, MaxPerClient: 1, MaxDurationSeconds: 10, IdleTimeoutSeconds: 5})
	server := httptest.NewServer(http.HandlerFunc(a.Public))
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	first := limitRequest(t, client, server.URL)
	defer first.Body.Close()
	prefix := make([]byte, len("data: ready\n\n"))
	if _, e := io.ReadFull(first.Body, prefix); e != nil {
		t.Fatal(e)
	}
	// A replacement snapshot/policy object must not reset the app-owned leases.
	old := a.active.Load()
	copy := *old
	copy.policyBindings = map[int64][]compiledPolicyBinding{1: append([]compiledPolicyBinding(nil), old.policyBindings[1]...)}
	policy := *copy.policyBindings[1][0].Protection
	copy.policyBindings[1][0].Protection = &policy
	a.active.Store(&copy)
	second := limitRequest(t, client, server.URL)
	io.Copy(io.Discard, second.Body)
	second.Body.Close()
	if second.StatusCode != 429 {
		t.Fatal("reload reset live connection cap", second.StatusCode)
	}
	first.Body.Close()
	deadline := time.Now().Add(time.Second)
	for {
		a.connections.mu.Lock()
		empty := len(a.connections.buckets) == 0
		a.connections.mu.Unlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client cancellation leaked lease")
		}
		time.Sleep(5 * time.Millisecond)
	}
	third := limitRequest(t, client, server.URL)
	if third.StatusCode != 200 {
		t.Fatal("lease not reusable", third.StatusCode)
	}
	third.Body.Close()
}
func TestStreamingDurationIdleAndObserve(t *testing.T) {
	for _, test := range []struct {
		name, mode     string
		duration, idle int
		active         bool
	}{{"duration", "block", 1, 5, true}, {"idle", "block", 5, 1, false}, {"observe", "observe", 1, 1, false}} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: ready\n\n")
				http.NewResponseController(w).Flush()
				if test.mode == "observe" {
					select {
					case <-time.After(1300 * time.Millisecond):
						io.WriteString(w, "data: final\n\n")
					case <-r.Context().Done():
					}
					return
				}
				if !test.active {
					<-r.Context().Done()
					return
				}
				ticker := time.NewTicker(50 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if _, e := io.WriteString(w, "data: tick\n\n"); e != nil {
							return
						}
						http.NewResponseController(w).Flush()
					case <-r.Context().Done():
						return
					}
				}
			}))
			defer upstream.Close()
			a := limitFixture(t, upstream.URL, test.mode, connectionLimitSettings{Enabled: true, MaxConcurrent: 2, MaxPerClient: 2, MaxDurationSeconds: test.duration, IdleTimeoutSeconds: test.idle})
			server := httptest.NewServer(http.HandlerFunc(a.Public))
			defer server.Close()
			response := limitRequest(t, &http.Client{Timeout: 3 * time.Second}, server.URL)
			defer response.Body.Close()
			body, e := io.ReadAll(response.Body)
			if test.mode == "observe" {
				if e != nil || !bytes.Contains(body, []byte("data: final")) {
					t.Fatal("Observe interrupted stream", e)
				}
			} else if e == nil {
				t.Fatal("enforcing stream was not terminated")
			}
			select {
			case event := <-a.access:
				if event.blocked != (test.mode == "block") {
					t.Fatal("wrong limit decision", event)
				}
				found := false
				for _, signal := range event.signals {
					found = found || signal == "upstream_duration_exceeded" || signal == "upstream_idle_timeout"
				}
				if !found {
					t.Fatal("missing timeout signal", event.signals)
				}
			case <-time.After(time.Second):
				t.Fatal("missing stream log")
			}
		})
	}
}
func TestConnectionTimeoutBeforeHeadersIsJSON(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer up.Close()
	a := limitFixture(t, up.URL, "block", connectionLimitSettings{Enabled: true, MaxConcurrent: 2, MaxPerClient: 1, MaxDurationSeconds: 1, IdleTimeoutSeconds: 5})
	request := httptest.NewRequest("GET", "http://managed.test/", nil)
	request.Header.Set("User-Agent", "curl/8")
	rec := httptest.NewRecorder()
	a.Public(rec, request)
	if rec.Code != 504 || !strings.Contains(rec.Body.String(), "upstream_duration_exceeded") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatal("wrong timeout response", rec.Code, rec.Body)
	}
}
func TestConnectionLimitsValidationAndDisabled(t *testing.T) {
	for _, cfg := range []connectionLimitSettings{{MaxConcurrent: -1}, {MaxConcurrent: 1, MaxPerClient: 2}, {MaxDurationSeconds: 86401}, {IdleTimeoutSeconds: 3601}} {
		if _, e := normalizeConnectionLimits(&cfg); e == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	a := &App{}
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	r, state, ok := a.beginConnectionLimits(req, &protectionPolicy{}, 1, netip.MustParseAddr("192.0.2.1"), httptest.NewRecorder())
	if !ok || state != nil || r != req || a.connections.buckets != nil {
		t.Fatal("disabled controls changed request")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, limited := connectionFailure(ctx); limited {
		t.Fatal("client cancellation misreported as limit")
	}
}
