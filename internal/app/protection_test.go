package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFloodBudgetAndBotSignals(t *testing.T) {
	p := defaultProtection()
	p.Mode = "block"
	p.RequestsPerSecond = 2
	p.Burst = 2
	p.BotMode = "observe"
	policy, e := compileProtection(p)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.4")
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.Header.Set("User-Agent", "sqlmap/1")
	for n := 0; n < 2; n++ {
		signals, blocked, _ := a.protect(policy, 1, r, ip, now)
		if blocked || len(signals) != 1 {
			t.Fatalf("unexpected initial decision %v %v", signals, blocked)
		}
	}
	signals, blocked, status := a.protect(policy, 1, r, ip, now)
	if !blocked || status != 429 || len(signals) != 2 {
		t.Fatalf("expected flood decision: %v %v %d", signals, blocked, status)
	}
	if _, blocked, _ = a.protect(policy, 2, r, ip, now); blocked {
		t.Fatal("rate leaked between applications")
	}
	if _, blocked, _ = a.protect(policy, 1, r, ip, now.Add(time.Second)); blocked {
		t.Fatal("tokens did not refill")
	}
	policy.Mode = "observe"
	if _, blocked, _ = a.protect(policy, 1, r, ip, now.Add(time.Second)); blocked {
		t.Fatal("observe blocked")
	}
	policy.BotMode = "block"
	if _, blocked, status = a.protect(policy, 3, r, ip, now); !blocked || status != 403 {
		t.Fatal("bot did not block")
	}
	r.Header.Set("User-Agent", "curl/8")
	if signals, blocked, _ = a.protect(policy, 3, r, ip, now); blocked || len(signals) != 0 {
		t.Fatal("ordinary client blocked")
	}
}
func TestFloodConcurrentBound(t *testing.T) {
	l := &floodLimiter{}
	now := time.Now()
	var mu sync.Mutex
	count := 0
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.allow(rateKey{1, "client"}, 1, 10, now) {
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if count != 10 {
		t.Fatalf("allowed %d, want 10", count)
	}
}
func TestTrustedClientIP(t *testing.T) {
	settings := defaultProtection()
	settings.TrustedProxies = []string{"10.0.0.0/8"}
	p, _ := compileProtection(settings)
	r := httptest.NewRequest("GET", "http://example.test", nil)
	r.RemoteAddr = "198.51.100.5:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if p.clientIP(r).String() != "198.51.100.5" {
		t.Fatal("trusted spoofed direct header")
	}
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.5, 10.0.0.2")
	if p.clientIP(r).String() != "198.51.100.5" {
		t.Fatal("walk did not stop at untrusted hop")
	}
	r.Header.Set("X-Forwarded-For", "garbage")
	if p.clientIP(r).String() != "10.0.0.1" {
		t.Fatal("invalid header did not retain peer")
	}
	settings.TrustedProxies = []string{"0.0.0.0/0"}
	if _, e := compileProtection(settings); e == nil {
		t.Fatal("accepted trust all")
	}
}
func TestConnectionAccounting(t *testing.T) {
	a := &App{}
	c, other := net.Pipe()
	defer c.Close()
	defer other.Close()
	a.ConnectionState(c, http.StateNew)
	r := httptest.NewRequest("GET", "http://example.test", nil).WithContext(a.ConnectionContext(context.Background(), c))
	done := a.metrics.begin(r, 1)
	done2 := a.metrics.begin(r, 2)
	counts := a.metrics.counts()
	if counts[0].Connections != 1 || counts[1].Connections != 1 || counts[2].Connections != 1 || counts[0].Inflight != 2 {
		t.Fatal(counts)
	}
	done()
	done2()
	a.ConnectionState(c, http.StateIdle)
	if a.metrics.counts()[0].Connections != 1 || a.metrics.counts()[0].Inflight != 0 {
		t.Fatal("keepalive lost")
	}
	a.ConnectionState(c, http.StateHijacked)
	if a.metrics.counts()[0].Connections != 1 {
		t.Fatal("upgraded connection lost")
	}
	a.ConnectionState(c, http.StateClosed)
	if a.metrics.counts()[0].Connections != 0 {
		t.Fatal("closed socket retained")
	}
}
func TestProtectionDashboardIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	server := httptest.NewServer(a.Management())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, server.URL, ""}
	c.call("GET", "/api/dashboard", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "long protection test password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "long protection test password"}, 200), &login)
	c.csrf = login["csrf"]
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer upstream.Close()
	makeSite := func(name string) int64 {
		return mustID(t, c.call("POST", "/api/sites", map[string]any{"name": name, "hostnames": []string{name + ".test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false}, 200))
	}
	inline := defaultProtection()
	inline.Mode = "observe"
	badInline := inline
	badInline.Mode = "invalid"
	inlineBody := map[string]any{"name": "Inline app", "hostnames": []string{"inline.test"}, "upstream": upstream.URL, "enabled": true, "redirect_https": false, "protection": badInline}
	c.call("POST", "/api/sites", inlineBody, 400)
	var inlineCount int
	a.db.QueryRow(ctx, "SELECT count(*) FROM sites WHERE name='Inline app'").Scan(&inlineCount)
	if inlineCount != 0 {
		t.Fatal("invalid protection created routing")
	}
	inlineBody["protection"] = inline
	inlineID := mustID(t, c.call("POST", "/api/sites", inlineBody, 200))
	var inlineSaved []byte
	if e := a.db.QueryRow(ctx, "SELECT settings FROM protection_settings WHERE site_id=$1", inlineID).Scan(&inlineSaved); e != nil {
		t.Fatal(e)
	}
	var restored ProtectionSettings
	json.Unmarshal(inlineSaved, &restored)
	if restored.Mode != "observe" {
		t.Fatal("inline protection not saved")
	}
	inlineBody["name"] = "Should not persist"
	inlineBody["protection"] = badInline
	c.call("PUT", fmt.Sprintf("/api/sites/%d", inlineID), inlineBody, 400)
	var inlineName string
	a.db.QueryRow(ctx, "SELECT name FROM sites WHERE id=$1", inlineID).Scan(&inlineName)
	if inlineName != "Inline app" {
		t.Fatal("invalid inline edit changed application")
	}
	site := makeSite("protected")
	other := makeSite("other")
	p := defaultProtection()
	p.Mode = "block"
	p.RequestsPerSecond = 1
	p.Burst = 1
	p.BotMode = "block"
	path := fmt.Sprintf("/api/protection-settings/%d", site)
	saved := c.csrf
	c.csrf = "wrong"
	c.call("PUT", path, p, 403)
	c.csrf = saved
	c.call("PUT", path, p, 200)
	c.call("PUT", "/api/protection-settings/999999", p, 404)
	for _, replica := range []*App{a, b} {
		if e := replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
	}
	request := func(replica *App, host, ip, ua string, want int) accessEvent {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.RemoteAddr = ip + ":1234"
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		replica.Public(w, r)
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
		return <-replica.access
	}
	events := []accessEvent{request(a, "protected.test", "203.0.113.1", "browser", 202), request(a, "protected.test", "203.0.113.1", "browser", 429), request(b, "protected.test", "203.0.113.2", "sqlmap", 403), request(b, "other.test", "203.0.113.1", "sqlmap", 202)}
	events[0].country = "US"
	if e := a.storeAccessBatch(ctx, events); e != nil {
		t.Fatal(e)
	}
	a.publishMetrics(ctx)
	b.publishMetrics(ctx)
	var report struct {
		Totals            struct{ Requests, Blocked, Flagged int }
		ReportingReplicas int `json:"reporting_replicas"`
		Countries         []struct {
			Country  string
			Requests int
		}
	}
	if e := a.dashboard(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/dashboard", nil), identity{}); e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(c.call("GET", "/api/dashboard", nil, 200), &report)
	if report.Totals.Requests != 4 || report.Totals.Blocked != 2 || report.Totals.Flagged != 2 || report.ReportingReplicas != 2 {
		t.Fatalf("bad report %+v", report)
	}
	json.Unmarshal(c.call("GET", fmt.Sprintf("/api/dashboard?site_id=%d&minutes=5", other), nil, 200), &report)
	if report.Totals.Requests != 1 || report.Totals.Blocked != 0 {
		t.Fatal("application filter incorrect")
	}
	c.call("GET", "/api/dashboard?minutes=2", nil, 400)
	c.call("GET", "/api/dashboard?site_id=-1", nil, 400)
	c.call("POST", "/api/geolocation/update", map[string]bool{"accept_license": false}, 400)
	p.Mode = "observe"
	p.BotMode = "observe"
	c.call("PUT", path, p, 200)
	if e := a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	ev := request(a, "protected.test", "203.0.113.1", "sqlmap", 202)
	if ev.blocked || !strings.Contains(strings.Join(ev.signals, ","), "automation") {
		t.Fatal("observe did not record correctly")
	}
	_ = site
}
