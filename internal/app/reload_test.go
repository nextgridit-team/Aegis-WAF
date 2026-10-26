package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestAtomicReloadPreservesActiveConnections(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	proceed := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(proceed) }) }
	defer finish()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/socket" {
			conn, buffer, e := http.NewResponseController(w).Hijack()
			if e != nil {
				return
			}
			defer conn.Close()
			buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			buffer.Flush()
			io.Copy(conn, conn)
			return
		}
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "before\n")
			http.NewResponseController(w).Flush()
			select {
			case <-proceed:
				io.WriteString(w, "after\n")
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, "healthy")
	}))
	defer upstream.Close()
	now := time.Now()
	chain, key := testCertificate(t, []string{"bot.test"}, 111, now.Add(-time.Hour), now.Add(time.Hour))
	cert := mustID(t, api.call("POST", "/api/certificates", map[string]string{"name": "Reload TLS", "chain_pem": chain, "private_key_pem": key}, 200))
	p := defaultProtection()
	p.TrustedProxies = []string{"127.0.0.1/32"}
	p.ClientIPHeader = "x-real-ip"
	input := map[string]any{"name": "Reload app", "hostnames": []string{"bot.test"}, "upstream": upstream.URL, "enabled": true, "certificate_id": cert, "protection": p, "headers": HeaderSettings{}, "traffic_profile": "streaming"}
	api.call("PUT", fmt.Sprintf("/api/sites/%d", site), input, 200)
	for _, app := range []*App{a, b} {
		if e := app.refresh(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	old := a.active.Load()
	public := httptest.NewUnstartedServer(http.HandlerFunc(a.Public))
	public.TLS = a.TLSConfig()
	public.EnableHTTP2 = true
	public.StartTLS()
	defer func() { finish(); public.Close() }()
	type liveStream struct {
		response  *http.Response
		transport *http.Transport
	}
	streams := []liveStream{}
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "bot.test"}, ForceAttemptHTTP2: h2}
		t.Cleanup(tr.CloseIdleConnections)
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		request, _ := http.NewRequest("GET", public.URL+"/stream", nil)
		request.Host = "bot.test"
		request.Header.Set("X-Real-IP", "198.51.100.1")
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		wantProtocol := 1
		if h2 {
			wantProtocol = 2
		}
		if response.ProtoMajor != wantProtocol {
			t.Fatal("unexpected protocol", response.Proto)
		}
		before := make([]byte, 7)
		if _, e = io.ReadFull(response.Body, before); e != nil || string(before) != "before\n" {
			t.Fatal("stream failed before reload", e)
		}
		streams = append(streams, liveStream{response, tr})
	}
	target, _ := url.Parse(public.URL)
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", target.Host, &tls.Config{InsecureSkipVerify: true, ServerName: "bot.test"})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: bot.test\r\nX-Real-IP: 198.51.100.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	upgrade, e := http.ReadResponse(reader, nil)
	if e != nil || upgrade.StatusCode != 101 {
		t.Fatal("upgrade failed", e)
	}
	echo := func(message string) {
		t.Helper()
		io.WriteString(conn, message)
		data := make([]byte, len(message))
		if _, e := io.ReadFull(reader, data); e != nil || string(data) != message {
			t.Fatal("upgraded connection interrupted", e)
		}
	}
	echo("before")
	rule := probeRule("path", "", "equals", "/stream")
	rule.Scope.SiteID = site
	ruleID := mustID(t, api.call("POST", "/api/rules", rule, 200))
	ipRule := probeRule("client_ip", "", "cidr", "198.51.100.8/32")
	ipRule.Scope.SiteID = site
	ipRuleID := mustID(t, api.call("POST", "/api/rules", ipRule, 200))
	spec := policySpecInput{Name: "Reload policy", Mode: "block", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, NetworkAccess: networkAccessSettings{BlockCIDRs: []string{"198.51.100.9/32"}}, Groups: []policyGroupInput{{Name: "Stream restriction", RuleIDs: []int64{ruleID, ipRuleID}}}}
	api.call("POST", "/api/policies", policyInput{Spec: spec, Applications: []policyAssignment{{SiteID: site}}}, 200)
	replacement, replacementKey := testCertificate(t, []string{"bot.test"}, 222, now.Add(-time.Hour), now.Add(time.Hour))
	api.call("PUT", fmt.Sprintf("/api/certificates/%d", cert), map[string]string{"name": "Reload TLS", "chain_pem": replacement, "private_key_pem": replacementKey}, 200)
	for _, app := range []*App{a, b} {
		if e := app.refresh(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if a.active.Load() == old {
		t.Fatal("snapshot was not swapped")
	}
	for _, app := range []*App{a, b} {
		for _, test := range []struct {
			path, ip string
			want     int
		}{{"/stream", "198.51.100.1", 403}, {"/healthy", "198.51.100.9", 403}, {"/healthy", "198.51.100.8", 403}, {"/healthy", "198.51.100.1", 200}} {
			r := httptest.NewRequest("GET", "http://bot.test"+test.path, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("X-Real-IP", test.ip)
			w := httptest.NewRecorder()
			app.Public(w, r)
			if w.Code != test.want {
				t.Fatalf("new request %s %s got %d want %d", test.path, test.ip, w.Code, test.want)
			}
		}
	}
	fresh, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", target.Host, &tls.Config{InsecureSkipVerify: true, ServerName: "bot.test"})
	if e != nil {
		t.Fatal(e)
	}
	if serial := fresh.ConnectionState().PeerCertificates[0].SerialNumber.Int64(); serial != 222 {
		t.Fatal("new TLS handshake used old certificate", serial)
	}
	fresh.Close()
	// A corrupt candidate must leave the entire last working snapshot active.
	active := a.active.Load()
	_, e = a.db.Exec(context.Background(), "UPDATE proxy_headers SET settings='{\"forwarded_headers\":\"invalid\"}'::jsonb WHERE site_id=$1", site)
	if e != nil {
		t.Fatal(e)
	}
	a.db.Exec(context.Background(), "UPDATE config_version SET version=version+1 WHERE id")
	if e = a.refresh(context.Background()); e == nil || a.active.Load() != active {
		t.Fatal("failed candidate replaced active snapshot", e)
	}
	echo("after")
	finish()
	for _, stream := range streams {
		rest, e := io.ReadAll(stream.response.Body)
		if e != nil || string(rest) != "after\n" {
			t.Fatal("reload dropped an active stream", e, string(rest))
		}
		if serial := stream.response.TLS.PeerCertificates[0].SerialNumber.Int64(); serial != 111 {
			t.Fatal("active TLS session changed certificate", serial)
		}
	}
}
