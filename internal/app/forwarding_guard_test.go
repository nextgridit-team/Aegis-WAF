package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// The dataplane forwarding path must not honor HTTP(S)_PROXY by default: an
// attacker-influenced environment proxy would observe and steer forwarded
// application traffic, and the plain dialer left the site-config path a
// strictly stronger recon oracle than the hardened upstream probe ever was.
func TestForwardingDataplaneIgnoresEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")
	target, _ := url.Parse("http://upstream.invalid./")
	proxy := newSiteProxy(target, Site{ID: 1, Hostnames: []string{"guard.test"}}, HeaderSettings{}, nil)
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("site proxy transport: %T", proxy.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("forwarding transport honors environment proxies by default")
	}
}

// The forwarding dial must refuse link-local and unspecified destinations as
// URL literals: link-local covers every cloud metadata endpoint, and an
// unspecified literal reaches local services on the proxy host itself.
func TestForwardingDataplaneRefusesLinkLocalAndUnspecified(t *testing.T) {
	target, _ := url.Parse("http://[fe80::1]/")
	proxy := newSiteProxy(target, Site{ID: 1, Hostnames: []string{"guard.test"}}, HeaderSettings{}, nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://guard.test/", nil))
	// Web-profile visitors get the block page: the coarse refusal class is
	// audited and returned as JSON on machine profiles, never as upstream
	// detail on the visitor page.
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("link-local upstream not refused: %d %s", w.Code, w.Body.String())
	}
}

func TestForwardingDataplaneRefusesUnspecifiedLiteral(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("local service"))
	}))
	t.Cleanup(local.Close)
	// Dialing the unspecified literal reaches loopback services on this host:
	// without a guard the forwarded request is served by the local listener.
	target, _ := url.Parse(strings.Replace(local.URL, "127.0.0.1", "0.0.0.0", 1))
	proxy := newSiteProxy(target, Site{ID: 1, Hostnames: []string{"guard.test"}}, HeaderSettings{}, nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://guard.test/", nil))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("unspecified literal reached a local service: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "local service") {
		t.Fatal("unspecified literal reached a local service")
	}
}

// Private, unique-local and loopback upstreams are the normal WAF topology —
// the guard must not over-block them.
func TestForwardingDataplaneKeepsLoopbackUpstreams(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("loopback upstream"))
	}))
	t.Cleanup(local.Close)
	target, _ := url.Parse(local.URL)
	proxy := newSiteProxy(target, Site{ID: 1, Hostnames: []string{"guard.test"}}, HeaderSettings{}, nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://guard.test/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "loopback upstream") {
		t.Fatalf("loopback upstream refused: %d %s", w.Code, w.Body.String())
	}
}

// Deployments that legitimately route egress through an environment proxy can
// opt back in; the default stays off.
func TestForwardingEnvProxyOptIn(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("FORWARD_USE_ENV_PROXY", "1")
	target, _ := url.Parse("http://upstream.invalid./")
	proxy := newSiteProxy(target, Site{ID: 1, Hostnames: []string{"guard.test"}}, HeaderSettings{}, nil)
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("site proxy transport: %T", proxy.Transport)
	}
	if transport.Proxy == nil {
		t.Fatal("FORWARD_USE_ENV_PROXY did not restore environment proxy egress")
	}
}

// Deployments that legitimately front link-local upstreams can opt back in;
// the refusal then no longer classifies the destination.
func TestForwardingLinkLocalOptIn(t *testing.T) {
	t.Setenv("FORWARD_ALLOW_LINK_LOCAL", "1")
	target, _ := url.Parse("http://[fe80::1]/")
	proxy := newSiteProxy(target, Site{ID: 1, Hostnames: []string{"guard.test"}}, HeaderSettings{}, nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://guard.test/", nil))
	if strings.Contains(w.Body.String(), "refused") {
		t.Fatalf("FORWARD_ALLOW_LINK_LOCAL did not restore link-local dialing: %d %s", w.Code, w.Body.String())
	}
}

// The forwarding guard and the upstream probe must refuse exactly the same
// address classes: they share nat64Embedded, and drift between the two
// predicates would reopen whichever path lagged behind.
func TestForwardingGuardMatchesProbe(t *testing.T) {
	for _, raw := range []string{
		"169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1",
		"64:ff9b::a9fe:a9fe", "64:ff9b:1:a9fe:a9:fe00::", "64:ff9b:1:a9fe:a9:fe00:808:808",
		"64:ff9b::f000:0", "64:ff9b:1:808:108:800::",
	} {
		if (forwardingAddressClass(netip.MustParseAddr(raw)) != "") != probeAddressRefused(netip.MustParseAddr(raw)) {
			t.Fatalf("forwarding guard and probe disagree on %s", raw)
		}
	}
	for _, raw := range []string{
		"8.8.8.8", "192.168.100.8", "10.0.0.1", "fd00::1", "127.0.0.1", "::1",
		"64:ff9b::808:808",
	} {
		if forwardingAddressClass(netip.MustParseAddr(raw)) != "" || probeAddressRefused(netip.MustParseAddr(raw)) {
			t.Fatalf("allowed upstream refused by a guard: %s", raw)
		}
	}
}

// A refused forwarding destination is audited with its class like the
// upstream probe, deduplicated per site, host and class, and machine-endpoint
// sites classify the refusal as upstream_refused.
func TestForwardingRefusalAudited(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("local service"))
	}))
	t.Cleanup(local.Close)
	target, _ := url.Parse(strings.Replace(local.URL, "127.0.0.1", "0.0.0.0", 1))
	site := Site{ID: 7, Hostnames: []string{"guard.test"}, TrafficProfile: "api"}
	for n := 0; n < 2; n++ {
		proxy := newSiteProxy(target, site, HeaderSettings{}, a)
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://guard.test/", nil))
		if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "upstream_refused") {
			t.Fatalf("refusal %d not classified on the machine endpoint: %d %s", n, w.Code, w.Body.String())
		}
	}
	var resource string
	if e := a.db.QueryRow(context.Background(), "SELECT resource FROM audit_events WHERE action='forwarding.refused'").Scan(&resource); e != nil {
		t.Fatal("forwarding refusal not audited:", e)
	}
	if !strings.HasPrefix(resource, "7:0.0.0.0:unspecified") {
		t.Fatalf("audit resource missing site/host/class: %s", resource)
	}
	var count int
	if e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE action='forwarding.refused'").Scan(&count); e != nil || count != 1 {
		t.Fatalf("refusal audit not deduplicated: count=%d err=%v", count, e)
	}
}
