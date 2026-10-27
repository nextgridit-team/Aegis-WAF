package app

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUpstreamTLSProbeAndProxy(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("probe must use GET")
		}
		w.WriteHeader(200)
		io.WriteString(w, "private backend")
	}))
	defer up.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw}))
	bad := probeUpstream(context.Background(), up.URL, upstreamTLSSettings{}, "")
	if bad.Reachable || bad.Stage != "tls_trust" || bad.Certificate == nil || !bad.Certificate.CanTrust || bad.Certificate.PEM != cert {
		t.Fatalf("untrusted accepted %+v", bad)
	}
	settings := upstreamTLSSettings{TrustedCertsPEM: cert}
	good := probeUpstream(context.Background(), up.URL, settings, "")
	if !good.Reachable || good.Status != 200 || !good.TLSVerified {
		t.Fatalf("trusted failed %+v", good)
	}
	settings.ServerName = "wrong.invalid"
	wrong := probeUpstream(context.Background(), up.URL, settings, "")
	if wrong.Reachable || wrong.Stage != "tls_name" || (wrong.Certificate != nil && wrong.Certificate.CanTrust) {
		t.Fatalf("hostname mismatch accepted %+v", wrong)
	}
	settings.ServerName = ""
	target, _ := url.Parse(up.URL)
	proxy := newSiteProxy(target, Site{UpstreamTLS: settings}, HeaderSettings{})
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "http://public.test/", nil))
	if rec.Code != 200 || rec.Body.String() != "private backend" {
		t.Fatal("proxy trust not applied", rec.Code, rec.Body)
	}
	for _, raw := range []string{"garbage", cert + "secret", strings.Replace(cert, "CERTIFICATE", "PRIVATE KEY", 2)} {
		if _, e := upstreamTLSConfig(upstreamTLSSettings{TrustedCertsPEM: raw}); e == nil {
			t.Fatal("invalid trust accepted")
		}
	}
}
func TestUpstreamProbeNoRedirectAndHTTPFailure(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer target.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer up.Close()
	result := probeUpstream(context.Background(), up.URL, upstreamTLSSettings{}, "")
	if !result.Reachable || result.Status != 302 || followed {
		t.Fatal("redirect followed", result)
	}
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer errorServer.Close()
	result = probeUpstream(context.Background(), errorServer.URL, upstreamTLSSettings{}, "")
	if !result.Reachable || result.Status != 401 {
		t.Fatal("HTTP error confused with reachability", result)
	}
}

func TestUpstreamTrustIntegration(t *testing.T) {
	a, b, api, id, _ := captchaFixture(t)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "trusted application") }))
	defer up.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw}))
	input := map[string]any{"name": "Private TLS", "hostnames": []string{"bot.test"}, "upstream": up.URL, "enabled": true, "upstream_tls": upstreamTLSSettings{TrustedCertsPEM: cert}}
	api.call("PUT", fmt.Sprintf("/api/sites/%d", id), input, 200)
	for _, replica := range []*App{a, b} {
		if err := replica.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://bot.test/", nil)
		req.Header.Set("User-Agent", "browser")
		replica.Public(rec, req)
		if rec.Code != 200 || rec.Body.String() != "trusted application" {
			t.Fatal("private backend not trusted", rec.Code, rec.Body)
		}
	}
	raw := api.call("POST", "/api/upstreams/test", map[string]any{"upstream": up.URL, "upstream_tls": input["upstream_tls"]}, 200)
	var result upstreamProbeResult
	if e := json.Unmarshal(raw, &result); e != nil || !result.Reachable || !result.TLSVerified {
		t.Fatal("probe failed", string(raw), e)
	}
	csrf := api.csrf
	api.csrf = ""
	api.call("POST", "/api/upstreams/test", map[string]any{"upstream": up.URL}, 403)
	api.csrf = csrf
	delete(input, "upstream_tls")
	raw = api.call("PUT", fmt.Sprintf("/api/sites/%d", id), input, 200)
	var saved Site
	if e := json.Unmarshal(raw, &saved); e != nil || saved.UpstreamTLS.TrustedCertsPEM != cert {
		t.Fatal("omitted trust missing from response", string(raw), e)
	}
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.active.Load().routes["bot.test"].site.UpstreamTLS.TrustedCertsPEM != cert {
		t.Fatal("omitted trust erased")
	}
	input["upstream_tls"] = upstreamTLSSettings{TrustedCertsPEM: "not a certificate"}
	api.call("PUT", fmt.Sprintf("/api/sites/%d", id), input, 400)
	var count int
	if e := a.db.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE action='upstream.tested'").Scan(&count); e != nil || count != 1 {
		t.Fatal("probe audit", count, e)
	}
}
