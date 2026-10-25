package app

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHSTSValidationAndCacheClearing(t *testing.T) {
	for _, settings := range []HeaderSettings{
		{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: -1}},
		{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 63072001}},
		{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 86400}, ResponseSet: map[string]string{"strict-transport-security": "max-age=100"}},
		{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 86400}, ResponseRemove: []string{"Strict-Transport-Security"}},
	} {
		if _, e := normalizeHeaders(settings); e == nil {
			t.Fatalf("accepted invalid/conflicting HSTS: %+v", settings)
		}
	}
	settings, e := normalizeHeaders(HeaderSettings{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 0}})
	if e != nil {
		t.Fatal(e)
	}
	h := http.Header{}
	settings.applyResponseSecurity(h, true)
	if h.Get("Strict-Transport-Security") != "max-age=0" {
		t.Fatal("cannot clear cached HSTS")
	}
	settings.applyResponseSecurity(h, false)
	if h.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS emitted on plain HTTP")
	}
}

func TestHSTSFrontendTLSAndTrustedProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=999; preload")
		w.Write([]byte("hello"))
	}))
	defer up.Close()
	a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: "block"})
	settings, e := normalizeHeaders(HeaderSettings{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 86400, IncludeSubdomains: true}})
	if e != nil {
		t.Fatal(e)
	}
	snapshot := a.active.Load()
	route := snapshot.routes["managed.test"]
	route.site.Headers = &settings
	target, _ := url.Parse(up.URL)
	route.proxy = newProxyWithHeaders(target, true, settings)
	protection := defaultProtection()
	protection.TrustedProxies = []string{"10.0.0.1/32"}
	compiled, e := compileProtection(protection)
	if e != nil {
		t.Fatal(e)
	}
	snapshot.policyBindings[1][0].Protection = compiled
	for _, test := range []struct {
		name, peer, forwarded string
		tls, attack, want     bool
	}{
		{name: "frontend TLS", peer: "203.0.113.4", tls: true, want: true},
		{name: "plain HTTP", peer: "203.0.113.4"},
		{name: "forged proto", peer: "203.0.113.4", forwarded: "https"},
		{name: "trusted offload", peer: "10.0.0.1", forwarded: "https", want: true},
		{name: "trusted HTTP", peer: "10.0.0.1", forwarded: "http"},
		{name: "blocked TLS", peer: "203.0.113.4", tls: true, attack: true, want: true},
		{name: "blocked offload", peer: "10.0.0.1", forwarded: "https", attack: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := "http://managed.test/"
			if test.attack {
				path += "?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
			}
			r := httptest.NewRequest("GET", path, nil)
			r.RemoteAddr = test.peer + ":1234"
			r.Header.Set("User-Agent", "browser")
			if test.tls {
				r.TLS = &tls.ConnectionState{ServerName: "managed.test"}
			}
			if test.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", test.forwarded)
			}
			w := httptest.NewRecorder()
			a.Public(w, r)
			<-a.access
			if (w.Code == 403) != test.attack {
				t.Fatalf("unexpected status %d", w.Code)
			}
			want := ""
			if test.want {
				want = "max-age=86400; includeSubDomains"
			}
			if w.Header().Get("Strict-Transport-Security") != want {
				t.Fatalf("got %q want %q", w.Header().Get("Strict-Transport-Security"), want)
			}
		})
	}
	route.site.RedirectHTTPS = true
	for _, trusted := range []bool{false, true} {
		r := httptest.NewRequest("GET", "http://managed.test/", nil)
		r.RemoteAddr = "203.0.113.4:1234"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("User-Agent", "browser")
		if trusted {
			r.RemoteAddr = "10.0.0.1:1234"
		}
		w := httptest.NewRecorder()
		a.Public(w, r)
		<-a.access
		if trusted && w.Code != 200 {
			t.Fatal("trusted HTTPS offload redirected in a loop", w.Code)
		}
		if !trusted && w.Code != 308 {
			t.Fatal("untrusted forwarded proto bypassed redirect", w.Code)
		}
	}

}

func TestHSTSDoesNotDisableUpstreamTLSVerification(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted backend was reached") }))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	settings, _ := normalizeHeaders(HeaderSettings{HSTS: &HSTSSettings{Enabled: true, MaxAgeSeconds: 86400}})
	proxy := newProxyWithHeaders(target, true, settings)
	r := httptest.NewRequest("GET", "https://public.test/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	if w.Code != 502 {
		t.Fatalf("untrusted upstream accepted: %d", w.Code)
	}
}
