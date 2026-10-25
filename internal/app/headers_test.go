package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestProxyHeaderValidation(t *testing.T) {
	for _, s := range []HeaderSettings{
		{RequestSet: map[string]string{"X-Test": "one\r\nInjected: yes"}},
		{RequestSet: map[string]string{"Bad Name": "bad"}},
		{RequestSet: map[string]string{"Host": "evil.test"}},
		{RequestSet: map[string]string{"X-Forwarded-For": "192.168.1.1"}},
		{ResponseSet: map[string]string{"Content-Length": "0"}},
		{ResponseSet: map[string]string{"Connection": "close"}},
		{RequestSet: map[string]string{"Authorization": "secret"}},
		{ResponseSet: map[string]string{"Set-Cookie": "secret"}},
		{RequestSet: map[string]string{"X-Test": "a", "x-test": "b"}},
		{RequestSet: map[string]string{"X-Test": "a"}, RequestRemove: []string{"x-test"}},
	} {
		if _, e := normalizeHeaders(s); e == nil {
			t.Errorf("accepted invalid settings %+v", s)
		}
	}
	s, e := normalizeHeaders(HeaderSettings{RequestSet: map[string]string{"x-application": "example"}, RequestRemove: []string{"Authorization"}})
	if e != nil || s.RequestSet["X-Application"] != "example" || s.ForwardedHeaders != "standard" {
		t.Fatal("valid settings rejected", e)
	}
}
func TestResolvedForwardingAndHeaderRewrites(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream")
		w.Header().Add("X-Test-Response", "old")
		json.NewEncoder(w).Encode(r.Header)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	settings, e := normalizeHeaders(HeaderSettings{RequestSet: map[string]string{"X-Test-Request": "configured"}, RequestRemove: []string{"X-Remove"}, ResponseSet: map[string]string{"X-Test-Response": "configured"}, ResponseRemove: []string{"Server"}})
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"standard", "off"} {
		settings.ForwardedHeaders = mode
		p := newProxyWithHeaders(target, true, settings)
		r := httptest.NewRequest("GET", "http://app.example.test/", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		for _, name := range identityHeaders {
			r.Header.Set(name, "spoofed")
		}
		r.Header.Set("X-Remove", "old")
		r = r.WithContext(context.WithValue(r.Context(), proxyIdentityKey{}, proxyIdentity{netip.MustParseAddr("198.51.100.42"), "https"}))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		var headers http.Header
		if e := json.Unmarshal(w.Body.Bytes(), &headers); e != nil {
			t.Fatal(e)
		}
		if headers.Get("X-Test-Request") != "configured" || headers.Get("X-Remove") != "" || w.Header().Get("Server") != "" || w.Header().Get("X-Test-Response") != "configured" {
			t.Fatal("custom headers not applied")
		}
		if mode == "standard" {
			if headers.Get("X-Forwarded-For") != "198.51.100.42" || headers.Get("X-Real-IP") != "198.51.100.42" || headers.Get("X-Forwarded-Proto") != "https" || headers.Get("X-Forwarded-Host") != "app.example.test" {
				t.Fatal("wrong forwarding", headers)
			}
			if headers.Get("CF-Connecting-IP") != "" || headers.Get("Forwarded") != "" {
				t.Fatal("spoofed alternate identity preserved")
			}
		} else {
			for _, name := range identityHeaders {
				if headers.Get(name) != "" {
					t.Fatal("disabled forwarding leaked", name)
				}
			}
		}
	}
}
