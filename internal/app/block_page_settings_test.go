package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestBlockPageEscapesSiteText(t *testing.T) {
	site := Site{ID: 21, Hostnames: []string{"blocked.test"}, BlockTitle: `<script>alert("a")</script>`, BlockContact: `security@example.test?a=<b>&c="d"`, BlockReference: `<img src=x onerror=alert(1)>`}
	if e := normalizeSiteTraffic(&site); e != nil {
		t.Fatal(e)
	}
	a := blockTestApp(t, site, botBlockProtection(), blockTestTarget(t))
	w, _ := deniedRequest(a, "")
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	body := w.Body.String()
	for _, hostile := range []string{"<script>", "<img", "a=<b>", `c="d"`} {
		if strings.Contains(body, hostile) {
			t.Fatalf("block page renders unescaped site text: %q found", hostile)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(&#34;a&#34;)&lt;/script&gt;") {
		t.Fatal("block page does not render the escaped site title")
	}
	if !strings.Contains(body, "security@example.test?a=&lt;b&gt;&amp;c=&#34;d&#34;") {
		t.Fatal("block page does not render the escaped site contact line")
	}
}

func TestBlockPageSettingsValidation(t *testing.T) {
	for name, value := range map[string]string{
		"too long":     strings.Repeat("x", 81),
		"control rune": "line\nbreak",
		"nul":          "before\x00after",
		"delete rune":  "before\x7fafter",
	} {
		site := Site{BlockTitle: value}
		if e := normalizeSiteTraffic(&site); e == nil {
			t.Fatalf("%s: accepted invalid block_title %q", name, value)
		}
	}
	for _, field := range []string{"block_contact", "block_reference"} {
		site := Site{BlockContact: strings.Repeat("x", 201), BlockReference: strings.Repeat("x", 81)}
		if e := normalizeSiteTraffic(&site); e == nil {
			t.Fatalf("%s: accepted oversized value", field)
		}
	}
	site := Site{BlockTitle: "Access denied — example service", BlockContact: "security@example.test", BlockReference: "policy-7"}
	if e := normalizeSiteTraffic(&site); e != nil {
		t.Fatalf("rejected valid block page settings: %v", e)
	}
	// JSON decoding keeps an encoded NUL; validation must refuse it before it
	// can reach a PostgreSQL text column.
	var decoded Site
	if e := json.Unmarshal([]byte(`{"block_title":"a\u0000b"}`), &decoded); e != nil {
		t.Fatal(e)
	}
	if e := normalizeSiteTraffic(&decoded); e == nil {
		t.Fatal("accepted NUL carried through JSON")
	}
}

func TestBlockPageSiteSettingsRoundTripIntegration(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	srv := httptest.NewServer(a.Management())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, srv.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "block page settings password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "block page settings password"}, 200), &login)
	c.csrf = login["csrf"]
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Block page settings", "hostnames": []string{"settings.example.com"}, "upstream": "http://127.0.0.1:1", "enabled": true, "traffic_profile": "web", "block_title": "Example service — access denied", "block_contact": "security@example.com", "block_reference": "ref-42"}, 200))
	var listed []Site
	json.Unmarshal(c.call("GET", "/api/sites", nil, 200), &listed)
	found := false
	for _, s := range listed {
		if s.ID == site {
			found = true
			if s.BlockTitle != "Example service — access denied" || s.BlockContact != "security@example.com" || s.BlockReference != "ref-42" {
				t.Fatalf("block page settings did not round-trip: %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("created site missing from site list")
	}
	c.call("PUT", "/api/sites/"+strconv.FormatInt(site, 10), map[string]any{"name": "Block page settings", "hostnames": []string{"settings.example.com"}, "upstream": "http://127.0.0.1:1", "enabled": true, "traffic_profile": "web", "block_title": strings.Repeat("x", 81)}, 400)
	c.call("PUT", "/api/sites/"+strconv.FormatInt(site, 10), map[string]any{"name": "Block page settings", "hostnames": []string{"settings.example.com"}, "upstream": "http://127.0.0.1:1", "enabled": true, "traffic_profile": "web", "block_title": "a\x00b"}, 400)
	c.call("PUT", "/api/protection-settings/"+strconv.FormatInt(site, 10), map[string]any{"mode": "block", "requests_per_second": 1, "burst": 1, "site_requests_per_second": 1000, "site_burst": 2000, "bot_mode": "off"}, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s := a.active.Load(); s == nil || s.routes["settings.example.com"] == nil {
		t.Fatal("created site missing from the active snapshot")
	}
	r := httptest.NewRequest("GET", "http://settings.example.com/", nil)
	r.Header.Set("User-Agent", "curl/8")
	w := httptest.NewRecorder()
	a.Public(w, r)
	r = httptest.NewRequest("GET", "http://settings.example.com/", nil)
	r.Header.Set("User-Agent", "curl/8")
	w = httptest.NewRecorder()
	a.Public(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("flood denial status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Example service — access denied") {
		t.Fatalf("block page does not carry the site title: %q", body)
	}
	if !strings.Contains(body, "security@example.com") || !strings.Contains(body, "ref-42") {
		t.Fatalf("block page does not carry the site contact/reference lines: %q", body)
	}
}
