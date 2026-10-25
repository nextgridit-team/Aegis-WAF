package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestResponseProvenance(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/403" {
			w.WriteHeader(403)
		} else if r.URL.Path == "/502" {
			w.WriteHeader(502)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	badTarget, _ := url.Parse(dead.URL)
	settings := defaultProtection()
	settings.BotMode = "block"
	p, _ := compileProtection(settings)
	site := Site{ID: 1, Hostnames: []string{"source.test"}, Headers: &HeaderSettings{}}
	rt := &route{site: site, proxy: newProxy(target, false)}
	a := &App{access: make(chan accessEvent, 16)}
	snapshot := &snapshot{routes: map[string]*route{"source.test": rt}, protection: map[int64]*protectionPolicy{1: p}}
	a.active.Store(snapshot)
	for _, test := range []struct {
		path, ua, source string
		status           int
	}{{"/", "curl/8", "upstream", 200}, {"/403", "curl/8", "upstream", 403}, {"/502", "curl/8", "upstream", 502}, {"/", "sqlmap/1", "waf", 403}} {
		r := httptest.NewRequest("GET", "http://source.test"+test.path, nil)
		r.Header.Set("User-Agent", test.ua)
		w := httptest.NewRecorder()
		a.Public(w, r)
		event := <-a.access
		if w.Code != test.status || event.responseSource != test.source {
			t.Fatalf("%+v -> status=%d source=%s", test, w.Code, event.responseSource)
		}
	}
	rt.site.RedirectHTTPS = true
	r := httptest.NewRequest("GET", "http://source.test/", nil)
	r.Header.Set("User-Agent", "curl/8")
	w := httptest.NewRecorder()
	a.Public(w, r)
	event := <-a.access
	if w.Code != 308 || event.responseSource != "redirect" {
		t.Fatalf("redirect %d %+v", w.Code, event)
	}
	rt.site.RedirectHTTPS = false
	rt.proxy = newProxy(badTarget, false)
	w = httptest.NewRecorder()
	a.Public(w, r)
	event = <-a.access
	if w.Code != 502 || event.responseSource != "gateway_error" {
		t.Fatalf("gateway failure %d %+v", w.Code, event)
	}
}
func TestAddressDisplaySpecificity(t *testing.T) {
	names := addressNames{{netip.MustParsePrefix("10.0.0.0/8"), "Internal"}, {netip.MustParsePrefix("10.1.2.0/24"), "Office"}, {netip.MustParsePrefix("10.1.2.3/32"), "Monitor"}, {netip.MustParsePrefix("10.1.2.3/32"), "Probe"}, {netip.MustParsePrefix("2001:db8::/32"), "IPv6 office"}}
	for _, test := range []struct {
		ip   string
		want []string
	}{{"10.1.2.3", []string{"Monitor", "Probe"}}, {"10.1.2.4", []string{"Office"}}, {"10.3.4.5:1234", []string{"Internal"}}, {"::ffff:10.1.2.4", []string{"Office"}}, {"2001:db8::1", []string{"IPv6 office"}}, {"198.51.100.1", []string{}}, {"invalid", []string{}}} {
		got, _ := json.Marshal(names.match(test.ip))
		want, _ := json.Marshal(test.want)
		if string(got) != string(want) {
			t.Fatalf("%s %s want %s", test.ip, got, want)
		}
	}
}
func TestResponseStatusBreakdownIntegration(t *testing.T) {
	cfg := testDB(t)
	a := newTestReplica(t, cfg)
	ctx := context.Background()
	srv := httptest.NewServer(a.Management())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, srv.URL, ""}
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "response dashboard test password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "response dashboard test password"}, 200), &login)
	c.csrf = login["csrf"]
	site := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "First proxy", "hostnames": []string{"first.test"}, "upstream": "http://127.0.0.1:18081", "enabled": true}, 200))
	other := mustID(t, c.call("POST", "/api/sites", map[string]any{"name": "Second proxy", "hostnames": []string{"second.test"}, "upstream": "http://127.0.0.1:18082", "enabled": true}, 200))
	object := mustID(t, c.call("POST", "/api/address-objects", map[string]string{"name": "Office monitor", "value": "198.51.100.4"}, 200))
	batch := []accessEvent{{site: site, status: 403, responseSource: "upstream"}, {site: site, status: 403, responseSource: "waf", blocked: true}, {site: site, status: 502, responseSource: "upstream"}, {site: other, status: 502, responseSource: "gateway_error"}, {site: other, status: 403}}
	for n := range batch {
		batch[n].at = time.Now()
		batch[n].method = "GET"
		batch[n].peer = "198.51.100.4"
	}
	if e := a.storeAccessBatch(ctx, batch); e != nil {
		t.Fatal(e)
	}
	var live struct {
		Events []struct {
			Site    int64    `json:"site_id"`
			Source  string   `json:"response_source"`
			Objects []string `json:"client_objects"`
		}
	}
	json.Unmarshal(c.call("GET", fmt.Sprintf("/api/live-traffic?site_id=%d", site), nil, 200), &live)
	if len(live.Events) != 3 {
		t.Fatal("live filter missing records")
	}
	for _, event := range live.Events {
		if event.Site != site || len(event.Objects) != 1 {
			t.Fatal("live context missing", event)
		}
	}
	c.call("GET", "/api/live-traffic?site_id=-1", nil, 400)
	type row struct {
		SiteID           int64   `json:"site_id"`
		Name             *string `json:"site_name"`
		Source           string  `json:"response_source"`
		Status, Requests int
		Hostnames        []string
	}
	var report struct {
		Rows   []row `json:"response_statuses"`
		Recent []struct {
			ID      int64
			Peer    string
			Objects []string `json:"client_objects"`
		}
	}
	json.Unmarshal(c.call("GET", "/api/dashboard", nil, 200), &report)
	if len(report.Rows) != 5 || len(report.Recent) != 5 {
		t.Fatalf("missing status/source/host groups %+v", report)
	}
	for _, event := range report.Recent {
		if event.Peer != "198.51.100.4" || len(event.Objects) != 1 || event.Objects[0] != "Office monitor" {
			t.Fatalf("missing IP identity %+v", event)
		}
	}
	var filtered struct {
		Rows []row `json:"response_statuses"`
	}
	json.Unmarshal(c.call("GET", fmt.Sprintf("/api/dashboard?site_id=%d", site), nil, 200), &filtered)
	if len(filtered.Rows) != 3 {
		t.Fatalf("site filter %+v", filtered)
	}
	for _, r := range filtered.Rows {
		if r.SiteID != site || r.Name == nil || *r.Name != "First proxy" || len(r.Hostnames) != 1 {
			t.Fatalf("missing host context %+v", r)
		}
	}
	c.call("PUT", fmt.Sprintf("/api/address-objects/%d", object), map[string]string{"name": "Renamed monitor", "value": "198.51.100.4"}, 200)
	var logs []struct {
		Peer    string
		Objects []string `json:"client_objects"`
	}
	json.Unmarshal(c.call("GET", "/api/access-logs", nil, 200), &logs)
	if len(logs) == 0 || logs[0].Objects[0] != "Renamed monitor" {
		t.Fatal("object rename not reflected")
	}
	var detail struct {
		Event struct {
			Objects []string `json:"client_objects"`
		}
	}
	json.Unmarshal(c.call("GET", fmt.Sprintf("/api/access-logs/%d", report.Recent[0].ID), nil, 200), &detail)
	if len(detail.Event.Objects) != 1 || detail.Event.Objects[0] != "Renamed monitor" {
		t.Fatal("details missing current object name")
	}
	c.call("DELETE", fmt.Sprintf("/api/sites/%d", other), nil, 200)
	json.Unmarshal(c.call("GET", fmt.Sprintf("/api/dashboard?site_id=%d", other), nil, 200), &filtered)
	if len(filtered.Rows) != 2 || filtered.Rows[0].Name != nil {
		t.Fatal("deleted proxy history lost or invented name")
	}
}
