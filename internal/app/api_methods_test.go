package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEndpointMethodDefaultsAndExplicitPolicy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	for _, profile := range []string{"web", "api", "streaming"} {
		app := managedPublicFixture(t, up.URL)
		route := app.active.Load().routes["managed.test"]
		route.site.TrafficProfile = profile
		target, _ := url.Parse(up.URL)
		route.proxy = newSiteProxy(target, route.site, HeaderSettings{})
		for _, method := range []string{"GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"} {
			req := httptest.NewRequest(method, "http://managed.test/api/items", nil)
			req.Host = "managed.test"
			req.Header.Set("User-Agent", "curl/8")
			req.Header.Set("Accept", "application/json")
			rec := httptest.NewRecorder()
			app.Public(rec, req)
			expected := 200
			if method == "TRACE" || method == "CONNECT" || (profile == "web" && (method == "PUT" || method == "PATCH" || method == "DELETE")) {
				expected = 403
			}
			if rec.Code != expected {
				t.Errorf("%s %s got%d want%d", profile, method, rec.Code, expected)
			}
			<-app.access
		}
		req := httptest.NewRequest("POST", "http://managed.test/api/items", strings.NewReader(`{"query":"1' UNION SELECT password FROM users --"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Host = "managed.test"
		req.Header.Set("User-Agent", "curl/8")
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		app.Public(rec, req)
		if rec.Code != 403 {
			t.Fatal("API methods disabled body protection", profile, rec.Code)
		}
		<-app.access
		if profile != "web" {
			out, _, e := simulatePayload(context.Background(), app, app.active.Load(), simulationPayload{Host: "managed.test", Method: "PUT", ClientIP: "198.51.100.2", Path: "/api/items", Headers: map[string]string{"User-Agent": "curl/8", "Accept": "application/json"}})
			if e != nil || out != "allow" {
				t.Fatal("simulation profile mismatch", out, e)
			}
		}
	}
	restricted := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", AllowedMethods: []string{"GET", "POST"}})
	restricted.active.Load().routes["managed.test"].site.TrafficProfile = "api"
	req := httptest.NewRequest("PUT", "http://managed.test/api/items", nil)
	req.Host = "managed.test"
	req.Header.Set("User-Agent", "curl/8")
	rec := httptest.NewRecorder()
	restricted.Public(rec, req)
	if rec.Code != 403 {
		t.Fatal("explicit method restriction lost", rec.Code)
	}

	// Configured methods are exact tokens; partial names must not exploit CRS @within.
	for _, method := range []string{"GE", "ET", "PO"} {
		request := httptest.NewRequest(method, "http://managed.test/api/items", nil)
		request.Host = "managed.test"
		request.Header.Set("User-Agent", "curl/8")
		response := httptest.NewRecorder()
		restricted.Public(response, request)
		if response.Code != 403 {
			t.Fatal("partial method token accepted", method, response.Code)
		}
	}
	custom := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", AllowedMethods: []string{"GET", "PROPFIND"}})
	request := httptest.NewRequest("PROPFIND", "http://managed.test/", nil)
	request.Host = "managed.test"
	request.Header.Set("User-Agent", "curl/8")
	response := httptest.NewRecorder()
	custom.Public(response, request)
	if response.Code != 200 {
		t.Fatal("explicit custom method rejected", response.Code)
	}
	// Deliberately excluding the method rule keeps its usual semantics; other checks stay active.
	noMethodRule := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", AllowedMethods: []string{"GET"}, Exclusions: []int{911100}})
	noMethodRule.active.Load().routes["managed.test"].site.TrafficProfile = "api"
	request = httptest.NewRequest("PUT", "http://managed.test/", strings.NewReader(`{"name":"chair"}`))
	request.Host = "managed.test"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "curl/8")
	request.Header.Set("Accept", "application/json")
	response = httptest.NewRecorder()
	noMethodRule.Public(response, request)
	if response.Code != 200 {
		t.Fatal("excluded CRS method rule unexpectedly enforced", response.Code)
	}
	for _, methods := range [][]string{{"GET;SecRuleEngine Off"}, {"GET POST"}, {""}} {
		if _, e := normalizeManagedSignatures(managedSignatureOptions{AllowedMethods: methods}); e == nil {
			t.Fatal("invalid methods accepted", methods)
		}
	}
}
