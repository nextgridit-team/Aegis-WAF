package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// /readyz answers directly: a 3xx from it must read as not ready, not be
// followed to whatever it points at.
func TestHealthcheckClientRefusesRedirects(t *testing.T) {
	var followed atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Add(1)
		w.WriteHeader(200)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	res, e := healthcheckClient(false).Get(redirector.URL)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if followed.Load() != 0 {
		t.Fatal("healthcheck client followed a redirect from /readyz")
	}
	if res.StatusCode == 200 {
		t.Fatal("a redirecting /readyz read as healthy")
	}
}
