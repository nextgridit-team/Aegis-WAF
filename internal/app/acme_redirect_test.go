package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The ACME directory client must not follow redirects: an admin-supplied
// directory URL that answers 30x must fail the operation instead of sending
// ACME protocol traffic to whatever the redirect points at.
func TestACMEClientRejectsRedirects(t *testing.T) {
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
	if _, e := acmeClient(redirector.URL, nil, "").Discover(context.Background()); e == nil {
		t.Fatal("acme directory redirect was followed")
	}
	if followed.Load() != 0 {
		t.Fatal("redirect target received a request")
	}
}
