package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestForwardingBufferReuseDoesNotLeakOrTruncate(t *testing.T) {
	payload := strings.Repeat("private-upstream-value", 10000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			io.WriteString(w, payload)
		} else {
			io.WriteString(w, "short")
		}
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	proxy := newProxy(target, false)
	for _, path := range []string{"/large", "/short", "/large", "/short"} {
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://app.test"+path, nil))
		want := "short"
		if path == "/large" {
			want = payload
		}
		if w.Code != 200 || w.Body.String() != want {
			t.Fatal("response changed or stale bytes leaked")
		}
	}
	pool := &proxyBufferPool{}
	buffer := pool.Get()
	copy(buffer, "sensitive")
	pool.Put(buffer)
	for _, value := range buffer {
		if value != 0 {
			t.Fatal("idle buffer retained response content")
		}
	}
}
