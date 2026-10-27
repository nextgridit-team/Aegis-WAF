package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConnectionIdleTracksActiveUpload(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, e := io.Copy(io.Discard, r.Body)
		if e == nil {
			io.WriteString(w, "uploaded")
		}
	}))
	defer up.Close()
	a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", BodyLimit: 4096, BodyLimitAction: "process_partial"})
	route := a.active.Load().routes["managed.test"]
	route.site.TrafficProfile = "api"
	target, _ := url.Parse(up.URL)
	route.proxy = newSiteProxy(target, route.site, HeaderSettings{})
	p := a.active.Load().policyBindings[1][0].Protection
	p.connectionMode = "block"
	p.connectionLimits = &connectionLimitSettings{Enabled: true, MaxConcurrent: 2, MaxPerClient: 1, MaxDurationSeconds: 5, IdleTimeoutSeconds: 1}
	server := httptest.NewServer(http.HandlerFunc(a.Public))
	defer server.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer writer.Close()
		if _, e := io.WriteString(writer, "payload="+strings.Repeat("x", 5000)); e != nil {
			return
		}
		for range 7 {
			time.Sleep(200 * time.Millisecond)
			if _, e := io.WriteString(writer, strings.Repeat("x", 1000)); e != nil {
				return
			}
		}
	}()
	req, _ := http.NewRequest("POST", server.URL, reader)
	req.Host = "managed.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "curl/8")
	req.Header.Set("Accept", "text/plain")
	response, e := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || string(body) != "uploaded" {
		t.Fatal("active upload treated as idle", response.StatusCode, string(body))
	}
	<-done
}
