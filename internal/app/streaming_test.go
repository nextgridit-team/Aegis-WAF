package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestStreamingProfileValidation(t *testing.T) {
	for _, site := range []Site{{TrafficProfile: "invalid"}, {StreamWindowBytes: 4095}, {StreamWindowBytes: 65537}} {
		if normalizeSiteTraffic(&site) == nil {
			t.Fatal("accepted invalid profile", site)
		}
	}
	for _, profile := range []string{"web", "api", "streaming"} {
		site := Site{TrafficProfile: profile}
		if err := normalizeSiteTraffic(&site); err != nil {
			t.Fatal(err)
		}
	}
	site := Site{}
	if normalizeSiteTraffic(&site) != nil || site.TrafficProfile != "web" || site.StreamWindowBytes != 8192 {
		t.Fatal("bad profile defaults", site)
	}
}
func TestStreamingWindowDetectionAndPreservation(t *testing.T) {
	for _, mode := range []string{"off", "observe", "block"} {
		t.Run(mode, func(t *testing.T) {
			second := make(chan struct{})
			tail := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: ORA-00")
				http.NewResponseController(w).Flush()
				select {
				case <-second:
				case <-r.Context().Done():
					return
				}
				io.WriteString(w, "933: database disclosure\n\n")
				http.NewResponseController(w).Flush()
				select {
				case <-tail:
					io.WriteString(w, "data: after\n\n")
				case <-r.Context().Done():
				}
			}))
			defer up.Close()
			a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: mode})
			public := httptest.NewServer(http.HandlerFunc(a.Public))
			defer public.Close()
			client := &http.Client{Timeout: 3 * time.Second}
			request, _ := http.NewRequest("GET", public.URL+"/stream", nil)
			request.Host = "managed.test"
			request.Header.Set("User-Agent", "browser")
			request.Header.Set("Accept", "text/event-stream")
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			prefix := make([]byte, len("data: ORA-00"))
			if _, e = io.ReadFull(response.Body, prefix); e != nil {
				t.Fatal("first chunk withheld", e)
			}
			close(second)
			part := make([]byte, len("933: database disclosure\n\n"))
			if _, e = io.ReadFull(response.Body, part); e != nil {
				t.Fatal("second chunk withheld", e)
			}
			if mode != "block" {
				close(tail)
			}
			rest, readErr := io.ReadAll(response.Body)
			if mode == "block" {
				if readErr == nil || len(rest) != 0 {
					t.Fatalf("stream not terminated: %q %v", rest, readErr)
				}
			} else if readErr != nil || string(rest) != "data: after\n\n" {
				t.Fatalf("stream changed: %q %v", rest, readErr)
			}
			select {
			case event := <-a.access:
				if event.blocked != (mode == "block") {
					t.Fatal("wrong block metadata", event.managed)
				}
				if mode != "off" {
					found := false
					for _, id := range event.managed.RuleIDs {
						found = found || id == 951120
					}
					if !found || event.managed.StreamWindows < 2 {
						t.Fatal("cross-chunk signature missing", event.managed)
					}
					if mode == "block" && (event.status != 200 || event.managed.ResponseInspection != "stream_match") {
						t.Fatal("stream outcome misrepresented", event.managed, event.status)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("missing stream log")
			}
			if len(a.managedSlots) != 0 {
				t.Fatal("stream reservation leaked")
			}
		})
	}
}
func TestStreamingWindowMemoryBoundAndBusy(t *testing.T) {
	set, _ := bundledSignatureSet()
	runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block", ResponseMode: "observe"})
	if e != nil {
		t.Fatal(e)
	}
	a := &App{managedSlots: make(chan struct{}, 1)}
	result := managedSignatureResult{}
	blocked := false
	request := httptest.NewRequest("GET", "http://managed.test/", nil)
	response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Request: request}
	s := &managedResponseState{app: a, runtime: runtime, result: &result, blocked: &blocked, clientIP: netip.MustParseAddr("198.51.100.1")}
	body := &streamSignatureBody{original: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 256<<10))), state: s, response: response, limit: 4096, window: make([]byte, 0, 4096)}
	result.ResponseInspection = "stream_windows"
	p := make([]byte, 32<<10)
	for {
		_, e := body.Read(p)
		if cap(body.window) > 4096 || len(body.window) > 4096 {
			t.Fatal("unbounded window")
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	body.Close()
	if result.StreamBytes != 256<<10 || result.StreamWindows != 128 {
		t.Fatal("incomplete rolling coverage", result)
	}
	a.managedSlots <- struct{}{}
	if e := body.inspectWindow(); e != nil || result.ResponseInspection != "stream_busy" {
		t.Fatal("observe busy behavior", e, result)
	}
	runtime.Options.ResponseMode = "block"
	if e := body.inspectWindow(); e == nil || !blocked {
		t.Fatal("block busy behavior", e)
	}
	<-a.managedSlots
	// Close must unblock an underlying read without waiting for it to finish.
	reader, writer := io.Pipe()
	defer writer.Close()
	b := &streamSignatureBody{original: reader, limit: 4096}
	done := make(chan struct{})
	go func() { b.Read(make([]byte, 1)); close(done) }()
	b.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close blocked")
	}
}

func TestStreamingProfileIntegration(t *testing.T) {
	a, _, api, site, _ := captchaFixture(t)
	path := fmt.Sprintf("/api/sites/%d", site)
	input := map[string]any{"name": "Stream app", "hostnames": []string{"bot.test"}, "upstream": "http://127.0.0.1:18080", "enabled": true, "traffic_profile": "streaming", "stream_window_bytes": 4096}
	api.call("PUT", path, input, 200)
	if e := a.refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	route := a.active.Load().routes["bot.test"]
	if route.site.TrafficProfile != "streaming" || route.site.StreamWindowBytes != 4096 || route.proxy.FlushInterval >= 0 || route.proxy.Transport.(*http.Transport).ResponseHeaderTimeout != 2*time.Minute {
		t.Fatal("profile did not become active")
	}
	raw := api.call("GET", "/api/sites", nil, 200)
	if !bytes.Contains(raw, []byte(`"traffic_profile": "streaming"`)) && !bytes.Contains(raw, []byte(`"traffic_profile":"streaming"`)) {
		t.Fatal("profile missing from reads", string(raw))
	}
	input["traffic_profile"] = "invalid"
	api.call("PUT", path, input, 400)
	input["traffic_profile"] = "streaming"
	input["stream_window_bytes"] = 65537
	api.call("PUT", path, input, 400)
	if a.active.Load().routes["bot.test"] != route {
		t.Fatal("invalid profile replaced working config")
	}
}
