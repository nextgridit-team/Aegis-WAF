package app

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sqlLeak = "Database error: ORA-00933: internal database credentials"

func TestManagedResponseSignatures(t *testing.T) {
	for _, mode := range []string{"off", "observe", "block"} {
		t.Run(mode, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode != "off" && r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("inspection did not request identity encoding")
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Upstream-Secret", "must-not-leak-on-block")
				io.WriteString(w, sqlLeak)
			}))
			defer up.Close()
			a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: mode})
			request := httptest.NewRequest("GET", "http://managed.test/", nil)
			request.Header.Set("User-Agent", "browser")
			request.Header.Set("Accept", "text/html")
			request.Header.Set("Accept-Encoding", "gzip")
			response := httptest.NewRecorder()
			a.Public(response, request)
			event := <-a.access
			if mode == "block" {
				if response.Code != 502 || strings.Contains(response.Body.String(), sqlLeak) || response.Header().Get("X-Upstream-Secret") != "" {
					t.Fatalf("response leaked: %d %s %v", response.Code, response.Body.String(), response.Header())
				}
				if !event.blocked || event.responseSource != "waf" || event.managed.ResponseInspection != "match" {
					t.Fatalf("missing response block metadata: %+v", event)
				}
			} else if response.Code != 200 || response.Body.String() != sqlLeak || event.blocked {
				t.Fatalf("response changed: %d %s", response.Code, response.Body.String())
			}
			if mode != "off" {
				found := false
				for _, id := range event.managed.RuleIDs {
					found = found || id == 951120
				}
				if !found {
					t.Fatalf("real outbound SQL signature not recorded: %+v", event.managed)
				}
			}
			if len(a.managedSlots) != 0 {
				t.Fatal("inspection reservation leaked")
			}
		})
	}
}

func TestManagedResponseLimitsAndPreservation(t *testing.T) {
	for _, test := range []struct {
		name, mode, action, content, encoding string
		size, want                            int
		chunked                               bool
		inspection                            string
	}{
		{name: "exact limit", mode: "block", size: 4096, want: 200, inspection: "complete"},
		{name: "known reject", mode: "block", size: 4097, want: 502, inspection: "body_limit"},
		{name: "chunked reject", mode: "block", size: 8192, want: 502, chunked: true, inspection: "body_limit"},
		{name: "partial block", mode: "block", action: "process_partial", size: 8192, want: 200, chunked: true, inspection: "partial"},
		{name: "observe oversized", mode: "observe", size: 8192, want: 200, inspection: "partial"},
		{name: "binary streams", mode: "block", content: "application/octet-stream", size: 8192, want: 200, inspection: "skipped_content_type"},
		{name: "encoded block", mode: "block", encoding: "gzip", size: 300, want: 502, inspection: "unsupported_encoding"},
		{name: "encoded observe", mode: "observe", encoding: "gzip", size: 300, want: 200, inspection: "unsupported_encoding"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := strings.Repeat("a", test.size)
			if test.encoding != "" {
				var b bytes.Buffer
				z := gzip.NewWriter(&b)
				z.Write([]byte(payload))
				z.Close()
				payload = b.String()
			}
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				content := test.content
				if content == "" {
					content = "text/plain"
				}
				w.Header().Set("Content-Type", content)
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				if test.chunked {
					http.NewResponseController(w).Flush()
				}
				io.WriteString(w, payload)
			}))
			defer up.Close()
			a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: test.mode, ResponseBodyLimit: 4096, ResponseBodyLimitAction: test.action})
			request := httptest.NewRequest("GET", "http://managed.test/", nil)
			request.Header.Set("User-Agent", "browser")
			response := httptest.NewRecorder()
			a.Public(response, request)
			event := <-a.access
			if response.Code != test.want || event.managed.ResponseInspection != test.inspection {
				t.Fatalf("got %d %+v", response.Code, event.managed)
			}
			if test.want == 200 && response.Body.String() != payload {
				t.Fatal("response bytes changed")
			}
			if len(a.managedSlots) != 0 {
				t.Fatal("reservation leaked")
			}
		})
	}
}

func TestManagedRequestPartialAndBoundary(t *testing.T) {
	set, _ := bundledSignatureSet()
	for _, kind := range []string{"binary", "multipart", "json", "form", "attack"} {
		t.Run(kind, func(t *testing.T) {
			payload := strings.Repeat("a", 8192)
			content := "application/octet-stream"
			switch kind {
			case "multipart":
				var b bytes.Buffer
				form := multipart.NewWriter(&b)
				file, _ := form.CreateFormFile("upload", "large.txt")
				io.WriteString(file, payload)
				form.Close()
				payload = b.String()
				content = form.FormDataContentType()
			case "json":
				payload = `{"message":"` + payload + `"}`
				content = "application/json"
			case "form":
				payload = "message=" + payload
				content = "application/x-www-form-urlencoded"
			case "attack":
				payload = "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&data=" + payload
				content = "application/x-www-form-urlencoded"
			}
			runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block", BodyLimit: 4096, BodyLimitAction: "process_partial", Exclusions: []int{920420}})
			if e != nil {
				t.Fatal(e)
			}
			a := &App{managedSlots: make(chan struct{}, 1)}
			r := httptest.NewRequest("POST", "http://managed.test/upload", strings.NewReader(payload))
			r.Header.Set("Content-Type", content)
			r.Header.Set("User-Agent", "browser")
			result, blocked, status := a.inspectManaged(runtime, r, mustManagedIP())
			if kind == "attack" {
				if !blocked {
					t.Fatal("partial action bypassed prefix attack")
				}
				return
			}
			if kind == "json" || kind == "multipart" { // A truncated structured body may remain fail-closed on parser errors.
				if blocked {
					if len(a.managedSlots) != 0 {
						t.Fatal("reservation leaked")
					}
					t.Logf("structured prefix rejected safely: status=%d inspection=%s", status, result.Inspection)
					return
				}
			}
			if blocked || result.Inspection != "partial" {
				t.Fatalf("partial upload rejected: %d %+v", status, result)
			}
			actual, e := io.ReadAll(r.Body)
			r.Body.Close()
			if e != nil || string(actual) != payload {
				t.Fatal("upload changed", e)
			}
			if len(a.managedSlots) != 0 {
				t.Fatal("reservation leaked")
			}
		})
	}
	runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block", BodyLimit: 4096, Exclusions: []int{920420}})
	if e != nil {
		t.Fatal(e)
	}
	a := &App{managedSlots: make(chan struct{}, 1)}
	r := httptest.NewRequest("POST", "http://managed.test/upload", strings.NewReader(strings.Repeat("a", 4096)))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("User-Agent", "browser")
	result, blocked, status := a.inspectManaged(runtime, r, mustManagedIP())
	if blocked || result.Inspection != "complete" {
		t.Fatalf("exact limit rejected: %d %+v", status, result)
	}
	r.Body.Close()
}

func TestManagedInspectionOptionValidation(t *testing.T) {
	for _, options := range []managedSignatureOptions{{BodyLimitAction: "allow"}, {ResponseMode: "invalid"}, {ResponseBodyLimitAction: "allow"}, {ResponseBodyLimit: 2}, {OutboundThreshold: 101}} {
		if _, e := normalizeManagedSignatures(options); e == nil {
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
	options, e := normalizeManagedSignatures(managedSignatureOptions{})
	if e != nil || options.ResponseMode != "off" || options.BodyLimitAction != "reject" || options.ResponseBodyLimit != 256<<10 {
		t.Fatal("legacy defaults changed", options, e)
	}
	options, e = normalizeManagedSignatures(managedSignatureOptions{SetID: "test", Mode: "observe", ResponseMode: "block"})
	if e != nil || options.ResponseMode != "block" || effectiveManagedOptions(options, "observe").ResponseMode != "observe" {
		t.Fatal("Observe did not preserve and cap configured response enforcement")
	}
}

func TestManagedResponseScopedExclusionAndThreshold(t *testing.T) {
	for _, test := range []struct {
		name, path          string
		threshold           int
		excluded, wantBlock bool
	}{
		{name: "normal block", path: "/public", threshold: 4, wantBlock: true},
		{name: "higher threshold", path: "/public", threshold: 10},
		{name: "path exception", path: "/debug/info", threshold: 4, excluded: true},
		{name: "exception outside path", path: "/public", threshold: 4, excluded: true, wantBlock: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, sqlLeak)
			}))
			defer up.Close()
			options := managedSignatureOptions{Mode: "block", ResponseMode: "block", OutboundThreshold: test.threshold}
			if test.excluded {
				options.ScopedExclusions = []signatureException{{RuleIDs: []int{951120}, PathPrefix: "/debug"}}
			}
			a := managedPublicFixture(t, up.URL, options)
			r := httptest.NewRequest("GET", "http://managed.test"+test.path, nil)
			r.Header.Set("User-Agent", "browser")
			w := httptest.NewRecorder()
			a.Public(w, r)
			event := <-a.access
			if event.blocked != test.wantBlock || (w.Code == 502) != test.wantBlock {
				t.Fatalf("got %d %+v", w.Code, event.managed)
			}
		})
	}
	if _, e := normalizeSignatureExceptions([]signatureException{{RuleIDs: []int{951120}, Parameters: []string{"q"}}}); e == nil {
		t.Fatal("request parameter accepted for response exception")
	}
}

func TestManagedResponseStallCancelsUpstream(t *testing.T) {
	canceled := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "prefix")
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer up.Close()
	a := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", ResponseMode: "block"})
	r := httptest.NewRequest("GET", "http://managed.test/stall", nil)
	r.Header.Set("User-Agent", "browser")
	w := httptest.NewRecorder()
	a.Public(w, r)
	event := <-a.access
	if w.Code != 502 || event.managed.ResponseInspection != "read_error_or_timeout" || strings.Contains(w.Body.String(), "prefix") {
		t.Fatalf("stalled response leaked: %d %+v", w.Code, event.managed)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream was not canceled")
	}
	if len(a.managedSlots) != 0 {
		t.Fatal("reservation leaked")
	}
}
