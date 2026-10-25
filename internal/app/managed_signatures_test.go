package app

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSignatureFilesystem(t *testing.T) {
	files := signatureFS{"@coraza.conf-recommended": []byte("sample"), "@owasp_crs/rules.conf": []byte("rules"), "@owasp_crs/data/names.data": []byte("names")}
	if e := fstest.TestFS(files, "@coraza.conf-recommended", "@owasp_crs/rules.conf", "@owasp_crs/data/names.data"); e != nil {
		t.Fatal(e)
	}
	if _, e := files.Open("../etc/passwd"); !fs.ValidPath(".") || e == nil {
		t.Fatal("host path accepted")
	}
}
func TestManagedRequestSignatures(t *testing.T) {
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	if set.RuleCount < 100 || len(set.Files) < 20 {
		t.Fatal("signature bundle incomplete")
	}
	a := &App{managedSlots: make(chan struct{}, 64)}
	for _, mode := range []string{"observe", "block"} {
		runtime, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: mode, BodyLimit: 4096})
		if e != nil {
			t.Fatal(e)
		}
		for _, test := range []struct {
			name, method, path, content, body string
			attack                            bool
		}{
			{name: "benign", method: "GET", path: "/products?q=chair"},
			{name: "SQL query", method: "GET", path: "/search?q=" + url.QueryEscape("1' UNION SELECT password FROM users --"), attack: true},
			{name: "XSS query", method: "GET", path: "/search?q=" + url.QueryEscape(`<script>alert(1)</script>`), attack: true},
			{name: "benign JSON", method: "POST", path: "/api/search", content: "application/json", body: `{"query":"chair"}`},
			{name: "JSON attack", method: "POST", path: "/api/search", content: "application/json", body: `{"query":"1' UNION SELECT password FROM users --"}`, attack: true},
			{name: "form attack", method: "POST", path: "/search", content: "application/x-www-form-urlencoded", body: "q=" + url.QueryEscape(`<script>alert(1)</script>`), attack: true},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				r := httptest.NewRequest(test.method, "http://app.test"+test.path, strings.NewReader(test.body))
				r.Header.Set("User-Agent", "browser")
				r.Header.Set("Accept", "text/html")
				if test.content != "" {
					r.Header.Set("Content-Type", test.content)
				}
				result, blocked, status := a.inspectManaged(runtime, r, netip.MustParseAddr("203.0.113.4"))
				wantBlock := test.attack && mode == "block"
				if blocked != wantBlock {
					t.Fatalf("blocked=%v expected=%v status=%d result=%+v", blocked, wantBlock, status, result)
				}
				if test.attack && len(result.RuleIDs) == 0 {
					t.Fatal("attack had no signature attribution")
				}
				if !blocked {
					body, e := io.ReadAll(r.Body)
					if e != nil || string(body) != test.body {
						t.Fatal("forwarded body changed", e, string(body))
					}
				}
				if len(a.managedSlots) != 0 {
					t.Fatal("inspection reservation leaked")
				}
			})
		}
		// Partial Observe preserves all bytes. Strict Block rejects oversized bodies.
		payload := strings.Repeat("x", 8192)
		r := httptest.NewRequest("POST", "http://app.test/upload", strings.NewReader(payload))
		r.Header.Set("User-Agent", "browser")
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Content-Type", "application/octet-stream")
		result, blocked, status := a.inspectManaged(runtime, r, netip.MustParseAddr("203.0.113.4"))
		if mode == "observe" {
			if blocked || result.Inspection != "partial" {
				t.Fatal("observe did not permit capped inspection", result, status)
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != payload {
				t.Fatal("partial inspection truncated body")
			}
		} else if !blocked || status != http.StatusRequestEntityTooLarge {
			t.Fatal("block body limit not enforced", result, blocked, status)
		}
		if len(a.managedSlots) != 0 {
			t.Fatal("body limit reservation leaked")
		}
	}
}

func TestManagedBusyAndTargetedExclusions(t *testing.T) {
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	observer, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "observe"})
	if e != nil {
		t.Fatal(e)
	}
	a := &App{managedSlots: make(chan struct{}, 1)}
	a.managedSlots <- struct{}{}
	r := httptest.NewRequest("GET", "http://app.test/", nil)
	result, blocked, _ := a.inspectManaged(observer, r, netip.MustParseAddr("203.0.113.4"))
	if blocked || result.Inspection != "busy" {
		t.Fatal("Observe rejected saturated inspection")
	}
	<-a.managedSlots
	makeRequest := func() *http.Request {
		r := httptest.NewRequest("GET", "http://app.test/search?q="+url.QueryEscape("1' UNION SELECT password FROM users --"), nil)
		r.Header.Set("User-Agent", "browser")
		r.Header.Set("Accept", "text/html")
		return r
	}
	result, _, _ = a.inspectManaged(observer, makeRequest(), netip.MustParseAddr("203.0.113.4"))
	excluded := []int{}
	for _, id := range result.RuleIDs {
		if id >= 942000 && id < 943000 {
			excluded = append(excluded, id)
		}
	}
	if len(excluded) == 0 {
		t.Fatal("SQLi fixture did not match SQL signatures")
	}
	blocker, e := compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block", Exclusions: excluded})
	if e != nil {
		t.Fatal(e)
	}
	result, blocked, status := a.inspectManaged(blocker, makeRequest(), netip.MustParseAddr("203.0.113.4"))
	if blocked {
		t.Fatal("selected SQL exclusions did not apply", result, status)
	}
	if _, e = compileManagedSignatures(set, managedSignatureOptions{SetID: set.ID, Mode: "block", Exclusions: []int{999999}}); e == nil {
		t.Fatal("unknown rule ID accepted")
	}
	a.managedSlots <- struct{}{}
	_, blocked, status = a.inspectManaged(blocker, makeRequest(), netip.MustParseAddr("203.0.113.4"))
	<-a.managedSlots
	if !blocked || status != 503 {
		t.Fatal("Block bypassed saturated inspection")
	}
}
