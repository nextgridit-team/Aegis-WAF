package evaluation

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	conf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/jcchavezs/mergefs"
)

func engine(tb testing.TB, mode string) http.Handler {
	tb.Helper()
	waf, e := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, conf.FS)).
		WithDirectivesFromFile("@coraza.conf-recommended").
		WithDirectivesFromFile("@crs-setup.conf.example").
		WithDirectivesFromFile("@owasp_crs/*.conf").
		WithDirectives("SecRuleEngine " + mode + "\nSecAuditEngine Off\nSecDebugLogLevel 0\nSecResponseBodyAccess Off\nSecRequestBodyLimit 65536\nSecRequestBodyNoFilesLimit 65536\nSecRequestBodyInMemoryLimit 65536\nSecRequestBodyLimitAction Reject"))
	if e != nil {
		tb.Fatal(e)
	}
	return corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(r.Body)
		if e != nil {
			tb.Error(e)
		}
		w.WriteHeader(202)
		w.Write(body)
	}))
}
func TestCRSCompatibilityFixtures(t *testing.T) {
	blocking := engine(t, "On")
	observing := engine(t, "DetectionOnly")
	cases := []struct {
		name, method, path, content, body string
		attack                            bool
	}{
		{name: "benign", method: "GET", path: "/products?q=chairs"},
		{name: "benign JSON", method: "POST", path: "/api/search", content: "application/json", body: `{"query":"chairs"}`},
		{name: "SQL injection", method: "GET", path: "/search?q=" + url.QueryEscape("1' UNION SELECT password FROM users --"), attack: true},
		{name: "XSS", method: "GET", path: "/search?q=" + url.QueryEscape(`<script>alert(1)</script>`), attack: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []struct {
				name string
				h    http.Handler
			}{{"block", blocking}, {"observe", observing}} {
				r := httptest.NewRequest(test.method, "http://app.test"+test.path, strings.NewReader(test.body))
				r.Header.Set("User-Agent", "Aegis-test-browser")
				r.Header.Set("Accept", "text/html")
				if test.content != "" {
					r.Header.Set("Content-Type", test.content)
				}
				w := httptest.NewRecorder()
				mode.h.ServeHTTP(w, r)
				want := 202
				if mode.name == "block" && test.attack {
					want = 403
				}
				if w.Code != want {
					t.Fatalf("%s got %d want %d", mode.name, w.Code, want)
				}
				if w.Code == 202 && w.Body.String() != test.body {
					t.Fatal("upstream body changed")
				}
			}
		})
	}
}
func BenchmarkCRSBenignRequest(b *testing.B) {
	h := engine(b, "On")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r := httptest.NewRequest("GET", "http://app.test/products?q=chairs", nil)
		r.Header.Set("User-Agent", "Aegis-test-browser")
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 202 {
			b.Fatal(w.Code)
		}
	}
}
