package app

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func BenchmarkRuleEvaluation(b *testing.B) {
	for _, count := range []int{0, 10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", count), func(b *testing.B) {
			rules := make([]compiledRule, count)
			for n := range rules {
				spec := probeRule("path", "", "equals", fmt.Sprintf("/blocked/%d", n))
				compiled, e := compileRule(spec)
				if e != nil {
					b.Fatal(e)
				}
				compiled.Expires = time.Now().Add(time.Hour)
				rules[n] = compiled
			}
			request := httptest.NewRequest("GET", "https://app.test/healthy", nil)
			now := time.Now()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, _ = evaluateRules(rules, newRequestFacts(request), now)
			}
		})
	}
}
func BenchmarkResolvedProtection(b *testing.B) {
	a := &App{}
	settings := defaultProtection()
	settings.Mode = "observe"
	settings.BotMode = "observe"
	settings.Burst = 1000000
	settings.RequestsPerSecond = 100000
	p, e := compileProtection(settings)
	if e != nil {
		b.Fatal(e)
	}
	request := httptest.NewRequest("GET", "https://app.test/healthy", nil)
	request.RemoteAddr = "203.0.113.4:1234"
	request.Header.Set("User-Agent", "browser")
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		now = now.Add(time.Millisecond)
		ip, reliable := p.resolveClientIP(request)
		a.protectResolved(p, 1, request, ip, now, reliable)
	}
}

// Forwarding includes an actual upstream HTTP round trip, with a local response
// recorder so allocation profiling isolates the proxy's copy path.
func BenchmarkForwarding(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "forwarded response") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := newProxy(target, false)
	request := httptest.NewRequest("GET", "http://app.test/healthy", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, request)
		if w.Code != 200 || w.Body.String() != "forwarded response" {
			b.Fatal("invalid proxy response")
		}
	}
}
