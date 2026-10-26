package app

import (
	"encoding/json"
	community "github.com/nextgridit-team/Aegis-WAF/rules/community"
	"net/http/httptest"
	"testing"
)

// Measures this actual catalogue's bounded matcher path, including fresh fact
// caches. It excludes TLS, upstream I/O, CRS, logging and network round trips.
func BenchmarkCommunityCatalogue(b *testing.B) {
	raw, e := community.Files.ReadFile("manifest.json")
	if e != nil {
		b.Fatal(e)
	}
	var manifest ruleManifest
	if e = json.Unmarshal(raw, &manifest); e != nil {
		b.Fatal(e)
	}
	rules := []compiledRule{}
	for _, entry := range manifest.Rules {
		raw, e = community.Files.ReadFile(entry.Path)
		if e != nil {
			b.Fatal(e)
		}
		file, e := parseCatalogueRule(raw, entry)
		if e != nil {
			b.Fatal(e)
		}
		rule, e := compileRule(file.Rule)
		if e != nil {
			b.Fatal(e)
		}
		rules = append(rules, rule)
	}
	for _, method := range []string{"GET", "POST"} {
		b.Run(method, func(b *testing.B) {
			request := httptest.NewRequest(method, "https://example.test/api/v1/models", nil)
			request.Header.Set("User-Agent", "Aegis benchmark browser")
			request.Header.Set("Accept", "application/json")
			matched := 0
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				facts := newRequestFacts(request)
				for _, rule := range rules {
					if rule.evaluate(facts.get) == "matched" {
						matched++
					}
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(len(rules)), "rules/op")
			if matched != 0 {
				b.Fatal("ordinary API control unexpectedly matched", matched)
			}
		})
	}
}
