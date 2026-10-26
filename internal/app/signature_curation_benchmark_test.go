package app

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

// Compare a benign request against the full source and one selected detector.
// Includes request construction and Coraza inspection, excludes network/logging.
func BenchmarkCuratedManaged(b *testing.B) {
	source, e := bundledSignatureSet()
	if e != nil {
		b.Fatal(e)
	}
	lean, e := curateSignatures(source, "Benchmark SQL", []int{942100})
	if e != nil {
		b.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		set  signatureSet
	}{{"full_source", source}, {"one_detector_plus_support", lean}} {
		b.Run(tc.name, func(b *testing.B) {
			runtime, e := compileManagedSignatures(tc.set, managedSignatureOptions{SetID: tc.set.ID, Mode: "observe"})
			if e != nil {
				b.Fatal(e)
			}
			defer closeManagedRuntime(runtime)
			app := &App{managedSlots: make(chan struct{}, 64)}
			ip := netip.MustParseAddr("203.0.113.4")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				request := httptest.NewRequest("GET", "http://app.test/products?q=chair", nil)
				request.Header.Set("User-Agent", "browser")
				request.Header.Set("Accept", "text/html")
				result, blocked, _ := app.inspectManaged(runtime, request, ip)
				if blocked || len(result.RuleIDs) > 0 {
					b.Fatal("ordinary control request unexpectedly matched")
				}
			}
		})
	}
}
