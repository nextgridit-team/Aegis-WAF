package app

import (
	"fmt"
	"testing"
)

// Config-refresh compile cost for the distinct-engine budget: every distinct
// managed-signature configuration compiles one Coraza CRS engine per replica
// at snapshot load. Memory per engine is cheap (~25 MiB measured live); this
// is the number that gates raising the cap. Thresholds mint distinct runtime
// keys exactly like distinct postures do.
func BenchmarkCompileManagedSignatures(b *testing.B) {
	source, e := bundledSignatureSet()
	if e != nil {
		b.Fatal(e)
	}
	for _, engines := range []int{1, 8, 16, 32} {
		b.Run(fmt.Sprintf("engines_%d", engines), func(b *testing.B) {
			options := make([]managedSignatureOptions, engines)
			for n := range options {
				options[n] = managedSignatureOptions{SetID: source.ID, Mode: "observe", Threshold: 1 + n}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for _, candidate := range options {
					runtime, e := compileManagedSignatures(source, candidate)
					if e != nil {
						b.Fatal(e)
					}
					closeManagedRuntime(runtime)
				}
			}
		})
	}
}
