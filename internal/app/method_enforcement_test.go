package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The policy-owned method allowlist must be enforced natively: excluding CRS
// rule 911100 from the signature set (or running with managed signatures off)
// may not silently disarm the safeguard.
func TestMethodAllowlistNativeEnforcement(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	probe := func(app *App, method string) (int, []string) {
		request := httptest.NewRequest(method, "http://managed.test/api/items", nil)
		request.Host = "managed.test"
		request.Header.Set("User-Agent", "curl/8")
		recorder := httptest.NewRecorder()
		app.Public(recorder, request)
		event := <-app.access
		return recorder.Code, event.signals
	}
	// Excluding the CRS method rule no longer disarms the allowlist.
	excluded := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "block", AllowedMethods: []string{"GET"}, Exclusions: []int{911100}})
	if code, signals := probe(excluded, "PUT"); code != http.StatusForbidden {
		t.Fatal("method allowlist silently unenforced with 911100 excluded:", code)
	} else if !containsSignal(signals, "method_not_allowed") {
		t.Fatal("method rejection not signalled:", signals)
	}
	if code, _ := probe(excluded, "GET"); code != 200 {
		t.Fatal("allowed method rejected with 911100 excluded:", code)
	}
	// Managed signatures off: the policy-owned allowlist still enforces.
	off := managedPublicFixture(t, up.URL, managedSignatureOptions{AllowedMethods: []string{"GET"}})
	bindings := off.active.Load().policyBindings[1]
	bindings[0].Managed = nil
	if code, signals := probe(off, "PUT"); code != http.StatusForbidden {
		t.Fatal("method allowlist silently unenforced with managed signatures off:", code)
	} else if !containsSignal(signals, "method_not_allowed") {
		t.Fatal("method rejection not signalled with managed off:", signals)
	}
	if code, _ := probe(off, "GET"); code != 200 {
		t.Fatal("allowed method rejected with managed signatures off:", code)
	}
	// Observe mode reports without blocking.
	observe := managedPublicFixture(t, up.URL, managedSignatureOptions{Mode: "observe", AllowedMethods: []string{"GET"}})
	observeBindings := observe.active.Load().policyBindings[1]
	observeBindings[0].Managed = nil
	observeBindings[0].Protection.connectionMode = "observe"
	if code, signals := probe(observe, "PUT"); code != 200 {
		t.Fatal("observe mode blocked a disallowed method:", code)
	} else if !containsSignal(signals, "method_would_block") {
		t.Fatal("observed method violation not signalled:", signals)
	}
}

func containsSignal(signals []string, want string) bool {
	for _, signal := range signals {
		if signal == want {
			return true
		}
	}
	return false
}
