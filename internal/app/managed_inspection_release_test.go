package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// managedReleaseFixture mirrors managedPublicFixture with a one-slot inspection
// budget so a single orphaned reservation saturates managedSlots.
func managedReleaseFixture(t *testing.T, upstreamURL string, options managedSignatureOptions) *App {
	t.Helper()
	set, e := bundledSignatureSet()
	if e != nil {
		t.Fatal(e)
	}
	options.SetID = set.ID
	options, _ = normalizeManagedSignatures(options)
	runtime, e := compileManagedSignatures(set, options)
	if e != nil {
		t.Fatal(e)
	}
	target, _ := url.Parse(upstreamURL)
	policy, _ := compileProtection(defaultProtection())
	a := &App{managedSlots: make(chan struct{}, 1), access: make(chan accessEvent, 8)}
	a.active.Store(&snapshot{routes: map[string]*route{"managed.test": {site: Site{ID: 1}, proxy: newProxy(target, true)}}, policyBindings: map[int64][]compiledPolicyBinding{1: {{ID: 1, Name: "Managed", Priority: 10000, Protection: policy, ManagedOptions: options, Managed: runtime}}}})
	return a
}

func managedReleasePost(t *testing.T, a *App, payload string) (*httptest.ResponseRecorder, accessEvent) {
	t.Helper()
	request := httptest.NewRequest("POST", "http://managed.test/webhook", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "browser")
	response := httptest.NewRecorder()
	a.Public(response, request)
	return response, <-a.access
}

// A dead upstream never consumes the request body, so the bufferedSignatureBody
// wrapper holding the only request-side reservation must still be released at
// handler scope. With a one-slot budget an orphaned release makes the second
// request busy (503) instead of inspected.
func TestManagedRequestBodyReservationReleasedOnUpstreamFailure(t *testing.T) {
	for _, responseMode := range []string{"off", "block"} {
		t.Run("response_mode_"+responseMode, func(t *testing.T) {
			a := managedReleaseFixture(t, "http://127.0.0.1:1", managedSignatureOptions{Mode: "block", ResponseMode: responseMode})
			for request := 1; request <= 2; request++ {
				response, event := managedReleasePost(t, a, "message=first")
				if event.managed.Inspection != "complete" {
					t.Fatalf("request %d not inspected (%s); an orphaned reservation keeps later requests busy", request, event.managed.Inspection)
				}
				if response.Code != 502 {
					t.Fatalf("request %d gateway status %d", request, response.Code)
				}
			}
		})
	}
}

// Normal forwarding must keep the reservation once-guarded: the slot is
// returned (by prefix drain or the handler backstop) without a double release,
// the upstream receives the full body, and repeated requests stay inspected.
func TestManagedRequestBodyReservationReleasedAfterForwarding(t *testing.T) {
	payload := "message=" + strings.Repeat("a", 2048)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			return
		}
		if string(body) != payload {
			t.Errorf("upstream received %d bytes, want %d", len(body), len(payload))
		}
		io.WriteString(w, "forwarded")
	}))
	defer up.Close()
	a := managedReleaseFixture(t, up.URL, managedSignatureOptions{Mode: "block"})
	for request := 1; request <= 2; request++ {
		response, event := managedReleasePost(t, a, payload)
		if response.Code != 200 || response.Body.String() != "forwarded" {
			t.Fatalf("request %d forwarded incorrectly: %d %s", request, response.Code, response.Body.String())
		}
		if event.managed.Inspection != "complete" {
			t.Fatalf("request %d inspection %s", request, event.managed.Inspection)
		}
		if len(a.managedSlots) != 0 {
			t.Fatalf("request %d leaked an inspection reservation", request)
		}
	}
}
