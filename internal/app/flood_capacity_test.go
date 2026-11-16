package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// The local limiter's bucket map is capped at 100,000 identities. When it is
// full, a first-time client must not be rejected as if it had exceeded its
// rate budget: the request is admitted unmetered and reported with a distinct
// capacity signal so an IP-spray event is visible instead of masquerading as
// mass rate limiting.
func TestFloodCapacityAdmitsNewClients(t *testing.T) {
	settings := defaultProtection()
	settings.Mode = "block"
	settings.RequestsPerSecond = 1
	settings.Burst = 1
	settings.SiteRequestsPerSecond = 1000
	settings.SiteBurst = 2000
	policy, e := compileProtection(settings)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	now := time.Now()
	for n := 0; n < 100000; n++ {
		a.flood.allow(rateKey{site: 1, ip: fmt.Sprintf("198.18.%d.%d", n>>8, n&0xff)}, 1, 1, now)
	}
	request := httptest.NewRequest("GET", "http://spray.test/", nil)
	signals, blocked, status := a.protectResolved(policy, 1, request, netip.MustParseAddr("203.0.113.9"), now, true)
	if blocked {
		t.Fatal("capacity rejection indistinguishable from rate exceeded:", status)
	}
	if !slices.Contains(signals, "flood_capacity_exceeded") {
		t.Fatal("capacity event not signalled:", signals)
	}
	// A genuine rate violation keeps its own denial and signal: the filler
	// key 198.18.0.1 already spent its single-token burst. (The site-total
	// key still reports capacity because it never obtained a bucket either.)
	violation := httptest.NewRequest("GET", "http://spray.test/", nil)
	violationSignals, violationBlocked, violationStatus := a.protectResolved(policy, 1, violation, netip.MustParseAddr("198.18.0.1"), now, true)
	if !violationBlocked || violationStatus != http.StatusTooManyRequests {
		t.Fatal("rate violation not denied:", violationBlocked, violationStatus)
	}
	if !slices.Contains(violationSignals, "client_rate") {
		t.Fatal("rate violation not signalled:", violationSignals)
	}
}
