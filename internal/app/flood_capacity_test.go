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
	// The site-total ('*') key never obtained a bucket either: while the map
	// is pinned, the aggregate application budget is unmetered too, and the
	// same request reports it (the 100k map is shared per replica across all
	// sites — a site whose '*' key has no bucket loses aggregate enforcement
	// until idle eviction frees space).
	violation := httptest.NewRequest("GET", "http://spray.test/", nil)
	violationSignals, violationBlocked, violationStatus := a.protectResolved(policy, 1, violation, netip.MustParseAddr("198.18.0.1"), now, true)
	if !violationBlocked || violationStatus != http.StatusTooManyRequests {
		t.Fatal("rate violation not denied:", violationBlocked, violationStatus)
	}
	if !slices.Contains(violationSignals, "client_rate") {
		t.Fatal("rate violation not signalled:", violationSignals)
	}
	if !slices.Contains(violationSignals, "flood_capacity_exceeded") {
		t.Fatal("site-total capacity not signalled alongside the violation:", violationSignals)
	}
}

// The bot risk-rate limiter shares the flood limiter's type and 100k cap: a
// full bot map must surface as a distinct reason and signal instead of
// admitting new clients silently unmetered.
func TestBotRateCapacitySignalled(t *testing.T) {
	settings := defaultProtection()
	settings.BotMode = "observe"
	settings.BotChallenge = botChallengeSettings{Enabled: true, Threshold: 90, ClearanceMinutes: 30, RequestsPerSecond: 25, Burst: 50}
	policy, e := compileProtection(settings)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	now := time.Now()
	for n := 0; n < 100000; n++ {
		a.botRates.allow(rateKey{site: 1, ip: fmt.Sprintf("198.19.%d.%d", n>>8, n&0xff)}, 25, 50, now)
	}
	request := httptest.NewRequest("GET", "http://spray.test/", nil)
	result := a.botScore(policy, 1, request, netip.MustParseAddr("203.0.113.9"), now)
	if !slices.Contains(result.Reasons, "bot_rate_capacity_exceeded") {
		t.Fatal("bot capacity event not surfaced as a reason:", result.Reasons)
	}
	// Saturation means the rate is unknown, not suspicious: no score bump.
	if result.Score != 0 {
		t.Fatal("bot capacity event changed the score:", result.Score)
	}
}
