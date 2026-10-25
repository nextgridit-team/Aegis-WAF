package app

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestComponentCIDRExemptions(t *testing.T) {
	s := defaultProtection()
	s.Mode = "block"
	s.BotMode = "block"
	s.RequestsPerSecond = 1
	s.Burst = 1
	s.SiteRequestsPerSecond = 1
	s.SiteBurst = 1
	s.FloodExemptCIDRs = []string{"192.168.1.99/24", "203.0.113.9", "2001:db8:1::/48"}
	p, e := compileProtection(s)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{}
	r := httptest.NewRequest("GET", "http://app.test/", nil)
	r.Header.Set("User-Agent", "ordinary-browser")
	now := time.Now()
	for _, address := range []string{"192.168.1.5", "203.0.113.9", "2001:db8:1::42", "::ffff:192.168.1.5"} {
		for range 10 {
			signals, blocked, _ := a.protect(p, 1, r, netip.MustParseAddr(address), now)
			if blocked || len(signals) > 0 {
				t.Fatal("flood exemption failed", address, signals)
			}
		}
	}
	external := netip.MustParseAddr("198.51.100.9")
	if _, blocked, _ := a.protect(p, 1, r, external, now); blocked {
		t.Fatal("exempt clients consumed application budget")
	}
	if _, blocked, status := a.protect(p, 1, r, external, now); !blocked || status != 429 {
		t.Fatal("external client escaped flood protection")
	}
	r.Header.Set("User-Agent", "sqlmap")
	if _, blocked, status := a.protect(p, 1, r, netip.MustParseAddr("192.168.1.5"), now); !blocked || status != 403 {
		t.Fatal("flood exemption bypassed bot checks")
	}
	s.BotExemptCIDRs = []string{"198.51.100.0/24"}
	p, e = compileProtection(s)
	if e != nil {
		t.Fatal(e)
	}
	a = &App{}
	if _, blocked, _ := a.protect(p, 1, r, external, now); blocked {
		t.Fatal("bot exemption failed")
	}
	if _, blocked, status := a.protect(p, 1, r, external, now); !blocked || status != 429 {
		t.Fatal("bot exemption bypassed flood checks")
	}
	if len(p.exemptions(netip.MustParseAddr("192.168.1.5"))) != 1 {
		t.Fatal("missing exemption metadata")
	}
	s.FloodExemptCIDRs = []string{"0.0.0.0/0"}
	if _, e = compileProtection(s); e == nil {
		t.Fatal("accepted all-address exception")
	}
}
func TestClientIdentityHeaderSelection(t *testing.T) {
	s := defaultProtection()
	s.TrustedProxies = []string{"10.0.0.1"}
	s.ClientIPHeader = "cf-connecting-ip"
	p, e := compileProtection(s)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "http://app.test/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("CF-Connecting-IP", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	if p.clientIP(r).String() != "203.0.113.7" || p.forwardedProto(r) != "https" {
		t.Fatal("trusted proxy identity not used")
	}
	r.RemoteAddr = "198.51.100.1:1234"
	if p.clientIP(r).String() != "198.51.100.1" || p.forwardedProto(r) != "http" {
		t.Fatal("untrusted request spoofed identity")
	}
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Add("CF-Connecting-IP", "192.168.1.5")
	if p.clientIP(r).String() != "10.0.0.1" {
		t.Fatal("ambiguous single-IP header accepted")
	}
}
func TestUnresolvedProxyIdentityCannotClaimExemption(t *testing.T) {
	s := defaultProtection()
	s.Mode = "block"
	s.RequestsPerSecond = 1
	s.Burst = 1
	s.TrustedProxies = []string{"10.0.0.1"}
	s.FloodExemptCIDRs = []string{"10.0.0.0/8"}
	p, e := compileProtection(s)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "http://app.test/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	ip, reliable := p.resolveClientIP(r)
	if reliable || ip.String() != "10.0.0.1" {
		t.Fatal("missing proxy header was accepted")
	}
	a := &App{}
	now := time.Now()
	a.protectResolved(p, 1, r, ip, now, reliable)
	if _, blocked, status := a.protectResolved(p, 1, r, ip, now, reliable); !blocked || status != 429 {
		t.Fatal("unresolved proxy peer acquired private-network exemption")
	}
}
