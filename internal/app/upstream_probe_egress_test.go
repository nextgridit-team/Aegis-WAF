package app

import (
	"context"
	"net/netip"
	"testing"
)

// The upstream probe is a diagnostic for configured upstreams, which are
// routinely private backends. It must never honor HTTP(S)_PROXY, and it must
// refuse destinations no legitimate upstream uses: link-local addresses
// (including cloud metadata endpoints), multicast and unspecified addresses —
// as URL literals and after DNS resolution.
func TestUpstreamProbeRefusesLinkLocalMetadata(t *testing.T) {
	for _, target := range []string{"http://169.254.169.254/", "http://[fe80::1]/"} {
		result := probeUpstream(context.Background(), target, upstreamTLSSettings{}, "")
		if result.Reachable || result.Stage != "refused" {
			t.Fatalf("probe of %s not refused: %+v", target, result)
		}
	}
}

// The probe transport must be free of the environment proxy hook entirely:
// net/http caches HTTP(S)_PROXY at first use per process, so the only reliable
// assertion is on the constructed transport itself.
func TestUpstreamProbeTransportHasNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	transport := upstreamProbeTransport(nil)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("upstream probe transport honors environment proxies")
	}
}

// A translating NAT64 gateway reaches refused IPv4 destinations through
// their embedded forms; the probe must refuse them, while NAT64 forms of
// legitimate upstreams and IPv6 loopback stay reachable.
func TestUpstreamProbeRefusesNAT64Metadata(t *testing.T) {
	for _, raw := range []string{"64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "64:ff9b::f000:0"} {
		if !probeAddressRefused(netip.MustParseAddr(raw)) {
			t.Fatalf("NAT64 form not refused: %s", raw)
		}
	}
	if probeAddressRefused(netip.MustParseAddr("64:ff9b::808:808")) {
		t.Fatal("NAT64 form of a public upstream refused")
	}
	if probeAddressRefused(netip.MustParseAddr("::1")) {
		t.Fatal("IPv6 loopback refused like a NAT64 address")
	}
	result := probeUpstream(context.Background(), "http://[64:ff9b::a9fe:a9fe]/", upstreamTLSSettings{}, "")
	if result.Reachable || result.Stage != "refused" {
		t.Fatalf("NAT64 metadata probe not refused: %+v", result)
	}
}

// An unresolvable hostname must be diagnosed at the DNS stage, not reported
// as a connection failure.
func TestUpstreamProbeReportsDNSStage(t *testing.T) {
	result := probeUpstream(context.Background(), "http://aegis-probe-nonexistent.invalid./", upstreamTLSSettings{}, "")
	if result.Reachable || result.Stage != "dns" {
		t.Fatalf("unresolvable host not reported at the dns stage: %+v", result)
	}
}
