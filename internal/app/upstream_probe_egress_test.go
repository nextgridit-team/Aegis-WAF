package app

import (
	"context"
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
