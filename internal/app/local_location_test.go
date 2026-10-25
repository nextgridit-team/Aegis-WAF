package app

import (
	"context"
	"encoding/json"
	"github.com/oschwald/maxminddb-golang/v2"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLocalLocationEnrichment(t *testing.T) {
	raw, err := os.ReadFile("testdata/geolocation/GeoIP2-City-Test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	db, err := maxminddb.OpenBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := &localGeoPolicy{PublicIP: "216.160.83.56", reader: db, Prefixes: map[netip.Prefix]bool{
		netip.MustParsePrefix("10.0.0.0/8"):  true,
		netip.MustParsePrefix("10.1.0.0/16"): false,
		netip.MustParsePrefix("10.1.2.3/32"): true,
		netip.MustParsePrefix("fd00::/8"):    true,
	}}
	for ip, want := range map[string]bool{"10.2.3.4": true, "::ffff:10.2.3.4": true, "10.1.0.1": false, "10.1.2.3": true, "fd00::1": true, "8.8.8.8": false} {
		if p.matches(netip.MustParseAddr(ip)) != want {
			t.Fatalf("incorrect match: %s", ip)
		}
	}
	event := accessEvent{clientIP: netip.MustParseAddr("10.2.3.4"), peer: "10.2.3.4", geo: db, regions: &regionCache{db: db}, localGeo: p, network: networkAccessResult{GeoChecked: true, Blocked: true, Decision: "geo_unknown"}}
	event.enrich()
	event.enrich()
	if event.country != "US" || event.regionCode != "WA" || event.locationSource != "local_reference" || event.observedCountry != "" || event.peer != "10.2.3.4" || event.clientIP.String() != "10.2.3.4" || !event.network.Blocked || event.network.Country != "" {
		t.Fatalf("location changed identity/enforcement or was lost: %+v", event)
	}
	for _, reference := range []string{"", "216.160.83.56"} {
		copy := *p
		copy.PublicIP = reference
		copy.reader = nil
		event := accessEvent{clientIP: netip.MustParseAddr("10.2.3.4"), localGeo: &copy}
		event.enrich()
		if event.country != "" || event.locationSource != "local_unlocated" {
			t.Fatalf("invented location: %+v", event)
		}
	}
	// Cache format preserves prefix keys and explicit non-local overrides.
	a := &App{cfg: Config{Key: make([]byte, 32), KeyID: "test", DatabaseURL: "test", SnapshotCacheMaxAge: time.Hour}}
	s := &snapshot{version: 1, localGeo: p, geoData: raw}
	sealed, err := a.archiveSnapshot(s, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := a.decodeSnapshot(sealed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !restored.localGeo.matches(netip.MustParseAddr("10.2.3.4")) || restored.localGeo.matches(netip.MustParseAddr("10.1.0.1")) || countryFor(restored.localGeo.reader, netip.MustParseAddr(p.PublicIP)) != "US" {
		t.Fatal("local cache round trip lost configuration")
	}
}
func TestLocalPublicIPValidation(t *testing.T) {
	for _, ip := range []string{"", "8.8.8.8", "2606:4700:4700::1111"} {
		if _, err := normalizeLocalPublicIP(ip); err != nil {
			t.Fatal(ip, err)
		}
	}
	for _, ip := range []string{"192.168.1.1", "::ffff:192.168.1.1", "127.0.0.1", "fd00::1", "example.com", "8.8.8.8/32", "fe80::1%eth0", "0.0.0.0"} {
		if _, err := normalizeLocalPublicIP(ip); err == nil {
			t.Fatal("accepted", ip)
		}
	}
}

func assertLocalReplica(t *testing.T, a *App, ip string, want bool) {
	t.Helper()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.active.Load().localGeo.matches(netip.MustParseAddr(ip)); got != want {
		t.Fatalf("local match=%v want=%v", got, want)
	}
}

func decodeLocalSetting(t *testing.T, raw []byte) string {
	t.Helper()
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v["public_ip"]
}

func TestGatewayPublicIPDetection(t *testing.T) {
	for _, test := range []struct {
		name, body, want string
		status           int
	}{
		{"ipv4", "8.8.8.8\n", "8.8.8.8", 200},
		{"ipv6", "2606:4700:4700::1111", "2606:4700:4700::1111", 200},
		{"empty", "", "", 200}, {"private", "10.1.2.3", "", 200},
		{"html", "<html>unavailable</html>", "", 200},
		{"oversized", strings.Repeat(" ", 129) + "8.8.8.8", "", 200},
		{"upstream error", "8.8.8.8", "", 502},
		{"redirect", "", "", 302},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			transport := dnsTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api64.ipify.org" || r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Fatalf("unexpected external request: %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Location": []string{"https://example.com"}}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})
			got, e := detectGatewayPublicIP(context.Background(), transport)
			if got != test.want || (e != nil) != (test.want == "") || calls != 1 {
				t.Fatalf("got=%q err=%v calls=%d", got, e, calls)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := detectGatewayPublicIP(ctx, dnsTestTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() }))
	if e == nil {
		t.Fatal("cancelled lookup succeeded")
	}
}
