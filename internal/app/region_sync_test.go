package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/oschwald/maxminddb-golang/v2"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestRegionalLookup(t *testing.T) {
	data, e := os.ReadFile("testdata/geolocation/GeoIP2-City-Test.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	db, e := maxminddb.OpenBytes(data)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	for _, test := range []struct{ ip, country, region string }{{"216.160.83.56", "US", "WA"}, {"81.2.69.160", "GB", "ENG"}, {"192.168.1.1", "", ""}, {"127.0.0.1", "", ""}} {
		got := regionFor(db, netip.MustParseAddr(test.ip))
		if got.Country != test.country || got.Code != test.region {
			t.Fatalf("%s: %+v", test.ip, got)
		}
	}
}
func TestGeoSyncIntegration(t *testing.T) {
	cfg := testDB(t)
	a, b := newTestReplica(t, cfg), newTestReplica(t, cfg)
	ctx := context.Background()
	srv := httptest.NewServer(a.Management())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := testAPI{t, &http.Client{Jar: jar}, srv.URL, ""}
	c.call("GET", "/api/geolocation/status", nil, 401)
	c.call("POST", "/api/setup", map[string]string{"username": "admin", "password": "geo sync integration password", "secret": cfg.BootstrapSecret}, 201)
	var login map[string]string
	json.Unmarshal(c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "geo sync integration password"}, 200), &login)
	c.csrf = login["csrf"]
	c.call("POST", "/api/geolocation/sync", map[string]any{"detail": "city"}, 400)
	c.call("POST", "/api/geolocation/sync", map[string]any{"detail": "city", "accept_license": true, "auto_sync": true}, 202)
	data, e := os.ReadFile("testdata/geolocation/GeoIP2-City-Test.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	gz.Write(data)
	gz.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	a.geoHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive.Bytes()))}, nil
	})
	completed := make(chan error, 1)
	go func() { _, e := a.syncNextGeo(ctx); completed <- e }()
	<-entered
	// Country job is leased to a. b may claim city, so isolate its transport too.
	b.geoHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive.Bytes()))}, nil
	})
	did, e := b.syncNextGeo(ctx)
	if e != nil || !did {
		t.Fatalf("second kind: %v %v", did, e)
	}
	close(release)
	if e = <-completed; e != nil {
		t.Fatal(e)
	}
	if did, e = b.syncNextGeo(ctx); e != nil || did {
		t.Fatalf("completed jobs reclaimed %v %v", did, e)
	}
	for _, replica := range []*App{a, b} {
		if e = replica.refresh(ctx); e != nil {
			t.Fatal(e)
		}
		if e = replica.refreshRegionCache(ctx); e != nil {
			t.Fatal(e)
		}
		if replica.regions.Load() == nil {
			t.Fatal("region cache missing")
		}
	}
	cached := a.regions.Load()
	if e = a.refreshRegionCache(ctx); e != nil || a.regions.Load() != cached {
		t.Fatal("unchanged data reloaded")
	}
	event := accessEvent{regions: cached, geo: a.active.Load().geo, clientIP: netip.MustParseAddr("216.160.83.56"), at: time.Now(), method: "GET", status: 200, peer: "216.160.83.56"}
	if e = a.storeAccessBatch(ctx, []accessEvent{event}); e != nil {
		t.Fatal(e)
	}
	report := c.call("GET", "/api/dashboard/regions?country=US&region=WA", nil, 200)
	var parsed struct {
		Regions []struct {
			Code string `json:"region_code"`
		}
		Recent []any
	}
	json.Unmarshal(report, &parsed)
	if len(parsed.Regions) != 1 || parsed.Regions[0].Code != "WA" || len(parsed.Recent) != 1 {
		t.Fatalf("regional report %s", report)
	}

	// Local display enrichment is persisted independently from the real Geo decision.
	c.call("PUT", "/api/geolocation/local", map[string]string{"public_ip": "216.160.83.56"}, 200)
	c.call("POST", "/api/address-objects", map[string]any{"name": "Local client", "value": "10.0.0.0/8", "is_local": true}, 200)
	for _, replica := range []*App{a, b} {
		assertLocalReplica(t, replica, "10.2.3.4", true)
		local := accessEvent{localGeo: replica.active.Load().localGeo, regions: replica.regions.Load(), geo: replica.active.Load().geo, clientIP: netip.MustParseAddr("10.2.3.4"), peer: "10.2.3.4", at: time.Now(), method: "GET", status: 403, blocked: true, network: networkAccessResult{GeoChecked: true, Blocked: true, Decision: "geo_unknown"}}
		local.enrich() // Logger enrichment followed by the store must remain idempotent.
		if e = replica.storeAccessBatch(ctx, []accessEvent{local}); e != nil {
			t.Fatal(e)
		}
	}
	var localCount int
	if e = a.db.QueryRow(ctx, `SELECT count(*) FROM access_logs WHERE peer='10.2.3.4' AND country='US' AND region_code='WA' AND observed_country='' AND location_source='local_reference' AND location_reference_ip='216.160.83.56' AND blocked AND network_access->>'country' IS NULL`).Scan(&localCount); e != nil || localCount != 2 {
		t.Fatalf("local stored provenance: %d %v", localCount, e)
	}
	var live struct {
		Gateway struct {
			Country  string
			PublicIP string `json:"public_ip"`
			Region   string
			Point    *liveMapPoint `json:"map_point"`
		} `json:"gateway_location"`
		Events []struct {
			Peer    string
			Country string
			Source  string        `json:"location_source"`
			Point   *liveMapPoint `json:"map_point"`
		}
	}
	if e = json.Unmarshal(c.call("GET", "/api/live-traffic", nil, 200), &live); e != nil {
		t.Fatal(e)
	}
	found := 0
	for _, event := range live.Events {
		if event.Peer == "10.2.3.4" && event.Country == "US" && event.Source == "local_reference" && event.Point != nil {
			found++
		}
	}
	if live.Gateway.Country != "US" || live.Gateway.PublicIP != "216.160.83.56" || live.Gateway.Region != "Washington" || live.Gateway.Point == nil {
		t.Fatalf("gateway location missing: %+v", live.Gateway)
	}
	if found != 2 {
		t.Fatalf("local live events: %+v", live)
	}
	// Failed replacement keeps the exact successfully loaded reader and database.
	if _, e = a.db.Exec(ctx, "UPDATE geo_sources SET status='queued',next_sync=now() WHERE kind='city'"); e != nil {
		t.Fatal(e)
	}
	a.geoHTTP = dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 502, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	if _, e = a.syncNextGeo(ctx); e != nil {
		t.Fatal(e)
	}
	if e = a.refreshRegionCache(ctx); e != nil || a.regions.Load() != cached {
		t.Fatal("failed download replaced active region data")
	}
	var status string
	if e = a.db.QueryRow(ctx, "SELECT status FROM geo_sources WHERE kind='city'").Scan(&status); e != nil || status != "retry" {
		t.Fatalf("retry %s %v", status, e)
	}
	c.call("POST", "/api/geolocation/sync", map[string]any{"detail": "country", "accept_license": true}, 202)
	if e = a.refreshRegionCache(ctx); e != nil || a.regions.Load() != nil {
		t.Fatal("country-only selection did not disable enrichment")
	}
}
