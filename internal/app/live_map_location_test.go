package app

import (
	"encoding/json"
	"github.com/oschwald/maxminddb-golang/v2"
	"os"
	"testing"
)

func TestLiveRegionalMapCoordinates(t *testing.T) {
	raw, e := os.ReadFile("testdata/geolocation/GeoIP2-City-Test.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	db, e := maxminddb.OpenBytes(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	point := livePointFor(db, "US", "216.160.83.56")
	if point == nil || point.Latitude < 45 || point.Latitude > 49 || point.Longitude > -120 || point.Longitude < -125 {
		t.Fatalf("not in Washington: %+v", point)
	}
	for _, test := range []struct{ country, ip string }{{"GB", "216.160.83.56"}, {"US", "10.0.0.1"}, {"US", "invalid"}, {"", "216.160.83.56"}} {
		if livePointFor(db, test.country, test.ip) != nil {
			t.Fatalf("invented coordinate: %+v", test)
		}
	}
	if livePointFor(nil, "US", "216.160.83.56") != nil {
		t.Fatal("coordinate without City data")
	}
	events, e := liveEventPoints([]byte(`[{"peer":"10.0.0.1","country":"US","location_source":"local_reference","location_reference_ip":"216.160.83.56"},{"peer":"10.0.0.1","country":"US"}]`), db)
	if e != nil {
		t.Fatal(e)
	}
	var got []struct {
		Peer  string
		Point *liveMapPoint `json:"map_point"`
	}
	json.Unmarshal(events, &got)
	if got[0].Peer != "10.0.0.1" || got[0].Point == nil || *got[0].Point != *point || got[1].Point != nil {
		t.Fatalf("reference lookup changed identity or invented private location: %s", events)
	}
}
