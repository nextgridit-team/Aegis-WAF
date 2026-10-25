package app

import (
	"encoding/json"
	"github.com/oschwald/maxminddb-golang/v2"
	"math"
	"net/netip"
)

type liveMapPoint struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// Coordinates are management-only hints from the current in-memory City data.
// Keep recorded country/identity and enforcement decisions unchanged.
func livePointFor(db *maxminddb.Reader, country, address string) *liveMapPoint {
	ip, e := netip.ParseAddr(address)
	if e != nil || db == nil || country == "" || ip.IsPrivate() || ip.IsLoopback() || !ip.IsGlobalUnicast() {
		return nil
	}
	var record struct {
		Country struct {
			Code string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Location struct {
			Latitude  *float64 `maxminddb:"latitude"`
			Longitude *float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if e = db.Lookup(ip.Unmap()).Decode(&record); e != nil || record.Country.Code != country || record.Location.Latitude == nil || record.Location.Longitude == nil {
		return nil
	}
	lat, lon := *record.Location.Latitude, *record.Location.Longitude
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) || math.Abs(lat) > 90 || math.Abs(lon) > 180 {
		return nil
	}
	return &liveMapPoint{lat, lon}
}
func liveEventPoints(raw []byte, db *maxminddb.Reader) ([]byte, error) {
	if db == nil {
		return raw, nil
	}
	var events []map[string]json.RawMessage
	if e := json.Unmarshal(raw, &events); e != nil {
		return nil, e
	}
	for _, event := range events {
		var peer, country, source, reference string
		json.Unmarshal(event["peer"], &peer)
		json.Unmarshal(event["country"], &country)
		json.Unmarshal(event["location_source"], &source)
		json.Unmarshal(event["location_reference_ip"], &reference)
		if source == "local_reference" {
			peer = reference
		}
		if point := livePointFor(db, country, peer); point != nil {
			event["map_point"], _ = json.Marshal(point)
		}
	}
	return json.Marshal(events)
}
