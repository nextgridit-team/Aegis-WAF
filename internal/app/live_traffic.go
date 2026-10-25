package app

import (
	"context"
	"encoding/json"
	"github.com/oschwald/maxminddb-golang/v2"
	"net/http"
	"strconv"
	"time"
)

func (a *App) liveTraffic(w http.ResponseWriter, r *http.Request, _ identity) error {
	site := int64(0)
	if raw := r.URL.Query().Get("site_id"); raw != "" {
		var e error
		site, e = strconv.ParseInt(raw, 10, 64)
		if e != nil || site < 1 {
			return invalid("invalid site_id")
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var raw []byte
	e := a.db.QueryRow(ctx, `SELECT coalesce(jsonb_agg(x ORDER BY x.id),'[]') FROM (SELECT l.id,l.at,l.site_id,s.name site_name,l.method,l.status,l.blocked,l.peer,l.country,l.region_code,l.region_name,l.response_source,l.observed_country,l.location_source,l.location_reference_ip FROM access_logs l LEFT JOIN sites s ON s.id=l.site_id WHERE l.at>=now()-interval '1 minute' AND ($1::bigint=0 OR l.site_id=$1) ORDER BY l.id DESC LIMIT 200) x`, site).Scan(&raw)
	if e != nil {
		return e
	}
	names, e := loadAddressNames(ctx, a.db)
	if e != nil {
		return e
	}
	raw, e = names.annotateList(raw)
	if e != nil {
		return e
	}
	gateway, e := a.localGatewayLocation(ctx)
	if e != nil {
		return e
	}
	var city *maxminddb.Reader
	if cached := a.regions.Load(); cached != nil {
		city = cached.db
	}
	raw, e = liveEventPoints(raw, city)
	if e != nil {
		return e
	}
	location := map[string]any{"public_ip": gateway["public_ip"], "country": gateway["country"], "region": gateway["region"]}
	if point := livePointFor(city, gateway["country"], gateway["public_ip"]); point != nil {
		location["map_point"] = point
	}
	respond(w, 200, map[string]any{"gateway_location": location, "events": json.RawMessage(raw), "at": time.Now().UTC(), "site_id": site, "limit": 200, "window_seconds": 60, "refresh_seconds": 1})
	return nil
}
