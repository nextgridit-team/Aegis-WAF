package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) regionDashboard(w http.ResponseWriter, r *http.Request, _ identity) error {
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return invalid("provide a two-letter country code")
	}
	site := int64(0)
	minutes := 15
	var e error
	if value := r.URL.Query().Get("site_id"); value != "" {
		site, e = strconv.ParseInt(value, 10, 64)
		if e != nil || site < 1 {
			return invalid("invalid site_id")
		}
	}
	if value := r.URL.Query().Get("minutes"); value != "" {
		minutes, e = strconv.Atoi(value)
		if e != nil || (minutes != 5 && minutes != 15 && minutes != 60) {
			return invalid("minutes must be 5, 15 or 60")
		}
	}
	selected := r.URL.Query().Get("region")
	if len(selected) > 32 {
		return invalid("invalid region code")
	}
	for _, c := range selected {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || selected == "unknown") {
			return invalid("invalid region code")
		}
	}
	var regions, recent []byte
	filter := ` FROM access_logs WHERE country=$1 AND at>=now()-($2::double precision*interval '1 minute') AND ($3::bigint=0 OR site_id=$3)`
	e = a.db.QueryRow(r.Context(), `SELECT coalesce(jsonb_agg(x ORDER BY x.requests DESC),'[]') FROM (SELECT region_code,region_name,count(*) requests,count(*) FILTER(WHERE blocked) blocked`+filter+` GROUP BY region_code,region_name LIMIT 500) x`, country, minutes, site).Scan(&regions)
	if e != nil {
		return e
	}
	e = a.db.QueryRow(r.Context(), `SELECT coalesce(jsonb_agg(x ORDER BY x.at DESC),'[]') FROM (SELECT id,at,site_id,method,status,peer,blocked,region_code,region_name`+filter+` AND ($4='' OR region_code=CASE WHEN $4='unknown' THEN '' ELSE $4 END) ORDER BY at DESC LIMIT 20) x`, country, minutes, site, selected).Scan(&recent)
	if e != nil {
		return e
	}
	names, e := loadAddressNames(r.Context(), a.db)
	if e != nil {
		return e
	}
	recent, e = names.annotateList(recent)
	if e != nil {
		return e
	}
	respond(w, 200, map[string]any{"country": country, "region": selected, "regions": json.RawMessage(regions), "recent": json.RawMessage(recent), "minutes": minutes, "site_id": site})
	return nil
}
