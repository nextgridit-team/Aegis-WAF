package app

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oschwald/maxminddb-golang/v2"
)

type connectionKey struct{}
type liveMetrics struct {
	mu          sync.Mutex
	connections map[net.Conn]map[int64]bool
	requests    map[int64]int64
}
type liveCounts struct {
	Connections int64 `json:"connections"`
	Inflight    int64 `json:"inflight"`
}

func (a *App) ConnectionContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connectionKey{}, c)
}
func (a *App) ConnectionState(c net.Conn, state http.ConnState) {
	a.metrics.mu.Lock()
	defer a.metrics.mu.Unlock()
	if a.metrics.connections == nil {
		a.metrics.connections = map[net.Conn]map[int64]bool{}
	}
	if state == http.StateClosed {
		delete(a.metrics.connections, c)
	} else if _, ok := a.metrics.connections[c]; !ok {
		a.metrics.connections[c] = map[int64]bool{}
	}
}
func (m *liveMetrics) begin(r *http.Request, site int64) func() {
	m.mu.Lock()
	if m.requests == nil {
		m.requests = map[int64]int64{}
	}
	m.requests[site]++
	if c, ok := r.Context().Value(connectionKey{}).(net.Conn); ok {
		if sites, exists := m.connections[c]; exists {
			sites[site] = true
		}
	}
	m.mu.Unlock()
	return func() { m.mu.Lock(); m.requests[site]--; m.mu.Unlock() }
}
func (m *liveMetrics) counts() map[int64]liveCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]liveCounts{0: {Connections: int64(len(m.connections))}}
	for _, sites := range m.connections {
		for site := range sites {
			v := out[site]
			v.Connections++
			out[site] = v
		}
	}
	for site, count := range m.requests {
		v := out[site]
		v.Inflight = count
		out[site] = v
		v = out[0]
		v.Inflight += count
		out[0] = v
	}
	return out
}
func (a *App) publishMetrics(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	data, _ := json.Marshal(a.metrics.counts())
	system, _ := json.Marshal(a.system.sample())
	_, _ = a.db.Exec(c, "INSERT INTO replica_metrics(id,at,data,dropped_logs,system) VALUES($1,clock_timestamp(),$2,$3,$4) ON CONFLICT(id) DO UPDATE SET at=excluded.at,data=excluded.data,dropped_logs=excluded.dropped_logs,system=excluded.system", a.replicaID, data, a.dropped.Load(), system)
	_, _ = a.db.Exec(c, "DELETE FROM replica_metrics WHERE at<now()-interval '1 hour'")
}
func countryFor(db *maxminddb.Reader, ip netip.Addr) string {
	if db == nil || !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || !ip.IsGlobalUnicast() {
		return ""
	}
	var country string
	if e := db.Lookup(ip).DecodePath(&country, "country", "iso_code"); e != nil || len(country) != 2 {
		return ""
	}
	return country
}
func (a *App) loadGeo(ctx context.Context, tx pgx.Tx, s *snapshot) error {
	var data []byte
	e := tx.QueryRow(ctx, "SELECT data FROM geo_database WHERE id").Scan(&data)
	if e == pgx.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	s.geoData = data
	s.geo, e = maxminddb.OpenBytes(data)
	return e
}
func (a *App) updateGeo(w http.ResponseWriter, r *http.Request, i identity) error {
	var body struct {
		AcceptLicense bool `json:"accept_license"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if !body.AcceptLicense {
		return invalid("accept DB-IP's CC BY 4.0 license before downloading")
	}
	// Only this fixed vendor endpoint is used. No administrator URL or visitor IP is sent.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://download.db-ip.com/free/dbip-country-lite-"+time.Now().UTC().Format("2006-01")+".mmdb.gz", nil)
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return apiError{502, "country database download failed; existing database retained"}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return apiError{502, "country database is unavailable; retry later"}
	}
	reader, e := gzip.NewReader(io.LimitReader(response.Body, 32<<20))
	if e != nil {
		return apiError{502, "invalid country database archive"}
	}
	defer reader.Close()
	data, e := io.ReadAll(io.LimitReader(reader, (32<<20)+1))
	if e != nil || len(data) > 32<<20 {
		return apiError{502, "invalid or oversized country database"}
	}
	db, e := maxminddb.OpenBytes(data)
	if e != nil {
		return apiError{502, "invalid country database"}
	}
	defer db.Close()
	if e = db.Verify(); e != nil {
		return apiError{502, "country database validation failed"}
	}
	if e = a.change(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO geo_database(id,data) VALUES(true,$1) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=now()", data); e != nil {
			return e
		}
		return audit(ctx, tx, i.Username, "geolocation.updated", "DB-IP Lite")
	}); e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"updated": true})
	return nil
}
func (a *App) dashboard(w http.ResponseWriter, r *http.Request, _ identity) error {
	site := int64(0)
	var e error
	if raw := r.URL.Query().Get("site_id"); raw != "" {
		site, e = strconv.ParseInt(raw, 10, 64)
		if e != nil || site < 1 {
			return invalid("invalid site_id")
		}
	}
	minutes := 15
	if raw := r.URL.Query().Get("minutes"); raw != "" {
		minutes, e = strconv.Atoi(raw)
		if e != nil || (minutes != 5 && minutes != 15 && minutes != 60) {
			return invalid("minutes must be 5, 15 or 60")
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	// One consistent snapshot for totals, chart, countries and replica heartbeats.
	tx, e := a.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT now()").Scan(&now); e != nil {
		return e
	}
	since := now.Add(-time.Duration(minutes) * time.Minute)
	var totals, series, countries, statuses, signals, recent []byte
	filter := " FROM access_logs WHERE at >= $1 AND at < $3::timestamptz AND ($2::bigint=0 OR site_id=$2)"
	queries := []struct {
		sql    string
		target *[]byte
	}{
		{`SELECT jsonb_build_object('requests',count(*),'blocked',count(*) FILTER(WHERE blocked),'flagged',count(*) FILTER(WHERE signals<>'[]'::jsonb),'exempt',count(*) FILTER(WHERE protection_exemptions<>'[]'::jsonb),'errors',count(*) FILTER(WHERE status>=500),'rps',count(*) FILTER(WHERE at >= $3::timestamptz-interval '10 seconds')/10.0,'clients',count(DISTINCT peer),'mean_duration_ms',coalesce(avg(duration_ms),0))` + filter, &totals},
		{`SELECT coalesce(jsonb_agg(x ORDER BY x.at),'[]') FROM (SELECT date_bin(interval '10 seconds',at,timestamptz '2000-01-01') at,count(*) requests,count(*) FILTER(WHERE blocked) blocked` + filter + ` GROUP BY 1) x`, &series},
		{`SELECT coalesce(jsonb_agg(x ORDER BY x.requests DESC),'[]') FROM (SELECT country,count(*) requests,count(*) FILTER(WHERE blocked) blocked` + filter + ` GROUP BY country) x`, &countries},
		{`SELECT coalesce(jsonb_agg(x ORDER BY x.status),'[]') FROM (SELECT status,count(*) requests` + filter + ` GROUP BY status) x`, &statuses},
		{`SELECT coalesce(jsonb_agg(x ORDER BY x.requests DESC),'[]') FROM (SELECT signal,count(*) requests FROM (SELECT jsonb_array_elements_text(signals) signal` + filter + `) s GROUP BY signal) x`, &signals},
		{`SELECT coalesce(jsonb_agg(x ORDER BY x.id DESC),'[]') FROM (SELECT id,at,site_id,method,status,duration_ms,peer,country,blocked,signals,protection_exemptions,policy_id,policy_revision,policy_name,managed_signatures,network_access,region_code,region_name` + filter + ` ORDER BY at DESC LIMIT 20) x`, &recent},
	}
	for index, q := range queries {
		if e = tx.QueryRow(ctx, q.sql, since, site, now).Scan(q.target); e != nil {
			return fmt.Errorf("dashboard query %d: %w", index, e)
		}
	}
	rows, e := tx.Query(ctx, "SELECT id,data,dropped_logs,system FROM replica_metrics WHERE at>now()-interval '10 seconds' ORDER BY id")
	if e != nil {
		return e
	}
	connections, inflight, replicas := int64(0), int64(0), 0
	var dropped uint64
	type replicaSystem struct {
		ID string `json:"id"`
		systemMetrics
	}
	systems := []replicaSystem{}
	for rows.Next() {
		var raw []byte
		var replicaDropped uint64
		var systemRaw []byte
		var system replicaSystem
		if e = rows.Scan(&system.ID, &raw, &replicaDropped, &systemRaw); e != nil {
			rows.Close()
			return e
		}
		var counts map[int64]liveCounts
		if e = json.Unmarshal(raw, &counts); e != nil {
			rows.Close()
			return e
		}
		if e = json.Unmarshal(systemRaw, &system.systemMetrics); e != nil {
			rows.Close()
			return e
		}
		if len(system.ID) > 8 {
			system.ID = system.ID[:8]
		}
		systems = append(systems, system)
		dropped += replicaDropped
		connections += counts[site].Connections
		inflight += counts[site].Inflight
		replicas++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var geoUpdated *time.Time
	if e = tx.QueryRow(ctx, "SELECT (SELECT updated_at FROM geo_database WHERE id)").Scan(&geoUpdated); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	var geoSources []byte
	if e = a.db.QueryRow(r.Context(), "SELECT coalesce(jsonb_agg(x),'[]') FROM ("+geoStatusSQL+") x").Scan(&geoSources); e != nil {
		return e
	}
	respond(w, 200, map[string]any{"geo_sources": json.RawMessage(geoSources), "at": now, "minutes": minutes, "site_id": site, "totals": json.RawMessage(totals), "series": json.RawMessage(series), "countries": json.RawMessage(countries), "statuses": json.RawMessage(statuses), "signals": json.RawMessage(signals), "recent": json.RawMessage(recent), "systems": systems, "dropped_logs": dropped, "connections": connections, "inflight": inflight, "reporting_replicas": replicas, "geo_updated_at": geoUpdated, "log_delay_seconds": 1, "connection_note": "Open gateway sockets, including keep-alive. Application sockets may be shared; do not sum application counts. Heartbeats expire after 10 seconds. Rates use completed requests over 10 seconds."})
	return nil
}
func dashboardAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/dashboard", a.wrap(true, a.dashboard))
	m.HandleFunc("GET /api/dashboard/regions", a.wrap(true, a.regionDashboard))
	m.HandleFunc("POST /api/geolocation/update", a.wrap(true, a.updateGeo))
	m.HandleFunc("POST /api/geolocation/sync", a.wrap(true, a.queueGeoSync))
	m.HandleFunc("GET /api/geolocation/status", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error { return a.list(w, r, geoStatusSQL) }))
	m.HandleFunc("GET /api/protection-settings", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, "SELECT site_id,settings FROM protection_settings ORDER BY site_id")
	}))
	m.HandleFunc("PUT /api/protection-settings/{id}", a.wrap(true, a.saveProtection))
}
