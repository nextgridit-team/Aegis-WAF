package app

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oschwald/maxminddb-golang/v2"
)

const geoStatusSQL = `SELECT k.kind,coalesce(s.enabled,false) enabled,coalesce(s.auto_sync,false) auto_sync,coalesce(s.status,CASE WHEN k.kind='country' AND c.id IS NOT NULL THEN 'manual' ELSE 'not_configured' END) status,coalesce(s.error,'') error,s.last_attempt,s.last_success,s.next_sync,CASE WHEN k.kind='country' THEN c.updated_at ELSE r.updated_at END updated_at FROM (VALUES('country'),('city')) k(kind) LEFT JOIN geo_sources s ON s.kind=k.kind LEFT JOIN geo_database c ON c.id LEFT JOIN geo_region_database r ON r.id ORDER BY k.kind`

func (a *App) queueGeoSync(w http.ResponseWriter, r *http.Request, i identity) error {
	var input struct {
		Detail string `json:"detail"`
		Auto   bool   `json:"auto_sync"`
		Accept bool   `json:"accept_license"`
	}
	if e := decode(w, r, &input); e != nil {
		return e
	}
	if !input.Accept {
		return invalid("accept DB-IP's CC BY 4.0 license and attribution before downloading")
	}
	if input.Detail != "country" && input.Detail != "city" {
		return invalid("choose country or city regional data")
	}
	if e := a.change(r.Context(), func(tx pgx.Tx) error {
		for _, kind := range []string{"country", "city"} {
			enabled := kind == "country" || input.Detail == "city"
			status := "queued"
			if !enabled {
				status = "disabled"
			}
			if _, e := tx.Exec(r.Context(), `INSERT INTO geo_sources(kind,enabled,auto_sync,status,next_sync) VALUES($1,$2,$3,$4,now()) ON CONFLICT(kind) DO UPDATE SET enabled=excluded.enabled,auto_sync=excluded.auto_sync,status=CASE WHEN excluded.enabled AND geo_sources.status='running' THEN 'running' ELSE excluded.status END,next_sync=now(),owner=CASE WHEN excluded.enabled AND geo_sources.status='running' THEN geo_sources.owner ELSE '' END,lease_until=CASE WHEN excluded.enabled AND geo_sources.status='running' THEN geo_sources.lease_until ELSE NULL END,error=''`, kind, enabled, enabled && input.Auto, status); e != nil {
				return e
			}
		}
		return audit(r.Context(), tx, i.Username, "geolocation.sync_queued", input.Detail)
	}); e != nil {
		return e
	}
	respond(w, 202, map[string]any{"queued": true, "detail": input.Detail, "auto_sync": input.Auto})
	return nil
}
func (a *App) downloadGeoDatabase(ctx context.Context, kind string) ([]byte, string, error) {
	if kind != "country" && kind != "city" {
		return nil, "", errors.New("invalid geolocation database kind")
	}
	month := time.Now().UTC().Format("2006-01")
	request, e := http.NewRequestWithContext(ctx, "GET", "https://download.db-ip.com/free/dbip-"+kind+"-lite-"+month+".mmdb.gz", nil)
	if e != nil {
		return nil, "", e
	}
	client := &http.Client{Timeout: 4 * time.Minute, Transport: a.geoHTTP, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		return nil, "", errors.New("database download failed; previous data retained")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, "", fmt.Errorf("database download returned HTTP %d; previous data retained", response.StatusCode)
	}
	compressedMax := int64(192 << 20)
	rawMax := int64(512 << 20)
	if kind == "country" {
		compressedMax = 32 << 20
		rawMax = 32 << 20
	}
	if response.ContentLength > compressedMax {
		return nil, "", errors.New("geolocation archive exceeds supported size")
	}
	compressed := &io.LimitedReader{R: response.Body, N: compressedMax + 1}
	archive, e := gzip.NewReader(compressed)
	if e != nil {
		return nil, "", errors.New("invalid geolocation archive")
	}
	defer archive.Close()
	data, e := io.ReadAll(io.LimitReader(archive, rawMax+1))
	if e != nil || int64(len(data)) > rawMax || compressed.N <= 0 {
		return nil, "", errors.New("invalid or oversized geolocation archive")
	}
	reader, e := maxminddb.OpenBytes(data)
	if e != nil {
		return nil, "", errors.New("invalid geolocation database")
	}
	defer reader.Close()
	dbType := strings.ToLower(reader.Metadata.DatabaseType)
	if kind == "city" && !strings.Contains(dbType, "city") {
		return nil, "", errors.New("database does not contain regional locations")
	}
	if e = reader.Verify(); e != nil {
		return nil, "", errors.New("geolocation database validation failed")
	}
	return data, month, nil
}
func (a *App) syncNextGeo(ctx context.Context) (bool, error) {
	owner := a.replicaID + ":" + token()
	var kind string
	var attempts int
	claim, cancel := context.WithTimeout(ctx, 3*time.Second)
	e := a.db.QueryRow(claim, `WITH due AS (SELECT kind FROM geo_sources WHERE enabled AND ((status IN ('queued','retry') AND next_sync<=now()) OR (status='ready' AND auto_sync AND next_sync<=now()) OR (status='running' AND lease_until<now())) ORDER BY CASE WHEN kind='country' THEN 0 ELSE 1 END,next_sync LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE geo_sources s SET status='running',owner=$1,lease_until=now()+interval '10 minutes',last_attempt=now(),attempts=attempts+1 FROM due WHERE s.kind=due.kind RETURNING s.kind,s.attempts`, owner).Scan(&kind, &attempts)
	cancel()
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	work, stop := context.WithTimeout(ctx, 5*time.Minute)
	defer stop()
	data, month, downloadError := a.downloadGeoDatabase(work, kind)
	if downloadError != nil {
		shift := min(attempts, 10)
		backoff := min(time.Minute*time.Duration(1<<shift), 24*time.Hour)
		update, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		_, e = a.db.Exec(update, "UPDATE geo_sources SET status='retry',error=$2,next_sync=now()+($3::double precision*interval '1 second'),owner='',lease_until=NULL WHERE kind=$1 AND owner=$4 AND enabled", kind, downloadError.Error(), backoff.Seconds(), owner)
		return true, e
	}
	now := time.Now().UTC()
	sourceMonth, _ := time.Parse("2006-01", month)
	next := sourceMonth.AddDate(0, 1, 0).Add(time.Hour)
	if !next.After(now) {
		next = now.Add(time.Hour)
	}
	e = a.change(work, func(tx pgx.Tx) error {
		tag, e := tx.Exec(work, "UPDATE geo_sources SET status='ready',last_success=now(),error='',next_sync=$3,owner='',lease_until=NULL,source_month=$4,attempts=0 WHERE kind=$1 AND owner=$2 AND enabled", kind, owner, next, month)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		table := "geo_database"
		if kind == "city" {
			table = "geo_region_database"
		}
		if _, e = tx.Exec(work, "INSERT INTO "+table+"(id,data) VALUES(true,$1) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=clock_timestamp()", data); e != nil {
			return e
		}
		return audit(work, tx, "scheduler", "geolocation.synced", kind+":"+month)
	})
	return true, e
}
func (a *App) GeoSyncWorker(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		if a.initialized.Load() {
			if worked, e := a.syncNextGeo(ctx); e == nil && worked {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
