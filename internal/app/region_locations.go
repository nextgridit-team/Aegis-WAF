package app

import (
	"context"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/oschwald/maxminddb-golang/v2"
)

type regionCache struct {
	db *maxminddb.Reader
	at time.Time
}
type regionLocation struct{ Country, Code, Name string }

func regionFor(db *maxminddb.Reader, ip netip.Addr) regionLocation {
	if db == nil || !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || !ip.IsGlobalUnicast() {
		return regionLocation{}
	}
	var record struct {
		Country struct {
			Code string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Subdivisions []struct {
			Code  string            `maxminddb:"iso_code"`
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
	}
	if e := db.Lookup(ip.Unmap()).Decode(&record); e != nil || len(record.Country.Code) != 2 {
		return regionLocation{}
	}
	result := regionLocation{Country: record.Country.Code}
	if len(record.Subdivisions) > 0 {
		region := record.Subdivisions[0]
		code := strings.ToUpper(region.Code)
		valid := len(code) <= 32
		for _, ch := range code {
			valid = valid && (ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-')
		}
		if valid {
			result.Code = strings.TrimPrefix(code, result.Country+"-")
		}
		result.Name = truncateUTF8(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, region.Names["en"]), 120)
	}
	return result
}

// Regional enrichment is independent of critical route snapshots. A large City
// dataset cannot delay routing/certificate refresh or invalidate the sealed cache.
func (a *App) refreshRegionCache(ctx context.Context) error {
	var enabled bool
	var at *time.Time
	e := a.db.QueryRow(ctx, "SELECT s.enabled,d.updated_at FROM geo_sources s LEFT JOIN geo_region_database d ON d.id WHERE s.kind='city'").Scan(&enabled, &at)
	if e == pgx.ErrNoRows || e == nil && (!enabled || at == nil) {
		a.regions.Store(nil)
		return nil
	}
	if e != nil {
		return e
	}
	old := a.regions.Load()
	if old != nil && old.at.Equal(*at) {
		return nil
	}
	var data []byte
	if e = a.db.QueryRow(ctx, "SELECT data FROM geo_region_database WHERE id AND updated_at=$1", *at).Scan(&data); e != nil {
		return e
	}
	reader, e := maxminddb.OpenBytes(data)
	if e != nil {
		return e
	}
	a.regions.Store(&regionCache{db: reader, at: *at})
	return nil
}
func (a *App) RegionCacheWorker(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		if a.initialized.Load() {
			c, cancel := context.WithTimeout(ctx, 60*time.Second)
			_ = a.refreshRegionCache(c)
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
