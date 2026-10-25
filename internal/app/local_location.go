package app

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oschwald/maxminddb-golang/v2"
)

type localGeoPolicy struct {
	PublicIP string                `json:"public_ip"`
	Prefixes map[netip.Prefix]bool `json:"prefixes"`
	reader   *maxminddb.Reader
}

func (p *localGeoPolicy) matches(ip netip.Addr) bool {
	if p == nil || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for bits := ip.BitLen(); bits > 0; bits-- {
		if local, ok := p.Prefixes[netip.PrefixFrom(ip, bits).Masked()]; ok {
			return local
		}
	}
	return false
}
func normalizeLocalPublicIP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	ip, e := netip.ParseAddr(raw)
	if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return "", invalid("provide one public IPv4/IPv6 address; leave empty to clear the location reference")
	}
	return ip.Unmap().String(), nil
}
func (a *App) loadLocalGeo(ctx context.Context, tx pgx.Tx, s *snapshot) error {
	var public string
	if e := tx.QueryRow(ctx, "SELECT public_ip FROM local_location WHERE id").Scan(&public); e != nil {
		return e
	}
	p := &localGeoPolicy{PublicIP: public, Prefixes: map[netip.Prefix]bool{}, reader: s.geo}
	rows, e := tx.Query(ctx, "SELECT value,is_local FROM address_objects")
	if e != nil {
		return e
	}
	defer rows.Close()
	hasLocal := false
	for rows.Next() {
		var value string
		var local bool
		if e = rows.Scan(&value, &local); e != nil {
			return e
		}
		prefix, e := netip.ParsePrefix(value)
		if e != nil {
			ip, e := netip.ParseAddr(value)
			if e != nil {
				return e
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		prefix = prefix.Masked()
		if previous, ok := p.Prefixes[prefix]; ok {
			p.Prefixes[prefix] = previous && local
		} else {
			p.Prefixes[prefix] = local
		}
		hasLocal = hasLocal || local
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if hasLocal {
		s.localGeo = p
	}
	return nil
}

// Only explicit administrator requests contact this fixed HTTPS endpoint. No
// visitor IPs, browser headers, credentials or saved settings are sent.
func detectGatewayPublicIP(ctx context.Context, transport http.RoundTripper) (string, error) {
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://api64.ipify.org", nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("Accept", "text/plain")
	response, e := client.Do(req)
	failure := apiError{503, "Public IP detection unavailable. Enter the address manually or try again."}
	if e != nil {
		return "", failure
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", failure
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 129))
	if e != nil || len(raw) > 128 {
		return "", failure
	}
	ip, e := normalizeLocalPublicIP(string(raw))
	if e != nil || ip == "" {
		return "", failure
	}
	return ip, nil
}
func localLocationAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("POST /api/geolocation/local/detect", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		ip, e := detectGatewayPublicIP(r.Context(), a.publicIPHTTP)
		if e != nil {
			return e
		}
		respond(w, 200, map[string]string{"public_ip": ip, "provider": "ipify", "source": "replica_egress"})
		return nil
	}))
	m.HandleFunc("GET /api/geolocation/local", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		location, e := a.localGatewayLocation(r.Context())
		if e != nil {
			return e
		}
		respond(w, 200, location)
		return nil
	}))
	m.HandleFunc("PUT /api/geolocation/local", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		var input struct {
			PublicIP string `json:"public_ip"`
		}
		if e := decode(w, r, &input); e != nil {
			return e
		}
		ip, e := normalizeLocalPublicIP(input.PublicIP)
		if e != nil {
			return e
		}
		if e = a.change(r.Context(), func(tx pgx.Tx) error {
			if _, e := tx.Exec(r.Context(), "UPDATE local_location SET public_ip=$1 WHERE id", ip); e != nil {
				return e
			}
			return audit(r.Context(), tx, i.Username, "geolocation.local_reference_saved", "gateway")
		}); e != nil {
			return e
		}
		respond(w, 200, map[string]string{"public_ip": ip})
		return nil
	}))
}

func (a *App) localGatewayLocation(ctx context.Context) (map[string]string, error) {
	var public string
	if e := a.db.QueryRow(ctx, "SELECT public_ip FROM local_location WHERE id").Scan(&public); e != nil {
		return nil, e
	}
	country, region := "", ""
	if ip, e := netip.ParseAddr(public); e == nil {
		if s := a.active.Load(); s != nil {
			country = countryFor(s.geo, ip)
		}
		if city := a.regions.Load(); city != nil {
			location := regionFor(city.db, ip)
			if location.Country == country {
				region = location.Name
			}
		}
	}
	return map[string]string{"public_ip": public, "country": country, "region": region}, nil
}
