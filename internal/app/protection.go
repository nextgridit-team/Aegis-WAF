package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Limits are local to each replica. No database round trip occurs on the request path.
type ProtectionSettings struct {
	Mode                  string   `json:"mode"`
	RequestsPerSecond     int      `json:"requests_per_second"`
	Burst                 int      `json:"burst"`
	SiteRequestsPerSecond int      `json:"site_requests_per_second"`
	SiteBurst             int      `json:"site_burst"`
	BotMode               string   `json:"bot_mode"`
	BlockEmptyUA          bool     `json:"block_empty_user_agent"`
	TrustedProxies        []string `json:"trusted_proxies"`
}
type protectionPolicy struct {
	ProtectionSettings
	trusted []netip.Prefix
}

func defaultProtection() ProtectionSettings {
	return ProtectionSettings{Mode: "off", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, BotMode: "off", TrustedProxies: []string{}}
}
func compileProtection(s ProtectionSettings) (*protectionPolicy, error) {
	validMode := func(m string) bool { return m == "off" || m == "observe" || m == "block" }
	if !validMode(s.Mode) || !validMode(s.BotMode) {
		return nil, invalid("mode must be off, observe or block")
	}
	if s.RequestsPerSecond < 1 || s.RequestsPerSecond > 100000 || s.Burst < s.RequestsPerSecond || s.Burst > 1000000 || s.SiteRequestsPerSecond < 1 || s.SiteRequestsPerSecond > 1000000 || s.SiteBurst < s.SiteRequestsPerSecond || s.SiteBurst > 2000000 {
		return nil, invalid("provide positive limits and bursts at least as large as the requests per second limit")
	}
	if len(s.TrustedProxies) > 32 {
		return nil, invalid("at most 32 trusted proxy CIDRs")
	}
	p := &protectionPolicy{ProtectionSettings: s}
	for _, v := range s.TrustedProxies {
		prefix, e := netip.ParsePrefix(v)
		if e != nil || prefix.Bits() == 0 {
			return nil, invalid("trusted proxies require explicit CIDRs; trusting all addresses is forbidden")
		}
		p.trusted = append(p.trusted, prefix.Masked())
	}
	return p, nil
}
func (p *protectionPolicy) trusts(ip netip.Addr) bool {
	if p == nil {
		return false
	}
	for _, prefix := range p.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (p *protectionPolicy) clientIP(r *http.Request) netip.Addr {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, _ := netip.ParseAddr(host)
	peer = peer.Unmap()
	if !p.trusts(peer) {
		return peer
	}
	// Walk from the transport peer towards the client. Never accept arbitrary leftmost input.
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(parts) > 32 {
		return peer
	}
	ip := peer
	for n := len(parts) - 1; n >= 0 && p.trusts(ip); n-- {
		next, e := netip.ParseAddr(strings.TrimSpace(parts[n]))
		if e != nil {
			return peer
		}
		ip = next.Unmap()
	}
	return ip
}

type rateKey struct {
	site int64
	ip   string
}
type rateBucket struct {
	tokens      float64
	at          time.Time
	rate, burst int
}
type floodLimiter struct {
	mu      sync.Mutex
	buckets map[rateKey]rateBucket
	cleaned time.Time
}

func (l *floodLimiter) allow(key rateKey, rate, burst int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[rateKey]rateBucket{}
	}
	if now.Sub(l.cleaned) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.at) > 5*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.cleaned = now
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= 100000 {
			return false
		}
		b = rateBucket{tokens: float64(burst), at: now, rate: rate, burst: burst}
	}
	if b.rate != rate || b.burst != burst {
		b = rateBucket{tokens: float64(burst), at: now, rate: rate, burst: burst}
	}
	elapsed := now.Sub(b.at).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens = min(float64(burst), b.tokens+elapsed*float64(rate))
	b.at = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.buckets[key] = b
	return allowed
}
func (a *App) protect(p *protectionPolicy, site int64, r *http.Request, ip netip.Addr, now time.Time) ([]string, bool, int) {
	signals := []string{}
	blocked := false
	status := http.StatusForbidden
	if p == nil {
		return signals, false, status
	}
	if p.Mode != "off" {
		client := a.flood.allow(rateKey{site, ip.String()}, p.RequestsPerSecond, p.Burst, now)
		total := a.flood.allow(rateKey{site, "*"}, p.SiteRequestsPerSecond, p.SiteBurst, now)
		if !client {
			signals = append(signals, "client_rate")
		}
		if !total {
			signals = append(signals, "application_rate")
		}
		if (!client || !total) && p.Mode == "block" {
			blocked = true
			status = http.StatusTooManyRequests
		}
	}
	if p.BotMode != "off" {
		ua := strings.ToLower(r.UserAgent())
		bot := ""
		for _, v := range []string{"sqlmap", "nikto", "nuclei", "masscan", "zgrab", "headlesschrome", "phantomjs"} {
			if strings.Contains(ua, v) {
				bot = "automation_user_agent"
				break
			}
		}
		if ua == "" && p.BlockEmptyUA {
			bot = "empty_user_agent"
		}
		if bot != "" {
			signals = append(signals, bot)
			if p.BotMode == "block" {
				blocked = true
			}
		}
	}
	return signals, blocked, status
}
func (a *App) loadProtection(ctx context.Context, tx pgx.Tx, s *snapshot) error {
	s.protection = map[int64]*protectionPolicy{}
	rows, e := tx.Query(ctx, "SELECT site_id,settings FROM protection_settings")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var raw []byte
		if e = rows.Scan(&id, &raw); e != nil {
			return e
		}
		var p ProtectionSettings
		if e = json.Unmarshal(raw, &p); e != nil {
			return e
		}
		compiled, e := compileProtection(p)
		if e != nil {
			return e
		}
		s.protection[id] = compiled
	}
	return rows.Err()
}
func (a *App) saveProtection(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	var p ProtectionSettings
	if e = decode(w, r, &p); e != nil {
		return e
	}
	if _, e = compileProtection(p); e != nil {
		return e
	}
	raw, _ := json.Marshal(p)
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1)", id).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return apiError{404, "application not found"}
		}
		if _, e := tx.Exec(r.Context(), "INSERT INTO protection_settings(site_id,settings) VALUES($1,$2) ON CONFLICT(site_id) DO UPDATE SET settings=excluded.settings", id, raw); e != nil {
			return e
		}
		return audit(r.Context(), tx, i.Username, "protection.saved", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, p)
	return nil
}
