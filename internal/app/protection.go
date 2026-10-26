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
	BotChallenge          botChallengeSettings `json:"bot_challenge"`
	TrustedAddresses      addressSelection     `json:"trusted_addresses"`
	FloodExemptAddresses  addressSelection     `json:"flood_exempt_addresses"`
	BotExemptAddresses    addressSelection     `json:"bot_exempt_addresses"`
	Mode                  string               `json:"mode"`
	RequestsPerSecond     int                  `json:"requests_per_second"`
	Burst                 int                  `json:"burst"`
	SiteRequestsPerSecond int                  `json:"site_requests_per_second"`
	SiteBurst             int                  `json:"site_burst"`
	BotMode               string               `json:"bot_mode"`
	BlockEmptyUA          bool                 `json:"block_empty_user_agent"`
	TrustedProxies        []string             `json:"trusted_proxies"`
	ClientIPHeader        string               `json:"client_ip_header"`
	FloodExemptCIDRs      []string             `json:"flood_exempt_cidrs"`
	BotExemptCIDRs        []string             `json:"bot_exempt_cidrs"`
}
type protectionPolicy struct {
	network        *networkAccessPolicy
	budgetScope    int64
	botFingerprint string
	ProtectionSettings
	trusted                []netip.Prefix
	floodExempt, botExempt []netip.Prefix
}

func defaultProtection() ProtectionSettings {
	return ProtectionSettings{Mode: "off", RequestsPerSecond: 20, Burst: 60, SiteRequestsPerSecond: 1000, SiteBurst: 2000, BotMode: "off", TrustedProxies: []string{}, ClientIPHeader: "x-forwarded-for", FloodExemptCIDRs: []string{}, BotExemptCIDRs: []string{}}
}
func compileProtection(s ProtectionSettings) (*protectionPolicy, error) {
	validMode := func(m string) bool { return m == "off" || m == "observe" || m == "block" }
	if !validMode(s.Mode) || !validMode(s.BotMode) {
		return nil, invalid("mode must be off, observe or block")
	}
	if s.RequestsPerSecond < 1 || s.RequestsPerSecond > 100000 || s.Burst < s.RequestsPerSecond || s.Burst > 1000000 || s.SiteRequestsPerSecond < 1 || s.SiteRequestsPerSecond > 1000000 || s.SiteBurst < s.SiteRequestsPerSecond || s.SiteBurst > 2000000 {
		return nil, invalid("provide positive limits and bursts at least as large as the requests per second limit")
	}
	s.ClientIPHeader = strings.ToLower(strings.TrimSpace(s.ClientIPHeader))
	if s.ClientIPHeader == "" {
		s.ClientIPHeader = "x-forwarded-for"
	}
	switch s.ClientIPHeader {
	case "x-forwarded-for", "x-real-ip", "cf-connecting-ip":
	default:
		return nil, invalid("client_ip_header must be x-forwarded-for, x-real-ip or cf-connecting-ip")
	}
	var err error
	s.BotChallenge, err = normalizeBotChallenge(s.BotChallenge)
	if err != nil {
		return nil, err
	}
	p := &protectionPolicy{ProtectionSettings: s}
	raw, _ := json.Marshal(s)
	p.botFingerprint = hash(string(raw))
	for _, list := range []struct {
		raw        []string
		target     *[]netip.Prefix
		normalized *[]string
		limit      int
		label      string
	}{
		{s.TrustedProxies, &p.trusted, &p.TrustedProxies, 32, "trusted proxies"},
		{s.FloodExemptCIDRs, &p.floodExempt, &p.FloodExemptCIDRs, 128, "HTTP flood exemptions"},
		{s.BotExemptCIDRs, &p.botExempt, &p.BotExemptCIDRs, 128, "bot exemptions"},
	} {
		if len(list.raw) > list.limit {
			return nil, invalid(list.label + " exceeds its entry limit")
		}
		*list.normalized = []string{}
		seen := map[netip.Prefix]bool{}
		for _, raw := range list.raw {
			prefix, e := netip.ParsePrefix(strings.TrimSpace(raw))
			if e != nil {
				ip, err := netip.ParseAddr(strings.TrimSpace(raw))
				if err != nil || ip.Zone() != "" {
					return nil, invalid(list.label + " requires valid IP addresses or CIDRs")
				}
				ip = ip.Unmap()
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, invalid("mapped IPv4 CIDRs require at least a /96 prefix")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			if prefix.Bits() == 0 {
				return nil, invalid(list.label + " cannot include all addresses; use Off to disable a component")
			}
			prefix = prefix.Masked()
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			*list.target = append(*list.target, prefix)
			*list.normalized = append(*list.normalized, prefix.String())
		}
	}

	return p, nil
}
func matchesCIDRs(prefixes []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (p *protectionPolicy) trusts(ip netip.Addr) bool { return p != nil && matchesCIDRs(p.trusted, ip) }
func (p *protectionPolicy) exemptions(ip netip.Addr) []string {
	out := []string{}
	if p != nil {
		if p.Mode != "off" && matchesCIDRs(p.floodExempt, ip) {
			out = append(out, "http_flood")
		}
		if p.BotMode != "off" && matchesCIDRs(p.botExempt, ip) {
			out = append(out, "anti_bot")
		}
	}
	return out
}
func (p *protectionPolicy) forwardedProto(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, _ := netip.ParseAddr(host)
	if p.trusts(peer.Unmap()) && len(r.Header.Values("X-Forwarded-Proto")) == 1 {
		v := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
		if v == "http" || v == "https" {
			proto = v
		}
	}
	return proto
}
func (p *protectionPolicy) clientIP(r *http.Request) netip.Addr {
	ip, _ := p.resolveClientIP(r)
	return ip
}
func (p *protectionPolicy) resolveClientIP(r *http.Request) (netip.Addr, bool) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, _ := netip.ParseAddr(host)
	peer = peer.Unmap()
	if !p.trusts(peer) {
		return peer, peer.IsValid()
	}
	header := "x-forwarded-for"
	if p.ClientIPHeader != "" {
		header = p.ClientIPHeader
	}
	if header != "x-forwarded-for" {
		if len(r.Header.Values(header)) != 1 {
			return peer, false
		}
		ip, e := netip.ParseAddr(strings.TrimSpace(r.Header.Get(header)))
		if e != nil || ip.Zone() != "" {
			return peer, false
		}
		return ip.Unmap(), true
	}
	// Walk from the transport peer towards the client. Never accept arbitrary leftmost input.
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	if len(parts) > 32 {
		return peer, false
	}
	ip := peer
	for n := len(parts) - 1; n >= 0 && p.trusts(ip); n-- {
		next, e := netip.ParseAddr(strings.TrimSpace(parts[n]))
		if e != nil || next.Zone() != "" {
			return peer, false
		}
		ip = next.Unmap()
	}
	return ip, true
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
			if now.Sub(b.at) > max(5*time.Minute, time.Duration(float64(b.burst)/float64(b.rate)*float64(time.Second))) {
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
	return a.protectResolved(p, site, r, ip, now, true)
}
func (a *App) protectResolved(p *protectionPolicy, site int64, r *http.Request, ip netip.Addr, now time.Time, reliable bool) ([]string, bool, int) {
	signals := []string{}
	blocked := false
	status := http.StatusForbidden
	if p == nil {
		return signals, false, status
	}
	if p.Mode != "off" && (!reliable || !matchesCIDRs(p.floodExempt, ip)) {
		budgetPrefix := ""
		if p.budgetScope != 0 {
			budgetPrefix = "policy:" + strconv.FormatInt(p.budgetScope, 10) + ":"
		}
		decisions, err := takeRateState(r.Context(), &a.flood, []rateLimit{{rateKey{site, budgetPrefix + ip.String()}, p.RequestsPerSecond, p.Burst}, {rateKey{site, budgetPrefix + "*"}, p.SiteRequestsPerSecond, p.SiteBurst}}, now)
		client, total := true, true
		if err != nil {
			signals = append(signals, "rate_state_unavailable")
			if p.Mode == "block" {
				return signals, true, http.StatusServiceUnavailable
			}
		} else {
			client, total = decisions[0], decisions[1]
		}
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
	if p.BotMode != "off" && !p.BotChallenge.Enabled && (!reliable || !matchesCIDRs(p.botExempt, ip)) {
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
	catalog, e := loadAddressCatalog(ctx, tx)
	if e != nil {
		return e
	}
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
		p, e = catalog.protection(p)
		if e != nil {
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
	compiled, e := compileProtection(p)
	if e != nil {
		return e
	}
	p = compiled.ProtectionSettings
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
		if e := validateAddressConsumers(r.Context(), tx); e != nil {
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
