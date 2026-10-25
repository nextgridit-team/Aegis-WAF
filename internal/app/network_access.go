package app

import (
	"net/netip"
	"sort"
	"strings"
)

type networkAccessSettings struct {
	BlockAddresses addressSelection `json:"block_addresses"`
	AllowAddresses addressSelection `json:"allow_addresses"`
	BlockCIDRs     []string         `json:"block_cidrs"`
	AllowCIDRs     []string         `json:"allow_cidrs"`
	AllowScope     string           `json:"allow_scope"`
	GeoMode        string           `json:"geo_mode"`
	GeoStrategy    string           `json:"geo_strategy"`
	Countries      []string         `json:"countries"`
	UnknownCountry string           `json:"unknown_country"`
}
type networkAccessPolicy struct {
	Settings         networkAccessSettings
	Mode             string
	blocked, allowed []netip.Prefix
	countries        map[string]bool
}
type networkAccessResult struct {
	Decision   string `json:"decision,omitempty"`
	Mode       string `json:"mode,omitempty"`
	CIDR       string `json:"cidr,omitempty"`
	AllowScope string `json:"allow_scope,omitempty"`
	Country    string `json:"country,omitempty"`
	GeoChecked bool   `json:"geo_checked,omitempty"`
	WouldBlock bool   `json:"would_block,omitempty"`
	Blocked    bool   `json:"blocked,omitempty"`
	BypassWAF  bool   `json:"bypass_waf,omitempty"`
}

func normalizeNetworkCIDRs(values []string) ([]string, []netip.Prefix, error) {
	p := defaultProtection()
	p.FloodExemptCIDRs = values
	compiled, e := compileProtection(p)
	if e != nil {
		return nil, nil, invalid("provide up to 128 valid client IPs/CIDRs; all-address /0 entries are not accepted")
	}
	normalized := append([]string{}, compiled.FloodExemptCIDRs...)
	sort.Strings(normalized)
	return normalized, compiled.floodExempt, nil
}
func compileNetworkAccess(s networkAccessSettings, mode string) (*networkAccessPolicy, error) {
	if s.AllowScope == "" {
		s.AllowScope = "geo"
	}
	if s.GeoMode == "" {
		s.GeoMode = "off"
	}
	if s.GeoStrategy == "" {
		s.GeoStrategy = "block_selected"
	}
	if s.UnknownCountry == "" {
		s.UnknownCountry = "allow"
	}
	if (s.AllowScope != "geo" && s.AllowScope != "all") || (s.GeoMode != "off" && s.GeoMode != "observe" && s.GeoMode != "block") || (s.GeoStrategy != "block_selected" && s.GeoStrategy != "allow_selected") || (s.UnknownCountry != "allow" && s.UnknownCountry != "block") {
		return nil, invalid("invalid network access or geographical policy option")
	}
	if mode == "" {
		mode = "off"
	}
	if mode != "off" && mode != "observe" && mode != "block" {
		return nil, invalid("invalid network policy mode")
	}
	var blocked, allowed []netip.Prefix
	var e error
	if s.BlockCIDRs, blocked, e = normalizeNetworkCIDRs(s.BlockCIDRs); e != nil {
		return nil, e
	}
	if s.AllowCIDRs, allowed, e = normalizeNetworkCIDRs(s.AllowCIDRs); e != nil {
		return nil, e
	}
	if len(s.Countries) > 250 {
		return nil, invalid("at most 250 geographical country codes")
	}
	countries := map[string]bool{}
	normalized := []string{}
	for _, country := range s.Countries {
		code := strings.ToUpper(strings.TrimSpace(country))
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || code == "ZZ" || code == "XX" {
			return nil, invalid("use two-letter country codes such as US, CA or GB; configure unknown locations separately")
		}
		if !countries[code] {
			countries[code] = true
			normalized = append(normalized, code)
		}
	}
	if s.GeoMode != "off" && len(countries) == 0 {
		return nil, invalid("select at least one country for a geographical policy")
	}
	sort.Strings(normalized)
	s.Countries = normalized
	return &networkAccessPolicy{Settings: s, Mode: mode, blocked: blocked, allowed: allowed, countries: countries}, nil
}
func matchNetworkCIDR(prefixes []netip.Prefix, ip netip.Addr) string {
	for _, prefix := range prefixes {
		if prefix.Contains(ip.Unmap()) {
			return prefix.String()
		}
	}
	return ""
}

// No lookup is attempted until explicit CIDR decisions have been exhausted.
// The lookup callback reads the cached country database, never PostgreSQL/network.
func (p *networkAccessPolicy) evaluate(ip netip.Addr, reliable bool, lookup func() string) networkAccessResult {
	result := networkAccessResult{}
	if p == nil || p.Mode == "off" {
		return result
	}
	if cidr := matchNetworkCIDR(p.blocked, ip); cidr != "" {
		return networkAccessResult{Decision: "cidr_block", Mode: p.Mode, CIDR: cidr, WouldBlock: true, Blocked: p.Mode == "block"}
	}
	if reliable {
		if cidr := matchNetworkCIDR(p.allowed, ip); cidr != "" {
			return networkAccessResult{Decision: "cidr_allow", Mode: p.Mode, CIDR: cidr, AllowScope: p.Settings.AllowScope, BypassWAF: p.Settings.AllowScope == "all"}
		}
	}
	if p.Settings.GeoMode == "off" {
		return result
	}
	mode := p.Settings.GeoMode
	if p.Mode == "observe" {
		mode = "observe"
	}
	country := ""
	if lookup != nil {
		country = lookup()
	}
	result = networkAccessResult{Decision: "geo_allow", Mode: mode, Country: country, GeoChecked: true}
	deny := false
	if country == "" {
		deny = p.Settings.UnknownCountry == "block"
	} else if p.Settings.GeoStrategy == "allow_selected" {
		deny = !p.countries[country]
	} else {
		deny = p.countries[country]
	}
	if deny {
		result.Decision = "geo_block"
		result.WouldBlock = true
		result.Blocked = mode == "block"
	}
	return result
}
