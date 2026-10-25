package app

import (
	"net/netip"
	"testing"
)

func TestNetworkAccessOrderingAndAllowScope(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.12")
	for _, scope := range []string{"geo", "all"} {
		settings := networkAccessSettings{BlockCIDRs: []string{"203.0.113.0/24"}, AllowCIDRs: []string{"198.51.100.0/24"}, AllowScope: scope, GeoMode: "block", Countries: []string{"US"}, UnknownCountry: "block"}
		policy, e := compileNetworkAccess(settings, "block")
		if e != nil {
			t.Fatal(e)
		}
		lookups := 0
		lookup := func() string { lookups++; return "US" }
		allowed := policy.evaluate(ip, true, lookup)
		if allowed.Decision != "cidr_allow" || allowed.GeoChecked || lookups != 0 || allowed.Blocked || allowed.BypassWAF != (scope == "all") {
			t.Fatal("allow did not bypass geography with the selected scope", allowed)
		}
		denied := policy.evaluate(netip.MustParseAddr("203.0.113.3"), true, lookup)
		if !denied.Blocked || denied.Decision != "cidr_block" || lookups != 0 {
			t.Fatal("CIDR block did a location lookup", denied)
		}
		spoofed := policy.evaluate(ip, false, lookup)
		if !spoofed.Blocked || spoofed.Decision != "geo_block" || lookups != 1 || spoofed.BypassWAF {
			t.Fatal("unreliable identity used allowlist", spoofed)
		}
		policy.blocked = append(policy.blocked, netip.MustParsePrefix("198.51.100.0/24"))
		overlap := policy.evaluate(ip, true, lookup)
		if !overlap.Blocked || overlap.Decision != "cidr_block" || lookups != 1 {
			t.Fatal("block did not take precedence", overlap)
		}
	}
}
func TestNetworkGeoModesAndUnknown(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, test := range []struct {
		mode, geo, strategy, unknown, country string
		blocked, would                        bool
	}{
		{"block", "block", "block_selected", "allow", "US", true, true},
		{"observe", "block", "block_selected", "allow", "US", false, true},
		{"block", "observe", "block_selected", "allow", "US", false, true},
		{"off", "block", "block_selected", "block", "US", false, false},
		{"block", "off", "block_selected", "block", "US", false, false},
		{"block", "block", "allow_selected", "allow", "US", false, false},
		{"block", "block", "allow_selected", "allow", "GB", true, true},
		{"block", "block", "allow_selected", "allow", "", false, false},
		{"block", "block", "allow_selected", "block", "", true, true},
	} {
		policy, e := compileNetworkAccess(networkAccessSettings{GeoMode: test.geo, GeoStrategy: test.strategy, Countries: []string{"us"}, UnknownCountry: test.unknown}, test.mode)
		if e != nil {
			t.Fatal(e)
		}
		lookups := 0
		result := policy.evaluate(ip, true, func() string { lookups++; return test.country })
		if result.Blocked != test.blocked || result.WouldBlock != test.would {
			t.Fatalf("%+v => %+v", test, result)
		}
		if (test.mode == "off" || test.geo == "off") && lookups != 0 {
			t.Fatal("disabled policy performed lookup")
		}
	}
	for _, settings := range []networkAccessSettings{{AllowScope: "invalid"}, {GeoMode: "block"}, {Countries: []string{"USA"}}, {AllowCIDRs: []string{"0.0.0.0/0"}}} {
		if _, e := compileNetworkAccess(settings, "block"); e == nil {
			t.Fatal("invalid access settings accepted")
		}
	}
}
