package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Endpoint rate overrides give a policy path-pattern budgets tighter than the
// per-client and per-application defaults. The list is ordered and
// first-matching-pattern-wins: one override applies per request, composed
// underneath (never instead of) the client, site and exemption budgets, so an
// override can only tighten a budget, never widen one.
type endpointRateRuleInput struct {
	PathPattern       string `json:"path_pattern"`
	Match             string `json:"match"`
	RequestsPerSecond int    `json:"requests_per_second"`
	Burst             int    `json:"burst"`
	Scope             string `json:"scope"`
}
type endpointRateRule struct {
	PathPattern       string `json:"path_pattern"`
	Match             string `json:"match,omitempty"`
	RequestsPerSecond int    `json:"requests_per_second"`
	Burst             int    `json:"burst"`
	Scope             string `json:"scope,omitempty"`
}

// The compiled form carried on protectionPolicy.
type compiledEndpointRate struct {
	Pattern  string
	Exact    bool
	Rate     int
	Burst    int
	SiteWide bool
	Index    int
}

const maxEndpointRateRules = 32

// endpointRateKeys is the complete allowlist of JSON keys an endpoint rate
// override accepts. Unknown keys are rejected by name so a misspelled scope
// cannot silently fall back to the default.
var endpointRateKeys = map[string]bool{"path_pattern": true, "match": true, "requests_per_second": true, "burst": true, "scope": true}

// rejectUnknownEndpointRateKeys scans a raw policy-save request body for
// endpoint rate override objects carrying keys outside the allowlist. It runs
// before the strict request decode because encoding/json drops unknown keys
// silently: a misspelled "scope" would leave the field empty and silently
// select the per-client default. Mirrors the scoped-exclusion rejection.
func rejectUnknownEndpointRateKeys(body []byte) error {
	var probe struct {
		Spec struct {
			EndpointRates []map[string]json.RawMessage `json:"endpoint_rates"`
		} `json:"spec"`
	}
	if e := json.Unmarshal(body, &probe); e != nil {
		return nil
	}
	for n, entry := range probe.Spec.EndpointRates {
		keys := make([]string, 0, len(entry))
		for key := range entry {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !endpointRateKeys[key] {
				return invalid(fmt.Sprintf("endpoint rate override %d has unknown key %q; allowed keys are path_pattern, match, requests_per_second, burst and scope", n+1, key))
			}
		}
	}
	return nil
}

// normalizeEndpointRates validates and normalizes the request form. Defaults:
// match prefix, scope per-client.
func normalizeEndpointRates(rules []endpointRateRuleInput) ([]endpointRateRule, error) {
	if len(rules) > maxEndpointRateRules {
		return nil, invalid("at most 32 endpoint rate overrides")
	}
	out := make([]endpointRateRule, 0, len(rules))
	for n := range rules {
		rule := rules[n]
		if rule.PathPattern == "" || len(rule.PathPattern) > 1024 || !strings.HasPrefix(rule.PathPattern, "/") {
			return nil, invalid("endpoint rate path patterns must start with / and fit 1024 bytes")
		}
		if rule.Match == "" {
			rule.Match = "prefix"
		}
		if rule.Match != "prefix" && rule.Match != "exact" {
			return nil, invalid("endpoint rate match must be prefix or exact")
		}
		if rule.Scope == "" {
			rule.Scope = "per-client"
		}
		if rule.Scope != "per-client" && rule.Scope != "site-wide" {
			return nil, invalid("endpoint rate scope must be per-client or site-wide")
		}
		if rule.RequestsPerSecond < 1 || rule.RequestsPerSecond > 100000 || rule.Burst < rule.RequestsPerSecond || rule.Burst > 1000000 {
			return nil, invalid("endpoint rate overrides require positive limits and bursts at least as large as the requests per second limit")
		}
		out = append(out, endpointRateRule{PathPattern: rule.PathPattern, Match: rule.Match, RequestsPerSecond: rule.RequestsPerSecond, Burst: rule.Burst, Scope: rule.Scope})
	}
	return out, nil
}

// compileEndpointRates validates the stored form and produces the compiled
// rules. It runs on every snapshot load as well as every save, so a corrupted
// stored spec fails the refresh instead of enforcement.
func compileEndpointRates(rules []endpointRateRule) ([]compiledEndpointRate, error) {
	if len(rules) > maxEndpointRateRules {
		return nil, invalid("at most 32 endpoint rate overrides")
	}
	out := make([]compiledEndpointRate, 0, len(rules))
	for n, rule := range rules {
		if rule.PathPattern == "" || len(rule.PathPattern) > 1024 || !strings.HasPrefix(rule.PathPattern, "/") {
			return nil, invalid("endpoint rate path patterns must start with / and fit 1024 bytes")
		}
		if rule.Match == "" {
			rule.Match = "prefix"
		}
		if rule.Match != "prefix" && rule.Match != "exact" {
			return nil, invalid("endpoint rate match must be prefix or exact")
		}
		if rule.Scope == "" {
			rule.Scope = "per-client"
		}
		if rule.Scope != "per-client" && rule.Scope != "site-wide" {
			return nil, invalid("endpoint rate scope must be per-client or site-wide")
		}
		if rule.RequestsPerSecond < 1 || rule.RequestsPerSecond > 100000 || rule.Burst < rule.RequestsPerSecond || rule.Burst > 1000000 {
			return nil, invalid("endpoint rate overrides require positive limits and bursts at least as large as the requests per second limit")
		}
		out = append(out, compiledEndpointRate{Pattern: rule.PathPattern, Exact: rule.Match == "exact", Rate: rule.RequestsPerSecond, Burst: rule.Burst, SiteWide: rule.Scope == "site-wide", Index: n})
	}
	return out, nil
}

// matchEndpoint returns the first override whose pattern matches the request
// path. Matching uses the scoped-exclusion semantics: raw prefix comparison
// against the request path (an exact match compares the whole path).
func (p *protectionPolicy) matchEndpoint(path string) (compiledEndpointRate, bool) {
	if p == nil {
		return compiledEndpointRate{}, false
	}
	for _, rule := range p.endpoints {
		if rule.Exact {
			if path == rule.Pattern {
				return rule, true
			}
			continue
		}
		if strings.HasPrefix(path, rule.Pattern) {
			return rule, true
		}
	}
	return compiledEndpointRate{}, false
}

// validateCachedEndpointRates re-checks the compiled overrides restored from
// the sealed disk snapshot cache. The cache is untrusted input like the policy
// spec itself: a corrupted cache must fail the restore (falling back to a
// database rebuild) instead of reaching enforcement with widened budgets.
func validateCachedEndpointRates(rules []compiledEndpointRate) ([]compiledEndpointRate, error) {
	if len(rules) > maxEndpointRateRules {
		return nil, invalid("at most 32 endpoint rate overrides")
	}
	for n, rule := range rules {
		if rule.Pattern == "" || len(rule.Pattern) > 1024 || !strings.HasPrefix(rule.Pattern, "/") {
			return nil, invalid("cached endpoint rate pattern is invalid")
		}
		if rule.Rate < 1 || rule.Rate > 100000 || rule.Burst < rule.Rate || rule.Burst > 1000000 {
			return nil, invalid("cached endpoint rate budget is invalid")
		}
		if rule.Index != n {
			return nil, invalid("cached endpoint rate order is invalid")
		}
	}
	return rules, nil
}
