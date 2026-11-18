package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Policy composition (issue #49): a site scope — the default (all clients) or
// one exact client-CIDR set — may stack up to policyCompositionLimit policies.
// At snapshot compile the stacked members merge into ONE compiled binding, so
// the request path keeps its single evaluation pass; the engine budget counts
// distinct MERGED configurations, and identical merges share one engine.
const policyCompositionLimit = 4

// composedPolicyRef names one contributing policy of a stacked scope. The
// first contributor is the scope's lead: its identity is what access rows and
// editors attribute the composed binding to.
type composedPolicyRef struct {
	ID       int64
	Revision int64
	Name     string
	Priority int
}

// scopeMember is one policy assignment inside a site scope, ordered by
// (priority, policy id) — the deterministic stacking order.
type scopeMember struct {
	ID       int64
	Revision int64
	Name     string
	Priority int
	CIDRs    []string
	Spec     policySpec
	// managed holds the member's normalized, policy-mode-capped signature
	// options; composition merges these.
	managed managedSignatureOptions
}

// scopeKey identifies a scope: the empty string is the default (all clients);
// otherwise the sorted, joined CIDR set. Assignments with identical CIDR sets
// stack; overlapping-but-different CIDR sets stay separate scopes selected by
// priority, exactly as before.
func scopeKey(cidrs []string) string {
	if len(cidrs) == 0 {
		return ""
	}
	joined := append([]string{}, cidrs...)
	sort.Strings(joined)
	return strings.Join(joined, ",")
}

// policyScope is one site scope with its ordered contributing members.
type policyScope struct {
	CIDRs   []string
	Members []scopeMember
}

// loadPolicyScopes walks every enabled site's assignments grouped into
// scopes, members ordered by (priority, policy id) — the deterministic
// stacking order. An optional replacement substitutes one policy's stored
// spec so preflight checks can preview an edit. Member specs are unmodified
// apart from the substitution; address-selection expansion is the caller's
// concern (it needs the catalog).
func loadPolicyScopes(ctx context.Context, q sqlQuerier, replacementID int64, replacement *policySpec) (map[int64][]policyScope, error) {
	rows, e := q.Query(ctx, "SELECT b.site_id,b.source_cidrs,b.priority,p.id,p.revision,coalesce(p.spec->>'name',''),p.spec FROM policy_assignments b JOIN policies p ON p.id=b.policy_id JOIN sites s ON s.id=b.site_id WHERE s.enabled ORDER BY b.site_id,b.priority,p.id")
	if e != nil {
		return nil, e
	}
	scopes := map[int64][]policyScope{}
	for rows.Next() {
		var site int64
		var cidrs []string
		var raw []byte
		member := scopeMember{}
		if e = rows.Scan(&site, &cidrs, &member.Priority, &member.ID, &member.Revision, &member.Name, &raw); e != nil {
			rows.Close()
			return nil, e
		}
		spec := policySpec{}
		if replacement != nil && member.ID == replacementID {
			spec = *replacement
		} else if e = json.Unmarshal(raw, &spec); e != nil {
			rows.Close()
			return nil, e
		}
		member.Spec = spec
		member.CIDRs = cidrs
		member.managed, e = normalizeManagedSignatures(spec.ManagedSignatures)
		if e != nil {
			rows.Close()
			return nil, e
		}
		member.managed = effectiveManagedOptions(member.managed, spec.Mode)
		siteScopes := scopes[site]
		key := scopeKey(cidrs)
		placed := false
		for n := range siteScopes {
			if scopeKey(siteScopes[n].CIDRs) == key {
				siteScopes[n].Members = append(siteScopes[n].Members, member)
				placed = true
				break
			}
		}
		if !placed {
			siteScopes = append(siteScopes, policyScope{CIDRs: cidrs, Members: []scopeMember{member}})
		}
		scopes[site] = siteScopes
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return nil, e
	}
	rows.Close()
	return scopes, nil
}

// expandScopeNetworks resolves each member's address-object selections into
// CIDR lists before composition, so merges operate on the expanded surfaces.
// The selection structs are emptied once expanded: the merged CIDR lists
// already carry their entries.
func expandScopeNetworks(scope *policyScope, catalog addressCatalog) error {
	for n := range scope.Members {
		network, e := catalog.network(scope.Members[n].Spec.NetworkAccess)
		if e != nil {
			return e
		}
		network.BlockAddresses = addressSelection{}
		network.AllowAddresses = addressSelection{}
		scope.Members[n].Spec.NetworkAccess = network
	}
	return nil
}

func mostProtectiveMode(modes ...string) string {
	out := "off"
	for _, mode := range modes {
		if mode == "block" {
			return "block"
		}
		if mode == "observe" {
			out = "observe"
		}
	}
	return out
}

// composePolicySpecs merges the protection-bearing fields of ordered member
// specs into the single spec a stacked scope compiles. Rules are NOT merged
// here: each member's rules compile with its own mode and group context (the
// union with per-rule dedup happens in loadPolicyBindings), so a member's
// scoped groups and community gating keep their saved meaning. The lead
// (first) member's identity and description carry the composed spec.
func composePolicySpecs(members []scopeMember) (policySpec, error) {
	lead := members[0].Spec
	composed := policySpec{Name: lead.Name, Description: lead.Description, Mode: mostProtectiveMode(memberModes(members)...), FloodEnabled: anyFloodEnabled(members), BotEnabled: anyBool(members, func(s policySpec) bool { return s.BotEnabled }), BlockEmptyUA: anyBool(members, func(s policySpec) bool { return s.BlockEmptyUA }), BotChallenge: composeBotChallenge(members), ConnectionLimits: composeConnectionLimits(members), NetworkAccess: composeNetworkAccess(members)}
	flood := floodMembers(members)
	if len(flood) == 0 {
		flood = members
	}
	composed.RequestsPerSecond = minInt(memberInts(flood, func(s policySpec) int { return s.RequestsPerSecond }))
	composed.Burst = minInt(memberInts(flood, func(s policySpec) int { return s.Burst }))
	composed.SiteRequestsPerSecond = minInt(memberInts(flood, func(s policySpec) int { return s.SiteRequestsPerSecond }))
	composed.SiteBurst = minInt(memberInts(flood, func(s policySpec) int { return s.SiteBurst }))
	managed, e := composeManagedOptions(members)
	if e != nil {
		return composed, e
	}
	composed.ManagedSignatures = managed
	rates := []endpointRateRule{}
	for _, member := range members {
		rates = append(rates, member.Spec.EndpointRates...)
	}
	if len(rates) > maxEndpointRateRules {
		return composed, invalid(fmt.Sprintf("stacked endpoint rate overrides exceed the %d-rule cap; remove overrides from a contributing policy", maxEndpointRateRules))
	}
	composed.EndpointRates = rates
	return composed, nil
}

func memberModes(members []scopeMember) []string {
	modes := make([]string, 0, len(members))
	for _, member := range members {
		modes = append(modes, member.Spec.Mode)
	}
	return modes
}
func anyFloodEnabled(members []scopeMember) bool {
	for _, member := range members {
		if member.Spec.FloodEnabled {
			return true
		}
	}
	return false
}
func floodMembers(members []scopeMember) []scopeMember {
	out := []scopeMember{}
	for _, member := range members {
		if member.Spec.FloodEnabled {
			out = append(out, member)
		}
	}
	return out
}
func anyBool(members []scopeMember, field func(policySpec) bool) bool {
	for _, member := range members {
		if field(member.Spec) {
			return true
		}
	}
	return false
}
func memberInts(members []scopeMember, field func(policySpec) int) []int {
	values := make([]int, 0, len(members))
	for _, member := range members {
		values = append(values, field(member.Spec))
	}
	return values
}
func minInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	out := values[0]
	for _, value := range values[1:] {
		if value < out {
			out = value
		}
	}
	return out
}
func maxInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	out := values[0]
	for _, value := range values[1:] {
		if value > out {
			out = value
		}
	}
	return out
}

// composeBotChallenge merges anti-bot settings: any member enabling the
// feature enables it, and among enabling members every threshold and budget
// takes the most restrictive (smallest) value.
func composeBotChallenge(members []scopeMember) botChallengeSettings {
	enabled := []scopeMember{}
	for _, member := range members {
		if member.Spec.BotChallenge.Enabled {
			enabled = append(enabled, member)
		}
	}
	if len(enabled) == 0 {
		return members[0].Spec.BotChallenge
	}
	out := enabled[0].Spec.BotChallenge
	out.Enabled = true
	out.Threshold = minInt(memberInts(enabled, func(s policySpec) int { return s.BotChallenge.Threshold }))
	out.ClearanceMinutes = minInt(memberInts(enabled, func(s policySpec) int { return s.BotChallenge.ClearanceMinutes }))
	out.RequestsPerSecond = minInt(memberInts(enabled, func(s policySpec) int { return s.BotChallenge.RequestsPerSecond }))
	out.Burst = minInt(memberInts(enabled, func(s policySpec) int { return s.BotChallenge.Burst }))
	return out
}

// composeConnectionLimits merges connection limits: any member enabling
// limits enables them, and among enabling members every bound takes the
// most restrictive (smallest) value.
func composeConnectionLimits(members []scopeMember) *connectionLimitSettings {
	enabled := []scopeMember{}
	for _, member := range members {
		if member.Spec.ConnectionLimits != nil && member.Spec.ConnectionLimits.Enabled {
			enabled = append(enabled, member)
		}
	}
	if len(enabled) == 0 {
		return members[0].Spec.ConnectionLimits
	}
	out := *enabled[0].Spec.ConnectionLimits
	out.Enabled = true
	out.MaxConcurrent = minInt(memberInts(enabled, func(s policySpec) int { return s.ConnectionLimits.MaxConcurrent }))
	out.MaxPerClient = minInt(memberInts(enabled, func(s policySpec) int { return s.ConnectionLimits.MaxPerClient }))
	out.MaxDurationSeconds = minInt(memberInts(enabled, func(s policySpec) int { return s.ConnectionLimits.MaxDurationSeconds }))
	out.IdleTimeoutSeconds = minInt(memberInts(enabled, func(s policySpec) int { return s.ConnectionLimits.IdleTimeoutSeconds }))
	return &out
}

// composeNetworkAccess merges network access: block lists UNION (block if any
// member blocks), allow lists INTERSECT (a client must pass every member's
// allow surface), and the remaining switches take the most protective value.
// Members must arrive with address-object selections already expanded into
// their CIDR lists (expandScopeNetworks); the merged selection structs are
// emptied so the expansion is not applied twice. A member with no allow
// surface imposes no allow constraint; geo strategy allow_selected wins over
// block_selected because only-allow is stricter, and under allow_selected the
// composed country list is the union of the allow_selected members' lists.
func composeNetworkAccess(members []scopeMember) networkAccessSettings {
	lead := members[0].Spec.NetworkAccess
	out := lead
	out.BlockAddresses = addressSelection{}
	out.AllowAddresses = addressSelection{}
	out.BlockCIDRs = unionStrings(members, func(s policySpec) []string { return s.NetworkAccess.BlockCIDRs })
	out.AllowCIDRs = intersectStrings(members, func(s policySpec) []string { return s.NetworkAccess.AllowCIDRs })
	if len(members) > 1 {
		allowScoped := []scopeMember{}
		for _, member := range members {
			settings := member.Spec.NetworkAccess
			if len(settings.AllowCIDRs) > 0 || len(settings.AllowAddresses.ObjectIDs) > 0 || len(settings.AllowAddresses.GroupIDs) > 0 {
				allowScoped = append(allowScoped, member)
			}
		}
		// "geo" keeps the CIDR allow list from bypassing signatures: the most
		// protective allow scope among members that actually allow someone.
		out.AllowScope = "all"
		for _, member := range allowScoped {
			if member.Spec.NetworkAccess.AllowScope == "geo" {
				out.AllowScope = "geo"
				break
			}
		}
		out.GeoMode = mostProtectiveMode(memberNetworkModes(members, func(s networkAccessSettings) string { return s.GeoMode })...)
		out.GeoStrategy = "block_selected"
		allowSelected := []scopeMember{}
		for _, member := range members {
			if member.Spec.NetworkAccess.GeoStrategy == "allow_selected" {
				allowSelected = append(allowSelected, member)
			}
		}
		if len(allowSelected) > 0 {
			out.GeoStrategy = "allow_selected"
			out.Countries = unionStrings(allowSelected, func(s policySpec) []string { return s.NetworkAccess.Countries })
		} else {
			out.Countries = unionStrings(members, func(s policySpec) []string { return s.NetworkAccess.Countries })
		}
		out.UnknownCountry = "allow"
		for _, member := range members {
			if member.Spec.NetworkAccess.UnknownCountry == "block" {
				out.UnknownCountry = "block"
				break
			}
		}
	}
	return out
}
func memberNetworkModes(members []scopeMember, field func(networkAccessSettings) string) []string {
	modes := make([]string, 0, len(members))
	for _, member := range members {
		modes = append(modes, field(member.Spec.NetworkAccess))
	}
	return modes
}

func unionStrings(members []scopeMember, field func(policySpec) []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, member := range members {
		for _, value := range field(member.Spec) {
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// intersectStrings intersects member lists; a member with no list imposes no
// constraint (an empty allow list allows everything).
func intersectStrings(members []scopeMember, field func(policySpec) []string) []string {
	out := field(members[0].Spec)
	for _, member := range members[1:] {
		allowed := map[string]bool{}
		for _, value := range field(member.Spec) {
			allowed[value] = true
		}
		next := out[:0]
		for _, value := range out {
			if allowed[value] {
				next = append(next, value)
			}
		}
		out = next
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// composeManagedOptions merges the members' normalized, policy-mode-capped
// signature options into the single configuration the stacked scope compiles:
//
//   - signature set: every enforcing member must reference the SAME set —
//     different rule universes cannot union at compile time
//   - modes (request and response): most protective wins
//   - paranoia: maximum; thresholds and body limits: minimum; oversize
//     actions: reject beats process_partial
//   - allowed methods: intersection
//   - rule exclusions and scoped exclusions: UNION — the documented,
//     deliberately visible widening — bounded by the single-policy caps
//   - stream window: smallest non-zero member value
//
// Members whose effective mode is off contribute nothing.
func composeManagedOptions(members []scopeMember) (managedSignatureOptions, error) {
	lead := members[0].managed
	out := lead
	enforcing := []scopeMember{}
	for _, member := range members {
		if member.managed.Mode != "off" {
			enforcing = append(enforcing, member)
		}
	}
	if len(enforcing) == 0 {
		return out, nil
	}
	out = enforcing[0].managed
	for _, member := range enforcing[1:] {
		options := member.managed
		if options.SetID != out.SetID {
			return out, invalid(fmt.Sprintf("stacked policies %d (%s) and %d (%s) use different signature sets (%s, %s); compose policies sharing one set", enforcing[0].ID, enforcing[0].Name, member.ID, member.Name, out.SetID, options.SetID))
		}
		out.Mode = mostProtectiveMode(out.Mode, options.Mode)
		out.ResponseMode = mostProtectiveMode(out.ResponseMode, options.ResponseMode)
		out.Paranoia = maxInt([]int{out.Paranoia, options.Paranoia})
		out.Threshold = minInt([]int{out.Threshold, options.Threshold})
		out.OutboundThreshold = minInt([]int{out.OutboundThreshold, options.OutboundThreshold})
		out.BodyLimit = minInt([]int{out.BodyLimit, options.BodyLimit})
		out.ResponseBodyLimit = minInt([]int{out.ResponseBodyLimit, options.ResponseBodyLimit})
		if options.BodyLimitAction == "reject" {
			out.BodyLimitAction = "reject"
		}
		if options.ResponseBodyLimitAction == "reject" {
			out.ResponseBodyLimitAction = "reject"
		}
		out.AllowedMethods = intersectMethodLists(out.AllowedMethods, options.AllowedMethods)
		out.Exclusions = append(out.Exclusions, options.Exclusions...)
		out.ScopedExclusions = append(out.ScopedExclusions, options.ScopedExclusions...)
		if options.StreamWindowBytes != 0 && (out.StreamWindowBytes == 0 || options.StreamWindowBytes < out.StreamWindowBytes) {
			out.StreamWindowBytes = options.StreamWindowBytes
		}
	}
	exclusions, e := normalizeManagedSignatures(out)
	if e != nil {
		return out, e
	}
	return exclusions, nil
}

// intersectMethodLists keeps only methods every list allows; an empty list
// imposes no constraint.
func intersectMethodLists(left, right []string) []string {
	if len(left) == 0 {
		return right
	}
	if len(right) == 0 {
		return left
	}
	allowed := map[string]bool{}
	for _, method := range right {
		allowed[method] = true
	}
	out := []string{}
	for _, method := range left {
		if allowed[method] {
			out = append(out, method)
		}
	}
	sort.Strings(out)
	return out
}
