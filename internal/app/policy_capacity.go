package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"

	"github.com/jackc/pgx/v5"
)

// managedConfigurationLimit is the default compiled-engine budget per replica
// when MANAGED_ENGINE_LIMIT is unset: every distinct managed-signature
// configuration (the full serialized options) is keyed by managedRuntimeKey
// and compiles one Coraza CRS engine per replica at snapshot load. The
// enforced value comes from Config.ManagedEngineLimit (see managedEngineLimit).
const managedConfigurationLimit = 8

// managedEngineMaxLimit caps MANAGED_ENGINE_LIMIT: each engine costs roughly
// 54 MiB resident and ~45 ms compile at config refresh (see docs/benchmarks.md),
// so the knob is bounded rather than unbounded.
const managedEngineMaxLimit = 64

// managedEngineLimit resolves the enforced budget: the configured value when
// it is in range, otherwise the default. Configs built directly (tests, bare
// App literals) carry the zero value and get the default, keeping unset
// behavior byte-identical to the previous constant.
func (a *App) managedEngineLimit() int {
	if a.cfg.ManagedEngineLimit >= 1 && a.cfg.ManagedEngineLimit <= managedEngineMaxLimit {
		return a.cfg.ManagedEngineLimit
	}
	return managedConfigurationLimit
}

type managedConfigurationPolicy struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type managedConfiguration struct {
	ID       string                       `json:"id"`
	Options  managedSignatureOptions      `json:"options"`
	Policies []managedConfigurationPolicy `json:"policies"`
}
type managedCapacity struct {
	Limit          int                    `json:"limit"`
	Distinct       int                    `json:"distinct"`
	Remaining      int                    `json:"remaining"`
	Configurations []managedConfiguration `json:"configurations"`
	// Sites reports per-application stacking: each scope's contributing
	// policies and the configuration the scope compiles (empty when its
	// signatures are off), so operators see what is stacked and how many
	// engines each application's scopes compile to.
	Sites []siteComposition `json:"sites"`
	// CommunityRules reports the stored-catalogue growth budget alongside the
	// engine budget so operators see both capacity surfaces in one place.
	CommunityRules communityRuleCapacity `json:"community_rules"`
}
type siteComposition struct {
	Site   int64                  `json:"site_id"`
	Scopes []siteCompositionScope `json:"scopes"`
}
type siteCompositionScope struct {
	SourceCIDRs     []string                     `json:"source_cidrs"`
	Policies        []managedConfigurationPolicy `json:"policies"`
	ConfigurationID string                       `json:"configuration_id,omitempty"`
}
type communityRuleCapacity struct {
	Limit          int `json:"limit"`
	Stored         int `json:"stored"`
	Remaining      int `json:"remaining"`
	PerSourceLimit int `json:"per_source_limit"`
	Sources        int `json:"sources"`
}
type policyCapacityCheckInput struct {
	PolicyID int64                   `json:"policy_id"`
	Mode     string                  `json:"mode"`
	Options  managedSignatureOptions `json:"options"`
}
type policyCapacityCheckOutput struct {
	Limit           int      `json:"limit"`
	Distinct        int      `json:"distinct"`
	DistinctAfter   int      `json:"distinct_after"`
	WouldCreateNew  bool     `json:"would_create_new"`
	Blocked         bool     `json:"blocked"`
	NearestPolicyID int64    `json:"nearest_policy_id"`
	NearestPolicy   string   `json:"nearest_policy"`
	DifferingFields []string `json:"differing_fields"`
}

type sqlQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// activeManagedConfigurations computes the same distinct engine set that
// checkPolicyAssignments enforces at save time — assignments on enabled
// sites grouped into scopes, stacked scopes merged, off excluded — while
// keeping the policy references editors need. The optional replacement
// mirrors checkAssignedRuleCapacity so a preflight check can preview an edit.
func activeManagedConfigurations(ctx context.Context, db sqlQuerier, replacementID int64, replacement *policySpec) (map[string]*managedConfiguration, error) {
	scopes, e := loadPolicyScopes(ctx, db, replacementID, replacement)
	if e != nil {
		return nil, e
	}
	configurations, _, e := managedScopeConfigurations(scopes)
	return configurations, e
}

// managedScopeConfigurations composes every scope's merged managed options
// and returns the distinct engine set plus the per-site composition surface.
func managedScopeConfigurations(scopes map[int64][]policyScope) (map[string]*managedConfiguration, []siteComposition, error) {
	configurations := map[string]*managedConfiguration{}
	sites := []siteComposition{}
	for site, siteScopes := range scopes {
		composition := siteComposition{Site: site, Scopes: []siteCompositionScope{}}
		for n := range siteScopes {
			scope := &siteScopes[n]
			options := scope.Members[0].managed
			if len(scope.Members) > 1 {
				composed, e := composePolicySpecs(scope.Members)
				if e != nil {
					return nil, nil, e
				}
				options = composed.ManagedSignatures
			}
			entry := &siteCompositionScope{SourceCIDRs: scope.CIDRs, Policies: []managedConfigurationPolicy{}}
			for _, member := range scope.Members {
				entry.Policies = append(entry.Policies, managedConfigurationPolicy{ID: member.ID, Name: member.Name, Mode: member.Spec.Mode})
			}
			if options.Mode != "off" {
				key := managedRuntimeKey(options)
				existing := configurations[key]
				if existing == nil {
					digest := sha256.Sum256([]byte(key))
					existing = &managedConfiguration{ID: hex.EncodeToString(digest[:8]), Options: options, Policies: []managedConfigurationPolicy{}}
					configurations[key] = existing
				}
				seen := map[int64]bool{}
				for _, policy := range existing.Policies {
					seen[policy.ID] = true
				}
				for _, member := range scope.Members {
					if !seen[member.ID] {
						existing.Policies = append(existing.Policies, managedConfigurationPolicy{ID: member.ID, Name: member.Name, Mode: member.Spec.Mode})
						seen[member.ID] = true
					}
				}
				entry.ConfigurationID = existing.ID
			}
			composition.Scopes = append(composition.Scopes, *entry)
		}
		sites = append(sites, composition)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Site < sites[j].Site })
	return configurations, sites, nil
}

// hasEnabledAssignment reports whether a policy is bound to at least one
// enabled site — the only condition under which saving it compiles an engine.
func hasEnabledAssignment(ctx context.Context, db sqlQuerier, policyID int64) (bool, error) {
	rows, e := db.Query(ctx, "SELECT EXISTS(SELECT 1 FROM policy_assignments b JOIN sites s ON s.id=b.site_id WHERE s.enabled AND b.policy_id=$1)", policyID)
	if e != nil {
		return false, e
	}
	defer rows.Close()
	if !rows.Next() {
		return false, errors.New("assignment existence check returned no rows")
	}
	var exists bool
	if e = rows.Scan(&exists); e != nil {
		return false, e
	}
	return exists, rows.Err()
}

func (a *App) policyCapacityReport(w http.ResponseWriter, r *http.Request, _ identity) error {
	scopes, e := loadPolicyScopes(r.Context(), a.db, 0, nil)
	if e != nil {
		return e
	}
	configurations, sites, e := managedScopeConfigurations(scopes)
	if e != nil {
		return e
	}
	report := managedCapacity{Limit: a.managedEngineLimit(), Distinct: len(configurations), Configurations: []managedConfiguration{}, Sites: sites}
	report.Remaining = max(0, report.Limit-report.Distinct)
	for _, entry := range configurations {
		report.Configurations = append(report.Configurations, *entry)
	}
	sort.Slice(report.Configurations, func(i, j int) bool { return report.Configurations[i].ID < report.Configurations[j].ID })
	report.CommunityRules = communityRuleCapacity{Limit: a.communityRuleBudget(), PerSourceLimit: a.feedSourceRuleLimit()}
	if e := a.db.QueryRow(r.Context(), "SELECT count(*),count(DISTINCT feed_id) FROM rule_catalog").Scan(&report.CommunityRules.Stored, &report.CommunityRules.Sources); e != nil {
		return e
	}
	report.CommunityRules.Remaining = max(0, report.CommunityRules.Limit-report.CommunityRules.Stored)
	respond(w, 200, report)
	return nil
}

func (a *App) policyCapacityCheck(w http.ResponseWriter, r *http.Request, _ identity) error {
	var in policyCapacityCheckInput
	if e := decode(w, r, &in); e != nil {
		return e
	}
	switch in.Mode {
	case "", "off", "observe", "block":
	default:
		return invalid("policy mode must be off, observe or block")
	}
	options, e := normalizeManagedSignatures(in.Options)
	if e != nil {
		return e
	}
	options = effectiveManagedOptions(options, in.Mode)
	// Mirror save-time validation so bad candidates surface before the
	// save attempt, not after the capacity math.
	if options.Mode != "off" {
		tx, e := a.db.Begin(r.Context())
		if e != nil {
			return e
		}
		set, e := readSignatureSet(r.Context(), tx, options.SetID)
		tx.Rollback(r.Context())
		if e != nil {
			return e
		}
		runtime, e := compileManagedSignatures(set, options)
		if e != nil {
			return e
		}
		closeManagedRuntime(runtime)
	}
	before, e := activeManagedConfigurations(r.Context(), a.db, 0, nil)
	if e != nil {
		return e
	}
	result := policyCapacityCheckOutput{Limit: a.managedEngineLimit(), Distinct: len(before), DifferingFields: []string{}}
	if options.Mode == "off" {
		result.DistinctAfter = result.Distinct
		respond(w, 200, result)
		return nil
	}
	// Model the policy's actual assignments: an existing policy only mints an
	// engine when it is bound to at least one enabled site, so an unassigned
	// edit that saves fine must not be counted against the budget. A new
	// policy (id 0) stays conservative because its save typically carries the
	// assignments that mint the engine.
	occupiesEngine := in.PolicyID == 0
	if !occupiesEngine {
		assigned, e := hasEnabledAssignment(r.Context(), a.db, in.PolicyID)
		if e != nil {
			return e
		}
		occupiesEngine = assigned
	}
	// Preview the save with composition: scopes stack, so the engines this
	// save would mint are the MERGED configurations its scopes compile, not
	// the candidate's own options. A policy composing with partners never
	// compiles alone, so its solo configuration is only counted when no scope
	// stacks it (a brand-new policy has no rows and always counts).
	scopes, e := loadPolicyScopes(r.Context(), a.db, in.PolicyID, &policySpec{Mode: in.Mode, ManagedSignatures: in.Options})
	if e != nil {
		return e
	}
	stacked := false
	for _, siteScopes := range scopes {
		for n := range siteScopes {
			if len(siteScopes[n].Members) > 1 {
				for _, member := range siteScopes[n].Members {
					if member.ID == in.PolicyID {
						stacked = true
					}
				}
			}
		}
	}
	after, _, e := managedScopeConfigurations(scopes)
	if e != nil {
		return e
	}
	if !stacked && occupiesEngine && after[managedRuntimeKey(options)] == nil {
		after[managedRuntimeKey(options)] = &managedConfiguration{}
	}
	result.DistinctAfter = len(after)
	result.Blocked = result.DistinctAfter > a.managedEngineLimit()
	result.WouldCreateNew = occupiesEngine && !stacked && before[managedRuntimeKey(options)] == nil
	if stacked {
		for key := range after {
			if before[key] == nil {
				result.WouldCreateNew = true
				break
			}
		}
	}
	if result.WouldCreateNew {
		if entry := nearestManagedConfiguration(before, options); entry != nil {
			result.NearestPolicyID = entry.Policies[0].ID
			result.NearestPolicy = entry.Policies[0].Name
			result.DifferingFields = managedOptionDiff(entry.Options, options)
		}
	}
	respond(w, 200, result)
	return nil
}

// The closest reusable posture by number of differing option fields.
func nearestManagedConfiguration(configurations map[string]*managedConfiguration, candidate managedSignatureOptions) *managedConfiguration {
	var best *managedConfiguration
	bestCount := -1
	for _, entry := range configurations {
		count := len(managedOptionDiff(entry.Options, candidate))
		if bestCount < 0 || count < bestCount {
			best, bestCount = entry, count
		}
	}
	return best
}

// Differing JSON fields between two option sets; omitempty absences on both
// sides compare equal, so an inert field only counts when it is actually set.
func managedOptionDiff(existing, candidate managedSignatureOptions) []string {
	left, right := map[string]any{}, map[string]any{}
	raw, _ := json.Marshal(existing)
	json.Unmarshal(raw, &left)
	raw, _ = json.Marshal(candidate)
	json.Unmarshal(raw, &right)
	seen := map[string]bool{}
	diffs := []string{}
	for field, value := range left {
		seen[field] = true
		if !reflect.DeepEqual(value, right[field]) {
			diffs = append(diffs, field)
		}
	}
	for field := range right {
		if !seen[field] {
			diffs = append(diffs, field)
		}
	}
	sort.Strings(diffs)
	return diffs
}
