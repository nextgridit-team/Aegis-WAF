package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"

	"github.com/jackc/pgx/v5"
)

// managedConfigurationLimit is the compiled-engine budget per replica: every
// distinct managed-signature configuration (the full serialized options) is
// keyed by managedRuntimeKey and compiles one Coraza CRS engine per replica
// at snapshot load. Raising it is a compile-time question, not a memory one.
const managedConfigurationLimit = 8

type managedConfigurationPolicy struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type managedConfiguration struct {
	ID       string                        `json:"id"`
	Options  managedSignatureOptions       `json:"options"`
	Policies []managedConfigurationPolicy  `json:"policies"`
}
type managedCapacity struct {
	Limit         int                     `json:"limit"`
	Distinct      int                     `json:"distinct"`
	Remaining     int                     `json:"remaining"`
	Configurations []managedConfiguration `json:"configurations"`
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
// sites, normalized then mode-capped options, off excluded — while keeping
// the policy references editors need. The optional replacement mirrors
// checkAssignedRuleCapacity so a preflight check can preview an edit.
func activeManagedConfigurations(ctx context.Context, db sqlQuerier, replacementID int64, replacement *policySpec) (map[string]*managedConfiguration, error) {
	rows, e := db.Query(ctx, "SELECT DISTINCT p.id,coalesce(p.spec->>'name',''),p.spec FROM policy_assignments b JOIN policies p ON p.id=b.policy_id JOIN sites s ON s.id=b.site_id WHERE s.enabled")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	configurations := map[string]*managedConfiguration{}
	for rows.Next() {
		var id int64
		var name string
		var raw []byte
		if e = rows.Scan(&id, &name, &raw); e != nil {
			return nil, e
		}
		spec := policySpec{}
		if replacement != nil && id == replacementID {
			spec = *replacement
		} else if e = json.Unmarshal(raw, &spec); e != nil {
			return nil, e
		}
		options, e := normalizeManagedSignatures(spec.ManagedSignatures)
		if e != nil {
			return nil, e
		}
		options = effectiveManagedOptions(options, spec.Mode)
		if options.Mode == "off" {
			continue
		}
		key := managedRuntimeKey(options)
		entry := configurations[key]
		if entry == nil {
			digest := sha256.Sum256([]byte(key))
			entry = &managedConfiguration{ID: hex.EncodeToString(digest[:8]), Options: options}
			configurations[key] = entry
		}
		entry.Policies = append(entry.Policies, managedConfigurationPolicy{ID: id, Name: name, Mode: spec.Mode})
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	return configurations, nil
}

func (a *App) policyCapacityReport(w http.ResponseWriter, r *http.Request, _ identity) error {
	configurations, e := activeManagedConfigurations(r.Context(), a.db, 0, nil)
	if e != nil {
		return e
	}
	report := managedCapacity{Limit: managedConfigurationLimit, Distinct: len(configurations), Configurations: []managedConfiguration{}}
	report.Remaining = max(0, report.Limit-report.Distinct)
	for _, entry := range configurations {
		report.Configurations = append(report.Configurations, *entry)
	}
	sort.Slice(report.Configurations, func(i, j int) bool { return report.Configurations[i].ID < report.Configurations[j].ID })
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
	result := policyCapacityCheckOutput{Limit: managedConfigurationLimit, Distinct: len(before), DifferingFields: []string{}}
	if options.Mode == "off" {
		result.DistinctAfter = result.Distinct
		respond(w, 200, result)
		return nil
	}
	result.WouldCreateNew = before[managedRuntimeKey(options)] == nil
	replacement := &policySpec{Mode: in.Mode, ManagedSignatures: in.Options}
	after, e := activeManagedConfigurations(r.Context(), a.db, in.PolicyID, replacement)
	if e != nil {
		return e
	}
	// The saved policy itself always carries the candidate configuration;
	// count it when no surviving policy already produces it.
	if after[managedRuntimeKey(options)] == nil {
		after[managedRuntimeKey(options)] = &managedConfiguration{}
	}
	result.DistinctAfter = len(after)
	result.Blocked = result.DistinctAfter > managedConfigurationLimit
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
