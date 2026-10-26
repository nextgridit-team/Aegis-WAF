package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type policyRule struct {
	RuleID int64    `json:"rule_id"`
	Spec   RuleSpec `json:"spec"`
}
type policyGroup struct {
	Name       string       `json:"name"`
	PathPrefix string       `json:"path_prefix"`
	Methods    []string     `json:"methods"`
	Rules      []policyRule `json:"rules"`
}
type policySpec struct {
	BotChallenge          botChallengeSettings    `json:"bot_challenge"`
	NetworkAccess         networkAccessSettings   `json:"network_access"`
	ManagedSignatures     managedSignatureOptions `json:"managed_signatures"`
	Name                  string                  `json:"name"`
	Description           string                  `json:"description"`
	Mode                  string                  `json:"mode"`
	FloodEnabled          bool                    `json:"flood_enabled"`
	BotEnabled            bool                    `json:"bot_enabled"`
	BlockEmptyUA          bool                    `json:"block_empty_user_agent"`
	RequestsPerSecond     int                     `json:"requests_per_second"`
	Burst                 int                     `json:"burst"`
	SiteRequestsPerSecond int                     `json:"site_requests_per_second"`
	SiteBurst             int                     `json:"site_burst"`
	Groups                []policyGroup           `json:"groups"`
}
type policyGroupInput struct {
	Name       string   `json:"name"`
	PathPrefix string   `json:"path_prefix"`
	Methods    []string `json:"methods"`
	RuleIDs    []int64  `json:"rule_ids"`
}
type policySpecInput struct {
	BotChallenge          botChallengeSettings    `json:"bot_challenge"`
	NetworkAccess         networkAccessSettings   `json:"network_access"`
	ManagedSignatures     managedSignatureOptions `json:"managed_signatures"`
	Name                  string                  `json:"name"`
	Description           string                  `json:"description"`
	Mode                  string                  `json:"mode"`
	FloodEnabled          bool                    `json:"flood_enabled"`
	BotEnabled            bool                    `json:"bot_enabled"`
	BlockEmptyUA          bool                    `json:"block_empty_user_agent"`
	RequestsPerSecond     int                     `json:"requests_per_second"`
	Burst                 int                     `json:"burst"`
	SiteRequestsPerSecond int                     `json:"site_requests_per_second"`
	SiteBurst             int                     `json:"site_burst"`
	Groups                []policyGroupInput      `json:"groups"`
}
type policyAssignment struct {
	SiteID      int64    `json:"site_id"`
	SourceCIDRs []string `json:"source_cidrs"`
	Priority    int      `json:"priority"`
}
type policyInput struct {
	Spec         policySpecInput    `json:"spec"`
	Applications []policyAssignment `json:"applications"`
	Revision     int64              `json:"revision"`
	RefreshRules bool               `json:"refresh_rules"`
}
type policyView struct {
	ID           int64              `json:"id"`
	Revision     int64              `json:"revision"`
	Spec         policySpec         `json:"spec"`
	Applications []policyAssignment `json:"applications"`
}
type compiledPolicyBinding struct {
	ManagedOptions managedSignatureOptions
	Managed        *managedSignatureRuntime
	ID, Revision   int64
	Name           string
	Priority       int
	CIDRs          []netip.Prefix
	Rules          []compiledRule
	Protection     *protectionPolicy
}

func selectPolicy(bindings []compiledPolicyBinding, ip netip.Addr, reliable bool) *compiledPolicyBinding {
	for n := range bindings {
		b := &bindings[n]
		if len(b.CIDRs) == 0 || (reliable && matchesCIDRs(b.CIDRs, ip)) {
			return b
		}
	}
	return nil
}
func policyProtection(base *protectionPolicy, s policySpec, id int64) (*protectionPolicy, error) {
	p := defaultProtection()
	if base != nil {
		p = base.ProtectionSettings
	}
	p.Mode = "off"
	p.BotMode = "off"
	if s.FloodEnabled {
		p.Mode = s.Mode
	}
	if s.BotEnabled {
		p.BotMode = s.Mode
	}
	p.RequestsPerSecond = s.RequestsPerSecond
	p.Burst = s.Burst
	p.SiteRequestsPerSecond = s.SiteRequestsPerSecond
	p.SiteBurst = s.SiteBurst
	p.BlockEmptyUA = s.BlockEmptyUA
	p.BotChallenge = s.BotChallenge
	compiled, e := compileProtection(p)
	if e == nil {
		compiled.budgetScope = id
		compiled.network, e = compileNetworkAccess(s.NetworkAccess, s.Mode)
	}
	return compiled, e
}
func policyRuleCount(s policySpec) int {
	n := 0
	for _, g := range s.Groups {
		n += len(g.Rules)
	}
	return n
}
func validatePolicySpec(s policySpec) error {
	if _, e := normalizeManagedSignatures(s.ManagedSignatures); e != nil {
		return e
	}
	if strings.TrimSpace(s.Name) == "" || len(s.Name) > 120 || len(s.Description) > 2000 {
		return invalid("provide a policy name of 1–120 bytes and description up to 2000 bytes")
	}
	if s.Mode != "off" && s.Mode != "observe" && s.Mode != "block" {
		return invalid("policy mode must be off, observe or block")
	}
	if _, e := policyProtection(nil, s, 0); e != nil {
		return e
	}
	if len(s.Groups) > 10 || policyRuleCount(s) > 100 {
		return invalid("at most 10 groups and 100 rules per policy")
	}
	names := map[string]bool{}
	for _, g := range s.Groups {
		if strings.TrimSpace(g.Name) == "" || len(g.Name) > 120 || names[g.Name] {
			return invalid("policy groups require unique names of 1–120 bytes")
		}
		names[g.Name] = true
		if len(g.PathPrefix) > 1024 || (g.PathPrefix != "" && !strings.HasPrefix(g.PathPrefix, "/")) {
			return invalid("group path prefixes must start with / and fit 1024 bytes")
		}
		if len(g.Methods) > 24 {
			return invalid("at most 24 methods per group")
		}
		for _, method := range g.Methods {
			if !methodName.MatchString(method) {
				return invalid("group methods must be uppercase HTTP method names")
			}
		}
		seen := map[int64]bool{}
		for _, rule := range g.Rules {
			if rule.RuleID < 1 || seen[rule.RuleID] {
				return invalid("select each rule only once within a group")
			}
			seen[rule.RuleID] = true
			spec := rule.Spec
			spec.Scope.SiteID = 1
			if _, e := compileRule(spec); e != nil {
				return invalid("invalid policy rule: " + e.Error())
			}
		}
	}
	return nil
}
func (a *App) normalizePolicy(ctx context.Context, tx pgx.Tx, in policySpecInput, frozen map[int64]RuleSpec) (policySpec, error) {
	managed, e := normalizeManagedSignatures(in.ManagedSignatures)
	if e != nil {
		return policySpec{}, e
	}
	if managed.Mode != "off" {
		set, e := readSignatureSet(ctx, tx, managed.SetID)
		if e != nil {
			return policySpec{}, e
		}
		if _, e = compileManagedSignatures(set, managed); e != nil {
			return policySpec{}, e
		}
	}
	network, e := compileNetworkAccess(in.NetworkAccess, in.Mode)
	if e != nil {
		return policySpec{}, e
	}
	if network.Settings.GeoMode != "off" {
		var available bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM geo_database WHERE id)").Scan(&available); e != nil {
			return policySpec{}, e
		}
		if !available {
			return policySpec{}, invalid("download a country database before enabling Geo blocking")
		}
	}
	challenge, e := normalizeBotChallenge(in.BotChallenge)
	if e != nil {
		return policySpec{}, e
	}
	s := policySpec{BotChallenge: challenge, NetworkAccess: network.Settings, ManagedSignatures: managed, Name: strings.TrimSpace(in.Name), Description: in.Description, Mode: in.Mode, FloodEnabled: in.FloodEnabled, BotEnabled: in.BotEnabled, BlockEmptyUA: in.BlockEmptyUA, RequestsPerSecond: in.RequestsPerSecond, Burst: in.Burst, SiteRequestsPerSecond: in.SiteRequestsPerSecond, SiteBurst: in.SiteBurst, Groups: []policyGroup{}}
	if len(in.Groups) > 10 {
		return s, invalid("at most 10 groups per policy")
	}
	count := 0
	for _, group := range in.Groups {
		count += len(group.RuleIDs)
		if count > 100 {
			return s, invalid("at most 100 rules per policy")
		}
		g := policyGroup{Name: strings.TrimSpace(group.Name), PathPrefix: group.PathPrefix, Methods: group.Methods, Rules: []policyRule{}}
		if g.Methods == nil {
			g.Methods = []string{}
		}
		for _, id := range group.RuleIDs {
			if prior, ok := frozen[id]; ok {
				g.Rules = append(g.Rules, policyRule{id, prior})
				continue
			}
			record, e := readRule(ctx, tx, id, false)
			if e != nil {
				return s, e
			}
			record.Spec.EvidenceIDs = nil
			g.Rules = append(g.Rules, policyRule{id, record.Spec})
		}
		s.Groups = append(s.Groups, g)
	}
	return s, validatePolicySpec(s)
}
func normalizeAssignments(assignments []policyAssignment) ([]policyAssignment, error) {
	if len(assignments) > 100 {
		return nil, invalid("at most 100 application assignments per policy")
	}
	seen := map[int64]bool{}
	for n := range assignments {
		assignment := &assignments[n]
		if assignment.SiteID < 1 || seen[assignment.SiteID] {
			return nil, invalid("select each application once per policy")
		}
		seen[assignment.SiteID] = true
		settings := defaultProtection()
		settings.FloodExemptCIDRs = assignment.SourceCIDRs
		p, e := compileProtection(settings)
		if e != nil {
			return nil, e
		}
		assignment.SourceCIDRs = p.FloodExemptCIDRs
		if len(assignment.SourceCIDRs) == 0 {
			assignment.Priority = 10000
		} else if assignment.Priority < 0 || assignment.Priority >= 10000 {
			return nil, invalid("CIDR assignment priority must be 0–9999; smaller values match first")
		}
	}
	return assignments, nil
}
func checkPolicyAssignments(ctx context.Context, tx pgx.Tx) error {
	var invalidSite bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT site_id FROM policy_assignments GROUP BY site_id HAVING count(*) FILTER(WHERE cardinality(source_cidrs)=0)<>1 OR count(*)>10)").Scan(&invalidSite); e != nil {
		return e
	}
	if invalidSite {
		return apiError{409, "each application with scoped policies needs one default policy; at most 10 policies per application"}
	}
	var total int
	if e := tx.QueryRow(ctx, "SELECT coalesce(sum((SELECT coalesce(sum(jsonb_array_length(g->'rules')),0) FROM jsonb_array_elements(p.spec->'groups') g)),0) FROM policy_assignments b JOIN policies p ON p.id=b.policy_id").Scan(&total); e != nil {
		return e
	}
	if total > 1000 {
		return apiError{409, "policy capacity exceeded: at most 1000 assigned rule instances"}
	}
	rows, e := tx.Query(ctx, "SELECT DISTINCT p.id,p.spec FROM policy_assignments b JOIN policies p ON p.id=b.policy_id JOIN sites s ON s.id=b.site_id WHERE s.enabled")
	if e != nil {
		return e
	}
	defer rows.Close()
	configurations := map[string]bool{}
	for rows.Next() {
		var id int64
		var raw []byte
		if e = rows.Scan(&id, &raw); e != nil {
			return e
		}
		var spec policySpec
		if e = json.Unmarshal(raw, &spec); e != nil {
			return e
		}
		options, e := normalizeManagedSignatures(spec.ManagedSignatures)
		if e != nil {
			return e
		}
		options = effectiveManagedOptions(options, spec.Mode)
		if options.Mode != "off" {
			configurations[managedRuntimeKey(options)] = true
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if len(configurations) > 8 {
		return apiError{409, "at most eight distinct active managed signature configurations"}
	}
	return nil
}
func (a *App) savePolicy(w http.ResponseWriter, r *http.Request, i identity) error {
	var input policyInput
	if e := decode(w, r, &input); e != nil {
		return e
	}
	var id int64
	var e error
	if r.Method == "PUT" {
		id, e = resourceID(r)
		if e != nil {
			return e
		}
	}
	input.Applications, e = normalizeAssignments(input.Applications)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		ctx := r.Context()
		frozen := map[int64]RuleSpec{}
		if id != 0 {
			var version int64
			var raw []byte
			if e := tx.QueryRow(ctx, "SELECT revision,spec FROM policies WHERE id=$1 FOR UPDATE", id).Scan(&version, &raw); errors.Is(e, pgx.ErrNoRows) {
				return apiError{404, "policy not found"}
			} else if e != nil {
				return e
			}
			if version != input.Revision {
				return apiError{409, "policy changed; reload before saving"}
			}
			if !input.RefreshRules {
				var prior policySpec
				if e := json.Unmarshal(raw, &prior); e != nil {
					return e
				}
				for _, g := range prior.Groups {
					for _, rule := range g.Rules {
						frozen[rule.RuleID] = rule.Spec
					}
				}
			}
		}
		spec, e := a.normalizePolicy(ctx, tx, input.Spec, frozen)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(spec)
		if id == 0 {
			var count int
			if e = tx.QueryRow(ctx, "SELECT count(*) FROM policies p WHERE NOT EXISTS(SELECT 1 FROM built_in_policies b WHERE b.policy_id=p.id)").Scan(&count); e != nil {
				return e
			}
			if count >= 50 {
				return apiError{409, "at most 50 custom policies are supported"}
			}
			if e = tx.QueryRow(ctx, "INSERT INTO policies(spec) VALUES($1) RETURNING id", raw).Scan(&id); e != nil {
				return e
			}
		} else {
			var version int64
			if e = tx.QueryRow(ctx, "SELECT revision FROM policies WHERE id=$1 FOR UPDATE", id).Scan(&version); errors.Is(e, pgx.ErrNoRows) {
				return apiError{404, "policy not found"}
			} else if e != nil {
				return e
			}
			if version != input.Revision {
				return apiError{409, "policy changed; reload before saving"}
			}
			if _, e = tx.Exec(ctx, "UPDATE policies SET spec=$2,revision=revision+1 WHERE id=$1", id, raw); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, "DELETE FROM policy_assignments WHERE policy_id=$1", id); e != nil {
			return e
		}
		for _, assignment := range input.Applications {
			var exists bool
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1)", assignment.SiteID).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				return invalid("an assigned application no longer exists")
			}
			if len(assignment.SourceCIDRs) == 0 {
				rows, err := tx.Query(ctx, "DELETE FROM policy_assignments WHERE site_id=$1 AND cardinality(source_cidrs)=0 RETURNING policy_id", assignment.SiteID)
				if err != nil {
					return err
				}
				displaced := []int64{}
				for rows.Next() {
					var previous int64
					if err = rows.Scan(&previous); err != nil {
						rows.Close()
						return err
					}
					displaced = append(displaced, previous)
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
				for _, previous := range displaced {
					if _, err = tx.Exec(ctx, "UPDATE policies SET revision=revision+1 WHERE id=$1", previous); err != nil {
						return err
					}
					if _, err = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor) SELECT id,revision,spec,$2 FROM policies WHERE id=$1", previous, i.Username); err != nil {
						return err
					}
					if err = audit(ctx, tx, i.Username, "policy.default_reassigned", strconv.FormatInt(previous, 10)); err != nil {
						return err
					}
				}
			} else {
				var conflict bool
				if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM policy_assignments WHERE site_id=$1 AND priority=$2)", assignment.SiteID, assignment.Priority).Scan(&conflict); e != nil {
					return e
				}
				if conflict {
					return apiError{409, "another CIDR policy has this priority on an application; choose a unique priority"}
				}
			}
			if _, e = tx.Exec(ctx, "INSERT INTO policy_assignments(policy_id,site_id,source_cidrs,priority) VALUES($1,$2,$3,$4)", id, assignment.SiteID, assignment.SourceCIDRs, assignment.Priority); e != nil {
				return e
			}
		}
		if e = checkPolicyAssignments(ctx, tx); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor) SELECT id,revision,spec,$2 FROM policies WHERE id=$1", id, i.Username); e != nil {
			return e
		}
		if e := validateAddressConsumers(ctx, tx); e != nil {
			return e
		}
		return audit(ctx, tx, i.Username, "policy.saved", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) loadPolicyBindings(ctx context.Context, tx pgx.Tx, next *snapshot) error {
	catalog, e := loadAddressCatalog(ctx, tx)
	if e != nil {
		return e
	}
	next.policyBindings = map[int64][]compiledPolicyBinding{}
	rows, e := tx.Query(ctx, "SELECT b.site_id,b.source_cidrs,b.priority,p.id,p.revision,p.spec FROM policy_assignments b JOIN policies p ON p.id=b.policy_id JOIN sites s ON s.id=b.site_id WHERE s.enabled ORDER BY b.site_id,b.priority")
	if e != nil {
		return e
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var site int64
		var cidrs []string
		var raw []byte
		var binding compiledPolicyBinding
		if e = rows.Scan(&site, &cidrs, &binding.Priority, &binding.ID, &binding.Revision, &raw); e != nil {
			return e
		}
		var spec policySpec
		if e = json.Unmarshal(raw, &spec); e != nil {
			return e
		}
		if e = validatePolicySpec(spec); e != nil {
			return e
		}
		binding.Name = spec.Name
		binding.ManagedOptions, e = normalizeManagedSignatures(spec.ManagedSignatures)
		if e != nil {
			return e
		}
		binding.ManagedOptions = effectiveManagedOptions(binding.ManagedOptions, spec.Mode)
		spec.NetworkAccess, e = catalog.network(spec.NetworkAccess)
		if e != nil {
			return e
		}
		binding.Protection, e = policyProtection(next.protection[site], spec, binding.ID)
		if e != nil {
			return e
		}
		for _, cidr := range cidrs {
			prefix, e := netip.ParsePrefix(cidr)
			if e != nil {
				return e
			}
			binding.CIDRs = append(binding.CIDRs, prefix)
		}
		for _, group := range spec.Groups {
			for _, rule := range group.Rules {
				total++
				if total > 1000 {
					return errors.New("stored policy rule capacity exceeded")
				}
				if spec.Mode == "off" {
					continue
				}
				rule.Spec.Scope.SiteID = site
				rule.Spec.Action = spec.Mode
				compiled, e := compileRule(rule.Spec)
				if e != nil {
					return e
				}
				compiled.ID = rule.RuleID
				compiled.PolicyID = binding.ID
				compiled.PolicyRevision = binding.Revision
				compiled.GroupName = group.Name
				compiled.GroupPrefix = group.PathPrefix
				compiled.GroupMethods = group.Methods
				binding.Rules = append(binding.Rules, compiled)
			}
		}
		next.policyBindings[site] = append(next.policyBindings[site], binding)
	}
	if e := rows.Err(); e != nil {
		return e
	}
	for _, bindings := range next.policyBindings {
		defaults := 0
		for _, b := range bindings {
			if len(b.CIDRs) == 0 {
				defaults++
			}
		}
		if defaults != 1 || len(bindings) > 10 {
			return errors.New("invalid stored policy assignments")
		}
	}
	return nil
}
func policyAPI(a *App, m *http.ServeMux) {
	m.HandleFunc("GET /api/policies", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		return a.list(w, r, `SELECT p.id,p.revision,p.spec,EXISTS(SELECT 1 FROM built_in_policies builtin WHERE builtin.policy_id=p.id) AS built_in,coalesce((SELECT jsonb_agg(jsonb_build_object('site_id',b.site_id,'source_cidrs',b.source_cidrs,'priority',b.priority) ORDER BY b.priority,b.site_id) FROM policy_assignments b WHERE b.policy_id=p.id),'[]'::jsonb) AS applications FROM policies p ORDER BY p.id`)
	}))
	m.HandleFunc("POST /api/policies", a.wrap(true, a.savePolicy))
	m.HandleFunc("PUT /api/policies/{id}", a.wrap(true, a.savePolicy))
	m.HandleFunc("GET /api/policies/{id}/history", a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		return a.list(w, r, "SELECT revision,spec,actor,at FROM policy_revisions WHERE policy_id="+strconv.FormatInt(id, 10)+" ORDER BY revision DESC LIMIT 20")
	}))
	m.HandleFunc("POST /api/policies/{id}/rollback", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		var body struct {
			Revision int64 `json:"revision"`
			Target   int64 `json:"target_revision"`
		}
		if e = decode(w, r, &body); e != nil {
			return e
		}
		e = a.change(r.Context(), func(tx pgx.Tx) error {
			ctx := r.Context()
			var raw []byte
			if e := tx.QueryRow(ctx, "SELECT spec FROM policy_revisions WHERE policy_id=$1 AND revision=$2", id, body.Target).Scan(&raw); errors.Is(e, pgx.ErrNoRows) {
				return apiError{404, "policy version not found"}
			} else if e != nil {
				return e
			}
			var spec policySpec
			if e := json.Unmarshal(raw, &spec); e != nil {
				return e
			}
			if e := validatePolicySpec(spec); e != nil {
				return e
			}
			tag, e := tx.Exec(ctx, "UPDATE policies SET spec=$3,revision=revision+1 WHERE id=$1 AND revision=$2", id, body.Revision, raw)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return apiError{409, "policy changed; reload before rollback"}
			}
			if e = checkPolicyAssignments(ctx, tx); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, "INSERT INTO policy_revisions(policy_id,revision,spec,actor) SELECT id,revision,spec,$2 FROM policies WHERE id=$1", id, i.Username); e != nil {
				return e
			}
			if e := validateAddressConsumers(ctx, tx); e != nil {
				return e
			}
			return audit(ctx, tx, i.Username, "policy.rolled_back", strconv.FormatInt(id, 10))
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"rolled_back": true})
		return nil
	}))
	m.HandleFunc("DELETE /api/policies/{id}", a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
		id, e := resourceID(r)
		if e != nil {
			return e
		}
		var body struct {
			Revision int64 `json:"revision"`
		}
		if e = decode(w, r, &body); e != nil {
			return e
		}
		e = a.change(r.Context(), func(tx pgx.Tx) error {
			tag, e := tx.Exec(r.Context(), "DELETE FROM policies WHERE id=$1 AND revision=$2", id, body.Revision)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return apiError{409, "policy changed or was removed; reload before deleting"}
			}
			if e = checkPolicyAssignments(r.Context(), tx); e != nil {
				return e
			}
			return audit(r.Context(), tx, i.Username, "policy.deleted", strconv.FormatInt(id, 10))
		})
		if e != nil {
			return e
		}
		respond(w, 200, map[string]bool{"deleted": true})
		return nil
	}))
}
