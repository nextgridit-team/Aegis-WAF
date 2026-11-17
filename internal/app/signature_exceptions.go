package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Exceptions are typed and scoped; no caller-provided SecLang is accepted.
// Path and source predicates are ANDed. Parameter targets only exempt that
// argument from the selected rules, not the entire request or entire rule.
type signatureException struct {
	RuleIDs     []int    `json:"rule_ids"`
	PathPrefix  string   `json:"path_prefix,omitempty"`
	ClientCIDRs []string `json:"client_cidrs,omitempty"`
	Parameters  []string `json:"parameters,omitempty"`
}

var exceptionParameter = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// scopedExclusionKeys is the complete allowlist of JSON keys a scoped
// exception accepts. Unknown keys are rejected by name so a misspelled scope
// cannot silently widen an exclusion.
var scopedExclusionKeys = map[string]bool{"rule_ids": true, "path_prefix": true, "parameters": true, "client_cidrs": true}

// rejectUnknownScopedExclusionKeys scans a raw policy-save request body for
// scoped exclusion objects carrying keys outside the allowlist. It runs before
// the strict request decode because encoding/json drops unknown keys silently:
// a misspelled scope such as "client_cidr" would leave the struct field empty
// and broaden the exclusion to every client. The rejection names the offending
// key and the exception's 1-based index. Malformed JSON is left to the strict
// decode step, which reports it.
func rejectUnknownScopedExclusionKeys(body []byte) error {
	var probe struct {
		Spec struct {
			ManagedSignatures struct {
				ScopedExclusions []map[string]json.RawMessage `json:"scoped_exclusions"`
			} `json:"managed_signatures"`
		} `json:"spec"`
	}
	if e := json.Unmarshal(body, &probe); e != nil {
		return nil
	}
	for n, entry := range probe.Spec.ManagedSignatures.ScopedExclusions {
		keys := make([]string, 0, len(entry))
		for key := range entry {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !scopedExclusionKeys[key] {
				return invalid(fmt.Sprintf("scoped exception %d has unknown key %q; allowed keys are rule_ids, path_prefix, parameters and client_cidrs", n+1, key))
			}
		}
	}
	return nil
}

func normalizeSignatureExceptions(values []signatureException) ([]signatureException, error) {
	if len(values) > 32 {
		return nil, invalid("at most 32 scoped signature exceptions")
	}
	for n := range values {
		v := &values[n]
		if len(v.RuleIDs) == 0 || len(v.RuleIDs) > 20 || len(v.Parameters) > 16 || len(v.ClientCIDRs) > 16 {
			return nil, invalid("exceptions require 1–20 rule IDs, at most 16 parameters and 16 client CIDRs")
		}
		if len(v.PathPrefix) > 1024 || (v.PathPrefix != "" && !strings.HasPrefix(v.PathPrefix, "/")) {
			return nil, invalid("exception path prefix must start with / and fit 1024 bytes")
		}
		if v.PathPrefix == "" && len(v.ClientCIDRs) == 0 && len(v.Parameters) == 0 {
			return nil, invalid("scope an exception to a path, client range or parameter")
		}
		for _, id := range v.RuleIDs {
			if id < 910000 || (id >= 949000 && id < 950000) || id >= 959000 {
				return nil, invalid("scoped exceptions apply to request detection IDs 910000–948999 or response detection IDs 950000–958999")
			}
			if id >= 950000 && len(v.Parameters) > 0 {
				return nil, invalid("response exceptions use path/client scopes, not request parameters")
			}
		}
		for _, p := range v.Parameters {
			if !exceptionParameter.MatchString(p) {
				return nil, invalid("parameter names must contain 1–64 letters, digits, dots, underscores or hyphens")
			}
		}
		cidrs, _, e := normalizeNetworkCIDRs(v.ClientCIDRs)
		if e != nil {
			return nil, e
		}
		v.ClientCIDRs = cidrs
	}
	return values, nil
}
func exceptionDirectives(values []signatureException) string {
	var out strings.Builder
	for n, v := range values {
		actions := []string{fmt.Sprintf("id:%d", 110000+n), "phase:1", "pass", "nolog", "t:none"}
		for _, id := range v.RuleIDs {
			if len(v.Parameters) == 0 {
				actions = append(actions, "ctl:ruleRemoveById="+strconv.Itoa(id))
			} else {
				for _, p := range v.Parameters {
					actions = append(actions, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s", id, p))
				}
			}
		}
		fmt.Fprintf(&out, "SecRule TX:AEGIS_EXCEPTION_%d \"@eq 1\" \"%s\"\n", n, strings.Join(actions, ","))
	}
	return out.String()
}
func applySignatureExceptions(tx types.Transaction, values []signatureException, r *http.Request, ip netip.Addr, reliable bool) error {
	if len(values) == 0 {
		return nil
	}
	accessor, ok := tx.(interface {
		Variables() plugintypes.TransactionVariables
	})
	if !ok {
		return fmt.Errorf("transaction variables unavailable")
	}
	for n, v := range values {
		if v.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, v.PathPrefix) {
			continue
		}
		if len(v.ClientCIDRs) > 0 {
			if !reliable {
				continue
			}
			matched := false
			for _, raw := range v.ClientCIDRs {
				prefix, e := netip.ParsePrefix(raw)
				if e == nil && prefix.Contains(ip.Unmap()) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		accessor.Variables().TX().Set(fmt.Sprintf("aegis_exception_%d", n), []string{"1"})
	}
	return nil
}
