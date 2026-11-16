package app

import (
	"context"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"strings"
)

type endpointProfileKey struct{}

func applyManagedMethods(tx types.Transaction, requestProfile string, configured []string, requestMethod string) error {
	methods := configured
	if len(methods) == 0 {
		if requestProfile != "api" && requestProfile != "streaming" {
			return nil
		}
		methods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	accessor, ok := tx.(interface {
		Variables() plugintypes.TransactionVariables
	})
	if !ok {
		return invalid("signature transaction methods unavailable")
	}
	// @within is substring-based in CRS911100. Preserve exact token matching.
	allowed := ""
	for _, method := range methods {
		if method == requestMethod {
			allowed = strings.Join(methods, " ")
			break
		}
	}
	accessor.Variables().TX().Set("allowed_methods", []string{allowed})
	return nil
}
func withEndpointProfile(ctx context.Context, profile string) context.Context {
	return context.WithValue(ctx, endpointProfileKey{}, profile)
}

// methodDisallowed reports whether the policy's explicitly configured method
// allowlist rejects this request. Enforcement is native and policy-owned: it
// no longer depends on CRS rule 911100 being present in the selected
// signature set, so excluding the rule — or running the site without managed
// signatures — cannot silently disarm the safeguard. Profile-derived defaults
// for api/streaming remain managed-signature behavior and are not enforced
// here.
func methodDisallowed(b *compiledPolicyBinding, requestMethod string) bool {
	if b == nil || len(b.ManagedOptions.AllowedMethods) == 0 {
		return false
	}
	for _, method := range b.ManagedOptions.AllowedMethods {
		if method == requestMethod {
			return false
		}
	}
	return true
}
