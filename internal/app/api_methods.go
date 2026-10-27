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
