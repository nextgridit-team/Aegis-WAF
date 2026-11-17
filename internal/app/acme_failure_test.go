package app

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Transport-level causes (url.Error) must survive acmeFailure so an operator
// with a redirecting custom directory can tell the refusal apart from an
// outage instead of getting generic connectivity advice.
func TestACMEFailureSurfacesTransportCauses(t *testing.T) {
	redirect := &url.Error{Op: "Get", URL: "https://ca.test/directory", Err: errACMERedirect}
	msg := acmeFailure("directory discovery", redirect)
	if !strings.Contains(msg, "acme redirects are not accepted") {
		t.Fatalf("redirect refusal flattened away: %s", msg)
	}
	if !strings.Contains(msg, "refuses outbound redirects") {
		t.Fatalf("redirect refusal tail missing: %s", msg)
	}
	if !strings.Contains(msg, "directory discovery") {
		t.Fatalf("stage lost: %s", msg)
	}
	// Non-transport failures keep the established guidance.
	generic := acmeFailure("validation", errors.New("connection reset"))
	if !strings.Contains(generic, "check CA connectivity") {
		t.Fatalf("generic guidance lost: %s", generic)
	}
	// A timeout wrapped in a transport error still reads as a timeout.
	if msg := acmeFailure("authorization", &url.Error{Op: "Post", URL: "https://ca.test/order", Err: context.DeadlineExceeded}); !strings.Contains(msg, "timed out") {
		t.Fatalf("timeout wording lost: %s", msg)
	}
	// A genuine outage is a transport error but not a redirect refusal: the
	// redirect guidance must not claim the gateway refused a redirect the
	// CA never issued.
	outage := &url.Error{Op: "Get", URL: "https://ca.test/directory", Err: errors.New("dial tcp: connection refused")}
	msg = acmeFailure("directory discovery", outage)
	if strings.Contains(msg, "refuses outbound redirects") {
		t.Fatalf("outage mislabeled as a redirect refusal: %s", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Fatalf("outage cause lost: %s", msg)
	}
}
