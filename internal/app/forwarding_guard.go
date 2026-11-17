package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// errForwardingAddressRefused marks a forwarding destination the dataplane
// refuses before a connection opens.
type errForwardingAddressRefused struct{ class string }

func (e errForwardingAddressRefused) Error() string {
	return "forwarding destination refused: " + e.class
}

// forwardingAddressClass reports why the forwarding path must not dial an
// address, mirroring the upstream probe's guard (probeAddressRefused — both
// share nat64Embedded, and TestForwardingGuardMatchesProbe locks the two
// predicates together). Link-local addresses — which include every cloud
// metadata endpoint — multicast and unspecified destinations are refused;
// private, unique-local and loopback upstreams are the normal WAF topology
// and stay dialable. An empty class means the address is allowed.
func forwardingAddressClass(ip netip.Addr) string {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() {
		return "unspecified"
	}
	if ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return "multicast"
	}
	if ip.IsLinkLocalUnicast() {
		return "link_local"
	}
	if embedded, ok := nat64Embedded(ip); ok {
		if class := forwardingAddressClass(embedded); class != "" {
			return "nat64_" + class
		}
		if netip.MustParsePrefix("240.0.0.0/4").Contains(embedded) || netip.MustParsePrefix("0.0.0.0/8").Contains(embedded) {
			return "nat64_reserved"
		}
	}
	return ""
}

// forwardingFlagEnabled reads a deployment opt-out flag. Both forwarding
// opt-outs default to off: the guarded posture is the secure default, and a
// deployment that legitimately needs the opted-out behavior must say so.
func forwardingFlagEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// forwardingProxySetting returns the environment-proxy hook only when a
// deployment explicitly opts in with FORWARD_USE_ENV_PROXY. By default the
// forwarding path ignores HTTP(S)_PROXY: an attacker-influenced proxy must
// not observe or steer forwarded application traffic.
func forwardingProxySetting() func(*http.Request) (*url.URL, error) {
	if forwardingFlagEnabled("FORWARD_USE_ENV_PROXY") {
		return http.ProxyFromEnvironment
	}
	return nil
}

// forwardingGuardedDialContext builds the forwarding dialer. The guard runs
// in the dialer's Control hook with the resolved (or literal) destination of
// every connection attempt, so refused addresses never open a connection —
// as URL literals and after DNS resolution — while the standard library keeps
// its own address-parallel dialing for the allowed remainder of a dual-stack
// upstream. Deployments that legitimately front link-local upstreams can opt
// back in with FORWARD_ALLOW_LINK_LOCAL.
func forwardingGuardedDialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !forwardingFlagEnabled("FORWARD_ALLOW_LINK_LOCAL") {
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, e := net.SplitHostPort(address)
			if e != nil {
				return e
			}
			ip, e := netip.ParseAddr(host)
			if e != nil {
				return e
			}
			if class := forwardingAddressClass(ip); class != "" {
				return errForwardingAddressRefused{class: class}
			}
			return nil
		}
	}
	return dialer.DialContext
}

// auditForwardingRefusals records the refusal class in the audit log the way
// the upstream probe does ('upstream.tested' with its stage), deduplicated per
// site, host and class so a misconfigured site under load does not flood the
// audit trail — the first refused connection attempt for a key is the event.
func auditForwardingRefusals(dial func(ctx context.Context, network, address string) (net.Conn, error), a *App, site int64) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, e := dial(ctx, network, address)
		if e != nil {
			var refused errForwardingAddressRefused
			if errors.As(e, &refused) {
				host, _, _ := net.SplitHostPort(address)
				a.noteForwardingRefusal(site, host, refused.class)
			}
		}
		return conn, e
	}
}

func (a *App) noteForwardingRefusal(site int64, host, class string) {
	if a == nil || a.db == nil {
		return
	}
	key := strconv.FormatInt(site, 10) + ":" + host + ":" + class
	a.forwardingAuditMu.Lock()
	if a.forwardingAudit == nil {
		a.forwardingAudit = map[string]bool{}
	}
	if a.forwardingAudit[key] {
		a.forwardingAuditMu.Unlock()
		return
	}
	a.forwardingAudit[key] = true
	a.forwardingAuditMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = a.db.Exec(ctx, "INSERT INTO audit_events(actor,action,resource) VALUES('forwarding','forwarding.refused',$1)", key)
}
