package app

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/http/httpguts"
)

type HeaderSettings struct {
	ForwardedHeaders string            `json:"forwarded_headers"`
	RequestSet       map[string]string `json:"request_set"`
	RequestRemove    []string          `json:"request_remove"`
	ResponseSet      map[string]string `json:"response_set"`
	ResponseRemove   []string          `json:"response_remove"`
}

var identityHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-Ip", "Cf-Connecting-Ip", "True-Client-Ip", "X-Client-Ip"}

func managedHeader(name string) bool {
	for _, h := range identityHeaders {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}
func reservedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "content-length", "trailer", "te", "upgrade", "proxy-authenticate", "proxy-authorization":
		return true
	}
	return managedHeader(name) || strings.HasPrefix(strings.ToLower(name), "sec-websocket-")
}
func normalizeHeaders(s HeaderSettings) (HeaderSettings, error) {
	out := HeaderSettings{ForwardedHeaders: s.ForwardedHeaders, RequestSet: map[string]string{}, ResponseSet: map[string]string{}, RequestRemove: []string{}, ResponseRemove: []string{}}
	if out.ForwardedHeaders == "" {
		out.ForwardedHeaders = "standard"
	}
	if out.ForwardedHeaders != "standard" && out.ForwardedHeaders != "off" {
		return out, invalid("forwarded_headers must be standard or off")
	}
	for _, side := range []struct {
		set       map[string]string
		remove    []string
		setOut    map[string]string
		removeOut *[]string
	}{{s.RequestSet, s.RequestRemove, out.RequestSet, &out.RequestRemove}, {s.ResponseSet, s.ResponseRemove, out.ResponseSet, &out.ResponseRemove}} {
		if len(side.set)+len(side.remove) > 32 {
			return out, invalid("at most 32 header operations per direction")
		}
		seen := map[string]bool{}
		size := 0
		name := func(raw string) (string, error) {
			if raw != strings.TrimSpace(raw) || len(raw) > 128 || !httpguts.ValidHeaderFieldName(raw) {
				return "", invalid("invalid header name")
			}
			n := http.CanonicalHeaderKey(raw)
			if reservedHeader(n) {
				return "", invalid("forwarding and protocol headers are gateway-managed; use forwarding and Host settings")
			}
			if seen[n] {
				return "", invalid("duplicate or conflicting header operations")
			}
			seen[n] = true
			return n, nil
		}
		for raw, value := range side.set {
			n, e := name(raw)
			if e != nil {
				return out, e
			}
			if sensitiveKey(n) {
				return out, invalid("static credential and cookie headers are not supported")
			}
			if len(value) > 4096 || !httpguts.ValidHeaderFieldValue(value) {
				return out, invalid("header values must be valid HTTP values of at most 4096 bytes")
			}
			size += len(n) + len(value)
			side.setOut[n] = value
		}
		for _, raw := range side.remove {
			n, e := name(raw)
			if e != nil {
				return out, e
			}
			*side.removeOut = append(*side.removeOut, n)
		}
		if size > 32768 {
			return out, invalid("custom headers exceed 32 KiB per direction")
		}
	}
	return out, nil
}
func (s *HeaderSettings) applyResponse(h http.Header) {
	if s == nil {
		return
	}
	for _, name := range s.ResponseRemove {
		h.Del(name)
	}
	for name, value := range s.ResponseSet {
		h.Set(name, value)
	}
}

type proxyIdentityKey struct{}
type proxyIdentity struct {
	IP    netip.Addr
	Proto string
}

func forwardingIdentity(r *http.Request) proxyIdentity {
	if identity, ok := r.Context().Value(proxyIdentityKey{}).(proxyIdentity); ok {
		return identity
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip, _ := netip.ParseAddr(host)
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	return proxyIdentity{ip.Unmap(), proto}
}
func rewriteProxyHeaders(pr *httputil.ProxyRequest, s HeaderSettings) {
	for _, name := range identityHeaders {
		pr.Out.Header.Del(name)
	}
	if s.ForwardedHeaders != "off" {
		identity := forwardingIdentity(pr.In)
		pr.SetXForwarded()
		if identity.IP.IsValid() {
			pr.Out.Header.Set("X-Forwarded-For", identity.IP.String())
			pr.Out.Header.Set("X-Real-IP", identity.IP.String())
		} else {
			pr.Out.Header.Del("X-Forwarded-For")
		}
		pr.Out.Header.Set("X-Forwarded-Proto", identity.Proto)
		_, port, e := net.SplitHostPort(pr.In.Host)
		if e != nil {
			port = "80"
			if identity.Proto == "https" {
				port = "443"
			}
		}
		pr.Out.Header.Set("X-Forwarded-Port", port)
	}
	for _, name := range s.RequestRemove {
		pr.Out.Header.Del(name)
	}
	for name, value := range s.RequestSet {
		pr.Out.Header.Set(name, value)
	}
}
func storeHeaderSettings(ctx context.Context, tx pgx.Tx, site int64, raw []byte) error {
	_, e := tx.Exec(ctx, "INSERT INTO proxy_headers(site_id,settings) VALUES($1,$2) ON CONFLICT(site_id) DO UPDATE SET settings=excluded.settings", site, raw)
	return e
}
