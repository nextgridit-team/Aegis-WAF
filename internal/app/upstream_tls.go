package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type upstreamTLSSettings struct {
	ServerName      string `json:"server_name,omitempty"`
	TrustedCertsPEM string `json:"trusted_certificates_pem,omitempty"`
}

func upstreamTLSConfig(s upstreamTLSSettings) (*tls.Config, error) {
	_, ipErr := netip.ParseAddr(s.ServerName)
	if s.ServerName != "" && ipErr != nil && (len(s.ServerName) > 253 || strings.ContainsAny(s.ServerName, " /\\\r\n\t:@?#*%[]") || strings.HasPrefix(s.ServerName, ".")) {
		return nil, invalid("upstream TLS server name must be a hostname or IP without a port")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.ServerName}
	if s.TrustedCertsPEM == "" {
		return cfg, nil
	}
	if len(s.TrustedCertsPEM) > 64<<10 {
		return nil, invalid("trusted upstream certificates must fit 64 KiB")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("system certificate trust store unavailable")
	}
	rest := []byte(s.TrustedCertsPEM)
	count := 0
	for len(strings.TrimSpace(string(rest))) > 0 {
		rest = []byte(strings.TrimSpace(string(rest)))
		if !strings.HasPrefix(string(rest), "-----BEGIN CERTIFICATE-----") {
			return nil, invalid("upstream trust accepts PEM certificates only, never private keys")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, invalid("invalid trusted upstream certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalid("invalid trusted upstream certificate")
		}
		pool.AddCert(cert)
		rest = tail
		count++
		if count > 16 {
			return nil, invalid("at most 16 trusted upstream certificates")
		}
	}
	if count == 0 {
		return nil, invalid("provide at least one trusted upstream certificate")
	}
	cfg.RootCAs = pool
	return cfg, nil
}

type rejectedUpstreamTransport struct{ err error }

func (t rejectedUpstreamTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

type upstreamPeerCertificate struct {
	PEM          string    `json:"pem"`
	SHA256       string    `json:"sha256"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names"`
	IPAddresses  []string  `json:"ip_addresses"`
	ExpectedName string    `json:"expected_name"`
	CanTrust     bool      `json:"can_trust"`
}

func describeUpstreamCertificate(cert *x509.Certificate, expectedName string, mayTrust bool) *upstreamPeerCertificate {
	if cert == nil || len(cert.Raw) > 48<<10 {
		return nil
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if len(encoded) > 64<<10 {
		return nil
	}
	now := time.Now()
	digest := sha256.Sum256(cert.Raw)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return &upstreamPeerCertificate{PEM: string(encoded), SHA256: hex.EncodeToString(digest[:]), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotAfter: cert.NotAfter, DNSNames: append([]string{}, cert.DNSNames...), IPAddresses: ips, ExpectedName: expectedName, CanTrust: mayTrust && cert.VerifyHostname(expectedName) == nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)}
}

type upstreamProbeResult struct {
	Certificate *upstreamPeerCertificate `json:"certificate,omitempty"`
	Reachable   bool                     `json:"reachable"`
	Status      int                      `json:"status,omitempty"`
	Stage       string                   `json:"stage"`
	Message     string                   `json:"message"`
	TLSVerified bool                     `json:"tls_verified"`
	DurationMS  int64                    `json:"duration_ms"`
}

type errUpstreamProbeAddress struct{}

func (errUpstreamProbeAddress) Error() string { return "upstream probe address refused" }

// The well-known NAT64 translation ranges: an IPv6-only deployment's
// resolver can synthesize these for any IPv4 destination, so a translating
// gateway reaches IPv4-only targets through their embedded forms.
var nat64Prefixes = []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48")}

// nat64Embedded extracts the IPv4 destination embedded in a NAT64-wrapped
// address (the final 32 bits).
func nat64Embedded(ip netip.Addr) (netip.Addr, bool) {
	for _, prefix := range nat64Prefixes {
		if prefix.Contains(ip) {
			b := ip.As16()
			return netip.AddrFromSlice(b[12:])
		}
	}
	return netip.Addr{}, false
}

// probeAddressRefused reports destinations no legitimate upstream uses. The
// probe is a diagnostic for configured upstreams, which are routinely private
// backends, so RFC1918 and unique-local addresses stay reachable — matching
// the forwarding path's own posture. Link-local addresses (which include
// every cloud metadata endpoint), multicast and unspecified addresses are
// refused: they are reconnaissance targets, never upstreams. NAT64-wrapped
// forms are refused when the embedded IPv4 destination is itself refused or
// sits in reserved space no upstream uses — a translating NAT64 gateway can
// otherwise reach cloud metadata through its embedded form, the same gap the
// feed guard closes by blocking NAT64 ranges outright.
func probeAddressRefused(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if embedded, ok := nat64Embedded(ip); ok {
		return probeAddressRefused(embedded) ||
			netip.MustParsePrefix("240.0.0.0/4").Contains(embedded) ||
			netip.MustParsePrefix("0.0.0.0/8").Contains(embedded)
	}
	return false
}

// The probe never honors HTTP(S)_PROXY — environment proxies would let an
// attacker-influenced proxy observe probe traffic and change the egress path.
// The dial resolves the destination and refuses link-local, multicast and
// unspecified addresses both as URL literals and after DNS resolution.
func upstreamProbeTransport(cfg *tls.Config) *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			// Wrap the resolver error so the net.DNSError case in the probe's
			// stage classification fires and unresolvable hosts report the
			// dns stage instead of a generic connection failure.
			return nil, fmt.Errorf("upstream host lookup failed: %w", e)
		}
		if len(ips) == 0 {
			return nil, errors.New("upstream host lookup failed")
		}
		for _, ip := range ips {
			if probeAddressRefused(ip) {
				return nil, errUpstreamProbeAddress{}
			}
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		// Sequential per-IP dialing is deliberate: addresses are pre-checked
		// so ANY refused address fails the probe before a connection opens,
		// and a control-hook design would hand refusal to the stdlib's
		// per-attempt path, weakening that guarantee. The cost is 5 s per
		// dead address (dual-stack upstreams with a blackholed first
		// address); restoring parallel dialing needs a pre-filtered fan-out
		// dialer to keep the any-bad-address-refuses semantics.
		var last error
		for _, ip := range ips {
			var conn net.Conn
			conn, last = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if last == nil {
				return conn, nil
			}
		}
		return nil, last
	}, TLSClientConfig: cfg, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true}
}

func probeUpstream(ctx context.Context, raw string, settings upstreamTLSSettings, host string) upstreamProbeResult {
	start := time.Now()
	result := upstreamProbeResult{Stage: "connection"}
	cfg, err := upstreamTLSConfig(settings)
	if err != nil {
		result.Stage = "configuration"
		result.Message = "Upstream TLS settings are invalid."
		return result
	}
	transport := upstreamProbeTransport(cfg)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		result.Stage = "configuration"
		result.Message = "Invalid upstream URL."
		return result
	}
	req.Host = host
	expected := settings.ServerName
	if expected == "" {
		expected = req.URL.Hostname()
	}
	req.Header.Set("User-Agent", "Aegis-Upstream-Check/1.0")
	req.Header.Set("Accept", "*/*")
	response, err := client.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		var unknown x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalidCert x509.CertificateInvalidError
		var dns *net.DNSError
		var timeout net.Error
		var refused errUpstreamProbeAddress
		switch {
		case errors.As(err, &refused):
			result.Stage = "refused"
			result.Message = "Aegis does not probe link-local, multicast or unspecified addresses; this includes cloud metadata endpoints."
		case errors.As(err, &unknown):
			result.Stage = "tls_trust"
			result.Message = "The upstream certificate has an untrusted issuer. Add its private CA certificate or an explicitly trusted server certificate under Upstream TLS."
		case errors.As(err, &hostname):
			result.Stage = "tls_name"
			result.Message = "The certificate does not cover the upstream address. Use a covered hostname or configure its TLS server name."
		case errors.As(err, &invalidCert):
			result.Stage = "tls_certificate"
			result.Message = "The upstream certificate is expired, not yet valid, or otherwise invalid."
		case errors.As(err, &dns):
			result.Stage = "dns"
			result.Message = "Aegis could not resolve the upstream hostname."
		case errors.As(err, &timeout) && timeout.Timeout():
			result.Stage = "timeout"
			result.Message = "The upstream connection or response timed out."
		default:
			result.Message = "Aegis could not connect to the upstream. Check its address, port, network access and service status."
		}
		var verification *tls.CertificateVerificationError
		if errors.As(err, &verification) && len(verification.UnverifiedCertificates) > 0 {
			result.Certificate = describeUpstreamCertificate(verification.UnverifiedCertificates[0], expected, result.Stage == "tls_trust")
		}
		return result
	}
	response.Body.Close()
	result.Reachable = true
	result.Status = response.StatusCode
	result.Stage = "http"
	result.TLSVerified = response.TLS != nil && len(response.TLS.VerifiedChains) > 0
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		result.Certificate = describeUpstreamCertificate(response.TLS.PeerCertificates[0], expected, false)
	}
	result.Message = "Connected successfully."
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		result.Message = "Connected; upstream returned a redirect. The check does not follow redirects."
	}
	if response.StatusCode >= 400 {
		result.Message = "Connected; upstream returned an HTTP error. Check its path, Host header or authentication requirements."
	}
	return result
}
func (a *App) testUpstream(w http.ResponseWriter, r *http.Request, actor identity) error {
	var input struct {
		Upstream string              `json:"upstream"`
		TLS      upstreamTLSSettings `json:"upstream_tls"`
		Host     string              `json:"host_header"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if err := validateUpstream(input.Upstream); err != nil {
		return invalid(err.Error())
	}
	if _, err := upstreamTLSConfig(input.TLS); err != nil {
		return err
	}
	if input.Host != "" {
		u, err := url.Parse("http://" + input.Host)
		if err != nil || u.Host != input.Host || u.Hostname() == "" || u.User != nil || strings.ContainsAny(input.Host, " /\\\r\n\t") {
			return invalid("invalid test Host header")
		}
	}
	select {
	case a.upstreamTests <- struct{}{}:
		defer func() { <-a.upstreamTests }()
	default:
		return apiError{429, "too many upstream tests; try again shortly"}
	}
	result := probeUpstream(r.Context(), input.Upstream, input.TLS, input.Host)
	if _, err := a.db.Exec(r.Context(), "INSERT INTO audit_events(actor,action,resource) VALUES($1,'upstream.tested',$2)", actor.Username, result.Stage); err != nil {
		return err
	}
	respond(w, 200, result)
	return nil
}

// Persisted trust settings are public certificates, never upstream private keys.
func decodeUpstreamTLS(raw []byte) (upstreamTLSSettings, error) {
	var s upstreamTLSSettings
	err := json.Unmarshal(raw, &s)
	return s, err
}

func marshalUpstreamTLS(value upstreamTLSSettings) []byte { raw, _ := json.Marshal(value); return raw }
