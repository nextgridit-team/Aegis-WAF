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
	PEM      string    `json:"pem"`
	SHA256   string    `json:"sha256"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	CanTrust bool      `json:"can_trust"`
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
	return &upstreamPeerCertificate{PEM: string(encoded), SHA256: hex.EncodeToString(digest[:]), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotAfter: cert.NotAfter, CanTrust: mayTrust && cert.VerifyHostname(expectedName) == nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)}
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

func probeUpstream(ctx context.Context, raw string, settings upstreamTLSSettings, host string) upstreamProbeResult {
	start := time.Now()
	result := upstreamProbeResult{Stage: "connection"}
	cfg, err := upstreamTLSConfig(settings)
	if err != nil {
		result.Stage = "configuration"
		result.Message = "Upstream TLS settings are invalid."
		return result
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: cfg, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		result.Stage = "configuration"
		result.Message = "Invalid upstream URL."
		return result
	}
	req.Host = host
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
		switch {
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
		expected := settings.ServerName
		if expected == "" {
			parsed, _ := url.Parse(raw)
			expected = parsed.Hostname()
		}
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
		result.Certificate = describeUpstreamCertificate(response.TLS.PeerCertificates[0], "", false)
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
