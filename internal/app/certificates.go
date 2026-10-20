package app

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func hostname(h string) (string, error) {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if len(h) > 253 || net.ParseIP(h) != nil {
		return "", errors.New("use a DNS hostname")
	}
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return "", errors.New("use a fully qualified DNS hostname")
	}
	for _, p := range parts {
		if !labelPattern.MatchString(p) {
			return "", errors.New("invalid DNS hostname; use ASCII/punycode")
		}
	}
	return h, nil
}
func domains(in []string) ([]string, error) {
	if len(in) == 0 || len(in) > 100 {
		return nil, errors.New("provide 1–100 hostnames")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, h := range in {
		v, e := hostname(h)
		if e != nil {
			return nil, e
		}
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out, nil
}
func validateUpstream(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("upstream must be an http(s) URL without credentials, query or fragment")
	}
	return nil
}
func parseCertificate(chain, key string, now time.Time) (tls.Certificate, *x509.Certificate, error) {
	var empty tls.Certificate
	rest := []byte(chain)
	count := 0
	for len(strings.TrimSpace(string(rest))) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(rest), []byte("-----BEGIN CERTIFICATE-----")) {
			return empty, nil, errors.New("chain must contain only PEM certificates")
		}
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
			return empty, nil, errors.New("chain must contain only PEM certificates")
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return empty, nil, errors.New("invalid X.509 certificate")
		}
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return empty, nil, errors.New("every chain certificate must currently be valid")
		}
		count++
	}
	if count == 0 {
		return empty, nil, errors.New("certificate chain is empty")
	}
	if !strings.HasPrefix(strings.TrimSpace(key), "-----BEGIN ") {
		return empty, nil, errors.New("invalid PEM private key")
	}
	b, rest := pem.Decode([]byte(key))
	if b == nil || len(strings.TrimSpace(string(rest))) != 0 || len(b.Headers) > 0 || (b.Type != "PRIVATE KEY" && b.Type != "RSA PRIVATE KEY" && b.Type != "EC PRIVATE KEY") {
		return empty, nil, errors.New("use one unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC PEM key")
	}
	pair, e := tls.X509KeyPair([]byte(chain), []byte(key))
	if e != nil {
		return empty, nil, errors.New("invalid key or certificate/key mismatch")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return empty, nil, e
	}
	if leaf.IsCA {
		return empty, nil, errors.New("leaf certificate must not be a CA")
	}
	if len(leaf.DNSNames) == 0 {
		return empty, nil, errors.New("certificate requires DNS subject alternative names")
	}
	pair.Leaf = leaf
	// Verify chain ordering/signatures while allowing private PKI trust roots.
	for i := 0; i+1 < len(pair.Certificate); i++ {
		child, _ := x509.ParseCertificate(pair.Certificate[i])
		parent, _ := x509.ParseCertificate(pair.Certificate[i+1])
		if e := child.CheckSignatureFrom(parent); e != nil {
			return empty, nil, errors.New("invalid or unordered certificate chain")
		}
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			ok = ok || u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny
		}
		if !ok {
			return empty, nil, errors.New("certificate does not allow TLS server authentication")
		}
	}
	return pair, leaf, nil
}
func covers(leaf *x509.Certificate, hosts []string) error {
	for _, h := range hosts {
		if e := leaf.VerifyHostname(h); e != nil {
			return fmt.Errorf("certificate does not cover %s", h)
		}
	}
	return nil
}
