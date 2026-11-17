package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strings"
	"time"
)

// releaseSignature carries a keyless cosign bundle inside a schema 3 release
// descriptor. The signature covers the SHA-256 digest of the packaged rule
// archive, so a descriptor cannot be re-pointed at different rules without
// failing here.
type releaseSignature struct {
	Algorithm        string `json:"algorithm"`
	Certificate      string `json:"certificate"`
	Value            string `json:"value"`
	IntegratedTimeMS int64  `json:"integrated_time_ms"`
}

const releaseSignatureAlgorithm = "cosign-keyless-v1"

// Official community releases are produced by the repository release workflow.
// Its GitHub Actions OIDC identity is pinned here: a keyless certificate whose
// URI subject names exactly this workflow and a v-tag. Anything else — another
// workflow, another repository, a branch build — is not an official release.
const officialReleaseSignerPrefix = "https://github.com/nextgridit-team/Aegis-WAF/.github/workflows/release.yml@refs/tags/"

var officialReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Sigstore's public Fulcio certificate authority issues the keyless signing
// certificates. Its root and current intermediate are pinned in the binary so
// verification never fetches trust anchors from the network. Anchors come from
// https://fulcio.sigstore.dev/api/v2/trustBundle (fetched 2026-11-17; root
// valid 2021-10-07 to 2031-10-05). When Fulcio rotates its root, releases stop
// verifying until a new Aegis version pins the new anchor.
const fulcioRootPEM = `-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----`

const fulcioIntermediatePEM = `-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----`

// releaseTrust holds the pinned trust anchors and signer identity for one
// release-verification policy. Intermediates are kept as certificates because
// bundles carry only the signing leaf; the pinned chain completes it.
type releaseTrust struct {
	roots         *x509.CertPool
	intermediates []*x509.Certificate
	prefix        string
}

func mustReleaseTrust(rootPEM, intermediatePEM, prefix string) releaseTrust {
	roots := x509.NewCertPool()
	if !appendPEM(roots, rootPEM) {
		panic("release trust root is not valid PEM")
	}
	first, chain, ok := parseCertificateChain(intermediatePEM)
	if !ok {
		panic("release trust intermediate is not valid PEM")
	}
	return releaseTrust{roots: roots, intermediates: append([]*x509.Certificate{first}, chain...), prefix: prefix}
}

// appendPEM adds every certificate block in a PEM document to the pool and
// reports whether at least one block was added.
func appendPEM(pool *x509.CertPool, document string) bool {
	found := false
	rest := []byte(document)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return found
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, e := x509.ParseCertificate(block.Bytes); e != nil {
			return false
		}
		pool.AppendCertsFromPEM([]byte(string(pem.EncodeToMemory(block))))
		found = true
	}
}

var officialReleaseTrust = mustReleaseTrust(fulcioRootPEM, fulcioIntermediatePEM, officialReleaseSignerPrefix)

// releaseSignerTrust selects the active trust anchors. It is a variable so the
// test suite can substitute a local certificate authority; package tests run
// sequentially, and production never reassigns it.
var releaseSignerTrust = officialReleaseTrust

// verifyReleaseSignature authenticates a schema 3 package. Official releases
// must carry a valid signature from the pinned workflow identity; a missing or
// invalid signature is rejected. Custom sources may publish unsigned releases —
// those are accepted as explicitly untrusted — but a signature they do present
// must still be a well-formed keyless bundle that chains to the pinned Fulcio
// authority, so tampering is never silently ignored.
func verifyReleaseSignature(archive []byte, sig *releaseSignature, official bool) error {
	return releaseSignerTrust.verify(archive, sig, official)
}

func (t releaseTrust) verify(archive []byte, sig *releaseSignature, official bool) error {
	if sig == nil {
		if official {
			return invalid("official catalogue releases must carry a release signature; sync refused for this unsigned descriptor")
		}
		return nil
	}
	if sig.Algorithm != releaseSignatureAlgorithm {
		return invalid("release signature uses an unsupported algorithm")
	}
	if len(sig.Certificate) > 16384 || len(sig.Value) > 8192 || sig.IntegratedTimeMS <= 0 {
		return invalid("release signature is malformed")
	}
	leaf, provided, ok := parseCertificateChain(sig.Certificate)
	if !ok {
		return invalid("release signature certificate is not a valid certificate chain")
	}
	// Keyless certificates are minutes old; the chain is checked at the
	// signature's log-integrated time instead of the current wall clock.
	// Bundles carry only the signing leaf, so the pinned intermediate chain
	// completes the path to the pinned root.
	chain := x509.NewCertPool()
	for _, cert := range provided {
		chain.AddCert(cert)
	}
	for _, cert := range t.intermediates {
		chain.AddCert(cert)
	}
	if _, e := leaf.Verify(x509.VerifyOptions{Roots: t.roots, Intermediates: chain, CurrentTime: time.UnixMilli(sig.IntegratedTimeMS), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); e != nil {
		return invalid("release signature certificate is not issued by a trusted release authority")
	}
	if len(leaf.URIs) != 1 || len(leaf.URIs[0].String()) > 2048 {
		return invalid("release signer identity is missing or ambiguous")
	}
	uri := leaf.URIs[0].String()
	if official && (!strings.HasPrefix(uri, t.prefix) || !officialReleaseTag.MatchString(strings.TrimPrefix(uri, t.prefix))) {
		return invalid("official catalogue signature was not produced by the Aegis release workflow")
	}
	value, e := base64.StdEncoding.DecodeString(sig.Value)
	if e != nil || len(value) == 0 {
		return invalid("release signature value is not valid base64")
	}
	// The signature covers the SHA-256 digest of the packaged rules, matching
	// how cosign signs blobs; raw-message ECDSA would truncate a full archive
	// to the curve size and cover only its first bytes.
	digest := sha256.Sum256(archive)
	switch key := leaf.PublicKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest[:], value) {
			return invalid("release signature does not match the packaged rules")
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], value) {
			return invalid("release signature does not match the packaged rules")
		}
	default:
		return invalid("release signature uses an unsupported key type")
	}
	return nil
}

// parseCertificateChain splits a PEM document into its leaf certificate and the
// remaining chain. The leaf is the first certificate in the document.
func parseCertificateChain(document string) (*x509.Certificate, []*x509.Certificate, bool) {
	var leaf *x509.Certificate
	chain := []*x509.Certificate{}
	rest := []byte(document)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, false
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, nil, false
		}
		if leaf == nil {
			leaf = cert
		} else {
			chain = append(chain, cert)
		}
	}
	if leaf == nil {
		return nil, nil, false
	}
	return leaf, chain, true
}
