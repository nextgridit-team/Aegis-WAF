package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const testOfficialSignerURI = "https://github.com/nextgridit-team/Aegis-WAF/.github/workflows/release.yml@refs/tags/v9.9.9"
const testForeignSignerURI = "https://github.com/example/other/.github/workflows/sign.yml@refs/tags/v1.0.0"

// testReleaseAuthority issues keyless-style signing certificates for tests,
// mirroring how the release workflow signs the official descriptor with a
// short-lived certificate issued through an intermediate by a root authority.
type testReleaseAuthority struct {
	key             *ecdsa.PrivateKey
	rootPEM         string
	intermediate    *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
}

func newTestReleaseAuthority(t *testing.T) testReleaseAuthority {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"Aegis Tests"}}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	rootDER, e := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	intermediateKey, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{Organization: []string{"Aegis Tests"}}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true}
	intermediateDER, e := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	intermediate, e := x509.ParseCertificate(intermediateDER)
	if e != nil {
		t.Fatal(e)
	}
	return testReleaseAuthority{key: key, rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})), intermediate: intermediate, intermediateKey: intermediateKey}
}

// sign produces a release signature over the package bytes for one signer URI,
// valid around the integrated time the verifier will check.
func (a testReleaseAuthority) sign(t *testing.T, packageBytes []byte, signerURI string, at time.Time) *releaseSignature {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	uri, e := url.Parse(signerURI)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{"Aegis Tests"}}, NotBefore: at.Add(-5 * time.Minute), NotAfter: at.Add(5 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, URIs: []*url.URL{uri}}
	der, e := x509.CreateCertificate(rand.Reader, template, a.intermediate, key.Public(), a.intermediateKey)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(packageBytes)
	value, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	return &releaseSignature{Algorithm: releaseSignatureAlgorithm, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Value: base64.StdEncoding.EncodeToString(value), IntegratedTimeMS: at.UnixMilli()}
}

// useTestReleaseTrust installs a local authority as the release trust anchor
// for the duration of one test. Like production, the descriptor carries only
// the signing leaf and the pinned intermediate completes the chain.
func useTestReleaseTrust(t *testing.T, authority testReleaseAuthority) {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(authority.rootPEM)) {
		t.Fatal("test authority root could not be parsed")
	}
	previous := releaseSignerTrust
	releaseSignerTrust = releaseTrust{roots: roots, intermediates: []*x509.Certificate{authority.intermediate}, prefix: officialReleaseSignerPrefix}
	t.Cleanup(func() { releaseSignerTrust = previous })
}

// testDescriptor renders a schema 3 release descriptor with an optional
// signature, keeping the shape explicit in one place.
func testDescriptor(t *testing.T, packagePath, digest string, count int, size int64, signature *releaseSignature) []byte {
	t.Helper()
	document := map[string]any{
		"schema_version": 3,
		"name":           "Aegis community mitigation rules",
		"revision":       9,
		"package":        map[string]any{"path": packagePath, "sha256": digest, "rule_count": count, "size_bytes": size},
	}
	if signature != nil {
		document["signature"] = signature
	}
	raw, e := json.Marshal(document)
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) > 4096 {
		t.Fatal("test descriptor exceeds the 4 KiB schema 3 limit", len(raw))
	}
	return raw
}

// signedPackageFixture loads the real community package and returns its bytes,
// its rule count and a descriptor signature covering those exact bytes.
func signedPackageFixture(t *testing.T, authority testReleaseAuthority, signerURI string) ([]byte, int, *releaseSignature) {
	t.Helper()
	raw, e := os.ReadFile("../../rules/community/community-rules.zip")
	if e != nil {
		t.Fatal(e)
	}
	manifestRaw, e := os.ReadFile("../../rules/community/release.json")
	if e != nil {
		t.Fatal(e)
	}
	var manifest struct {
		Package struct {
			RuleCount int `json:"rule_count"`
		} `json:"package"`
	}
	if e = json.Unmarshal(manifestRaw, &manifest); e != nil {
		t.Fatal(e)
	}
	return raw, manifest.Package.RuleCount, authority.sign(t, raw, signerURI, time.Now())
}

func digestOf(t *testing.T, raw []byte) string {
	t.Helper()
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func catalogueTestApp(t *testing.T, descriptor, archive []byte) *App {
	t.Helper()
	return &App{feedHTTP: dnsTestTransport(func(r *http.Request) (*http.Response, error) {
		body := archive
		if strings.HasSuffix(r.URL.Path, "release.json") {
			body = descriptor
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
}

func TestOfficialCatalogueRejectsUnsignedRelease(t *testing.T) {
	archive, ruleCount, _ := signedPackageFixture(t, newTestReleaseAuthority(t), testOfficialSignerURI)
	descriptor := testDescriptor(t, "community-rules.zip", digestOf(t, archive), ruleCount, int64(len(archive)), nil)
	_, _, _, _, e := catalogueTestApp(t, descriptor, archive).fetchCatalogue(context.Background(), communityFeedURL, "")
	if e == nil {
		t.Fatal("official catalogue accepted an unsigned release")
	}
	if !strings.Contains(e.Error(), "signature") {
		t.Fatal("official catalogue rejection must name the signature requirement", e)
	}
}

func TestOfficialCatalogueVerifiesSignedRelease(t *testing.T) {
	authority := newTestReleaseAuthority(t)
	useTestReleaseTrust(t, authority)
	archive, ruleCount, signature := signedPackageFixture(t, authority, testOfficialSignerURI)
	descriptor := testDescriptor(t, "community-rules.zip", digestOf(t, archive), ruleCount, int64(len(archive)), signature)
	manifest, items, _, _, e := catalogueTestApp(t, descriptor, archive).fetchCatalogue(context.Background(), communityFeedURL, "")
	if e != nil {
		t.Fatal("signed official catalogue rejected", e)
	}
	if manifest.Package == nil || manifest.Package.RuleCount != len(items) || len(items) == 0 {
		t.Fatal("signed official catalogue returned no rules", len(items))
	}
}

func TestOfficialCatalogueRejectsTamperedPackage(t *testing.T) {
	authority := newTestReleaseAuthority(t)
	useTestReleaseTrust(t, authority)
	archive, ruleCount, signature := signedPackageFixture(t, authority, testOfficialSignerURI)
	tampered := append([]byte{}, archive...)
	tampered[len(tampered)/2] ^= 1
	descriptor := testDescriptor(t, "community-rules.zip", digestOf(t, tampered), ruleCount, int64(len(tampered)), signature)
	_, _, _, _, e := catalogueTestApp(t, descriptor, tampered).fetchCatalogue(context.Background(), communityFeedURL, "")
	if e == nil || !strings.Contains(e.Error(), "signature") {
		t.Fatal("tampered official package accepted", e)
	}
}

func TestOfficialCatalogueRejectsForeignSigner(t *testing.T) {
	authority := newTestReleaseAuthority(t)
	useTestReleaseTrust(t, authority)
	archive, ruleCount, signature := signedPackageFixture(t, authority, testForeignSignerURI)
	descriptor := testDescriptor(t, "community-rules.zip", digestOf(t, archive), ruleCount, int64(len(archive)), signature)
	_, _, _, _, e := catalogueTestApp(t, descriptor, archive).fetchCatalogue(context.Background(), communityFeedURL, "")
	if e == nil || !strings.Contains(e.Error(), "release workflow") {
		t.Fatal("foreign signer accepted as the official release workflow", e)
	}
}

func TestCustomCatalogueAcceptsForeignSignedRelease(t *testing.T) {
	authority := newTestReleaseAuthority(t)
	useTestReleaseTrust(t, authority)
	archive, ruleCount, signature := signedPackageFixture(t, authority, testForeignSignerURI)
	descriptor := testDescriptor(t, "community-rules.zip", digestOf(t, archive), ruleCount, int64(len(archive)), signature)
	_, items, _, _, e := catalogueTestApp(t, descriptor, archive).fetchCatalogue(context.Background(), "https://example.com/release.json", "")
	if e != nil {
		t.Fatal("custom catalogue rejected a coherently signed foreign release", e)
	}
	if len(items) == 0 {
		t.Fatal("custom catalogue returned no rules")
	}
}

func TestCustomCatalogueAcceptsUnsignedRelease(t *testing.T) {
	archive, ruleCount, _ := signedPackageFixture(t, newTestReleaseAuthority(t), testOfficialSignerURI)
	descriptor := testDescriptor(t, "community-rules.zip", digestOf(t, archive), ruleCount, int64(len(archive)), nil)
	_, items, _, _, e := catalogueTestApp(t, descriptor, archive).fetchCatalogue(context.Background(), "https://example.com/release.json", "")
	if e != nil {
		t.Fatal("unsigned custom catalogue rejected", e)
	}
	if len(items) == 0 {
		t.Fatal("custom catalogue returned no rules")
	}
}

func TestReleaseSignatureVerification(t *testing.T) {
	if len(officialReleaseTrust.intermediates) == 0 || officialReleaseTrust.roots == nil {
		t.Fatal("production release trust must pin a root and at least one intermediate")
	}
	authority := newTestReleaseAuthority(t)
	useTestReleaseTrust(t, authority)
	archive, _, signature := signedPackageFixture(t, authority, testOfficialSignerURI)
	if e := verifyReleaseSignature(archive, signature, true); e != nil {
		t.Fatal("valid official signature rejected", e)
	}
	if e := verifyReleaseSignature(archive, nil, false); e != nil {
		t.Fatal("unsigned custom release rejected", e)
	}
	if e := verifyReleaseSignature(archive, nil, true); e == nil {
		t.Fatal("unsigned official release accepted")
	}
	tampered := append([]byte{}, archive...)
	tampered[10] ^= 1
	if e := verifyReleaseSignature(tampered, signature, true); e == nil {
		t.Fatal("signature over other bytes accepted")
	}
	foreign := authority.sign(t, archive, testForeignSignerURI, time.Now())
	if e := verifyReleaseSignature(archive, foreign, true); e == nil {
		t.Fatal("foreign signer accepted as official")
	}
	untrusted := newTestReleaseAuthority(t).sign(t, archive, testOfficialSignerURI, time.Now())
	if e := verifyReleaseSignature(archive, untrusted, false); e == nil {
		t.Fatal("signature from an untrusted authority accepted")
	}
	// The certificate was valid when issued, but the claimed integrated time
	// now falls outside its validity window, so the chain check must reject it.
	expired := authority.sign(t, archive, testOfficialSignerURI, time.Now())
	expired.IntegratedTimeMS += int64(time.Minute/time.Millisecond) * 10
	if e := verifyReleaseSignature(archive, expired, true); e == nil {
		t.Fatal("signature with a certificate invalid at its integrated time accepted")
	}
	broken := *signature
	broken.Value = base64.StdEncoding.EncodeToString([]byte("not a signature"))
	if e := verifyReleaseSignature(archive, &broken, true); e == nil {
		t.Fatal("garbage signature value accepted")
	}
	broken = *signature
	broken.Algorithm = "minisign"
	if e := verifyReleaseSignature(archive, &broken, true); e == nil {
		t.Fatal("unknown signature algorithm accepted")
	}
	broken = *signature
	broken.Certificate = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
	if e := verifyReleaseSignature(archive, &broken, true); e == nil {
		t.Fatal("garbage certificate accepted")
	}
	broken = *signature
	broken.IntegratedTimeMS = 0
	if e := verifyReleaseSignature(archive, &broken, true); e == nil {
		t.Fatal("missing integrated time accepted")
	}
}

// TestReleaseSignatureFromReleaseAssets verifies a release the workflow just
// built, using the production trust anchors. The release job sets
// AEGIS_SIGNED_RELEASE_FILE and AEGIS_SIGNED_PACKAGE_FILE to the signed
// descriptor and rule archive before running this test.
func TestReleaseSignatureFromReleaseAssets(t *testing.T) {
	descriptorPath := os.Getenv("AEGIS_SIGNED_RELEASE_FILE")
	packagePath := os.Getenv("AEGIS_SIGNED_PACKAGE_FILE")
	if descriptorPath == "" || packagePath == "" {
		t.Skip("set AEGIS_SIGNED_RELEASE_FILE and AEGIS_SIGNED_PACKAGE_FILE to verify a release")
	}
	descriptor, e := os.ReadFile(descriptorPath)
	if e != nil {
		t.Fatal(e)
	}
	archive, e := os.ReadFile(packagePath)
	if e != nil {
		t.Fatal(e)
	}
	base, e := url.Parse(communityFeedURL)
	if e != nil {
		t.Fatal(e)
	}
	manifest, e := parseRuleManifest(descriptor, base)
	if e != nil {
		t.Fatal(e)
	}
	if manifest.Package == nil || manifest.Signature == nil {
		t.Fatal("release descriptor is not a signed schema 3 release")
	}
	if digestOf(t, archive) != manifest.Package.SHA256 {
		t.Fatal("packaged rules do not match the descriptor checksum")
	}
	if _, e := parseCataloguePackage(context.Background(), manifest, archive); e != nil {
		t.Fatal(e)
	}
	if e := verifyReleaseSignature(archive, manifest.Signature, true); e != nil {
		t.Fatal(e)
	}
}
