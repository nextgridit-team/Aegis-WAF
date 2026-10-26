package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ruleManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Name          string            `json:"name"`
	Revision      int               `json:"revision"`
	Rules         []manifestEntry   `json:"rules"`
	Package       *cataloguePackage `json:"package,omitempty"`
}
type manifestEntry struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type catalogueMetadata struct {
	Revision          int      `json:"revision"`
	Pack              string   `json:"pack"`
	Technology        []string `json:"technology"`
	CVEs              []string `json:"cves"`
	Description       string   `json:"description"`
	AffectedVersions  string   `json:"affected_versions"`
	Coverage          string   `json:"coverage"`
	Limitations       string   `json:"limitations"`
	FalsePositiveRisk string   `json:"false_positive_risk"`
	References        []string `json:"references"`
}
type feedRuleFile struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	catalogueMetadata
	Rule  RuleSpec            `json:"rule"`
	Tests []catalogueRuleTest `json:"tests"`
}
type catalogueRuleTest struct {
	Name          string            `json:"name"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	ExpectedMatch bool              `json:"expected_match"`
}
type catalogueCandidate struct {
	File   feedRuleFile
	Digest string
}

var cveName = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
var fileDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func strictFeedJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return invalid("invalid or unsupported feed JSON")
	}
	return nil
}
func resolveRuleFile(base *url.URL, path string) (string, error) {
	return resolveFeedFile(base, path, ".json")
}
func resolveFeedFile(base *url.URL, path, extension string) (string, error) {
	if len(path) == 0 || len(path) > 240 || !strings.HasSuffix(path, extension) {
		return "", invalid("feed path must be a relative filename with the expected extension")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || !namedKey.MatchString(part) {
			return "", invalid("rule paths must stay beneath the manifest directory")
		}
	}
	// namedKey excludes URL escapes, query strings, credentials and alternate origins.
	relative, e := url.Parse(path)
	if e != nil || relative.IsAbs() || relative.Host != "" {
		return "", invalid("invalid relative rule path")
	}
	target := base.ResolveReference(relative)
	if _, e = feedURL(target.String()); e != nil {
		return "", e
	}
	return target.String(), nil
}
func parseRuleManifest(raw []byte, base *url.URL) (ruleManifest, error) {
	var m ruleManifest
	if len(raw) > 1<<20 {
		return m, invalid("manifest exceeds 1 MiB")
	}
	if e := strictFeedJSON(raw, &m); e != nil {
		return m, e
	}
	if strings.TrimSpace(m.Name) == "" || len(m.Name) > 120 || m.Revision < 1 || m.Revision > 1000000 {
		return m, invalid("release requires name and positive revision")
	}
	if m.SchemaVersion == 3 {
		pkg := m.Package
		if len(raw) > 4096 || m.Rules != nil || pkg == nil || !fileDigest.MatchString(pkg.SHA256) || pkg.RuleCount < 0 || pkg.RuleCount > maxPackedCatalogueRules || pkg.SizeBytes < 22 || pkg.SizeBytes > maxCataloguePackageBytes {
			return m, invalid("version 3 requires a small release descriptor and bounded ZIP package")
		}
		if _, e := resolveFeedFile(base, pkg.Path, ".zip"); e != nil {
			return m, e
		}
		return m, nil
	}
	if m.SchemaVersion != 2 || m.Package != nil || m.Rules == nil || len(m.Rules) > 100 {
		return m, invalid("use a version 3 release or a version 2 manifest with at most 100 entries")
	}
	seen, paths := map[string]bool{}, map[string]bool{}
	for _, entry := range m.Rules {
		if len(entry.ID) < 1 || len(entry.ID) > 64 || !namedKey.MatchString(entry.ID) || seen[entry.ID] || paths[entry.Path] || !fileDigest.MatchString(entry.SHA256) {
			return m, invalid("manifest IDs/paths must be unique and checksums must be lowercase SHA256")
		}
		if _, e := resolveRuleFile(base, entry.Path); e != nil {
			return m, e
		}
		seen[entry.ID] = true
		paths[entry.Path] = true
	}
	return m, nil
}
func parseCatalogueRule(raw []byte, entry manifestEntry) (feedRuleFile, error) {
	var f feedRuleFile
	if len(raw) > 64<<10 {
		return f, invalid("rule file exceeds 64 KiB")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != entry.SHA256 {
		return f, invalid("rule file checksum mismatch")
	}
	if e := strictFeedJSON(raw, &f); e != nil {
		return f, e
	}
	if f.SchemaVersion != 1 || f.ID != entry.ID || f.Revision < 1 || f.Revision > 1000000 || strings.TrimSpace(f.Pack) == "" || len(f.Pack) > 120 || len(f.Technology) == 0 || len(f.Technology) > 8 || len(f.CVEs) > 16 || len(f.References) == 0 || len(f.References) > 8 {
		return f, invalid("rule requires matching ID, revision, pack, technology and references")
	}
	for _, value := range []string{f.Description, f.AffectedVersions, f.Coverage, f.Limitations, f.FalsePositiveRisk} {
		if strings.TrimSpace(value) == "" || len(value) > 2000 {
			return f, invalid("rule applicability and mitigation limits are required (up to 2000 bytes each)")
		}
	}
	for _, value := range f.Technology {
		if len(value) < 1 || len(value) > 64 {
			return f, invalid("invalid technology label")
		}
	}
	for _, cve := range f.CVEs {
		if !cveName.MatchString(cve) {
			return f, invalid("invalid CVE identifier")
		}
	}
	for _, reference := range f.References {
		u, e := url.Parse(reference)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(reference) > 2048 {
			return f, invalid("advisory references must be HTTPS URLs")
		}
	}
	f.Rule.Scope.SiteID = 1
	f.Rule.Action = "observe"
	f.Rule.EvidenceIDs = nil
	compiled, e := compileRule(f.Rule)
	if e != nil {
		return f, invalid("invalid catalogue rule: " + e.Error())
	}
	if len(f.Tests) < 2 || len(f.Tests) > 16 {
		return f, invalid("provide 2–16 rule regression cases")
	}
	positive, negative := false, false
	for _, test := range f.Tests {
		if len(test.Name) < 1 || len(test.Name) > 120 || !methodName.MatchString(test.Method) || !strings.HasPrefix(test.Path, "/") || strings.HasPrefix(test.Path, "//") || len(test.Path) > 1024 || len(test.Body) > 4096 || len(test.Headers) > 16 {
			return f, invalid("invalid or oversized rule regression case")
		}
		request, e := http.NewRequestWithContext(context.Background(), test.Method, "https://feed-test.invalid"+test.Path, strings.NewReader(test.Body))
		if e != nil {
			return f, invalid("invalid regression request")
		}
		for key, value := range test.Headers {
			if len(key) > 64 || len(value) > 4096 || strings.ContainsAny(key+value, "\r\n") {
				return f, invalid("invalid regression header")
			}
			request.Header.Set(key, value)
		}
		facts := newRequestFacts(request)
		result := compiled.evaluate(facts.get)
		if result == "unknown" || (result == "matched") != test.ExpectedMatch {
			return f, invalid("rule regression case failed: " + test.Name)
		}
		if test.ExpectedMatch {
			positive = true
		} else {
			negative = true
		}
	}
	if !positive || !negative {
		return f, invalid("include matching and nonmatching regression cases")
	}
	return f, nil
}

func (a *App) fetchFeedBytes(ctx context.Context, rawURL, etag string, limit int64) ([]byte, string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	parsed, e := feedURL(rawURL)
	if e != nil {
		return nil, "", false, e
	}
	request, e := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if e != nil {
		return nil, "", false, e
	}
	request.Header.Set("Accept", "application/json")
	if parsed.Hostname() == "api.github.com" && strings.HasPrefix(parsed.Path, "/repos/") && strings.Contains(parsed.Path, "/contents/") {
		request.Header.Set("Accept", "application/vnd.github.raw+json")
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	transport := a.feedHTTP
	if transport == nil {
		transport = feedTransport()
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		return nil, "", false, apiError{502, "feed download failed; check DNS, HTTPS and certificate trust"}
	}
	defer response.Body.Close()
	if response.StatusCode == 304 && etag != "" {
		return nil, etag, true, nil
	}
	if response.StatusCode != 200 {
		return nil, "", false, apiError{502, "feed file returned an unsuccessful HTTP status"}
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, "", false, invalid("feed file exceeds its size limit or could not be read")
	}
	tag := response.Header.Get("ETag")
	if len(tag) > 256 {
		tag = ""
	}
	return raw, tag, false, nil
}
func (a *App) fetchCatalogue(ctx context.Context, rawURL, etag string) (ruleManifest, []catalogueCandidate, string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var m ruleManifest
	raw, tag, unchanged, e := a.fetchFeedBytes(ctx, rawURL, etag, 1<<20)
	if e != nil || unchanged {
		return m, nil, tag, unchanged, e
	}
	base, _ := url.Parse(rawURL)
	m, e = parseRuleManifest(raw, base)
	if e != nil {
		return m, nil, "", false, e
	}
	if m.SchemaVersion == 3 {
		target, _ := resolveFeedFile(base, m.Package.Path, ".zip")
		raw, _, _, e = a.fetchFeedBytes(ctx, target, "", maxCataloguePackageBytes)
		if e != nil {
			return m, nil, "", false, e
		}
		items, e := parseCataloguePackage(ctx, m, raw)
		return m, items, tag, false, e
	}
	result := []catalogueCandidate{}
	var total int
	for _, entry := range m.Rules {
		target, _ := resolveRuleFile(base, entry.Path)
		raw, _, _, e = a.fetchFeedBytes(ctx, target, "", 64<<10)
		if e != nil {
			return m, nil, "", false, e
		}
		total += len(raw)
		if total > 8<<20 {
			return m, nil, "", false, errors.New("catalogue download exceeds 8 MiB")
		}
		file, e := parseCatalogueRule(raw, entry)
		if e != nil {
			return m, nil, "", false, e
		}
		result = append(result, catalogueCandidate{File: file, Digest: entry.SHA256})
	}
	return m, result, tag, false, nil
}
