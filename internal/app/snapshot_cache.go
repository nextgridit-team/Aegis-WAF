package app

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

const snapshotCacheLimit = 64 << 20

type cachedCertificate struct {
	Chain [][]byte
	Key   []byte
}
type cachedRule struct {
	ID                       int64
	Spec                     RuleSpec
	Expires                  time.Time
	PolicyID, PolicyRevision int64
	GroupName, GroupPrefix   string
	GroupMethods             []string
}
type cachedBinding struct {
	NetworkAccess  networkAccessSettings
	NetworkMode    string
	ManagedOptions managedSignatureOptions
	ID, Revision   int64
	Name           string
	Priority       int
	CIDRs          []string
	Protection     ProtectionSettings
	Rules          []cachedRule
}
type cachedSnapshot struct {
	LocalGeo     *localGeoPolicy
	ManagedSets  map[string]signatureSet
	Format       int
	At           time.Time
	Version      int64
	Certificates map[int64]cachedCertificate
	Sites        []Site
	Rules        map[int64][]cachedRule
	Capture      map[int64]TrafficSettings
	Protection   map[int64]ProtectionSettings
	Bindings     map[int64][]cachedBinding
	Geo          []byte
}

func cacheRules(rules []compiledRule) []cachedRule {
	out := make([]cachedRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, cachedRule{r.ID, r.Spec, r.Expires, r.PolicyID, r.PolicyRevision, r.GroupName, r.GroupPrefix, r.GroupMethods})
	}
	return out
}
func restoreRules(rules []cachedRule) ([]compiledRule, error) {
	if len(rules) > maxRulesTotal {
		return nil, errors.New("cache rule capacity exceeded")
	}
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		compiled, e := compileRule(r.Spec)
		if e != nil {
			return nil, e
		}
		compiled.ID = r.ID
		compiled.Expires = r.Expires
		compiled.PolicyID = r.PolicyID
		compiled.PolicyRevision = r.PolicyRevision
		compiled.GroupName = r.GroupName
		compiled.GroupPrefix = r.GroupPrefix
		compiled.GroupMethods = r.GroupMethods
		out = append(out, compiled)
	}
	return out, nil
}
func (a *App) cacheAAD() string {
	identity := sha256.Sum256([]byte(a.cfg.DatabaseURL))
	return a.cfg.KeyID + ":snapshot-cache:v1:" + hex.EncodeToString(identity[:])
}
func (a *App) archiveSnapshot(s *snapshot, now time.Time) ([]byte, error) {
	cache := cachedSnapshot{LocalGeo: s.localGeo, ManagedSets: s.managedSets, Format: 1, At: now, Version: s.version, Certificates: map[int64]cachedCertificate{}, Sites: []Site{}, Rules: map[int64][]cachedRule{}, Capture: map[int64]TrafficSettings{}, Protection: map[int64]ProtectionSettings{}, Bindings: map[int64][]cachedBinding{}, Geo: s.geoData}
	for id, cert := range s.certificates {
		key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if e != nil {
			return nil, e
		}
		cache.Certificates[id] = cachedCertificate{cert.Certificate, key}
	}
	seen := map[int64]bool{}
	for _, route := range s.routes {
		if !seen[route.site.ID] {
			seen[route.site.ID] = true
			cache.Sites = append(cache.Sites, route.site)
		}
	}
	for id, rules := range s.rules {
		cache.Rules[id] = cacheRules(rules)
	}
	for id, p := range s.capture {
		cache.Capture[id] = p.Settings
	}
	for id, p := range s.protection {
		cache.Protection[id] = p.ProtectionSettings
	}
	for site, bindings := range s.policyBindings {
		for _, b := range bindings {
			binding := cachedBinding{ManagedOptions: b.ManagedOptions, ID: b.ID, Revision: b.Revision, Name: b.Name, Priority: b.Priority, Protection: b.Protection.ProtectionSettings, Rules: cacheRules(b.Rules), CIDRs: []string{}}
			if b.Protection.network != nil {
				binding.NetworkAccess = b.Protection.network.Settings
				binding.NetworkMode = b.Protection.network.Mode
			}
			for _, cidr := range b.CIDRs {
				binding.CIDRs = append(binding.CIDRs, cidr.String())
			}
			cache.Bindings[site] = append(cache.Bindings[site], binding)
		}
	}
	raw, e := json.Marshal(cache)
	if e != nil {
		return nil, e
	}
	if len(raw) > snapshotCacheLimit {
		return nil, errors.New("snapshot cache is too large")
	}
	return seal(a.cfg.Key, a.cacheAAD(), raw)
}
func (a *App) decodeSnapshot(ciphertext []byte, now time.Time) (*snapshot, error) {
	raw, e := open(a.cfg.Key, a.cacheAAD(), ciphertext)
	if e != nil {
		return nil, e
	}
	var cached cachedSnapshot
	if e = json.Unmarshal(raw, &cached); e != nil {
		return nil, e
	}
	age := a.cfg.SnapshotCacheMaxAge
	if age <= 0 {
		age = 24 * time.Hour
	}
	if cached.Format != 1 || cached.Version < 1 || cached.At.IsZero() || now.Sub(cached.At) > age || cached.At.After(now.Add(5*time.Minute)) {
		return nil, errors.New("snapshot cache format or freshness rejected")
	}
	s := &snapshot{managedSets: map[string]signatureSet{}, managedWAFs: map[string]*managedSignatureRuntime{}, version: cached.Version, certificates: map[int64]*tls.Certificate{}, routes: map[string]*route{}, rules: map[int64][]compiledRule{}, capture: map[int64]*capturePolicy{}, protection: map[int64]*protectionPolicy{}, policyBindings: map[int64][]compiledPolicyBinding{}}
	for id, set := range cached.ManagedSets {
		digest, count, e := validateSignatureFiles(set.Files)
		if e != nil {
			return nil, e
		}
		if id != set.ID || digest != set.Digest || count != set.RuleCount {
			return nil, errors.New("cached signature set integrity rejected")
		}
		s.managedSets[id] = set
	}
	for id, cert := range cached.Certificates {
		var chain []byte
		for _, block := range cert.Chain {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block})...)
		}
		pair, e := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.Key}))
		if e != nil {
			return nil, e
		}
		pair.Leaf, e = x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return nil, e
		}
		s.certificates[id] = &pair
	}
	for _, site := range cached.Sites {
		target, e := url.Parse(site.Upstream)
		if e != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
			return nil, errors.New("invalid cached upstream")
		}
		headers := HeaderSettings{}
		if site.Headers != nil {
			headers = *site.Headers
		}
		headers, e = normalizeHeaders(headers)
		if e != nil {
			return nil, e
		}
		site.Headers = &headers
		r := &route{site: site, proxy: newProxyWithHeaders(target, site.PreserveHost, headers)}
		if site.CertificateID != nil {
			r.cert = s.certificates[*site.CertificateID]
			if r.cert == nil {
				return nil, errors.New("missing cached certificate")
			}
		}
		for _, host := range site.Hostnames {
			if r.cert != nil && r.cert.Leaf.VerifyHostname(host) != nil {
				return nil, errors.New("cached hostname coverage rejected")
			}
			if requestHost(host) != host || host == "" {
				return nil, errors.New("invalid cached hostname")
			}
			if _, exists := s.routes[host]; exists {
				return nil, errors.New("duplicate cached hostname")
			}
			s.routes[host] = r
		}
	}
	for id, rules := range cached.Rules {
		s.rules[id], e = restoreRules(rules)
		if e != nil {
			return nil, e
		}
	}
	for id, settings := range cached.Capture {
		if e = validateTrafficSettings(settings); e != nil {
			return nil, e
		}
		s.capture[id] = &capturePolicy{Settings: settings, budget: &captureBudget{}, redactors: evidenceRedactors(settings)}
	}
	for id, settings := range cached.Protection {
		s.protection[id], e = compileProtection(settings)
		if e != nil {
			return nil, e
		}
	}
	for site, bindings := range cached.Bindings {
		if len(bindings) > 10 {
			return nil, errors.New("cache policy capacity exceeded")
		}
		defaults := 0
		previous := -1
		for _, b := range bindings {
			p, e := compileProtection(b.Protection)
			if e != nil {
				return nil, e
			}
			p.budgetScope = b.ID
			p.network, e = compileNetworkAccess(b.NetworkAccess, b.NetworkMode)
			if e != nil {
				return nil, e
			}
			options, e := normalizeManagedSignatures(b.ManagedOptions)
			if e != nil {
				return nil, e
			}
			binding := compiledPolicyBinding{ManagedOptions: options, ID: b.ID, Revision: b.Revision, Name: b.Name, Priority: b.Priority, Protection: p}
			if b.Priority <= previous {
				return nil, errors.New("invalid cached policy ordering")
			}
			previous = b.Priority
			for _, cidr := range b.CIDRs {
				prefix, e := netip.ParsePrefix(cidr)
				if e != nil || prefix.Bits() == 0 {
					return nil, errors.New("invalid cached policy CIDR")
				}
				binding.CIDRs = append(binding.CIDRs, prefix)
			}
			if len(b.CIDRs) == 0 {
				defaults++
				if b.Priority != 10000 {
					return nil, errors.New("invalid cached default policy")
				}
			}
			if options.Mode != "off" {
				set, ok := s.managedSets[options.SetID]
				if !ok {
					return nil, errors.New("cached signature set missing")
				}
				key := managedRuntimeKey(options)
				runtime := s.managedWAFs[key]
				if runtime == nil {
					if len(s.managedWAFs) >= 8 {
						return nil, errors.New("cached signature capacity exceeded")
					}
					runtime, e = compileManagedSignatures(set, options)
					if e != nil {
						return nil, e
					}
					s.managedWAFs[key] = runtime
				}
				binding.Managed = runtime
			}
			binding.Rules, e = restoreRules(b.Rules)
			if e != nil {
				return nil, e
			}
			s.policyBindings[site] = append(s.policyBindings[site], binding)
		}
		if len(bindings) > 0 && defaults != 1 {
			return nil, errors.New("cached policy fallback missing")
		}
	}
	if len(cached.Geo) > 0 {
		s.geo, e = maxminddb.OpenBytes(cached.Geo)
		if e != nil {
			return nil, e
		}
		s.geoData = cached.Geo
	}
	if cached.LocalGeo != nil {
		if _, e := normalizeLocalPublicIP(cached.LocalGeo.PublicIP); e != nil {
			return nil, e
		}
		if len(cached.LocalGeo.Prefixes) > 1024 {
			return nil, errors.New("invalid cached local object count")
		}
		for prefix := range cached.LocalGeo.Prefixes {
			if !prefix.IsValid() || prefix.Bits() == 0 {
				return nil, errors.New("invalid cached local object")
			}
		}
		s.localGeo = cached.LocalGeo
		s.localGeo.reader = s.geo
	}
	return s, nil
}

// Cache files are optional, sealed and written only from database-confirmed snapshots.
func (a *App) persistSnapshot(s *snapshot) {
	if a.cfg.SnapshotCacheFile == "" {
		return
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if a.cacheVersion == s.version && time.Since(a.cacheAt) < 5*time.Minute {
		return
	}
	e := a.writeSnapshotCache(s)
	a.cacheAvailable.Store(e == nil)
	if e != nil {
		slog.Warn("snapshot cache write unavailable; previous file retained")
		return
	}
	a.cacheVersion = s.version
	a.cacheAt = time.Now()
}
func (a *App) writeSnapshotCache(s *snapshot) error {
	sealed, e := a.archiveSnapshot(s, time.Now())
	if e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(a.cfg.SnapshotCacheFile), ".aegis-snapshot-*")
	if e != nil {
		return e
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	if e = file.Chmod(0600); e != nil {
		return e
	}
	if _, e = file.Write(sealed); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, a.cfg.SnapshotCacheFile); e != nil {
		return e
	}
	directory, e := os.Open(filepath.Dir(a.cfg.SnapshotCacheFile))
	if e == nil {
		defer directory.Close()
		_ = directory.Sync()
	}
	return nil
}
func (a *App) restoreSnapshotCache() error {
	file, e := os.Open(a.cfg.SnapshotCacheFile)
	if e != nil {
		return e
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > snapshotCacheLimit+64 {
		return errors.New("snapshot cache file permissions or size rejected")
	}
	sealed, e := io.ReadAll(io.LimitReader(file, snapshotCacheLimit+65))
	if e != nil {
		return e
	}
	if len(sealed) > snapshotCacheLimit+64 {
		return errors.New("snapshot cache size rejected")
	}
	s, e := a.decodeSnapshot(sealed, time.Now())
	if e != nil {
		return e
	}
	a.active.Store(s)
	a.cacheRestored.Store(true)
	a.cacheAvailable.Store(true)
	return nil
}
