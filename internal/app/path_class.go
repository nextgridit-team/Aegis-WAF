package app

import (
	"strings"
	"sync"
)

// Endpoint path classes give the cost-of-protection view a bounded path
// dimension. Dynamic segments are bucketed so per-endpoint aggregates do not
// explode into one row per identifier: numeric segments become {id}, UUIDs
// become {uuid} and long hex identifiers become {hash}. Query strings and
// fragments are excluded; only the URL path is classified.

const (
	// pathClassOverflow is the bucket every class beyond a site's budget folds
	// into, keeping stored cardinality bounded no matter how unusual traffic is.
	pathClassOverflow = "other"
	// pathClassCapPerSite bounds distinct classes tracked per application.
	pathClassCapPerSite = 256
	// pathClassMaxSites bounds the number of applications carrying state; with
	// the per-site cap this is a hard ceiling on tracked classes per replica.
	pathClassMaxSites = 256
	// pathClassMaxBytes bounds the stored class text.
	pathClassMaxBytes = 256
	// pathClassSegmentMax bounds each individual segment before bucketing.
	pathClassSegmentMax = 64
	// pathClassHexMin is the shortest pure-hex segment bucketed as {hash}.
	pathClassHexMin = 16
)

// normalizePathClass buckets dynamic path segments into stable placeholders.
// It is a pure function: identical paths always produce the identical class.
func normalizePathClass(path string) string {
	// Only the path is classified; strip any query or fragment defensively.
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	parts := strings.Split(path, "/")
	for n, segment := range parts {
		parts[n] = classifySegment(segment)
	}
	class := strings.Join(parts, "/")
	// Defensive: NUL is valid UTF-8 but PostgreSQL text rejects it, so a NUL
	// anywhere in the class would fail the whole access-log CopyFrom batch
	// (SQLSTATE 22021). classifySegment already strips it; this backstop
	// keeps the invariant true no matter which branch built the class.
	class = strings.ReplaceAll(class, "\x00", "")
	if len(class) > pathClassMaxBytes {
		class = truncateUTF8(class, pathClassMaxBytes)
	}
	return class
}

// classifySegment buckets one path segment; static segments are kept (bounded
// in length) so readable routes stay readable in reports.
func classifySegment(segment string) string {
	// Paths arrive percent-decoded by net/http and can carry invalid UTF-8
	// (e.g. /%ff%fe); one invalid path class would fail the whole access-log
	// CopyFrom batch, so sanitize before any byte-level handling.
	segment = strings.ToValidUTF8(segment, "�")
	// NUL is valid UTF-8, so ToValidUTF8 leaves it in place — but PostgreSQL
	// text rejects it (SQLSTATE 22021) and one bad class drops the whole
	// access-log batch (#75). Strip it before bucketing.
	segment = strings.ReplaceAll(segment, "\x00", "")
	if len(segment) > pathClassSegmentMax {
		segment = truncateUTF8(segment, pathClassSegmentMax)
	}
	if segment == "" {
		return segment
	}
	if isDigits(segment) {
		return "{id}"
	}
	if isUUID(segment) {
		return "{uuid}"
	}
	if len(segment) >= pathClassHexMin && isHex(segment) {
		return "{hash}"
	}
	return segment
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return len(s) > 0
}

// isUUID matches the canonical 8-4-4-4-12 hexadecimal shape, case-insensitive.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i] | 0x20
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// pathClassTracker enforces the per-replica class budget. The zero value is
// ready to use: a bare App without an explicit constructor classifies paths
// with the same bounds. Classification happens while building the access
// event, so one mutex-guarded lookup rides the forwarding goroutine; the map
// itself is bounded by pathClassMaxSites × pathClassCapPerSite entries.
type pathClassTracker struct {
	mu    sync.Mutex
	sites map[int64]map[string]struct{}
}

// classify normalizes the path and enforces the site's class budget: known
// classes resolve to themselves, unknown classes fold into pathClassOverflow
// once the budget is full.
func (t *pathClassTracker) classify(site int64, path string) string {
	class := normalizePathClass(path)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sites == nil {
		t.sites = make(map[int64]map[string]struct{})
	}
	classes := t.sites[site]
	if classes == nil {
		if len(t.sites) >= pathClassMaxSites {
			return pathClassOverflow
		}
		classes = make(map[string]struct{})
		t.sites[site] = classes
	}
	if _, ok := classes[class]; ok {
		return class
	}
	if len(classes) >= pathClassCapPerSite {
		return pathClassOverflow
	}
	classes[class] = struct{}{}
	return class
}
