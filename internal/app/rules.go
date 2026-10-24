package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maxRulesPerSite = 100
const maxRulesTotal = 1000
const maxInspectionBytes = 64 << 10
const maxFieldBytes = 4096

type RuleScope struct {
	SiteID     int64  `json:"site_id"`
	PathPrefix string `json:"path_prefix,omitempty"`
}
type RuleCondition struct {
	Field string          `json:"field"`
	Key   string          `json:"key,omitempty"`
	Op    string          `json:"op"`
	Value json.RawMessage `json:"value"`
}
type RuleSpec struct {
	SchemaVersion int             `json:"schema_version"`
	Name          string          `json:"name"`
	Scope         RuleScope       `json:"scope"`
	All           []RuleCondition `json:"all"`
	Action        string          `json:"action"`
	TTLSeconds    int             `json:"ttl_seconds"`
	EvidenceIDs   []string        `json:"evidence_ids,omitempty"`
}
type compiledCondition struct {
	RuleCondition
	values []string
	regex  *regexp.Regexp
	prefix netip.Prefix
}
type compiledRule struct {
	ID         int64
	Spec       RuleSpec
	Conditions []compiledCondition
	Expires    time.Time
}
type RuleResult struct {
	RuleID int64  `json:"rule_id"`
	Action string `json:"action"`
	Result string `json:"result"`
}
type Fact struct {
	State  string   `json:"state"`
	Values []string `json:"values,omitempty"`
}
type requestFacts struct {
	request   *http.Request
	facts     map[string]Fact
	query     url.Values
	queryDone bool
	queryErr  bool
	body      any
	bodyDone  bool
	bodyState string
}

var namedKey = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var methodName = regexp.MustCompile(`^[A-Z]{1,24}$`)

func sensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, part := range []string{"password", "passwd", "secret", "token", "authorization", "cookie", "apikey", "api_key", "api-key", "session", "credential", "csrf", "xsrf"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}
func validSelector(field, key string) error {
	switch field {
	case "method", "path", "client_ip":
		if key != "" {
			return errors.New("scalar fields cannot have a key")
		}
	case "header", "query":
		if !namedKey.MatchString(key) || sensitiveKey(key) {
			return errors.New("use a non-sensitive named field")
		}
		if field == "header" && (strings.EqualFold(key, "referer") || strings.HasPrefix(strings.ToLower(key), "x-forwarded-") || strings.EqualFold(key, "forwarded")) {
			return errors.New("referrer and forwarding headers cannot be selected")
		}
	case "json_body":
		if len(key) > 128 || !strings.HasPrefix(key, "/") || len(strings.Split(key, "/")) > 9 || sensitiveKey(key) {
			return errors.New("JSON field must be a non-sensitive JSON pointer, at most eight levels")
		}
		for _, p := range strings.Split(key[1:], "/") {
			for i := 0; i < len(p); i++ {
				if p[i] == '~' {
					if i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1') {
						return errors.New("invalid JSON pointer escape")
					}
					i++
				}
			}
		}
	default:
		return errors.New("unknown rule field")
	}
	return nil
}
func compileRule(spec RuleSpec) (compiledRule, error) {
	out := compiledRule{Spec: spec}
	fail := func(s string) (compiledRule, error) { return out, errors.New(s) }
	if spec.SchemaVersion != 1 {
		return fail("schema_version must be 1")
	}
	if strings.TrimSpace(spec.Name) == "" || len(spec.Name) > 120 {
		return fail("name must be 1–120 bytes")
	}
	if spec.Scope.SiteID < 1 {
		return fail("scope.site_id is required")
	}
	if len(spec.Scope.PathPrefix) > 1024 || (spec.Scope.PathPrefix != "" && !strings.HasPrefix(spec.Scope.PathPrefix, "/")) {
		return fail("path_prefix must start with / and fit 1024 bytes")
	}
	if len(spec.All) < 1 || len(spec.All) > 12 {
		return fail("all must contain 1–12 conditions")
	}
	if spec.Action != "observe" && spec.Action != "block" {
		return fail("action must be observe or block")
	}
	if spec.TTLSeconds < 60 || spec.TTLSeconds > 86400 {
		return fail("ttl_seconds must be between 60 and 86400")
	}
	if len(spec.EvidenceIDs) > 20 {
		return fail("at most 20 evidence IDs are allowed")
	}
	for _, id := range spec.EvidenceIDs {
		if len(id) < 1 || len(id) > 128 {
			return fail("invalid evidence ID")
		}
	}
	for _, condition := range spec.All {
		if e := validSelector(condition.Field, condition.Key); e != nil {
			return fail(e.Error())
		}
		c := compiledCondition{RuleCondition: condition}
		if condition.Op == "in" {
			if e := json.Unmarshal(condition.Value, &c.values); e != nil || len(c.values) < 1 || len(c.values) > 32 {
				return fail("in requires an array of 1–32 strings")
			}
		} else {
			var value string
			if e := json.Unmarshal(condition.Value, &value); e != nil {
				return fail("operator requires a string value")
			}
			c.values = []string{value}
		}
		for _, v := range c.values {
			if v == "" || len(v) > 512 || !utf8.ValidString(v) {
				return fail("condition values must contain 1–512 UTF-8 bytes")
			}
		}
		if condition.Field == "method" {
			if condition.Op != "equals" && condition.Op != "in" {
				return fail("method supports equals and in")
			}
			for _, v := range c.values {
				if !methodName.MatchString(v) {
					return fail("method values must be uppercase HTTP tokens")
				}
			}
		}
		if condition.Field == "client_ip" && condition.Op != "cidr" {
			return fail("client_ip requires cidr")
		}
		switch condition.Op {
		case "equals", "in", "contains", "prefix":
		case "regex":
			var e error
			c.regex, e = regexp.Compile(c.values[0])
			if e != nil {
				return fail("invalid Go/RE2 regex; lookaround and backreferences are unsupported")
			}
			if c.regex.NumSubexp() > 32 {
				return fail("regex has too many capture groups")
			}
		case "cidr":
			if condition.Field != "client_ip" {
				return fail("cidr requires client_ip")
			}
			var e error
			c.prefix, e = netip.ParsePrefix(c.values[0])
			if e != nil {
				return fail("invalid CIDR network")
			}
			if c.prefix.Addr().Is4In6() {
				if c.prefix.Bits() < 96 {
					return fail("mapped IPv4 CIDR prefix must be at least /96")
				}
				c.prefix = netip.PrefixFrom(c.prefix.Addr().Unmap(), c.prefix.Bits()-96)
			}
			c.prefix = c.prefix.Masked()
		default:
			return fail("unknown operator")
		}
		out.Conditions = append(out.Conditions, c)
	}
	return out, nil
}
func factKey(field, key string) string {
	if field == "header" {
		key = strings.ToLower(key)
	}
	return field + ":" + key
}
func newRequestFacts(r *http.Request) *requestFacts {
	return &requestFacts{request: r, facts: map[string]Fact{}}
}
func (f *requestFacts) get(field, key string) Fact {
	id := factKey(field, key)
	if v, ok := f.facts[id]; ok {
		return v
	}
	r := f.request
	v := Fact{State: "missing"}
	switch field {
	case "method":
		v = Fact{State: "present", Values: []string{r.Method}}
	case "path":
		v = Fact{State: "present", Values: []string{r.URL.Path}}
	case "client_ip":
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e == nil {
			if ip, e := netip.ParseAddr(host); e == nil {
				v = Fact{State: "present", Values: []string{ip.Unmap().String()}}
			}
		}
	case "header":
		if values, ok := r.Header[http.CanonicalHeaderKey(key)]; ok {
			v = Fact{State: "present", Values: append([]string(nil), values...)}
		}
	case "query":
		if !f.queryDone {
			f.queryDone = true
			var e error
			f.query, e = url.ParseQuery(r.URL.RawQuery)
			f.queryErr = e != nil
		}
		if f.queryErr {
			v.State = "invalid"
		} else if values, ok := f.query[key]; ok {
			v = Fact{State: "present", Values: append([]string(nil), values...)}
		}
	case "json_body":
		f.readBody()
		if f.bodyState != "complete" {
			v.State = f.bodyState
		} else {
			current, found := jsonPointer(f.body, key)
			if found {
				switch n := current.(type) {
				case string:
					v = Fact{State: "present", Values: []string{n}}
				case json.Number:
					v = Fact{State: "present", Values: []string{n.String()}}
				case bool:
					v = Fact{State: "present", Values: []string{fmt.Sprint(n)}}
				default:
					v.State = "unsupported"
				}
			}
		}
	}
	if v.State == "present" {
		if len(v.Values) > 32 {
			v = Fact{State: "truncated"}
		} else {
			for _, s := range v.Values {
				if len(s) > maxFieldBytes || !utf8.ValidString(s) {
					v = Fact{State: "truncated"}
					break
				}
			}
		}
	}
	f.facts[id] = v
	return v
}
func (f *requestFacts) readBody() {
	if f.bodyDone {
		return
	}
	f.bodyDone = true
	r := f.request
	f.bodyState = "unsupported"
	contentType, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || (contentType != "application/json" && !strings.HasSuffix(contentType, "+json")) {
		return
	}
	if r.Body == nil {
		f.bodyState = "missing"
		return
	}
	if r.ContentLength > maxInspectionBytes {
		f.bodyState = "truncated"
		return
	}
	body := r.Body
	prefix, e := io.ReadAll(io.LimitReader(body, maxInspectionBytes+1))
	r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(prefix), body), original: body}
	if e != nil {
		f.bodyState = "invalid"
		return
	}
	if len(prefix) > maxInspectionBytes {
		f.bodyState = "truncated"
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(prefix))
	decoder.UseNumber()
	count := 0
	f.body, e = decodeInspectionJSON(decoder, 0, &count)
	if e != nil {
		f.bodyState = "invalid"
		return
	}
	if _, e = decoder.Token(); e != io.EOF {
		f.bodyState = "invalid"
		return
	}
	f.bodyState = "complete"
}

type replayBody struct {
	io.Reader
	original io.Closer
}

func (b *replayBody) Close() error { return b.original.Close() }
func decodeInspectionJSON(d *json.Decoder, depth int, count *int) (any, error) {
	if depth > 16 || *count > 512 {
		return nil, errors.New("JSON inspection budget exceeded")
	}
	*count = *count + 1
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, e
				}
				s, ok := key.(string)
				if !ok {
					return nil, errors.New("invalid JSON key")
				}
				if _, ok = m[s]; ok {
					return nil, errors.New("duplicate JSON key")
				}
				val, e := decodeInspectionJSON(d, depth+1, count)
				if e != nil {
					return nil, e
				}
				m[s] = val
			}
			_, e = d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				val, e := decodeInspectionJSON(d, depth+1, count)
				if e != nil {
					return nil, e
				}
				a = append(a, val)
			}
			_, e = d.Token()
			return a, e
		}
		return nil, errors.New("invalid JSON delimiter")
	default:
		return v, nil
	}
}
func jsonPointer(value any, pointer string) (any, bool) {
	for _, part := range strings.Split(pointer[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch current := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = current[part]
			if !ok {
				return nil, false
			}
		case []any:
			index, e := strconv.Atoi(part)
			if e != nil || index < 0 || index >= len(current) || strconv.Itoa(index) != part {
				return nil, false
			}
			value = current[index]
		default:
			return nil, false
		}
	}
	return value, true
}

func (c compiledCondition) match(f Fact) string {
	if f.State == "missing" {
		return "not_matched"
	}
	if f.State != "present" {
		return "unknown"
	}
	for _, s := range f.Values {
		switch c.Op {
		case "equals", "in":
			for _, v := range c.values {
				if s == v {
					return "matched"
				}
			}
		case "contains":
			if strings.Contains(s, c.values[0]) {
				return "matched"
			}
		case "prefix":
			if strings.HasPrefix(s, c.values[0]) {
				return "matched"
			}
		case "regex":
			if c.regex.MatchString(s) {
				return "matched"
			}
		case "cidr":
			if ip, e := netip.ParseAddr(s); e == nil && c.prefix.Contains(ip.Unmap()) {
				return "matched"
			}
		}
	}
	return "not_matched"
}
func (r compiledRule) evaluate(get func(string, string) Fact) string {
	unknown := false
	if r.Spec.Scope.PathPrefix != "" {
		path := get("path", "")
		if path.State != "present" || len(path.Values) == 0 {
			unknown = true
		} else if !strings.HasPrefix(path.Values[0], r.Spec.Scope.PathPrefix) {
			return "not_matched"
		}
	}
	for _, c := range r.Conditions {
		switch c.match(get(c.Field, c.Key)) {
		case "not_matched":
			return "not_matched"
		case "unknown":
			unknown = true
		}
	}
	if unknown {
		return "unknown"
	}
	return "matched"
}
func evaluateRules(rules []compiledRule, f *requestFacts, now time.Time) ([]RuleResult, bool) {
	results := []RuleResult{}
	blocked := false
	for _, r := range rules {
		if !now.Before(r.Expires) {
			continue
		}
		result := r.evaluate(f.get)
		if result != "not_matched" {
			results = append(results, RuleResult{r.ID, r.Spec.Action, result})
			blocked = blocked || (result == "matched" && r.Spec.Action == "block")
		}
	}
	return results, blocked
}
