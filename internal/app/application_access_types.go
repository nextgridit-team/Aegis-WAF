package app

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const applicationAuthPrefix = "/__aegis/auth/"
const applicationSessionCookie = "__Host-aegis_application"
const applicationFlowCookie = "__Host-aegis_auth_flow"

type oidcSettings struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	GroupsClaim string   `json:"groups_claim"`
}
type ldapSettings struct {
	URL                string `json:"url"`
	BindDN             string `json:"bind_dn"`
	UserBaseDN         string `json:"user_base_dn"`
	UserFilter         string `json:"user_filter"`
	UsernameAttribute  string `json:"username_attribute"`
	EmailAttribute     string `json:"email_attribute"`
	GroupsAttribute    string `json:"groups_attribute"`
	GroupBaseDN        string `json:"group_base_dn"`
	GroupFilter        string `json:"group_filter"`
	GroupNameAttribute string `json:"group_name_attribute"`
}
type identityProviderSettings struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Enabled bool          `json:"enabled"`
	OIDC    *oidcSettings `json:"oidc,omitempty"`
	LDAP    *ldapSettings `json:"ldap,omitempty"`
	CAPEM   string        `json:"ca_pem,omitempty"`
}
type identityProviderInput struct {
	identityProviderSettings
	Revision    int64  `json:"revision"`
	Secret      string `json:"secret,omitempty"`
	ClearSecret bool   `json:"clear_secret,omitempty"`
}
type storedIdentityProvider struct {
	ID        int64                    `json:"id"`
	Revision  int64                    `json:"revision"`
	Settings  identityProviderSettings `json:"settings"`
	HasSecret bool                     `json:"has_secret"`
	Cipher    []byte                   `json:"-"`
	KeyID     string                   `json:"-"`
}
type applicationAccessSettings struct {
	Enabled               bool     `json:"enabled"`
	ProviderID            int64    `json:"provider_id"`
	PublicOrigin          string   `json:"public_origin"`
	AllowedGroups         []string `json:"allowed_groups"`
	AllowAnyAuthenticated bool     `json:"allow_any_authenticated"`
	SessionMinutes        int      `json:"session_minutes"`
}
type applicationAccessInput struct {
	applicationAccessSettings
	Revision int64 `json:"revision"`
}
type applicationAccess struct {
	SiteID   int64                     `json:"site_id"`
	Revision int64                     `json:"revision"`
	Settings applicationAccessSettings `json:"settings"`
}
type applicationIdentity struct {
	Subject  string   `json:"subject"`
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups"`
}

var identityAttribute = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

func validGroupDN(value string) bool { _, e := ldap.ParseDN(value); return value != "" && e == nil }

func identityProviderPresets() []identityProviderSettings {
	oidc := func(name, issuer, claim string) identityProviderSettings {
		return identityProviderSettings{Name: name, Type: "oidc", Enabled: true, OIDC: &oidcSettings{Issuer: issuer, Scopes: []string{"openid", "profile", "email"}, GroupsClaim: claim}}
	}
	directory := identityProviderSettings{Name: "OpenLDAP", Type: "ldap", Enabled: true, LDAP: &ldapSettings{URL: "ldaps://ldap.example.com:636", UserFilter: "(uid={username})", UsernameAttribute: "uid", EmailAttribute: "mail", GroupsAttribute: "memberOf", GroupFilter: "(member={dn})", GroupNameAttribute: "cn"}}
	ad := directory
	config := *directory.LDAP
	ad.LDAP = &config
	ad.Name = "Active Directory"
	ad.LDAP.UserFilter = "(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	ad.LDAP.UsernameAttribute = "sAMAccountName"
	return []identityProviderSettings{oidc("Custom OIDC", "", "groups"), oidc("Authentik", "https://auth.example.com/application/o/application/", "groups"), oidc("Microsoft Entra ID", "https://login.microsoftonline.com/TENANT-ID/v2.0", "roles"), oidc("Google", "https://accounts.google.com", "groups"), directory, ad}
}

func providerURL(raw string, directory bool) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\\") {
		return nil, invalid("provide a provider URL without credentials, query or fragment")
	}
	if directory {
		if (u.Scheme != "ldaps" && u.Scheme != "ldap") || (u.Path != "" && u.Path != "/") {
			return nil, invalid("LDAP URL must use ldaps:// or ldap:// with mandatory StartTLS and no path")
		}
	} else if u.Scheme != "https" {
		return nil, invalid("OIDC providers require HTTPS")
	}
	return u, nil
}
func identityTLS(ca string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		if len(ca) > 128<<10 {
			return nil, invalid("provider CA certificate exceeds 128 KiB")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(ca)) {
			return nil, invalid("provide a PEM CA certificate")
		}
		c.RootCAs = roots
	}
	return c, nil
}
func normalizeIdentityProvider(s identityProviderSettings) (identityProviderSettings, error) {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || len(s.Name) > 120 {
		return s, invalid("provide a provider name of 1–120 bytes")
	}
	if _, e := identityTLS(s.CAPEM); e != nil {
		return s, e
	}
	switch s.Type {
	case "oidc":
		if s.OIDC == nil || s.LDAP != nil {
			return s, invalid("OIDC providers require only oidc settings")
		}
		o := *s.OIDC
		s.OIDC = &o
		if _, e := providerURL(o.Issuer, false); e != nil {
			return s, e
		}
		if len(o.Issuer) > 2048 || strings.TrimSpace(o.ClientID) == "" || len(o.ClientID) > 512 {
			return s, invalid("provide an issuer URL and client ID")
		}
		if len(o.Scopes) == 0 {
			o.Scopes = []string{"openid", "profile", "email"}
		}
		if len(o.Scopes) > 16 {
			return s, invalid("at most 16 OIDC scopes")
		}
		seen := map[string]bool{}
		for _, v := range o.Scopes {
			if v == "" || len(v) > 128 || strings.ContainsAny(v, " \r\n\t") || seen[v] {
				return s, invalid("OIDC scopes must be distinct nonempty tokens")
			}
			seen[v] = true
		}
		if !seen["openid"] {
			return s, invalid("OIDC scopes must include openid")
		}
		if o.GroupsClaim == "" {
			o.GroupsClaim = "groups"
		}
		if !identityAttribute.MatchString(o.GroupsClaim) {
			return s, invalid("groups_claim must name a top-level token claim, such as groups or roles")
		}
		s.OIDC = &o
	case "ldap":
		if s.LDAP == nil || s.OIDC != nil {
			return s, invalid("LDAP providers require only ldap settings")
		}
		l := *s.LDAP
		if _, e := providerURL(l.URL, true); e != nil {
			return s, e
		}
		for _, dn := range []string{l.BindDN, l.UserBaseDN} {
			if dn == "" || len(dn) > 2048 {
				return s, invalid("provide the bind DN and user base DN")
			}
			if _, e := ldap.ParseDN(dn); e != nil {
				return s, invalid("invalid LDAP distinguished name")
			}
		}
		if l.GroupBaseDN != "" {
			if _, e := ldap.ParseDN(l.GroupBaseDN); e != nil || len(l.GroupBaseDN) > 2048 {
				return s, invalid("invalid group base DN")
			}
		}
		if l.UserFilter == "" {
			l.UserFilter = "(uid={username})"
		}
		if strings.Count(l.UserFilter, "{username}") != 1 || len(l.UserFilter) > 2048 {
			return s, invalid("user_filter must contain {username} exactly once")
		}
		if _, e := ldap.CompileFilter(strings.ReplaceAll(l.UserFilter, "{username}", "test")); e != nil {
			return s, invalid("invalid LDAP user filter")
		}
		if l.UsernameAttribute == "" {
			l.UsernameAttribute = "uid"
		}
		if l.EmailAttribute == "" {
			l.EmailAttribute = "mail"
		}
		if l.GroupsAttribute == "" {
			l.GroupsAttribute = "memberOf"
		}
		if l.GroupNameAttribute == "" {
			l.GroupNameAttribute = "cn"
		}
		for _, attr := range []string{l.UsernameAttribute, l.EmailAttribute, l.GroupsAttribute, l.GroupNameAttribute} {
			if !identityAttribute.MatchString(attr) {
				return s, invalid("invalid LDAP attribute name")
			}
		}
		if l.GroupFilter == "" {
			l.GroupFilter = "(member={dn})"
		}
		filter := strings.NewReplacer("{dn}", "cn=test", "{username}", "test").Replace(l.GroupFilter)
		if len(filter) > 2048 || strings.ContainsAny(filter, "{}") {
			return s, invalid("invalid LDAP group filter placeholders")
		}
		if _, e := ldap.CompileFilter(filter); e != nil {
			return s, invalid("invalid LDAP group filter")
		}
		s.LDAP = &l
	default:
		return s, invalid("provider type must be oidc or ldap")
	}
	return s, nil
}
func normalizeApplicationAccess(s applicationAccessSettings) (applicationAccessSettings, error) {
	if s.SessionMinutes == 0 {
		s.SessionMinutes = 30
	}
	if s.SessionMinutes < 5 || s.SessionMinutes > 1440 {
		return s, invalid("session_minutes must be between 5 and 1440")
	}
	if s.AllowedGroups == nil {
		s.AllowedGroups = []string{}
	}
	if len(s.AllowedGroups) > 100 {
		return s, invalid("at most 100 allowed groups")
	}
	seen := map[string]bool{}
	for _, g := range s.AllowedGroups {
		if g == "" || len(g) > 2048 || strings.TrimSpace(g) != g || seen[g] {
			return s, invalid("provide distinct nonempty group identifiers")
		}
		seen[g] = true
	}
	if s.AllowAnyAuthenticated && len(s.AllowedGroups) > 0 {
		return s, invalid("choose groups or allow all authenticated users, not both")
	}
	if s.Enabled && (s.ProviderID < 1 || (!s.AllowAnyAuthenticated && len(s.AllowedGroups) == 0)) {
		return s, invalid("choose a provider and allowed groups, or explicitly allow all authenticated users")
	}
	if s.PublicOrigin != "" || s.Enabled {
		u, e := providerURL(s.PublicOrigin, false)
		if e != nil {
			return s, e
		}
		if u.Path != "" && u.Path != "/" {
			return s, invalid("public_origin must be an HTTPS origin without a path")
		}
		if u.Port() == "443" {
			u.Host = u.Hostname()
			if strings.Contains(u.Host, ":") {
				u.Host = "[" + u.Host + "]"
			}
		}
		s.PublicOrigin = "https://" + strings.ToLower(u.Host)
	}
	return s, nil
}
func identityAllowed(settings applicationAccessSettings, identity applicationIdentity, providerType string) bool {
	if identity.Subject == "" {
		return false
	}
	if settings.AllowAnyAuthenticated {
		return true
	}
	for _, wanted := range settings.AllowedGroups {
		for _, group := range identity.Groups {
			if providerType == "ldap" {
				a, ea := ldap.ParseDN(wanted)
				b, eb := ldap.ParseDN(group)
				if ea == nil && eb == nil && a.EqualFold(b) {
					return true
				}
			} else if wanted == group {
				return true
			}
		}
	}
	return false
}
