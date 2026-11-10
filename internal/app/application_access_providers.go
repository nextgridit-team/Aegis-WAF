package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"
)

// Set once before any directory connection is opened, never during requests.
func init() { ber.MaxPacketLengthBytes = 1 << 20 }

type identityHTTPTransport struct {
	base    http.RoundTripper
	origins map[string]bool
}

func (t identityHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil || !t.origins["https://"+strings.ToLower(r.URL.Host)] {
		return nil, errors.New("OIDC endpoint origin is not trusted")
	}
	response, e := t.base.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("OIDC response exceeds 1 MiB")
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, nil
}
func (a *App) oidcProvider(ctx context.Context, p storedIdentityProvider, origin string) (*oidc.Provider, *oauth2.Config, context.Context, error) {
	settings := p.Settings.OIDC
	u, e := providerURL(settings.Issuer, false)
	if e != nil {
		return nil, nil, ctx, e
	}
	tlsConfig, e := identityTLS(p.Settings.CAPEM)
	if e != nil {
		return nil, nil, ctx, e
	}
	origins := map[string]bool{"https://" + strings.ToLower(u.Host): true}
	// Google's documented discovery uses these separate token and key origins.
	if settings.Issuer == "https://accounts.google.com" {
		origins["https://oauth2.googleapis.com"] = true
		origins["https://www.googleapis.com"] = true
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, DisableKeepAlives: true}
	var base http.RoundTripper = transport
	if a.identityHTTP != nil {
		base = a.identityHTTP
	}
	client := &http.Client{Transport: identityHTTPTransport{base: base, origins: origins}, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects are not accepted") }}
	ctx = oidc.ClientContext(ctx, client)
	provider, e := oidc.NewProvider(ctx, settings.Issuer)
	if e != nil {
		return nil, nil, ctx, e
	}
	endpoint := provider.Endpoint()
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if e = provider.Claims(&metadata); e != nil {
		return nil, nil, ctx, e
	}
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKS} {
		target, err := providerURL(raw, false)
		if err != nil || !origins["https://"+strings.ToLower(target.Host)] {
			return nil, nil, ctx, errors.New("OIDC discovery advertises an untrusted endpoint origin")
		}
	}
	secret, e := a.identitySecret(p)
	if e != nil {
		return nil, nil, ctx, e
	}
	config := &oauth2.Config{ClientID: settings.ClientID, ClientSecret: secret, Endpoint: endpoint, Scopes: settings.Scopes, RedirectURL: origin + applicationAuthPrefix + "callback"}
	return provider, config, ctx, nil
}

type boundedLDAPConn struct {
	net.Conn
	remaining int64
}

func (c *boundedLDAPConn) Read(b []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errors.New("LDAP response budget exceeded")
	}
	if int64(len(b)) > c.remaining {
		b = b[:c.remaining]
	}
	n, e := c.Conn.Read(b)
	c.remaining -= int64(n)
	return n, e
}
func (a *App) connectLDAP(ctx context.Context, p storedIdentityProvider) (*ldap.Conn, func(), error) {
	u, e := providerURL(p.Settings.LDAP.URL, true)
	if e != nil {
		return nil, nil, e
	}
	tlsConfig, e := identityTLS(p.Settings.CAPEM)
	if e != nil {
		return nil, nil, e
	}
	tlsConfig.ServerName = u.Hostname()
	port := u.Port()
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	raw, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if e != nil {
		return nil, nil, e
	}
	socket := net.Conn(&boundedLDAPConn{Conn: raw, remaining: 2 << 20})
	if u.Scheme == "ldaps" {
		secure := tls.Client(socket, tlsConfig)
		if e = secure.HandshakeContext(ctx); e != nil {
			raw.Close()
			return nil, nil, e
		}
		socket = secure
	}
	conn := ldap.NewConn(socket, u.Scheme == "ldaps")
	conn.Start()
	conn.SetTimeout(5 * time.Second)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	cleanup := func() { stop(); conn.Close() }
	if u.Scheme == "ldap" {
		if e = conn.StartTLS(tlsConfig); e != nil {
			cleanup()
			return nil, nil, e
		}
	}
	secret, e := a.identitySecret(p)
	if e != nil || secret == "" {
		cleanup()
		return nil, nil, errors.New("directory bind credential unavailable")
	}
	if e = conn.Bind(p.Settings.LDAP.BindDN, secret); e != nil {
		cleanup()
		return nil, nil, e
	}
	return conn, cleanup, nil
}
func (a *App) ldapIdentity(ctx context.Context, p storedIdentityProvider, username, password string) (applicationIdentity, error) {
	identity := applicationIdentity{Groups: []string{}}
	if username == "" || len(username) > 256 || password == "" || len(password) > 4096 || strings.ContainsAny(username, "\x00\r\n") {
		return identity, errors.New("invalid directory credentials")
	}
	conn, close, e := a.connectLDAP(ctx, p)
	if e != nil {
		return identity, e
	}
	defer close()
	settings := p.Settings.LDAP
	filter := strings.ReplaceAll(settings.UserFilter, "{username}", ldap.EscapeFilter(username))
	result, e := conn.Search(ldap.NewSearchRequest(settings.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{settings.UsernameAttribute, settings.EmailAttribute, settings.GroupsAttribute}, nil))
	if e != nil || len(result.Entries) != 1 {
		return identity, errors.New("directory identity not uniquely resolved")
	}
	entry := result.Entries[0]
	// A nonempty password is mandatory: an empty LDAP simple bind can succeed
	// anonymously even when its DN names a real user.
	if e = conn.Bind(entry.DN, password); e != nil {
		return identity, errors.New("invalid directory credentials")
	}
	identity.Subject = entry.DN
	identity.Username = entry.GetAttributeValue(settings.UsernameAttribute)
	identity.Email = entry.GetAttributeValue(settings.EmailAttribute)
	if identity.Username == "" {
		identity.Username = username
	}
	identity.Groups = entry.GetAttributeValues(settings.GroupsAttribute)
	if settings.GroupBaseDN != "" {
		secret, e := a.identitySecret(p)
		if e != nil {
			return applicationIdentity{}, e
		}
		if e = conn.Bind(settings.BindDN, secret); e != nil {
			return applicationIdentity{}, e
		}
		filter = strings.NewReplacer("{dn}", ldap.EscapeFilter(entry.DN), "{username}", ldap.EscapeFilter(username)).Replace(settings.GroupFilter)
		groups, e := conn.Search(ldap.NewSearchRequest(settings.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 5, false, filter, []string{settings.GroupNameAttribute}, nil))
		if e != nil {
			return applicationIdentity{}, e
		}
		for _, group := range groups.Entries {
			identity.Groups = append(identity.Groups, group.DN)
		}
	}
	if !boundedApplicationIdentity(identity) {
		return applicationIdentity{}, errors.New("directory identity exceeds limits")
	}
	return identity, nil
}
func boundedApplicationIdentity(identity applicationIdentity) bool {
	if identity.Subject == "" || len(identity.Subject) > 2048 || len(identity.Username) > 512 || len(identity.Email) > 512 || len(identity.Groups) > 512 {
		return false
	}
	for _, g := range identity.Groups {
		if g == "" || len(g) > 2048 {
			return false
		}
	}
	return true
}
func (a *App) identityWork(r *http.Request) (func(), error) {
	if e := a.throttle(r.Context(), "application-auth-global", 300, time.Minute); e != nil {
		return nil, e
	}
	select {
	case a.identitySlots <- struct{}{}:
		return func() { <-a.identitySlots }, nil
	default:
		return nil, apiError{503, "authentication capacity reached; retry shortly"}
	}
}
func (a *App) testIdentityProvider(w http.ResponseWriter, r *http.Request, actor identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	p, e := readIdentityProvider(r.Context(), a.db, id)
	if e != nil {
		return e
	}
	release, e := a.identityWork(r)
	if e != nil {
		return e
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	stage := "oidc_discovery"
	message := "Discovery, TLS and endpoint origins verified. Register each application's callback URL, then test a real sign-in."
	if p.Settings.Type == "oidc" {
		_, _, _, e = a.oidcProvider(ctx, p, "")
	} else {
		stage = "ldap_bind"
		message = "TLS and service bind verified. Use group lookup to select allowed group distinguished names."
		var cleanup func()
		_, cleanup, e = a.connectLDAP(ctx, p)
		if cleanup != nil {
			cleanup()
		}
	}
	if e != nil {
		stage, message = identityFailure(e, stage)
	}
	if _, err := a.db.Exec(r.Context(), "INSERT INTO audit_events(actor,action,resource) VALUES($1,'identity_provider.tested',$2)", actor.Username, strconv.FormatInt(id, 10)); err != nil {
		return err
	}
	respond(w, 200, map[string]any{"ok": e == nil, "stage": stage, "message": message})
	return nil
}

func identityFailure(err error, stage string) (string, string) {
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	var network *net.OpError
	switch {
	case errors.As(err, &authority):
		return "tls_trust", "Provider certificate issuer is not trusted. Add the directory or identity provider's CA certificate."
	case errors.As(err, &hostname):
		return "tls_name", "Provider certificate does not cover the configured hostname. Use a hostname covered by its certificate."
	case errors.As(err, &certificate):
		return "tls_certificate", "Provider certificate is expired, not yet valid, or otherwise invalid. Check the certificate and system clock."
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return "ldap_bind", "Directory rejected the service bind credentials. Check the bind DN, password and account status."
	case errors.As(err, &network):
		return "network", "Cannot connect to the provider. Check DNS, the configured port and network reachability from Aegis."
	default:
		return stage, "Provider test failed. Check discovery metadata, trusted endpoint origins, credentials and network reachability."
	}
}
func (a *App) identityGroups(w http.ResponseWriter, r *http.Request, _ identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	p, e := readIdentityProvider(r.Context(), a.db, id)
	if e != nil {
		return e
	}
	if p.Settings.Type != "ldap" {
		respond(w, 200, map[string]any{"supported": false, "groups": []any{}, "message": "OIDC has no standard group directory API. Enter exact groups or roles from the configured token claim."})
		return nil
	}
	var input struct {
		Search string `json:"search"`
	}
	if e = decode(w, r, &input); e != nil {
		return e
	}
	if len(input.Search) > 120 {
		return invalid("group search is limited to 120 bytes")
	}
	if p.Settings.LDAP.GroupBaseDN == "" {
		return invalid("configure group_base_dn before browsing directory groups")
	}
	release, e := a.identityWork(r)
	if e != nil {
		return e
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	conn, cleanup, e := a.connectLDAP(ctx, p)
	if e != nil {
		return apiError{502, "directory connection or service bind failed"}
	}
	defer cleanup()
	filter := "(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(" + p.Settings.LDAP.GroupNameAttribute + "=*" + ldap.EscapeFilter(input.Search) + "*))"
	result, e := conn.Search(ldap.NewSearchRequest(p.Settings.LDAP.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 100, 5, false, filter, []string{p.Settings.LDAP.GroupNameAttribute}, nil))
	truncated := ldap.IsErrorWithCode(e, ldap.LDAPResultSizeLimitExceeded)
	if e != nil && !truncated {
		return apiError{502, "directory group lookup failed"}
	}
	groups := []map[string]string{}
	if result != nil {
		for _, entry := range result.Entries {
			if len(groups) >= 100 {
				truncated = true
				break
			}
			groups = append(groups, map[string]string{"id": entry.DN, "name": entry.GetAttributeValue(p.Settings.LDAP.GroupNameAttribute)})
		}
	}
	respond(w, 200, map[string]any{"supported": true, "groups": groups, "truncated": truncated})
	return nil
}
