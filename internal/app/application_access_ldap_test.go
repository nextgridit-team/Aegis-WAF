package app

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// A small real TLS/BER directory exercises binds, filters, membership searches
// and StartTLS without substituting the LDAP client implementation.
func testLDAPDirectory(t *testing.T, startTLS bool) (string, string) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.TLS.Certificates[0]
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certServer.Certificate().Raw}))
	certServer.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	write := func(conn net.Conn, id int64, op *ber.Packet) error {
		message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		message.AppendChild(op)
		_, e := conn.Write(message.Bytes())
		return e
	}
	result := func(tag ber.Tag, code int64) *ber.Packet {
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
		op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		return op
	}
	entry := func(dn string, attrs map[string][]string) *ber.Packet {
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
		list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for name, values := range attrs {
			attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			for _, value := range values {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
			}
			attr.AppendChild(set)
			list.AppendChild(attr)
		}
		op.AppendChild(list)
		return op
	}
	go func() {
		defer wg.Done()
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				var conn net.Conn = raw
				secure := !startTLS
				if secure {
					conn = tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				}
				for {
					packet, e := ber.ReadPacket(conn)
					if e != nil {
						return
					}
					if len(packet.Children) != 2 {
						return
					}
					id := packet.Children[0].Value.(int64)
					op := packet.Children[1]
					if op.Tag == 23 && !secure {
						if e = write(conn, id, result(24, 0)); e != nil {
							return
						}
						conn = tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
						secure = true
						continue
					}
					if !secure {
						t.Error("LDAP operation before TLS")
						return
					}
					switch op.Tag {
					case 0:
						dn := op.Children[1].Value.(string)
						password := string(op.Children[2].Data.Bytes())
						code := int64(49)
						if dn == "cn=reader,dc=example,dc=test" && password == "read-secret" || dn == "uid=alice,ou=people,dc=example,dc=test" && password == "wonderland" || password == "" {
							code = 0
						}
						if e = write(conn, id, result(1, code)); e != nil {
							return
						}
					case 3:
						base := op.Children[0].Value.(string)
						filter, e := ldap.DecompileFilter(op.Children[6])
						if e != nil {
							return
						}
						if base == "ou=people,dc=example,dc=test" && filter == "(uid=alice)" {
							if e = write(conn, id, entry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{"uid": {"alice"}, "mail": {"alice@example.test"}, "memberOf": {"cn=finance,ou=groups,dc=example,dc=test"}})); e != nil {
								return
							}
						}
						if base == "ou=groups,dc=example,dc=test" {
							if e = write(conn, id, entry("cn=finance,ou=groups,dc=example,dc=test", map[string][]string{"cn": {"Finance"}})); e != nil {
								return
							}
						}
						if e = write(conn, id, result(5, 0)); e != nil {
							return
						}
					case 2:
						return
					default:
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); wg.Wait() })
	scheme := "ldaps://"
	if startTLS {
		scheme = "ldap://"
	}
	return scheme + listener.Addr().String(), ca
}

func TestApplicationLDAPLogin(t *testing.T) {
	a, b, api, site, _ := captchaFixture(t)
	for _, startTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("startTLS=%t", startTLS), func(t *testing.T) {
			address, ca := testLDAPDirectory(t, startTLS)
			input := identityProviderInput{identityProviderSettings: identityProviderSettings{Name: "Directory <test>", Type: "ldap", Enabled: true, CAPEM: ca, LDAP: &ldapSettings{URL: address, BindDN: "cn=reader,dc=example,dc=test", UserBaseDN: "ou=people,dc=example,dc=test", GroupBaseDN: "ou=groups,dc=example,dc=test"}}, Secret: "read-secret"}
			provider := mustID(t, api.call("POST", "/api/identity-providers", input, 200))
			path := fmt.Sprintf("/api/identity-providers/%d", provider)
			p, e := readIdentityProvider(context.Background(), a.db, provider)
			if e != nil {
				t.Fatal(e)
			}
			for _, creds := range [][2]string{{"alice", ""}, {"alice", "wrong"}, {"alice)(uid=*)", "wonderland"}} {
				if _, e = a.ldapIdentity(context.Background(), p, creds[0], creds[1]); e == nil {
					t.Fatal("invalid directory credential accepted", creds[0])
				}
			}
			untrusted := p
			untrusted.Settings.CAPEM = ""
			if _, e = a.ldapIdentity(context.Background(), untrusted, "alice", "wonderland"); e == nil {
				t.Fatal("untrusted directory certificate accepted")
			}
			if raw := api.call("POST", path+"/test", map[string]any{}, 200); !strings.Contains(string(raw), `"ok":true`) {
				t.Fatal(string(raw))
			}
			if raw := api.call("POST", path+"/groups", map[string]string{"search": "finance"}, 200); !strings.Contains(string(raw), "cn=finance,ou=groups,dc=example,dc=test") {
				t.Fatal(string(raw))
			}
			old, e := readApplicationAccess(context.Background(), a.db, site)
			if e != nil {
				t.Fatal(e)
			}
			api.call("PUT", fmt.Sprintf("/api/application-access/%d", site), applicationAccessInput{Revision: old.Revision, applicationAccessSettings: applicationAccessSettings{Enabled: true, ProviderID: provider, PublicOrigin: "https://bot.test", AllowedGroups: []string{"CN=finance,OU=groups,DC=example,DC=test"}, SessionMinutes: 30}}, 200)
			for _, app := range []*App{a, b} {
				if e = app.refresh(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			w, _ := botProbe(t, a, "GET", applicationAuthPrefix+"login?return=%2Fprivate", "Mozilla/5.0", "")
			if w.Code != 200 || strings.Contains(w.Body.String(), "Directory <test>") {
				t.Fatal("unsafe login page", w.Code)
			}
			var browser *http.Cookie
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == applicationFlowCookie {
					browser = cookie
				}
			}
			if browser == nil {
				t.Fatal("missing browser binding")
			}
			form := url.Values{"username": {"alice"}, "password": {"wonderland"}, "csrf": {"bad"}, "return": {"//evil.test"}}
			w, _ = botProbe(t, b, "POST", applicationAuthPrefix+"login", "Mozilla/5.0", form.Encode(), browser)
			if w.Code != 403 {
				t.Fatal("login CSRF accepted", w.Code)
			}
			form.Set("csrf", hash(browser.Value))
			w, event := botProbe(t, b, "POST", applicationAuthPrefix+"login", "Mozilla/5.0", form.Encode(), browser)
			if w.Code != 303 || w.Header().Get("Location") != "https://bot.test/" || event.evidence != nil {
				t.Fatal("LDAP login failed", w.Code, w.Body.String())
			}
			var session *http.Cookie
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == applicationSessionCookie {
					session = cookie
				}
			}
			if session == nil {
				t.Fatal("missing session")
			}
			w, _ = botProbe(t, a, "GET", "/private", "Mozilla/5.0", "", session)
			if w.Code != 200 {
				t.Fatal("directory session not shared", w.Code)
			}
			form = url.Values{"csrf": {hash(session.Value + ":logout")}}
			w, _ = botProbe(t, b, "POST", applicationAuthPrefix+"logout", "Mozilla/5.0", form.Encode(), session)
			if w.Code != 200 {
				t.Fatal("logout failed", w.Code)
			}
			w, _ = botProbe(t, a, "GET", "/private", "Mozilla/5.0", "", session)
			if w.Code != 302 {
				t.Fatal("logout session still accepted", w.Code)
			}
		})
	}
}
