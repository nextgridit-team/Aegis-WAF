package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUpstreamTLSNameAndExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		now := time.Now()
		to := now.Add(time.Hour)
		if expired {
			to = now.Add(-time.Hour)
		}
		chain, key := testCertificate(t, []string{"backend.test"}, 123, now.Add(-2*time.Hour), to)
		pair, e := tls.X509KeyPair([]byte(chain), []byte(key))
		if e != nil {
			t.Fatal(e)
		}
		hosts := make(chan string, 1)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hosts <- r.Host; io.WriteString(w, "ok") }))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		server.StartTLS()
		result := probeUpstream(context.Background(), server.URL, upstreamTLSSettings{ServerName: "backend.test", TrustedCertsPEM: chain}, "public.test")
		if expired {
			if result.Reachable || result.Stage != "tls_certificate" || (result.Certificate != nil && result.Certificate.CanTrust) {
				t.Fatal("expired pin trusted", result)
			}
		} else {
			if !result.Reachable || !result.TLSVerified {
				t.Fatal("server name override failed", result)
			}
			if <-hosts != "public.test" {
				t.Fatal("server name changed Host header")
			}
		}
		server.Close()
	}
}
func TestUpstreamProbeCancellationAndCapacity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := probeUpstream(ctx, server.URL, upstreamTLSSettings{}, "")
	if result.Reachable || result.Stage != "timeout" || time.Since(start) > time.Second {
		t.Fatal("probe did not honor deadline", result)
	}
	a := &App{upstreamTests: make(chan struct{}, 4)}
	for range 4 {
		a.upstreamTests <- struct{}{}
	}
	request := httptest.NewRequest("POST", "/api/upstreams/test", strings.NewReader(`{"upstream":"http://127.0.0.1:12345"}`))
	request.Header.Set("Content-Type", "application/json")
	if e := a.testUpstream(httptest.NewRecorder(), request, identity{}); e == nil {
		t.Fatal("probe capacity ignored")
	} else if api, ok := e.(apiError); !ok || api.status != 429 {
		t.Fatalf("wrong capacity error: %#v", e)
	}
}

func TestUpstreamCertificatePEMSizeBoundary(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tc := range []struct {
		name      string
		derSize   int
		wantTrust bool
	}{
		{"largest importable PEM", 48354, true},
		{"first oversized PEM", 48355, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1), DNSNames: []string{"backend.test"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 47000)}},
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
			if err != nil {
				t.Fatal(err)
			}
			template.ExtraExtensions[0].Value = make([]byte, 47000+tc.derSize-len(der))
			der, err = x509.CreateCertificate(rand.Reader, template, template, public, private)
			if err != nil {
				t.Fatal(err)
			}
			if len(der) != tc.derSize || len(der) > 48<<10 {
				t.Fatalf("unexpected DER size: %d", len(der))
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			encoded := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			_, importErr := upstreamTLSConfig(upstreamTLSSettings{TrustedCertsPEM: encoded})
			if (importErr == nil) != tc.wantTrust {
				t.Fatalf("unexpected import result for %d-byte PEM: %v", len(encoded), importErr)
			}
			peer := describeUpstreamCertificate(cert, "backend.test", true)
			if !tc.wantTrust {
				if peer != nil {
					t.Fatal("offered a certificate whose PEM exceeds the trust limit")
				}
				return
			}
			if peer == nil || !peer.CanTrust || peer.PEM != encoded {
				t.Fatal("importable boundary certificate was not offered for trust")
			}
		})
	}
}
