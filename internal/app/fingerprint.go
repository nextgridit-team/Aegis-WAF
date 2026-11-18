package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

// Client fingerprinting, phase 1. A wrapped listener captures the TLS
// ClientHello below the TLS server so a JA4 fingerprint is computed from what
// the client actually sends, and sites that opt in get it as a rate-limit
// identity dimension and an investigation field. The stored and keyed form is
// always an install-key HMAC scoped to the site: a bare hash of a low-entropy
// fingerprint would be dictionary-reversible, and a site-scoped MAC cannot
// be correlated across applications. Raw JA4 values are never persisted.

// fingerprintPeekLimit bounds the bytes buffered while looking for a complete
// ClientHello. Anything larger gives up on fingerprinting and replays what was
// read; the TLS server rejects oversized hellos itself.
const fingerprintPeekLimit = 1 << 16

// clientFingerprintKey carries the site-scoped fingerprint HMAC through the
// request context, mirroring the existing rate-state and connection keys. It
// is set by Public only for sites that opted in, so every other request path
// is untouched.
type clientFingerprintKey struct{}

// NewFingerprintListener wraps the public HTTPS listener so accepted
// connections capture the client's ClientHello before the TLS server reads
// it. The peek is lazy — it runs on the first read of the TLS handshake, never
// on the accept loop, so a client that stalls cannot delay other
// connections, and the connection's existing deadlines apply unchanged.
func NewFingerprintListener(l net.Listener) net.Listener {
	return &fingerprintListener{Listener: l}
}

type fingerprintListener struct{ net.Listener }

func (l *fingerprintListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &fingerprintConn{Conn: c}, nil
}

// fingerprintConn is a transparent net.Conn that inspects the first TLS
// handshake records. Everything read is replayed byte-for-byte to the TLS
// server above it; the handshake, deadlines and error behavior are unchanged
// apart from that buffered copy. The direct read path deliberately runs
// WITHOUT the mutex: http.Server keeps a background reader on the connection
// while the handler runs, so blocking on the socket while holding the mutex
// would deadlock a handler waiting for the fingerprint.
type fingerprintConn struct {
	net.Conn
	mu       sync.Mutex
	buffered []byte
	peeked   bool
	savedErr error
	ja4Value string
}

func (c *fingerprintConn) ja4() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ja4Value
}

func (c *fingerprintConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.peeked {
		// The peek blocks only during the TLS handshake, before any request
		// handler or background reader exists on this connection, so holding
		// the mutex across its reads cannot deadlock a reader.
		c.peek()
	}
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		c.mu.Unlock()
		return n, nil
	}
	err := c.savedErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// fill reads exactly len(want) bytes, appending everything consumed to raw so
// it is replayed later. An error is saved and surfaces after the buffer
// drains, matching io.Reader semantics for partial reads.
func (c *fingerprintConn) fill(raw *[]byte, want []byte) bool {
	for len(want) > 0 {
		n, e := c.Conn.Read(want)
		*raw = append(*raw, want[:n]...)
		want = want[n:]
		if e != nil {
			if c.savedErr == nil {
				c.savedErr = e
			}
			return false
		}
	}
	return true
}

// peek reads TLS records until the ClientHello handshake message is complete
// and computes its JA4 fingerprint. It never sets deadlines and buffers at
// most fingerprintPeekLimit bytes; every failure mode replays what was read
// and leaves the fingerprint empty, leaving the TLS server's own validation
// untouched.
func (c *fingerprintConn) peek() {
	c.peeked = true
	var raw []byte
	readRecord := func() ([]byte, bool) {
		var head [5]byte
		if !c.fill(&raw, head[:]) {
			return nil, false
		}
		if head[0] != 0x16 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(head[3:5]))
		if n < 4 || len(raw)+n > fingerprintPeekLimit {
			return nil, false
		}
		body := make([]byte, n)
		if !c.fill(&raw, body) {
			return nil, false
		}
		return body, true
	}
	payload, ok := readRecord()
	if ok && len(payload) >= 4 && payload[0] == 0x01 {
		// The handshake message may span several records; reassemble it
		// before parsing.
		message := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		for ok && len(payload) < 4+message {
			var more []byte
			more, ok = readRecord()
			payload = append(payload, more...)
		}
		if ok && message > 0 {
			if ja4, parsed := clientHelloJA4(payload[4 : 4+message]); parsed {
				c.ja4Value = ja4
			}
		}
	}
	c.buffered = raw
}

// connectionFingerprint returns the site-scoped HMAC of the request
// connection's JA4 fingerprint, or "" when the request did not arrive over a
// fingerprint-captured TLS connection (plain HTTP, or a handshake that could
// not be parsed). Raw JA4 never leaves this function.
func (a *App) connectionFingerprint(site int64, r *http.Request) string {
	conn, ok := r.Context().Value(connectionKey{}).(*tls.Conn)
	if !ok {
		return ""
	}
	wrapped, ok := conn.NetConn().(*fingerprintConn)
	if !ok {
		return ""
	}
	ja4 := wrapped.ja4()
	if ja4 == "" {
		return ""
	}
	return a.fingerprintMAC(site, ja4)
}

// fingerprintMAC keys the install encryption key through a purpose-separated
// HMAC and scopes the result to one site, so stored fingerprints cannot be
// reversed into a known JA4 dictionary or correlated across applications.
func (a *App) fingerprintMAC(site int64, ja4 string) string {
	mac := hmac.New(sha256.New, a.cfg.Key)
	io.WriteString(mac, "aegis-fingerprint-v1:")
	io.WriteString(mac, strconv.FormatInt(site, 10))
	io.WriteString(mac, ":")
	io.WriteString(mac, ja4)
	return hex.EncodeToString(mac.Sum(nil))
}
