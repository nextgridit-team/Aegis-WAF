package app

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// JA4 TLS client fingerprinting (FoxIO, https://github.com/FoxIO-LLC/ja4).
// The ClientHello is attacker-controlled network input: every field is read
// through a bounds-checked cursor, any inconsistency aborts parsing without
// panicking, and the fingerprint is computed only from what the client
// actually sent. It is never accepted from a client-supplied header.

type clientHello struct {
	legacyVersion       uint16
	sniPresent          bool
	ciphers             []uint16
	extensionTypes      []uint16
	supportedVersions   []uint16
	signatureAlgorithms []uint16
	alpnFirst           []byte
}

// ja4Cursor reads big-endian TLS fields with strict bounds. A failed read
// marks the whole parse invalid; the caller reports no fingerprint.
type ja4Cursor struct {
	data []byte
	off  int
	ok   bool
}

func (c *ja4Cursor) take(n int) []byte {
	if !c.ok || n < 0 || c.off+n > len(c.data) {
		c.ok = false
		return nil
	}
	v := c.data[c.off : c.off+n]
	c.off += n
	return v
}

func (c *ja4Cursor) uint8() uint8 {
	v := c.take(1)
	if !c.ok {
		return 0
	}
	return v[0]
}

func (c *ja4Cursor) uint16() uint16 {
	v := c.take(2)
	if !c.ok {
		return 0
	}
	return uint16(v[0])<<8 | uint16(v[1])
}

// vector8 reads a one-byte length-prefixed vector.
func (c *ja4Cursor) vector8() []byte {
	n := int(c.uint8())
	return c.take(n)
}

// vector16 reads a two-byte length-prefixed vector.
func (c *ja4Cursor) vector16() []byte {
	n := int(c.uint16())
	return c.take(n)
}

// uint16Vector decodes a length-prefixed list of two-byte values, rejecting
// an odd trailing byte.
func uint16Vector(data []byte, oneByteLength bool) []uint16 {
	c := &ja4Cursor{data: data, ok: true}
	var raw []byte
	if oneByteLength {
		raw = c.vector8()
	} else {
		raw = c.vector16()
	}
	if !c.ok || c.off != len(data) || len(raw)%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		out = append(out, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return out
}

// parseClientHello decodes a ClientHello body — the bytes after the four-byte
// handshake header. It reports ok only for a structurally complete hello, so
// every strict prefix of a valid hello is rejected.
func parseClientHello(body []byte) (clientHello, bool) {
	var hello clientHello
	c := &ja4Cursor{data: body, ok: true}
	hello.legacyVersion = c.uint16()
	c.take(32)  // random
	c.vector8() // legacy session id
	hello.ciphers = uint16List(c)
	c.vector8() // compression methods
	extensions := c.vector16()
	if !c.ok || c.off != len(body) {
		return hello, false
	}
	e := &ja4Cursor{data: extensions, ok: true}
	for e.ok && e.off < len(extensions) {
		typ := e.uint16()
		data := e.vector16()
		if !e.ok {
			return hello, false
		}
		hello.extensionTypes = append(hello.extensionTypes, typ)
		switch typ {
		case 0x0000: // server_name: only presence matters for JA4
			hello.sniPresent = true
		case 0x0010: // application_layer_protocol_negotiation
			hello.alpnFirst = firstALPNValue(data)
		case 0x000d: // signature_algorithms (two-byte length)
			hello.signatureAlgorithms = uint16Vector(data, false)
		case 0x002b: // supported_versions (one-byte length)
			hello.supportedVersions = uint16Vector(data, true)
		}
	}
	if !e.ok || e.off != len(extensions) {
		return hello, false
	}
	return hello, true
}

func uint16List(c *ja4Cursor) []uint16 {
	raw := c.vector16()
	if !c.ok || len(raw)%2 != 0 {
		c.ok = false
		return nil
	}
	out := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		out = append(out, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return out
}

// firstALPNValue returns the first protocol identifier of the ALPN list, or
// nil when the extension carries no parseable value. Later values in the list
// are irrelevant to the fingerprint.
func firstALPNValue(data []byte) []byte {
	c := &ja4Cursor{data: data, ok: true}
	list := c.vector16()
	if !c.ok || len(list) == 0 {
		return nil
	}
	p := &ja4Cursor{data: list, ok: true}
	return p.vector8()
}

// clientHelloJA4 computes the JA4 fingerprint of a ClientHello body.
func clientHelloJA4(body []byte) (string, bool) {
	hello, ok := parseClientHello(body)
	if !ok {
		return "", false
	}
	return hello.JA4(), true
}

// isGREASE reports RFC 8701 GREASE values (0x0a0a, 0x1a1a … 0xfafa): both
// bytes equal with a trailing 0xa nibble. They are ignored anywhere JA4
// counts, sorts or hashes a list.
func isGREASE(v uint16) bool {
	return v&0xff == v>>8 && v&0x0f == 0x0a
}

// tlsVersionCode maps a protocol version to its two-character JA4 form.
func tlsVersionCode(v uint16) (string, bool) {
	switch v {
	case 0x0304:
		return "13", true
	case 0x0303:
		return "12", true
	case 0x0302:
		return "11", true
	case 0x0301:
		return "10", true
	case 0x0300:
		return "s3", true
	case 0x0002:
		return "s2", true
	case 0xfeff:
		return "d1", true
	case 0xfefd:
		return "d2", true
	case 0xfefc:
		return "d3", true
	}
	return "", false
}

// versionCode prefers the highest known version advertised in
// supported_versions — GREASE and unmapped values such as TLS 1.3 drafts are
// skipped — and falls back to the legacy version field.
func (h clientHello) versionCode() string {
	best, found := uint16(0), false
	for _, v := range h.supportedVersions {
		if isGREASE(v) {
			continue
		}
		if _, known := tlsVersionCode(v); !known {
			continue
		}
		if !found || v > best {
			best, found = v, true
		}
	}
	if found {
		code, _ := tlsVersionCode(best)
		return code
	}
	if code, known := tlsVersionCode(h.legacyVersion); known {
		return code
	}
	return "00"
}

// alpnChars renders the first ALPN value for part A: its first and last
// characters when both endpoint bytes are ASCII alphanumeric, otherwise the
// first and last nibble of the value's lowercase hex form.
func alpnChars(value []byte) string {
	if len(value) == 0 {
		return "00"
	}
	alnum := func(b byte) bool {
		return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
	}
	if alnum(value[0]) && alnum(value[len(value)-1]) {
		return string([]byte{value[0], value[len(value)-1]})
	}
	encoded := hex.EncodeToString(value)
	return encoded[:1] + encoded[len(encoded)-1:]
}

func ja4Hex(v uint16) string {
	encoded := make([]byte, 4)
	hex.Encode(encoded, []byte{byte(v >> 8), byte(v)})
	return string(encoded)
}

func ja4TruncatedHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:12]
}

// JA4 renders the fingerprint: ten characters of connection details, then
// truncated SHA-256 hashes of the sorted cipher list and of the sorted
// extension list (without SNI and ALPN) joined to the signature algorithms in
// their original order.
func (h clientHello) JA4() string {
	ciphers := make([]uint16, 0, len(h.ciphers))
	for _, v := range h.ciphers {
		if !isGREASE(v) {
			ciphers = append(ciphers, v)
		}
	}
	// The part A count includes SNI and ALPN; only the part C hash excludes
	// them, so the same application keeps its hash regardless of destination
	// domain or negotiated protocol.
	counted := 0
	hashed := make([]uint16, 0, len(h.extensionTypes))
	for _, v := range h.extensionTypes {
		if isGREASE(v) {
			continue
		}
		counted++
		if v != 0x0000 && v != 0x0010 {
			hashed = append(hashed, v)
		}
	}
	signatures := make([]uint16, 0, len(h.signatureAlgorithms))
	for _, v := range h.signatureAlgorithms {
		if !isGREASE(v) {
			signatures = append(signatures, v)
		}
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	sort.Slice(hashed, func(i, j int) bool { return hashed[i] < hashed[j] })
	sni := "i"
	if h.sniPresent {
		sni = "d"
	}
	partA := "t" + h.versionCode() + sni + paddedCount(len(ciphers)) + paddedCount(counted) + alpnChars(h.alpnFirst)
	partB := "000000000000"
	if len(ciphers) > 0 {
		partB = ja4TruncatedHash(joinHex(ciphers))
	}
	partC := "000000000000"
	if len(hashed) > 0 {
		input := joinHex(hashed)
		if len(signatures) > 0 {
			input += "_" + joinHex(signatures)
		}
		partC = ja4TruncatedHash(input)
	}
	return partA + "_" + partB + "_" + partC
}

func paddedCount(n int) string {
	if n > 99 {
		n = 99
	}
	digits := [2]byte{'0', '0'}
	if n >= 10 {
		digits[0] = byte('0' + n/10)
	}
	digits[1] = byte('0' + n%10)
	return string(digits[:])
}

func joinHex(values []uint16) string {
	out := make([]byte, 0, len(values)*5)
	for i, v := range values {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, ja4Hex(v)...)
	}
	return string(out)
}
