package app

import (
	"encoding/binary"
	"testing"
)

// JA4 test vectors. The byte-level fixtures are built here from the exact
// lists published in the FoxIO JA4 technical specification and in an
// independent Rust implementation of the standard (crates.io `ja4`), whose
// worked example includes both the ClientHello construction and the expected
// fingerprint string. Hash expectations were cross-verified against sha256 of
// the spec's literal hash inputs before being pinned here.

func ja4TestExt(typ uint16, data []byte) []byte {
	out := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(data)))
	return append(out, data...)
}

func ja4TestSNI(name string) []byte {
	n := []byte(name)
	data := make([]byte, 5, 5+len(n))
	binary.BigEndian.PutUint16(data[0:2], uint16(3+len(n)))
	data[2] = 0
	binary.BigEndian.PutUint16(data[3:5], uint16(len(n)))
	copy(data[5:], n)
	return ja4TestExt(0x0000, data)
}

func ja4TestALPN(protos ...[]byte) []byte {
	total := 2
	for _, p := range protos {
		total += 1 + len(p)
	}
	data := make([]byte, 2, total)
	binary.BigEndian.PutUint16(data[0:2], uint16(total-2))
	for _, p := range protos {
		data = append(data, byte(len(p)))
		data = append(data, p...)
	}
	return ja4TestExt(0x0010, data)
}

func ja4TestUint16List(values ...uint16) []byte {
	out := make([]byte, 2, 2+2*len(values))
	binary.BigEndian.PutUint16(out[0:2], uint16(2*len(values)))
	for _, v := range values {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		out = append(out, b[:]...)
	}
	return out
}

func ja4TestSigAlgs(values ...uint16) []byte {
	return ja4TestExt(0x000d, ja4TestUint16List(values...))
}

func ja4TestSupportedVersions(values ...uint16) []byte {
	out := make([]byte, 1, 1+2*len(values))
	out[0] = byte(2 * len(values))
	for _, v := range values {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		out = append(out, b[:]...)
	}
	return ja4TestExt(0x002b, out)
}

// ja4TestHello builds a ClientHello body (everything after the four-byte
// handshake header) with a zero random, no session id and null compression.
func ja4TestHello(legacyVersion uint16, ciphers []uint16, extensions [][]byte) []byte {
	total := 0
	for _, e := range extensions {
		total += len(e)
	}
	size := 2 + 32 + 1 + 2 + 2*len(ciphers) + 1 + 1 + 2 + total
	body := make([]byte, 0, size)
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], legacyVersion)
	body = append(body, b[:]...)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	binary.BigEndian.PutUint16(b[:], uint16(2*len(ciphers)))
	body = append(body, b[:]...)
	for _, c := range ciphers {
		binary.BigEndian.PutUint16(b[:], c)
		body = append(body, b[:]...)
	}
	body = append(body, 1, 0)
	binary.BigEndian.PutUint16(b[:], uint16(total))
	body = append(body, b[:]...)
	for _, e := range extensions {
		body = append(body, e...)
	}
	return body
}

// The independent Rust implementation's documented example: TLS 1.2 record,
// one cipher, ALPN h2, one signature algorithm, supported_versions TLS 1.3,
// no SNI.
func ja4TestRustVectorHello() []byte {
	return ja4TestHello(0x0303, []uint16{0x1301}, [][]byte{
		ja4TestALPN([]byte("h2")),
		ja4TestSigAlgs(0x0403),
		ja4TestSupportedVersions(0x0304),
	})
}

func TestJA4RustCrateVector(t *testing.T) {
	ja4, ok := clientHelloJA4(ja4TestRustVectorHello())
	if !ok {
		t.Fatal("independent vector ClientHello did not parse")
	}
	if ja4 != "t13i0103h2_0f2cb44170f4_3953dc75acc4" {
		t.Fatalf("ja4 = %q, want t13i0103h2_0f2cb44170f4_3953dc75acc4", ja4)
	}
}

// The FoxIO specification's own worked example: 15 ciphers, 16 extensions
// (including SNI and ALPN), signature algorithms in original order.
func TestJA4SpecWorkedExample(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	extensions := [][]byte{
		ja4TestExt(0x001b, nil), ja4TestSNI("example.com"), ja4TestExt(0x0033, nil),
		ja4TestALPN([]byte("h2"), []byte("http/1.1")),
		ja4TestExt(0x4469, nil), ja4TestExt(0x0017, nil), ja4TestExt(0x002d, nil),
		ja4TestSigAlgs(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601),
		ja4TestExt(0x0005, nil), ja4TestExt(0x0023, nil), ja4TestExt(0x0012, nil),
		ja4TestSupportedVersions(0x0304),
		ja4TestExt(0xff01, nil), ja4TestExt(0x000b, nil), ja4TestExt(0x000a, nil), ja4TestExt(0x0015, nil),
	}
	ja4, ok := clientHelloJA4(ja4TestHello(0x0303, ciphers, extensions))
	if !ok {
		t.Fatal("spec ClientHello did not parse")
	}
	if ja4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("ja4 = %q, want t13d1516h2_8daaf6152771_e5627efa2ab1", ja4)
	}
}

// The specification's no-signature-algorithms example: the extension hash
// covers the extension list alone with no trailing underscore.
func TestJA4SpecNoSignatureAlgorithms(t *testing.T) {
	extensions := [][]byte{
		ja4TestExt(0x001b, nil), ja4TestSNI("example.com"), ja4TestExt(0x0033, nil),
		ja4TestALPN([]byte("h2")),
		ja4TestExt(0x4469, nil), ja4TestExt(0x0017, nil), ja4TestExt(0x002d, nil),
		ja4TestSigAlgs(),
		ja4TestExt(0x0005, nil), ja4TestExt(0x0023, nil), ja4TestExt(0x0012, nil),
		ja4TestSupportedVersions(0x0304),
		ja4TestExt(0xff01, nil), ja4TestExt(0x000b, nil), ja4TestExt(0x000a, nil), ja4TestExt(0x0015, nil),
	}
	ja4, ok := clientHelloJA4(ja4TestHello(0x0303, nil, extensions))
	if !ok {
		t.Fatal("spec no-signature-algorithms ClientHello did not parse")
	}
	// Cipher list is empty: JA4_b is the documented zero placeholder.
	if ja4 != "t13d0016h2_000000000000_6d807ffa2a79" {
		t.Fatalf("ja4 = %q, want t13d0016h2_000000000000_6d807ffa2a79", ja4)
	}
}

// GREASE values must not count toward either list or leak into either hash.
func TestJA4IgnoresGREASE(t *testing.T) {
	base := ja4TestRustVectorHello()
	ja4, ok := clientHelloJA4(base)
	if !ok {
		t.Fatal("base ClientHello did not parse")
	}
	greased := ja4TestHello(0x0303, []uint16{0x0a0a, 0x1301, 0x1a1a}, [][]byte{
		ja4TestALPN([]byte("h2")),
		ja4TestExt(0xaaaa, []byte{1, 2, 3}),
		ja4TestSigAlgs(0x0403),
		ja4TestSupportedVersions(0x7f1a, 0x0304),
	})
	// 0x7f1a is a TLS 1.3 draft, not GREASE: it must still be ignored as an
	// unknown version only when selecting the version, and the highest known
	// supported version (0x0304) wins.
	other, ok := clientHelloJA4(greased)
	if !ok {
		t.Fatal("greased ClientHello did not parse")
	}
	if other != ja4 {
		t.Fatalf("greased ja4 = %q, want identical to %q", other, ja4)
	}
}

func TestJA4ALPNRepresentation(t *testing.T) {
	cases := []struct {
		name   string
		ext    []byte
		expect string
	}{
		{"no alpn", nil, "00"},
		{"h2", ja4TestALPN([]byte("h2")), "h2"},
		{"http/1.1 first and last", ja4TestALPN([]byte("http/1.1")), "h1"},
		{"single character doubled", ja4TestALPN([]byte("h")), "hh"},
		{"binary bytes as hex", ja4TestALPN([]byte{0xAB, 0xCD}), "ad"},
		{"space then a", ja4TestALPN([]byte{0x20, 0x61}), "21"},
		{"alnum endpoints with binary middle", ja4TestALPN([]byte{0x30, 0xAB, 0xCD, 0x31}), "01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extensions := [][]byte{ja4TestSigAlgs(0x0403), ja4TestSupportedVersions(0x0304)}
			if tc.ext != nil {
				extensions = append(extensions, tc.ext)
			}
			ja4, ok := clientHelloJA4(ja4TestHello(0x0303, []uint16{0x1301}, extensions))
			if !ok {
				t.Fatal("ClientHello did not parse")
			}
			partA := ja4[:10]
			if got := partA[8:10]; got != tc.expect {
				t.Fatalf("alpn representation = %q, want %q (ja4 %s)", got, tc.expect, ja4)
			}
		})
	}
}

func TestJA4VersionSelection(t *testing.T) {
	cases := []struct {
		name      string
		legacy    uint16
		supported []uint16
		useExt    bool
		expect    string
	}{{
		name:   "legacy 1.2 without supported_versions",
		legacy: 0x0303,
		expect: "12",
	}, {
		name:   "legacy 1.0",
		legacy: 0x0301,
		expect: "10",
	}, {
		name:   "ssl 3.0",
		legacy: 0x0300,
		expect: "s3",
	}, {
		name:   "unknown legacy",
		legacy: 0x1234,
		expect: "00",
	}, {
		name:      "supported_versions highest known wins",
		legacy:    0x0303,
		useExt:    true,
		supported: []uint16{0x0303, 0x0304},
		expect:    "13",
	}, {
		name:      "supported_versions drafts do not downgrade",
		legacy:    0x0303,
		useExt:    true,
		supported: []uint16{0x7f1c},
		expect:    "12",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extensions := [][]byte{ja4TestALPN([]byte("h2"))}
			if tc.useExt {
				extensions = append(extensions, ja4TestSupportedVersions(tc.supported...))
			}
			ja4, ok := clientHelloJA4(ja4TestHello(tc.legacy, []uint16{0x1301}, extensions))
			if !ok {
				t.Fatal("ClientHello did not parse")
			}
			if got := ja4[1:3]; got != tc.expect {
				t.Fatalf("version = %q, want %q (ja4 %s)", got, tc.expect, ja4)
			}
		})
	}
}

func TestJA4CountsCappedAt99(t *testing.T) {
	ciphers := make([]uint16, 120)
	for i := range ciphers {
		ciphers[i] = uint16(0x1300 + i)
	}
	ja4, ok := clientHelloJA4(ja4TestHello(0x0303, ciphers, [][]byte{ja4TestALPN([]byte("h2"))}))
	if !ok {
		t.Fatal("ClientHello did not parse")
	}
	if got := ja4[4:6]; got != "99" {
		t.Fatalf("cipher count = %q, want 99 (ja4 %s)", got, ja4)
	}
}

// Truncating a valid ClientHello at any byte must fail parsing (every field
// carries an explicit length, so no strict prefix is structurally complete)
// and must never panic.
func TestJA4TruncationAndMutationNeverPanics(t *testing.T) {
	body := ja4TestRustVectorHello()
	for i := 0; i < len(body); i++ {
		if ja4, ok := clientHelloJA4(body[:i]); ok {
			t.Fatalf("truncation at %d unexpectedly parsed: %s", i, ja4)
		}
	}
	// Deterministic pseudo-random mutations: parsing garbage must be safe.
	state := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < 2000; i++ {
		mutated := append([]byte(nil), body...)
		for n := 0; n < 4; n++ {
			state = state*6364136223846793005 + 1442695040888963407
			mutated[int(state>>33)%len(mutated)] ^= byte(state >> 8)
		}
		clientHelloJA4(mutated)
	}
}
