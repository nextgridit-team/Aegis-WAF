package app

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// The wrapped listener must be transparent to the TLS server above it: every
// byte the client sent is replayed in order, and a ClientHello that spans
// multiple TLS records is reassembled before the JA4 fingerprint is computed.

func fpTestRecord(payload []byte) []byte {
	out := make([]byte, 5, 5+len(payload))
	out[0] = 0x16
	out[1], out[2] = 3, 1
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	return append(out, payload...)
}

func fpTestHandshake(body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	out[0] = 1
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	return append(out, body...)
}

// fpTestPipe hands one end of an in-memory connection to the caller and wraps
// the other end in a fingerprintConn, mirroring the production listener.
func fpTestPipe(t *testing.T, write func(client net.Conn)) (*fingerprintConn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	wrapped := &fingerprintConn{Conn: server}
	go func() {
		defer client.Close()
		write(client)
		// Keep the write side open briefly so reads are not raced by close.
		time.Sleep(200 * time.Millisecond)
	}()
	return wrapped, client
}

func TestFingerprintConnSingleRecord(t *testing.T) {
	raw := fpTestRecord(fpTestHandshake(ja4TestRustVectorHello()))
	wrapped, _ := fpTestPipe(t, func(client net.Conn) {
		if _, e := client.Write(raw); e != nil {
			t.Error(e)
		}
	})
	replayed := make([]byte, len(raw))
	if _, e := io.ReadFull(wrapped, replayed); e != nil {
		t.Fatalf("replay read: %v", e)
	}
	if string(replayed) != string(raw) {
		t.Fatal("peek conn did not replay the exact record bytes")
	}
	if ja4 := wrapped.ja4(); ja4 != "t13i0103h2_0f2cb44170f4_3953dc75acc4" {
		t.Fatalf("ja4 = %q", ja4)
	}
}

func TestFingerprintConnFragmentedAcrossRecords(t *testing.T) {
	message := fpTestHandshake(ja4TestRustVectorHello())
	split := len(message) / 3
	first := fpTestRecord(message[:split])
	second := fpTestRecord(message[split:])
	wrapped, _ := fpTestPipe(t, func(client net.Conn) {
		if _, e := client.Write(first); e != nil {
			t.Error(e)
		}
		if _, e := client.Write(second); e != nil {
			t.Error(e)
		}
	})
	replayed := make([]byte, len(first)+len(second))
	if _, e := io.ReadFull(wrapped, replayed); e != nil {
		t.Fatalf("replay read: %v", e)
	}
	if string(replayed) != string(first)+string(second) {
		t.Fatal("peek conn did not replay both records in order")
	}
	if ja4 := wrapped.ja4(); ja4 != "t13i0103h2_0f2cb44170f4_3953dc75acc4" {
		t.Fatalf("fragmented ja4 = %q", ja4)
	}
}

func TestFingerprintConnPlainGarbageReplaysUntouched(t *testing.T) {
	garbage := []byte("GET / HTTP/1.1\r\nHost: fp.example.com\r\n\r\n")
	wrapped, _ := fpTestPipe(t, func(client net.Conn) {
		if _, e := client.Write(garbage); e != nil {
			t.Error(e)
		}
	})
	replayed := make([]byte, len(garbage))
	if _, e := io.ReadFull(wrapped, replayed); e != nil {
		t.Fatalf("replay read: %v", e)
	}
	if string(replayed) != string(garbage) {
		t.Fatal("peek conn mutated non-TLS bytes")
	}
	if ja4 := wrapped.ja4(); ja4 != "" {
		t.Fatalf("non-TLS input produced ja4 %q", ja4)
	}
}

// A record header claiming more bytes than the client will send must not
// wedge the connection: the buffered header bytes are replayed and the saved
// error surfaces after they drain, exactly as a bare socket would.
func TestFingerprintConnTruncatedRecordHeaderReplaysAndErrors(t *testing.T) {
	header := []byte{0x16, 3, 1, 0x0f, 0xff}
	wrapped, _ := fpTestPipe(t, func(client net.Conn) {
		if _, e := client.Write(header); e != nil {
			t.Error(e)
		}
	})
	replayed := make([]byte, len(header))
	if _, e := io.ReadFull(wrapped, replayed); e != nil {
		t.Fatalf("replay read: %v", e)
	}
	if string(replayed) != string(header) {
		t.Fatal("peek conn did not replay the record header bytes")
	}
	if ja4 := wrapped.ja4(); ja4 != "" {
		t.Fatalf("truncated record produced ja4 %q", ja4)
	}
}

// A ClientHello far past the peek cap must give up on fingerprinting and
// replay everything read so far, leaving the TLS handshake to fail on its own.
func TestFingerprintConnOversizedHelloGivesUp(t *testing.T) {
	message := fpTestHandshake(make([]byte, 70000))
	first := message[:60000]
	second := message[60000:]
	wrapped, _ := fpTestPipe(t, func(client net.Conn) {
		if _, e := client.Write(fpTestRecord(first)); e != nil {
			t.Error(e)
		}
		if _, e := client.Write(fpTestRecord(second)); e != nil {
			t.Error(e)
		}
	})
	all, e := io.ReadAll(wrapped)
	if e != nil {
		t.Fatalf("replay read: %v", e)
	}
	if len(all) != len(message)+10 {
		t.Fatalf("replayed %d bytes, want %d", len(all), len(message)+10)
	}
	if ja4 := wrapped.ja4(); ja4 != "" {
		t.Fatalf("oversized hello produced ja4 %q", ja4)
	}
}
