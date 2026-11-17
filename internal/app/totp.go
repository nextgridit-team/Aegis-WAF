package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// RFC 6238 time-based one-time passwords: SHA-1, six digits, a 30-second
// step. These are the parameters every authenticator app derives from the
// otpauth URI below, so no negotiation or storage of algorithm choice is
// needed server-side.
const (
	totpStepSeconds = 30
	totpSecretBytes = 20
)

// totpAt derives the six-digit code for one 30-second step.
func totpAt(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]) & 0x7f) << 24
	value |= uint32(sum[offset+1]) << 16
	value |= uint32(sum[offset+2]) << 8
	value |= uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000)
}

// verifyTOTP checks a submitted code against the current step plus and minus
// one step (RFC 6238 section 5.2 clock-skew tolerance) and rejects every step
// at or before lastStep, which makes a code single-use across its window.
// Candidates are tried newest-first so the accepted step advances lastStep as
// far as possible and a later replay of the same code can never succeed.
func verifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpStepSeconds
	for _, step := range [3]int64{current + 1, current, current - 1} {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// newTOTPSecret returns the raw shared secret and the base32 form an
// authenticator expects.
func newTOTPSecret() (raw []byte, encoded string) {
	raw = make([]byte, totpSecretBytes)
	if _, e := rand.Read(raw); e != nil {
		panic(e)
	}
	return raw, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

// otpauthURI builds the enrollment URI the dashboard turns into a QR code.
func otpauthURI(username, secretB32 string) string {
	v := url.Values{}
	v.Set("secret", secretB32)
	v.Set("issuer", "Aegis")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape("Aegis:"+username) + "?" + v.Encode()
}
