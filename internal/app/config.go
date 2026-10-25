package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ManagementTLS                                                            bool
	DatabaseURL, BootstrapSecret, KeyID, HTTPAddr, HTTPSAddr, ManagementAddr string
	Key                                                                      []byte
	Refresh                                                                  time.Duration
}

func secret(name string) (string, error) {
	v, f := os.Getenv(name), os.Getenv(name+"_FILE")
	if v != "" && f != "" {
		return "", fmt.Errorf("set only %s or %s_FILE", name, name)
	}
	if f != "" {
		b, e := os.ReadFile(f)
		if e != nil {
			return "", fmt.Errorf("read %s_FILE: %w", name, e)
		}
		v = strings.TrimSpace(string(b))
	}
	return v, nil
}
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func LoadConfig() (Config, error) {
	var c Config
	var e error
	if c.DatabaseURL, e = secret("DATABASE_URL"); e != nil {
		return c, e
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL is required")
	}
	if c.BootstrapSecret, e = secret("BOOTSTRAP_SECRET"); e != nil {
		return c, e
	}
	if len(c.BootstrapSecret) < 32 {
		return c, errors.New("BOOTSTRAP_SECRET must contain at least 32 characters")
	}
	k, e := secret("ENCRYPTION_KEY")
	if e != nil {
		return c, e
	}
	c.Key, e = base64.StdEncoding.DecodeString(k)
	if e != nil || len(c.Key) != 32 {
		return c, errors.New("ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}
	c.KeyID = env("ENCRYPTION_KEY_ID", "primary")
	c.HTTPAddr = env("HTTP_ADDR", ":8080")
	c.HTTPSAddr = env("HTTPS_ADDR", ":8443")
	c.ManagementAddr = env("MANAGEMENT_ADDR", ":9090")
	c.ManagementTLS, e = strconv.ParseBool(env("MANAGEMENT_TLS", "false"))
	if e != nil {
		return c, errors.New("MANAGEMENT_TLS must be true or false")
	}
	c.Refresh = 2 * time.Second
	return c, nil
}
func seal(key []byte, aad string, plaintext []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return a.Seal(n, n, plaintext, []byte(aad)), nil
}
func open(key []byte, aad string, ciphertext []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(ciphertext) < a.NonceSize() {
		return nil, errors.New("invalid encrypted material")
	}
	return a.Open(nil, ciphertext[:a.NonceSize()], ciphertext[a.NonceSize():], []byte(aad))
}
func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
