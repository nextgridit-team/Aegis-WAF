package app

import (
	"crypto/tls"
	"errors"
	"time"
)

// Management TLS selects from cached certificates independently of public-site
// routing. This allows recovery/setup with an uploaded or ACME-issued wildcard
// before any upstream application exists. Private keys never leave the process in plaintext.
func (a *App) ManagementTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		snapshot := a.active.Load()
		if snapshot == nil {
			return nil, errors.New("management certificates are not loaded")
		}
		name := requestHost(hello.ServerName)
		now := time.Now()
		var selected *tls.Certificate
		var selectedID int64
		for id, pair := range snapshot.certificates {
			if pair == nil || pair.Leaf == nil || now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
				continue
			}
			if name != "" && pair.Leaf.VerifyHostname(name) != nil {
				continue
			}
			if selected == nil || pair.Leaf.NotAfter.After(selected.Leaf.NotAfter) || (pair.Leaf.NotAfter.Equal(selected.Leaf.NotAfter) && id < selectedID) {
				selected = pair
				selectedID = id
			}
		}
		if selected == nil {
			return nil, errors.New("no currently valid management certificate for hostname")
		}
		return selected, nil
	}}
}
