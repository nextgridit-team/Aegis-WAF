package app

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/acme"
)

const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
const ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

func privateKey() ([]byte, crypto.Signer, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), key, nil
}
func signer(b []byte) (crypto.Signer, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid account key")
	}
	key, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid account signer")
	}
	return s, nil
}
func acmeClient(directory string, key crypto.Signer, kid string) *acme.Client {
	return &acme.Client{Key: key, KID: acme.KeyID(kid), DirectoryURL: directory, HTTPClient: &http.Client{Timeout: 30 * time.Second}, UserAgent: "aegis-waf/0.1"}
}
func (a *App) registerAccount(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		Directory   string `json:"directory"`
		Email       string `json:"email"`
		AcceptTerms bool   `json:"accept_terms"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if b.Directory == "staging" {
		b.Directory = StagingDirectory
	}
	if b.Directory == "production" {
		b.Directory = ProductionDirectory
	}
	u, e := url.Parse(b.Directory)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return invalid("ACME directory must be an HTTPS URL")
	}
	addr, e := mail.ParseAddress(b.Email)
	if e != nil || addr.Address != b.Email || len(b.Email) > 254 {
		return invalid("provide a valid email address")
	}
	if !b.AcceptTerms {
		return invalid("explicit CA terms acceptance is required")
	}
	material, key, e := privateKey()
	if e != nil {
		return e
	}
	encrypted, e := seal(a.cfg.Key, a.cfg.KeyID+":account", material)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(700013)"); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM acme_accounts WHERE directory=$1)", b.Directory).Scan(&exists); e != nil {
		return e
	}
	if exists {
		return apiError{409, "an account is already registered for this directory"}
	}
	account, e := acmeClient(b.Directory, key, "").Register(r.Context(), &acme.Account{Contact: []string{"mailto:" + b.Email}}, func(string) bool { return b.AcceptTerms })
	if e != nil {
		return invalid(acmeFailure("account registration", e))
	}
	var id int64
	if e = tx.QueryRow(r.Context(), "INSERT INTO acme_accounts(directory,email,key_cipher,key_id,account_url) VALUES($1,$2,$3,$4,$5) RETURNING id", b.Directory, b.Email, encrypted, a.cfg.KeyID, account.URI).Scan(&id); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, i.Username, "acme.account.registered", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 201, map[string]int64{"id": id})
	return nil
}
func (a *App) issue(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		Name      string   `json:"name"`
		Domains   []string `json:"domains"`
		AccountID int64    `json:"account_id"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if strings.TrimSpace(b.Name) == "" || len(b.Name) > 120 {
		return invalid("name must be 1–120 characters")
	}
	d, e := domains(b.Domains)
	if e != nil {
		return invalid(e.Error())
	}
	var id int64
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM acme_accounts WHERE id=$1)", b.AccountID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return invalid("ACME account not found")
		}
		if e := tx.QueryRow(r.Context(), "INSERT INTO certificates(name,origin,domains,account_id) VALUES($1,'acme',$2,$3) RETURNING id", b.Name, d, b.AccountID).Scan(&id); e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), "INSERT INTO jobs(certificate_id) VALUES($1)", id); e != nil {
			return e
		}
		return audit(r.Context(), tx, i.Username, "acme.issuance.queued", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 202, map[string]int64{"id": id})
	return nil
}
func (a *App) retryJob(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	tag, e := tx.Exec(r.Context(), "UPDATE jobs SET status='queued',next_attempt=now(),updated_at=now() WHERE id=$1 AND status='retry'", id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{409, "only a failed job can be retried"}
	}
	if e = audit(r.Context(), tx, i.Username, "acme.retry.queued", strconv.FormatInt(id, 10)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	respond(w, 202, map[string]bool{"queued": true})
	return nil
}

// ChallengeProvider is the extension point for later DNS-01 implementations.
type ChallengeProvider interface {
	Present(context.Context, string, string, string, int64) error
	CleanUp(context.Context, int64) error
}
type http01Provider struct{ app *App }

func (p http01Provider) Present(ctx context.Context, host, token, response string, job int64) error {
	_, e := p.app.db.Exec(ctx, "INSERT INTO acme_challenges(hostname,token,response,job_id,expires_at) VALUES($1,$2,$3,$4,now()+interval '15 minutes') ON CONFLICT(hostname,token) DO UPDATE SET response=excluded.response,job_id=excluded.job_id,expires_at=excluded.expires_at", host, token, response, job)
	return e
}
func (p http01Provider) CleanUp(ctx context.Context, job int64) error {
	_, e := p.app.db.Exec(ctx, "DELETE FROM acme_challenges WHERE job_id=$1", job)
	return e
}
func acmeFailure(stage string, e error) string {
	var ae *acme.Error
	if errors.As(e, &ae) {
		return fmt.Sprintf("%s failed (ACME HTTP %d); check DNS, port 80 reachability and CA policy", stage, ae.StatusCode)
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return stage + " timed out; will retry"
	}
	return stage + " failed; check CA connectivity, DNS, and database health"
}
func (a *App) ACMEWorker(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !a.initialized.Load() {
				continue
			}
			a.schedule(ctx)
			a.runJobs(ctx)
		}
	}
}
func (a *App) schedule(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = a.db.Exec(c, `INSERT INTO jobs(certificate_id) SELECT id FROM certificates WHERE origin='acme' AND (not_after IS NULL OR not_after<now()+LEAST(interval '30 days',(not_after-not_before)/3)) ON CONFLICT DO NOTHING`)
	_, _ = a.db.Exec(c, "DELETE FROM sessions WHERE expires_at<now(); DELETE FROM login_limits WHERE expires_at<now(); DELETE FROM acme_challenges WHERE expires_at<now()")
}
func (a *App) runJobs(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	rows, e := a.db.Query(c, "SELECT id,certificate_id FROM jobs WHERE status IN ('queued','retry','running') AND next_attempt<=now() ORDER BY next_attempt LIMIT 20")
	if e != nil {
		cancel()
		return
	}
	type candidate struct{ id, cert int64 }
	var jobs []candidate
	for rows.Next() {
		var j candidate
		if e = rows.Scan(&j.id, &j.cert); e != nil {
			break
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	cancel()
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		a.runJob(ctx, j.id, j.cert)
	}
}
func (a *App) runJob(parent context.Context, job, cert int64) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	conn, e := a.db.Acquire(ctx)
	if e != nil {
		return
	}
	defer conn.Release()
	lock := int64(1000000000) + cert
	var acquired bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lock).Scan(&acquired); e != nil || !acquired {
		return
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		var ok bool
		if e := conn.QueryRow(c, "SELECT pg_advisory_unlock($1)", lock).Scan(&ok); e != nil || !ok {
			conn.Conn().Close(c)
		}
	}()
	var lost atomic.Bool
	stopHeartbeat := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				c, stop := context.WithTimeout(ctx, 2*time.Second)
				er := conn.Ping(c)
				stop()
				if er != nil {
					lost.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(stopHeartbeat); <-heartbeatDone }()
	owner := token()
	var attempts int
	e = a.db.QueryRow(ctx, "UPDATE jobs SET status='running',owner=$2,attempts=attempts+1,updated_at=now() WHERE id=$1 AND status IN ('queued','retry','running') AND next_attempt<=now() RETURNING attempts", job, owner).Scan(&attempts)
	if e != nil {
		return
	}
	e = a.obtain(ctx, job, cert, owner)
	if lost.Load() {
		return
	}
	if e != nil {
		msg := acmeFailure("certificate issuance", e)
		var ae apiError
		if errors.As(e, &ae) {
			msg = ae.message
		}
		backoff := time.Minute * time.Duration(1<<min(attempts-1, 11))
		if backoff > 24*time.Hour {
			backoff = 24 * time.Hour
		}
		c, stop := context.WithTimeout(parent, 5*time.Second)
		defer stop()
		_, _ = a.db.Exec(c, "UPDATE jobs SET status='retry',error=$3,next_attempt=now()+$4::interval,updated_at=now() WHERE id=$1 AND owner=$2 AND status='running'", job, owner, msg, fmt.Sprintf("%d seconds", int(backoff.Seconds())))
	}
	c, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = (http01Provider{a}).CleanUp(c, job)
}
func (a *App) obtain(ctx context.Context, job, cert int64, owner string) error {
	var hosts []string
	var directory, kid, keyID string
	var encrypted []byte
	if e := a.db.QueryRow(ctx, "SELECT c.domains,a.directory,a.account_url,a.key_cipher,a.key_id FROM certificates c JOIN acme_accounts a ON a.id=c.account_id WHERE c.id=$1", cert).Scan(&hosts, &directory, &kid, &encrypted, &keyID); e != nil {
		return e
	}
	if keyID != a.cfg.KeyID {
		return errors.New("unknown key identifier")
	}
	material, e := open(a.cfg.Key, keyID+":account", encrypted)
	if e != nil {
		return e
	}
	key, e := signer(material)
	if e != nil {
		return e
	}
	client := acmeClient(directory, key, kid)
	order, e := client.AuthorizeOrder(ctx, acme.DomainIDs(hosts...))
	if e != nil {
		return e
	}
	var orderID int64
	if e = a.db.QueryRow(ctx, "INSERT INTO acme_orders(job_id,url,status) VALUES($1,$2,$3) RETURNING id", job, order.URI, order.Status).Scan(&orderID); e != nil {
		return e
	}
	done := false
	defer func() {
		if !done {
			c, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_, _ = a.db.Exec(c, "UPDATE acme_orders SET status='failed',error='Issuance interrupted or failed; see job status' WHERE id=$1", orderID)
		}
	}()
	provider := http01Provider{a}
	for _, authURL := range order.AuthzURLs {
		auth, e := client.GetAuthorization(ctx, authURL)
		if e != nil {
			return e
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		if auth.Wildcard {
			return invalid("HTTP-01 cannot validate wildcard domains")
		}
		var ch *acme.Challenge
		for _, v := range auth.Challenges {
			if v.Type == "http-01" {
				ch = v
				break
			}
		}
		if ch == nil {
			return invalid("CA did not offer HTTP-01")
		}
		response, e := client.HTTP01ChallengeResponse(ch.Token)
		if e != nil {
			return e
		}
		if e = provider.Present(ctx, auth.Identifier.Value, ch.Token, response, job); e != nil {
			return e
		}
		if _, e = client.Accept(ctx, ch); e != nil {
			return e
		}
		if _, e = client.WaitAuthorization(ctx, authURL); e != nil {
			return e
		}
	}
	ready, e := client.WaitOrder(ctx, order.URI)
	if e != nil {
		return e
	}
	keyPEM, certKey, e := privateKey()
	if e != nil {
		return e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: hosts}, certKey)
	if e != nil {
		return e
	}
	der, _, e := client.CreateOrderCert(ctx, ready.FinalizeURL, csr, true)
	if e != nil {
		return e
	}
	var chain strings.Builder
	for _, b := range der {
		chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
	}
	_, leaf, e := parseCertificate(chain.String(), string(keyPEM), time.Now())
	if e != nil {
		return e
	}
	if e = covers(leaf, hosts); e != nil {
		return e
	}
	encrypted, e = seal(a.cfg.Key, a.cfg.KeyID+":certificate", keyPEM)
	if e != nil {
		return e
	}
	e = a.change(ctx, func(tx pgx.Tx) error {
		var active bool
		if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM jobs WHERE id=$1 AND owner=$2 AND status='running')", job, owner).Scan(&active); e != nil {
			return e
		}
		if !active {
			return errors.New("job ownership lost")
		}
		rows, e := tx.Query(ctx, "SELECT hostnames FROM sites WHERE certificate_id=$1", cert)
		if e != nil {
			return e
		}
		for rows.Next() {
			var h []string
			if e = rows.Scan(&h); e != nil {
				rows.Close()
				return e
			}
			if e = covers(leaf, h); e != nil {
				rows.Close()
				return e
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE certificates SET chain_pem=$2,key_cipher=$3,key_id=$4,domains=$5,issuer=$6,not_before=$7,not_after=$8,updated_at=now() WHERE id=$1", cert, chain.String(), encrypted, a.cfg.KeyID, leaf.DNSNames, leaf.Issuer.String(), leaf.NotBefore, leaf.NotAfter); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE jobs SET status='succeeded',error='',updated_at=now() WHERE id=$1 AND owner=$2", job, owner); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE acme_orders SET status='valid' WHERE id=$1", orderID); e != nil {
			return e
		}
		return audit(ctx, tx, "system", "acme.certificate.issued", strconv.FormatInt(cert, 10))
	})
	done = e == nil
	return e
}

func (a *App) directoryTerms(w http.ResponseWriter, r *http.Request, i identity) error {
	directory := r.URL.Query().Get("url")
	if directory == "staging" {
		directory = StagingDirectory
	}
	if directory == "production" {
		directory = ProductionDirectory
	}
	u, e := url.Parse(directory)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return invalid("ACME directory must be an HTTPS URL")
	}
	d, e := acmeClient(directory, nil, "").Discover(r.Context())
	if e != nil {
		return invalid(acmeFailure("directory discovery", e))
	}
	respond(w, 200, map[string]string{"terms_url": d.Terms})
	return nil
}
