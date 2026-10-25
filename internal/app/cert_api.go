package app

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func pemLeaf(chain string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(chain))
	if b == nil {
		return nil, errors.New("empty certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}
func (a *App) upload(w http.ResponseWriter, r *http.Request, i identity) error {
	var b struct {
		Name  string `json:"name"`
		Chain string `json:"chain_pem"`
		Key   string `json:"private_key_pem"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if strings.TrimSpace(b.Name) == "" || len(b.Name) > 120 {
		return invalid("certificate name must be 1–120 characters")
	}
	_, leaf, e := parseCertificate(b.Chain, b.Key, time.Now())
	if e != nil {
		return invalid(e.Error())
	}
	enc, e := seal(a.cfg.Key, a.cfg.KeyID+":certificate", []byte(b.Key))
	if e != nil {
		return e
	}
	var id int64
	if r.Method == "PUT" {
		id, e = resourceID(r)
		if e != nil {
			return e
		}
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		if id == 0 {
			e := tx.QueryRow(r.Context(), "INSERT INTO certificates(name,origin,domains,chain_pem,key_cipher,key_id,issuer,not_before,not_after) VALUES($1,'upload',$2,$3,$4,$5,$6,$7,$8) RETURNING id", b.Name, leaf.DNSNames, b.Chain, enc, a.cfg.KeyID, leaf.Issuer.String(), leaf.NotBefore, leaf.NotAfter).Scan(&id)
			if e != nil {
				return e
			}
			return audit(r.Context(), tx, i.Username, "certificate.uploaded", strconv.FormatInt(id, 10))
		}
		var origin string
		e := tx.QueryRow(r.Context(), "SELECT origin FROM certificates WHERE id=$1 FOR UPDATE", id).Scan(&origin)
		if errors.Is(e, pgx.ErrNoRows) {
			return apiError{404, "certificate not found"}
		}
		if e != nil {
			return e
		}
		if origin != "upload" {
			return invalid("ACME-managed certificates must be renewed through ACME")
		}
		rows, e := tx.Query(r.Context(), "SELECT hostnames FROM sites WHERE certificate_id=$1", id)
		if e != nil {
			return e
		}
		for rows.Next() {
			var hosts []string
			if e = rows.Scan(&hosts); e != nil {
				rows.Close()
				return e
			}
			if e = covers(leaf, hosts); e != nil {
				rows.Close()
				return invalid(e.Error())
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		_, e = tx.Exec(r.Context(), "UPDATE certificates SET name=$2,domains=$3,chain_pem=$4,key_cipher=$5,key_id=$6,issuer=$7,not_before=$8,not_after=$9,updated_at=now() WHERE id=$1", id, b.Name, leaf.DNSNames, b.Chain, enc, a.cfg.KeyID, leaf.Issuer.String(), leaf.NotBefore, leaf.NotAfter)
		if e != nil {
			return e
		}
		return audit(r.Context(), tx, i.Username, "certificate.replaced", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]int64{"id": id})
	return nil
}
func (a *App) deleteCertificate(w http.ResponseWriter, r *http.Request, i identity) error {
	id, e := resourceID(r)
	if e != nil {
		return e
	}
	e = a.change(r.Context(), func(tx pgx.Tx) error {
		var used bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM sites WHERE certificate_id=$1)", id).Scan(&used); e != nil {
			return e
		}
		if used {
			return apiError{409, "detach this certificate from its sites first"}
		}
		var pendingDNS bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM dns_challenges d JOIN jobs j ON j.id=d.job_id WHERE j.certificate_id=$1)", id).Scan(&pendingDNS); e != nil {
			return e
		}
		if pendingDNS {
			return apiError{409, "DNS challenge cleanup is pending; check the Cloudflare credential"}
		}
		var active bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM jobs WHERE certificate_id=$1 AND status IN ('queued','retry','running'))", id).Scan(&active); e != nil {
			return e
		}
		if active {
			return apiError{409, "certificate has an active ACME job"}
		}
		if _, e := tx.Exec(r.Context(), "DELETE FROM acme_challenges WHERE job_id IN (SELECT id FROM jobs WHERE certificate_id=$1)", id); e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), "DELETE FROM acme_orders WHERE job_id IN (SELECT id FROM jobs WHERE certificate_id=$1)", id); e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), "DELETE FROM jobs WHERE certificate_id=$1", id); e != nil {
			return e
		}
		tag, e := tx.Exec(r.Context(), "DELETE FROM certificates WHERE id=$1", id)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return apiError{404, "certificate not found"}
		}
		return audit(r.Context(), tx, i.Username, "certificate.deleted", strconv.FormatInt(id, 10))
	})
	if e != nil {
		return e
	}
	respond(w, 200, map[string]bool{"deleted": true})
	return nil
}
