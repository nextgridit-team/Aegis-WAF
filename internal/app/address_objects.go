package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Selections retain references in PostgreSQL. Expansion happens only on a
// configuration refresh, never on the forwarding path. Groups contain objects,
// not other groups: this makes membership and the effects of edits explicit.
type addressSelection struct {
	ObjectIDs []int64 `json:"object_ids"`
	GroupIDs  []int64 `json:"group_ids"`
}
type addressCatalog struct {
	objects map[int64]string
	groups  map[int64][]int64
}

func normalizeAddressValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if ip, e := netip.ParseAddr(raw); e == nil && ip.Zone() == "" {
		return ip.Unmap().String(), nil
	}
	if p, e := netip.ParsePrefix(raw); e == nil {
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return "", invalid("mapped IPv4 subnet is too broad")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			return "", invalid("all-address /0 objects are not supported")
		}
		return p.Masked().String(), nil
	}
	parts := strings.Fields(strings.ReplaceAll(raw, "/", " "))
	if len(parts) == 2 {
		ip, e := netip.ParseAddr(parts[0])
		mask := net.ParseIP(parts[1]).To4()
		if e == nil && ip.Is4() && mask != nil {
			ones, bits := net.IPMask(mask).Size()
			if bits == 32 && ones > 0 {
				return netip.PrefixFrom(ip, ones).Masked().String(), nil
			}
		}
	}
	return "", invalid("provide one IPv4/IPv6 address, CIDR, or IPv4 subnet with a contiguous dotted mask")
}
func loadAddressCatalog(ctx context.Context, tx pgx.Tx) (addressCatalog, error) {
	c := addressCatalog{objects: map[int64]string{}, groups: map[int64][]int64{}}
	rows, e := tx.Query(ctx, "SELECT id,value FROM address_objects")
	if e != nil {
		return c, e
	}
	for rows.Next() {
		var id int64
		var v string
		if e = rows.Scan(&id, &v); e != nil {
			rows.Close()
			return c, e
		}
		c.objects[id] = v
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return c, e
	}
	rows, e = tx.Query(ctx, "SELECT id,object_ids FROM address_groups")
	if e != nil {
		return c, e
	}
	for rows.Next() {
		var id int64
		var ids []int64
		if e = rows.Scan(&id, &ids); e != nil {
			rows.Close()
			return c, e
		}
		c.groups[id] = ids
	}
	e = rows.Err()
	rows.Close()
	return c, e
}
func (c addressCatalog) expand(s addressSelection) ([]string, error) {
	if len(s.ObjectIDs)+len(s.GroupIDs) > 128 {
		return nil, invalid("select at most 128 address objects and groups")
	}
	ids := map[int64]bool{}
	for _, id := range s.ObjectIDs {
		ids[id] = true
	}
	for _, id := range s.GroupIDs {
		members, ok := c.groups[id]
		if !ok {
			return nil, invalid("selected address group does not exist")
		}
		for _, member := range members {
			ids[member] = true
		}
	}
	values := map[string]bool{}
	for id := range ids {
		v, ok := c.objects[id]
		if !ok {
			return nil, invalid("selected address object does not exist")
		}
		values[v] = true
	}
	out := []string{}
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}
func (c addressCatalog) protection(p ProtectionSettings) (ProtectionSettings, error) {
	for _, item := range []struct {
		s   addressSelection
		dst *[]string
	}{{p.TrustedAddresses, &p.TrustedProxies}, {p.FloodExemptAddresses, &p.FloodExemptCIDRs}, {p.BotExemptAddresses, &p.BotExemptCIDRs}} {
		values, e := c.expand(item.s)
		if e != nil {
			return p, e
		}
		*item.dst = append(append([]string{}, *item.dst...), values...)
	}
	return p, nil
}
func (c addressCatalog) network(n networkAccessSettings) (networkAccessSettings, error) {
	for _, item := range []struct {
		s   addressSelection
		dst *[]string
	}{{n.BlockAddresses, &n.BlockCIDRs}, {n.AllowAddresses, &n.AllowCIDRs}} {
		values, e := c.expand(item.s)
		if e != nil {
			return n, e
		}
		*item.dst = append(append([]string{}, *item.dst...), values...)
	}
	return n, nil
}

// Called inside the configuration write lock. Reject deletion of referenced
// objects/groups and edits that would exceed an existing control's capacity.
func validateAddressConsumers(ctx context.Context, tx pgx.Tx) error {
	if e := validateAgentAddresses(ctx, tx); e != nil {
		return e
	}
	c, e := loadAddressCatalog(ctx, tx)
	if e != nil {
		return e
	}
	for _, ids := range c.groups {
		if len(ids) == 0 || len(ids) > 128 {
			return invalid("groups require 1–128 objects")
		}
		for _, id := range ids {
			if _, ok := c.objects[id]; !ok {
				return apiError{409, "address object is used by a group; remove it from the group first"}
			}
		}
	}
	rows, e := tx.Query(ctx, "SELECT settings FROM protection_settings")
	if e != nil {
		return e
	}
	for rows.Next() {
		var raw []byte
		var p ProtectionSettings
		if e = rows.Scan(&raw); e == nil {
			e = json.Unmarshal(raw, &p)
		}
		if e == nil {
			p, e = c.protection(p)
		}
		if e == nil {
			_, e = compileProtection(p)
		}
		if e != nil {
			rows.Close()
			return apiError{409, "address change would invalidate a proxy host: " + e.Error()}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = tx.Query(ctx, "SELECT spec FROM policies")
	if e != nil {
		return e
	}
	for rows.Next() {
		var raw []byte
		var p policySpec
		if e = rows.Scan(&raw); e == nil {
			e = json.Unmarshal(raw, &p)
		}
		if e == nil {
			p.NetworkAccess, e = c.network(p.NetworkAccess)
		}
		if e == nil {
			_, e = compileNetworkAccess(p.NetworkAccess, p.Mode)
		}
		if e != nil {
			rows.Close()
			return apiError{409, "address change would invalidate a policy: " + e.Error()}
		}
	}
	e = rows.Err()
	rows.Close()
	return e
}
func addressAPI(a *App, m *http.ServeMux) {
	for _, kind := range []string{"objects", "groups"} {
		table := "address_" + kind
		m.HandleFunc("GET /api/address-"+kind, a.wrap(true, func(w http.ResponseWriter, r *http.Request, _ identity) error {
			return a.list(w, r, "SELECT * FROM "+table+" ORDER BY lower(name),id")
		}))
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			pattern := method + " /api/address-" + kind
			if method != "POST" {
				pattern += "/{id}"
			}
			m.HandleFunc(pattern, a.wrap(true, func(w http.ResponseWriter, r *http.Request, i identity) error {
				var in struct {
					Name        string  `json:"name"`
					Description string  `json:"description"`
					Value       string  `json:"value"`
					ObjectIDs   []int64 `json:"object_ids"`
					IsLocal     *bool   `json:"is_local"`
				}
				var id int64
				var e error
				if method != "POST" {
					id, e = resourceID(r)
					if e != nil {
						return e
					}
				}
				if method != "DELETE" {
					if e = decode(w, r, &in); e != nil {
						return e
					}
					in.Name = strings.TrimSpace(in.Name)
					if in.Name == "" || len(in.Name) > 120 || len(in.Description) > 2000 {
						return invalid("provide a name of 1–120 bytes and description up to 2000 bytes")
					}
					if kind == "objects" {
						in.Value, e = normalizeAddressValue(in.Value)
						if e != nil {
							return e
						}
					} else {
						if len(in.ObjectIDs) == 0 || len(in.ObjectIDs) > 128 {
							return invalid("groups require 1–128 objects")
						}
						seen := map[int64]bool{}
						for _, v := range in.ObjectIDs {
							if v < 1 || seen[v] {
								return invalid("select each valid address object once")
							}
							seen[v] = true
						}
					}
				}
				e = a.change(r.Context(), func(tx pgx.Tx) error {
					if method == "DELETE" {
						tag, err := tx.Exec(r.Context(), "DELETE FROM "+table+" WHERE id=$1", id)
						if err != nil {
							return err
						}
						if tag.RowsAffected() == 0 {
							return apiError{404, "address entry not found"}
						}
					} else {
						var duplicate bool
						if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE lower(name)=lower($1) AND id<>$2)", in.Name, id).Scan(&duplicate); e != nil {
							return e
						}
						if duplicate {
							return apiError{409, "this name is already in use"}
						}
						column := "value"
						var value any = in.Value
						if kind == "groups" {
							column = "object_ids"
							value = in.ObjectIDs
						}
						if method == "POST" {
							var count int
							if e := tx.QueryRow(r.Context(), "SELECT count(*) FROM "+table).Scan(&count); e != nil {
								return e
							}
							limit := 1024
							if kind == "groups" {
								limit = 128
							}
							if count >= limit {
								return invalid("address inventory capacity reached")
							}
							if e := tx.QueryRow(r.Context(), "INSERT INTO "+table+"(name,description,"+column+") VALUES($1,$2,$3) RETURNING id", in.Name, in.Description, value).Scan(&id); e != nil {
								return e
							}
						} else {
							tag, e := tx.Exec(r.Context(), "UPDATE "+table+" SET name=$2,description=$3,"+column+"=$4,updated_at=now() WHERE id=$1", id, in.Name, in.Description, value)
							if e != nil {
								return e
							}
							if tag.RowsAffected() == 0 {
								return apiError{404, "address entry not found"}
							}
						}
					}
					if kind == "objects" && method != "DELETE" && in.IsLocal != nil {
						if _, e := tx.Exec(r.Context(), "UPDATE address_objects SET is_local=$2 WHERE id=$1", id, *in.IsLocal); e != nil {
							return e
						}
					}
					if e := validateAddressConsumers(r.Context(), tx); e != nil {
						return e
					}
					return audit(r.Context(), tx, i.Username, "address."+kind+"."+strings.ToLower(method), strconv.FormatInt(id, 10))
				})
				if e != nil {
					return e
				}
				respond(w, 200, map[string]int64{"id": id})
				return nil
			}))
		}
	}
}
