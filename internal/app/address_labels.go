package app

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5"
)

type addressName struct {
	prefix netip.Prefix
	name   string
}
type addressNames []addressName
type addressNameQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// Resolve display labels only on management reads. This adds no work to proxy
// forwarding and does not change policy decisions or rewrite historical logs.
func loadAddressNames(ctx context.Context, query addressNameQuery) (addressNames, error) {
	rows, e := query.Query(ctx, "SELECT name,value FROM address_objects ORDER BY lower(name),id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	names := addressNames{}
	for rows.Next() {
		var name, value string
		if e = rows.Scan(&name, &value); e != nil {
			return nil, e
		}
		p, e := netip.ParsePrefix(value)
		if e != nil {
			ip, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		names = append(names, addressName{p, name})
	}
	return names, rows.Err()
}
func (names addressNames) match(raw string) []string {
	ip, e := netip.ParseAddr(strings.TrimSpace(raw))
	if e != nil {
		addr, err := netip.ParseAddrPort(raw)
		if err != nil {
			return []string{}
		}
		ip = addr.Addr()
	}
	ip = ip.Unmap()
	best := -1
	out := []string{}
	for _, entry := range names {
		if !entry.prefix.Contains(ip) {
			continue
		}
		bits := entry.prefix.Bits()
		if bits < best {
			continue
		}
		if bits > best {
			best = bits
			out = []string{}
		}
		if len(out) < 8 {
			out = append(out, entry.name)
		}
	}
	return out
}
func (names addressNames) annotate(raw []byte) ([]byte, error) {
	var event map[string]json.RawMessage
	if e := json.Unmarshal(raw, &event); e != nil {
		return nil, e
	}
	var peer string
	if e := json.Unmarshal(event["peer"], &peer); e != nil {
		return nil, e
	}
	event["client_objects"], _ = json.Marshal(names.match(peer))
	return json.Marshal(event)
}
func (names addressNames) annotateList(raw []byte) ([]byte, error) {
	var events []json.RawMessage
	if e := json.Unmarshal(raw, &events); e != nil {
		return nil, e
	}
	for n := range events {
		value, e := names.annotate(events[n])
		if e != nil {
			return nil, e
		}
		events[n] = value
	}
	return json.Marshal(events)
}
