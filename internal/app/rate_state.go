package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

type rateStateLogger struct{}

func (rateStateLogger) Printf(ctx context.Context, _ string, _ ...interface{}) {
	slog.DebugContext(ctx, "shared rate-state client diagnostic")
}
func init() { redis.SetLogger(rateStateLogger{}) }

type rateLimit struct {
	Key         rateKey
	Rate, Burst int
}
type rateState interface {
	Take(context.Context, []rateLimit, time.Time) ([2]bool, error)
}
type localRateState struct{ limiter *floodLimiter }

func (s localRateState) Take(_ context.Context, limits []rateLimit, now time.Time) ([2]bool, error) {
	var out [2]bool
	for i, l := range limits {
		out[i] = s.limiter.allow(l.Key, l.Rate, l.Burst, now)
	}
	return out, nil
}

type rateStateKey struct{}

// Concrete dispatch keeps local limits and result bits on the stack; both
// backends implement the same bounded state contract for future extensions.
var _ rateState = localRateState{}
var _ rateState = (*sharedRateState)(nil)

func takeRateState(ctx context.Context, local *floodLimiter, limits []rateLimit, now time.Time) ([2]bool, error) {
	if shared, _ := ctx.Value(rateStateKey{}).(*sharedRateState); shared != nil && shared.stored.Settings.Backend == "redis" {
		return shared.Take(ctx, limits, now)
	}
	return (localRateState{local}).Take(ctx, limits, now)
}

type rateStateSettings struct {
	Backend   string `json:"backend"`
	Address   string `json:"address"`
	Username  string `json:"username"`
	TLS       bool   `json:"tls"`
	TimeoutMS int    `json:"timeout_ms"`
}
type storedRateState struct {
	Settings         rateStateSettings
	Cipher           []byte
	KeyID, Namespace string
	Revision         int64
}

func normalizeRateState(s rateStateSettings) (rateStateSettings, error) {
	if s.Backend == "" {
		s.Backend = "memory"
	}
	if s.TimeoutMS == 0 {
		s.TimeoutMS = 100
	}
	if s.Backend != "memory" && s.Backend != "redis" {
		return s, invalid("backend must be memory or redis (Redis/Dragonfly compatible)")
	}
	if s.TimeoutMS < 20 || s.TimeoutMS > 250 {
		return s, invalid("rate-state timeout must be 20–250 ms")
	}
	if len(s.Username) > 128 || strings.ContainsAny(s.Username, "\r\n\x00") {
		return s, invalid("invalid rate-state username")
	}
	if len(s.Address) > 300 || strings.ContainsAny(s.Address, "\r\n\x00") {
		return s, invalid("invalid rate-state address")
	}
	if s.Backend == "redis" {
		host, port, e := net.SplitHostPort(s.Address)
		number, pe := strconv.Atoi(port)
		if e != nil || host == "" || pe != nil || number < 1 || number > 65535 || len(s.Address) > 300 || strings.ContainsAny(host, " /\\@\r\n\x00") {
			return s, invalid("provide a Redis/Dragonfly host:port address without credentials or URL scheme")
		}
	}
	return s, nil
}
func readRateState(ctx context.Context, q rowQuerier) (storedRateState, error) {
	var stored storedRateState
	var raw []byte
	e := q.QueryRow(ctx, "SELECT settings,password_cipher,key_id,namespace,revision FROM rate_state WHERE id").Scan(&raw, &stored.Cipher, &stored.KeyID, &stored.Namespace, &stored.Revision)
	if e != nil {
		return stored, e
	}
	if e = json.Unmarshal(raw, &stored.Settings); e != nil {
		return stored, e
	}
	stored.Settings, e = normalizeRateState(stored.Settings)
	return stored, e
}
func (a *App) compileRateState(stored storedRateState) (*sharedRateState, error) {
	settings, e := normalizeRateState(stored.Settings)
	if e != nil {
		return nil, e
	}
	stored.Settings = settings
	if len(stored.Namespace) > 128 || strings.ContainsAny(stored.Namespace, "{}\r\n") || stored.Namespace == "" {
		return nil, errors.New("invalid rate-state namespace")
	}
	raw, _ := json.Marshal(stored)
	if old := a.active.Load(); old != nil && old.rateState != nil && old.rateState.fingerprint == hash(string(raw)) {
		return old.rateState, nil
	}
	password := ""
	if len(stored.Cipher) > 0 {
		if stored.KeyID != a.cfg.KeyID {
			return nil, errors.New("unknown rate-state encryption key")
		}
		plain, e := open(a.cfg.Key, stored.KeyID+":rate-state-password", stored.Cipher)
		if e != nil {
			return nil, e
		}
		password = string(plain)
	}
	return &sharedRateState{stored: stored, password: password, fingerprint: hash(string(raw)), work: make(chan struct{}, 64)}, nil
}
func (a *App) loadRateState(ctx context.Context, tx pgx.Tx, next *snapshot) error {
	stored, e := readRateState(ctx, tx)
	if e != nil {
		return e
	}
	next.rateState, e = a.compileRateState(stored)
	return e
}

type sharedRateState struct {
	stored                storedRateState
	password, fingerprint string
	mu                    sync.Mutex
	client                *redis.Client
	users                 int
	retired               bool
	work                  chan struct{}
	retryAfter            atomic.Int64
	failures              atomic.Uint64
}

func (s *sharedRateState) newClient() *redis.Client {
	settings := s.stored.Settings
	timeout := time.Duration(settings.TimeoutMS) * time.Millisecond
	options := &redis.Options{Addr: settings.Address, Username: settings.Username, Password: s.password, Protocol: 2, DisableIdentity: true, MaxRetries: -1, DialerRetries: 1, MaxConcurrentDials: 8, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout, PoolTimeout: timeout, ContextTimeoutEnabled: true, PoolSize: 32, MaxActiveConns: 32, MinIdleConns: 0, ConnMaxIdleTime: time.Minute}
	if settings.TLS {
		host, _, _ := net.SplitHostPort(settings.Address)
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}
	return redis.NewClient(options)
}
func (s *sharedRateState) acquire() (*redis.Client, func()) {
	s.mu.Lock()
	if s.client == nil {
		s.client = s.newClient()
	}
	client := s.client
	s.users++
	s.mu.Unlock()
	return client, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.users--
		if s.retired && s.users == 0 && s.client != nil {
			s.client.Close()
			s.client = nil
		}
	}
}
func (s *sharedRateState) retire() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retired = true
	if s.users == 0 && s.client != nil {
		s.client.Close()
		s.client = nil
	}
}
func (s *sharedRateState) Take(parent context.Context, limits []rateLimit, _ time.Time) ([2]bool, error) {
	if len(limits) < 1 || len(limits) > 2 {
		return [2]bool{}, errors.New("invalid rate-state operation")
	}
	if time.Now().UnixMilli() < s.retryAfter.Load() {
		return [2]bool{}, errors.New("shared rate-state unavailable")
	}
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	default:
		return [2]bool{}, errors.New("shared rate-state busy")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(s.stored.Settings.TimeoutMS)*time.Millisecond)
	defer cancel()
	client, release := s.acquire()
	defer release()
	prefix := "aegis:{" + s.stored.Namespace + "}:rates:"
	keys := []string{prefix + "registry"}
	args := make([]any, 0, len(limits)*2)
	for _, limit := range limits {
		keys = append(keys, prefix+hash(fmt.Sprintf("%d:%s", limit.Key.site, limit.Key.ip)))
		args = append(args, limit.Rate, limit.Burst)
	}
	values, e := sharedBucketScript.Run(ctx, client, keys, args...).Int64Slice()
	if e != nil || len(values) != len(limits) {
		s.failures.Add(1)
		s.retryAfter.Store(time.Now().Add(250 * time.Millisecond).UnixMilli())
		return [2]bool{}, errors.New("shared rate-state unavailable")
	}
	var out [2]bool
	for i, value := range values {
		out[i] = value == 1
	}
	return out, nil
}

// Server time and one atomic script prevent replica clock skew or races from
// multiplying budgets. The namespace-wide registry bounds live bucket count.
// No retry is permitted after an ambiguous write; a store restart resets budgets.
var sharedBucketScript = redis.NewScript(`
local t=redis.call('TIME')
local now=tonumber(t[1])*1000+tonumber(t[2])/1000
local registry=KEYS[1]
local expired=redis.call('ZRANGEBYSCORE',registry,'-inf',now,'LIMIT',0,128)
if #expired>0 then redis.call('ZREM',registry,unpack(expired)) end
local additions=0
for i=2,#KEYS do
 if redis.call('ZSCORE',registry,KEYS[i])==false then additions=additions+1 end
end
if redis.call('ZCARD',registry)+additions>100000 then return redis.error_reply('RATE_STATE_CAPACITY') end
local results={}
for i=2,#KEYS do
 local rate=tonumber(ARGV[(i-2)*2+1])
 local burst=tonumber(ARGV[(i-2)*2+2])
 local previous=redis.call('HMGET',KEYS[i],'tokens','at','rate','burst')
 local tokens=burst
 local at=now
 if previous[1] and tonumber(previous[3])==rate and tonumber(previous[4])==burst then
  at=math.max(now,tonumber(previous[2]))
  tokens=math.min(burst,tonumber(previous[1])+math.max(0,now-tonumber(previous[2]))*rate/1000)
 end
 local allowed=0
 if tokens>=1 then allowed=1 tokens=tokens-1 end
 local ttl=math.ceil(burst/rate*1000)+60000
 redis.call('HSET',KEYS[i],'tokens',tokens,'at',at,'rate',rate,'burst',burst)
 redis.call('PEXPIRE',KEYS[i],ttl)
 redis.call('ZADD',registry,now+ttl,KEYS[i])
 table.insert(results,allowed)
end
redis.call('PEXPIRE',registry,2000060000)
return results
`)
