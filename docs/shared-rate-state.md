# Shared rate-limit counters

Policies, CIDR lists, address objects and rule versions already share PostgreSQL and refresh into each replica's memory. **System → Rate-limit state** chooses where HTTP flood and CAPTCHA suspicion-frequency counters live. The default is local memory; Redis/Dragonfly is optional and adds no inference worker.

## Choose a backend

- **Local memory:** no network lookup on the counter path. Budgets apply independently per replica and reset on restart. A bounded mutex-protected token-bucket map preserves existing behavior; it does not claim lock-free execution.
- **Redis / Dragonfly:** all replicas use one shared budget per application, selected policy and client/application counter. Bot-frequency counters share their own corresponding budgets. PostgreSQL still owns configuration, certificates, rules, accounts, audit logs and challenge state. Redis holds transient counters only.

For an existing private backend, enter its `host:port`, optional username/password, TLS option and timeout. Test the connection, then save. Credentials are authenticated-encrypted with the external application key and a key identifier; read APIs return only `has_password`. A changed address, username or TLS setting requires resupplying or explicitly clearing existing credentials. TLS verifies the backend certificate using the application's CA trust; there is no skip-verification option.

To add the supplied optional private Redis container:

```sh
docker compose -f compose.yaml -f compose.redis.yaml up -d
```

In System, choose Redis / Dragonfly, set `redis:6379`, test, and save. The overlay publishes no Redis port, uses no persistent Redis volume and configures `noeviction`. It trusts the deployment's private Docker network and has no Redis password by default. Use authenticated/TLS backend credentials when the network requires them. Existing Redis or Dragonfly deployments can be used without this overlay. Local mode still needs only the original application and PostgreSQL containers.

## Decisions and failure behavior

A single atomic Lua operation checks both client and application flood buckets using **backend server time**, preventing competing replicas or differing app clocks from multiplying the budget. Bot frequency needs a separate operation only when enabled. This adds backend round-trip latency; measure in your network before enabling enforcement. Default lookup deadline is 100 ms, configurable 20–250 ms. Work/pools are bounded, dials are limited, and a short failure cooldown avoids a connection storm. Ambiguous writes are not retried automatically; they may have consumed a token even though Aegis returns failure.

An enforcing control returns **503** when its shared counter cannot be evaluated. Observe records `rate_state_unavailable` and continues other independent protections. Bot-frequency failure in enforcing CAPTCHA mode also returns 503. There is **no silent fallback to local counters**. CIDR/Geo decisions precede these checks, and all-WAF bypasses retain their documented behavior. Existing replicas continue using cached backend settings during a PostgreSQL outage; administrative changes and new startup still require PostgreSQL unless sealed recovery was explicitly configured.

A store restart, flush, eviction or operator-initiated backend switch can reset effective budgets. Use a dedicated, private, non-evicting store with suitable memory and availability. Single-endpoint Redis-compatible operation is supported; Sentinel discovery, Redis Cluster topology handling and durable counter recovery are not implemented. PostgreSQL configuration propagation remains normally two seconds plus compile time; replicas can briefly use the prior backend during a settings transition.

## Bounds and privacy

Local maps cap each limiter at 100,000 identities and remove idle buckets only after at least five minutes **and** enough time for their burst to refill. Shared counters expire after their full refill time plus 60 seconds. A database-specific namespace caps shared live buckets at 100,000; reaching capacity reports backend failure instead of evicting active budgets. Application and bot counters count toward that shared cap. Redis memory pressure with `noeviction` likewise fails closed for enforcing controls.

Keys hash client identifiers and separate database namespaces; they do not contain request bodies, paths or cleartext IP strings. Hashing is pseudonymization, not anonymization: IP identities can be guessed. Treat backend placement, ACLs, logs and snapshots as part of your traffic-data residency boundary. Shared counter settings/credentials are included in the optional encrypted snapshot cache so recovery does not silently revert to local budgets.

## API and verification

`GET /api/rate-state` returns settings, revision, `has_password`, this replica's loaded revision and backend failure count. `PUT /api/rate-state` accepts flattened `backend`, `address`, `username`, `tls`, `timeout_ms`, `revision`, optional write-only `password` and `clear_password`. `POST /api/rate-state/test` accepts the same draft and performs an authenticated Ping without spending tokens. Normal session/CSRF protection applies. MCP uses Configuration scope; saving settings requires the standard exact-candidate simulation receipt.

The client is pinned to official [go-redis](https://github.com/redis/go-redis/releases/tag/v9.23.0). The design follows Redis's [atomic Lua token-bucket pattern](https://redis.io/docs/latest/develop/use-cases/rate-limiter/go/) with additional capacity/expiry/failure bounds. Integration tests run against real Redis 8 and Dragonfly 2.0.0, covering independent replicas, concurrent mutation, bot frequency, ciphertext validation, credential changes, failure/recovery and sealed snapshots. This is counter compatibility, not a claim of full Redis/Dragonfly feature parity.
