# Limitations review

Reviewed against the implementation and regression tests on 2026-10-25. [Current limits](limitations.md) remain the operator-facing statement; this review separates completed work, practical next improvements and boundaries that should stay explicit.

## Addressed in the current work

| Gap | Implemented outcome | Remaining boundary |
| --- | --- | --- |
| Every suspicious client is simply blocked, with no verification | Selective self-hosted image/audio CAPTCHA and scoped, expiring clearance | Heuristic scoring is spoofable; solving a challenge is not permanent bot identity. |
| Agents can change production protection without an enforced test | Exact-candidate MCP impact simulation and single-use key/config/version-bound receipts | Missing facts stay unknown; a test harness cannot prove traffic legitimacy or policy safety. Unconfigured hostnames cannot satisfy test assertions. |
| Response inspection can delay streaming endpoints | Per-host Web/SSE profile and bounded overlapping response windows with immediate delivery | Detection can terminate future output; already-delivered bytes cannot be recalled. |
| Flood budgets multiply across replicas | Optional Redis/Dragonfly shared counters with explicit failure behavior | Local remains per replica; store resets can reset counters. Shared mode adds network latency. |
| Rule/TLS changes might interrupt long-lived connections | Existing atomic snapshot swap verified with live HTTP/1.1, HTTP/2 and upgraded connections | Existing requests keep their admitted configuration; edits are not immediate revocation of open sessions. |
| Container monitoring lacks standard metrics | Management-only authenticated Prometheus counters/histograms and structured MCP completion events | Scrape each replica. Authentication depends on PostgreSQL; counters reset on restart. |

The dependency review also applied the available `golang.org/x/net` HTTP/2 advisory fixes. The audit had classified those functions outside this application's imported/called graph, but the dependency could still be patched safely. Vulnerability and runtime verification evidence is recorded separately in [verification](verification.md).

## Practical next work

1. **Automatic access/audit retention.** This is the most direct operational improvement: sustained traffic otherwise grows PostgreSQL indefinitely. Add separate dashboard-controlled retention windows, batched database-backed cleanup, progress/error reporting and clear evidence/export semantics. Preserve existing data unless an operator enables a retention policy; test cleanup load so forwarding remains independent of it. Sampled evidence already expires automatically.
2. **Administrator MFA and recovery.** Add TOTP or WebAuthn with a complete enrollment/recovery flow, encrypted authenticator material, rate-limited verification, one-use recovery codes and security audits. Do not call an extra login checkbox MFA or ship a recovery bypass.
3. **Narrower agent/administrator authority.** Existing MCP permissions cover management domains across the workspace. Per-application/resource restrictions would reduce the impact of an agent mistake or stolen credential, but every direct and generic route must enforce the same boundary.
4. **Verified-bot identity.** Optional provider-specific verification can reduce challenges for legitimate crawlers. It requires authenticated provider evidence or forward-confirmed reverse DNS with bounded caching/failure behavior; a User-Agent string is insufficient.
5. **Online encryption-key rotation.** Key identifiers already exist. Rotation still needs a keyring/deployment overlap, transactional resealing of all secret types, replica compatibility and rollback/recovery testing. Replacing one environment key while old ciphertext remains is not rotation.

I would take retention next, then MFA. Both improve a deployed system without expanding the request-detection engine or adding mandatory infrastructure.

## Keep these boundaries honest

- Bounded request/response inspection and unsupported protocols are deliberate controls, not unlimited coverage. Larger upload handling or richer gRPC/WebSocket inspection needs a specific protocol/format design and a memory/latency budget.
- Best-effort asynchronous access logging trades durability for forwarding independence. Automatic retention solves database growth, not loss during queue saturation, crashes or collector failure. Transactional administrative audits have different semantics.
- Runtime database loss is served from cached configuration; default cold startup still requires PostgreSQL. Explicit sealed recovery is available and can restore stale configuration within its allowed age. New CAPTCHA verification, HTTP-01 lookup and management authentication still require PostgreSQL.
- Network-layer DDoS protection belongs outside this HTTP application. A challenge cannot protect a saturated uplink.
- Performance claims must distinguish measured proxy-added overhead from complete request latency. Published small-workload results cannot establish universal sub-millisecond latency, production capacity or security parity with another WAF.
