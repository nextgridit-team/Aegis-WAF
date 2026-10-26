# Change history

This records shipped behavior rather than proposed features. Container builds use `latest` plus unique build tags/digests; these dated entries are not semantic-version releases.

## 2026-10-25 — Bot verification and platform hardening

### Added

- Selective, fully self-hosted image/audio CAPTCHA with explainable suspicion scores, expiring application/client-bound clearance and PostgreSQL-backed multi-replica verification. Existing policies keep it disabled until configured. [Bot protection](docs/bot-protection.md).
- Enforced MCP `simulate_rule_impact` before live rule/policy/host/protection/existing-address mutations. Receipts bind the key, exact candidate and configuration version, expire after two minutes and can be used once. Unknown evidence stays unknown; unconfigured test hosts cannot satisfy assertions. [Agent workflow](docs/agent-access.md#required-simulation-before-live-protection-changes).
- Per-host Web or SSE/streaming profiles and bounded overlapping response inspection. Streams deliver immediately; detections can terminate future output, not retract sent bytes. [Inspection modes](docs/body-inspection.md).
- Optional Redis/Dragonfly rate-state backend for shared flood and bot-frequency budgets, configured in **System** with encrypted write-only credentials and connection testing. Default local mode and the two-container deployment remain available. [Shared counters](docs/shared-rate-state.md).
- Authenticated management Prometheus request/decision counters, inspection histograms, MCP completion counts and process metrics, plus secret-free structured MCP completion events. Read keys can scrape metrics with MCP disabled. [Observability](docs/observability.md).

### Verified and corrected

- Atomic configuration reload preserves admitted HTTP/1.1, HTTP/2 and upgraded connections while new requests and TLS handshakes use the refreshed policy/certificate. Invalid candidates retain the working snapshot. [Architecture](docs/architecture.md#atomic-reload-and-active-connections).
- Native client-IP rules use the resolved trusted-proxy identity. Local idle-bucket cleanup preserves full-refill semantics for large bursts. MCP tool panics and typed-nil SDK results are contained safely.
- Updated `golang.org/x/net` to v0.60.0 for available HTTP/2 advisory fixes. Dependency notices and vulnerability checks cover the distributed build. [Verification](docs/verification.md).
- Real PostgreSQL/Redis/Dragonfly, race/vet, browser/Pebble, container outage/recovery and latency checks passed. The measured small-request CRS baseline was approximately 10,808 requests/sec, 1.471 ms mean and 3.793 ms p99; these are fixture results, not production capacity. [Measurements](docs/benchmarks.md#platform-hardening-verification-2026-10-25).

### Upgrade notes and limits

- Additive schema migrations reach version 18. Existing applications default to Web, an 8192-byte streaming window and local counters; existing policies, assignments, certificates and credentials are preserved. Update all replicas before enabling new shared policy fields.
- Existing MCP enforcement clients must obtain and pass simulation receipts. Import the updated agent skill; a receipt grants no extra authority and does not impose a separate human-review requirement.
- Redis/Dragonfly is optional. Shared enforcing counters fail with 503 on backend failure; there is no automatic fallback to multiplying local budgets.
- Response inspection remains off by default. CAPTCHA does not prove bot identity, and clearance does not bypass other protections. Logging remains best effort; automatic access/audit retention, MFA and online encryption-key rotation are not implemented.

See [upgrade instructions](docs/updating.md), [current limits](docs/limitations.md) and the [limitations review](docs/limitations-review.md).
