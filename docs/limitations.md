# Capabilities and current limits

Aegis is under active development. Request protection and the optional MCP agent endpoint are implemented; Aegis runs no AI traffic analysis itself.

- **Flood budgets are replica-local.** More replicas increase the effective aggregate allowance; budgets reset on process restart. Cluster-wide rate coordination is not implemented.
- **Body inspection remains bounded.** Request inspection defaults to 64 KiB for new custom policies and 1 MiB for the included baseline; both request and optional response limits range from 4 KiB to 1 MiB. Explicit partial actions forward uninspected tails. Truncated structured request bodies may still fail parsing. Response inspection is opt-in and buffers eligible text before forwarding; SSE, WebSockets and unsupported content types are skipped. This does not provide arbitrary stream inspection or unlimited uploads with full inspection. [Body controls and failure behavior](body-inspection.md).

- **Bot detection is basic and spoofable.** There is no CAPTCHA, browser challenge, verified-bot identity, behavioral learning or network-layer DDoS protection.
- **Agents are external and opt-in.** MCP provides scoped access for your agent; Aegis runs no inference or built-in AI workflow. Grant live enforcement separately from read/evidence/draft access. CRS inbound anomaly scoring is independent. [Agent setup](agent-access.md).
- **Database outages have defined limits.** Running replicas retain their last loaded routes, certificates and policies; sign-in, administrative changes and HTTP-01 lookup still require PostgreSQL. A default replica starting during an outage remains unready. [Failure and recovery behavior](deployment.md#health-and-database-outages).
- **Logs are best effort.** Forwarding/enforcement precede queued log writes. Queue saturation, outages or process crashes can lose records. Access/audit retention is manual; sampled evidence has its own automatic expiry. [Logging](logging.md) · [Privacy](evidence-privacy.md).
- **Encryption covers secret values.** Private keys and saved credentials use AES-256-GCM with an external key. Public certificate chains, configuration and logs are not encrypted by that application layer. Online key rotation, MFA, password recovery and granular administrator roles are not implemented. [Encryption details](encryption-at-rest.md).

See [measured performance and comparison limits](proxy-comparison.md). Those small-workload results do not establish production capacity or security parity with other WAFs.

See the [documentation index](README.md) for deployment and tuning guides.
