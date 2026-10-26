# Metrics and structured security events

Aegis writes JSON to container stdout and exposes Prometheus metrics on the **management listener**. No monitoring container or external collector is required to run the gateway.

## Prometheus access

Open `/metrics` using your authenticated dashboard session, or configure a scraper with a source-restricted **Read** API key created in Agent access. Remote bearer authentication requires HTTPS and uses the socket peer, not forwarded headers. The MCP endpoint can remain disabled; revoking/expiring the key immediately removes metrics access too. Keys are shown once and stored as hashes. Session/key authorization requires PostgreSQL; database failure returns 503 rather than exposing metrics without authorization.

`/api/metrics` exposes the same format to authenticated sessions and permitted MCP `management_operation` reads. Protected application listeners do not expose gateway metrics: an application's own `/metrics` path follows its normal routing and policy. Exposition uses no-store responses, limits concurrent scrapes to four per replica and bounds scrape handling to five seconds.

Example Prometheus scrape configuration (use a read key with the scraper's source address allowed):

```yaml
scrape_configs:
  - job_name: aegis
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /run/secrets/aegis_metrics_key
    static_configs:
      - targets: [aegis-1.example.com:9090, aegis-2.example.com:9090]
```

For a private CA, configure the scraper's `tls_config.ca_file`. Scrape each replica directly; scraping only a load-balanced address rotates between independent counters and cannot produce accurate cluster totals. Use a shared monitoring system to aggregate them. Counters reset on process restart and are not stored in PostgreSQL.

## Metric meanings

| Metric | Labels | Meaning |
| --- | --- | --- |
| `aegis_requests_total` | `status`, `rule_id` | Completed public HTTP requests, counted once per request. Includes unknown-host and HTTP-01 handling; excludes TLS handshakes that fail before HTTP and management requests. |
| `aegis_decisions_total` | `action` | Allowed, blocked or challenged decisions, independent of the HTTP status. |
| `aegis_inspection_duration_seconds_bucket` | `phase`, `le` | Histogram for request inspection, buffered response/header inspection, or each streaming window. Includes bounded body reads/counter checks; excludes the upstream round-trip wait. |
| `aegis_mcp_actions_total` | `tool`, `status` | Dispatched tool calls completed successfully, returned an error or had a contained panic. HTTP authorization failures before tool dispatch are not tool calls. |
| `aegis_access_logs_dropped` | — | This replica's dropped access-log count since startup. |
| `aegis_configuration_version` | — | This replica's active configuration version. |

The official Go client also exposes process/Go-runtime metrics such as CPU consumption, resident memory and garbage collection. These cover the application process, not PostgreSQL or the host's other services.

Request attribution chooses one primary match: lowest custom rule ID, otherwise lowest CRS detection ID, otherwise fixed `network`/`bot`/`signal`/`none` categories. `unrouted` and `acme` describe those public handlers. It is not a complete match inventory; use request details/logs for every match. Request-series creation caps at 4096 status/rule pairs, with at most 501 additional status/`other` overflow series. No IP, URL, hostname, payload, arbitrary tool name or combined list of rule IDs becomes a metric label. Unknown MCP tool names collapse to `unknown`.

Long-lived streams count when they end. A stream terminated after output may retain status 200 while `aegis_decisions_total{action="blocked"}` increases. A challenge returning 403 is `challenged`, not proof that the sender was malicious. Observe matches can have successful HTTP status; rules alone do not prove traffic legitimacy. Inspection windows are separate samples, so histogram counts are not request counts. Queued logging loss does not suppress in-memory request metrics.

Example queries:

```promql
sum(rate(aegis_requests_total[5m]))
sum by (status) (rate(aegis_requests_total[5m]))
sum(rate(aegis_decisions_total{action="blocked"}[5m]))
histogram_quantile(0.99, sum by (le) (rate(aegis_inspection_duration_seconds_bucket{phase="request"}[5m])))
sum by (tool, status) (rate(aegis_mcp_actions_total[5m]))
```

## JSON security and administrative events

[Security event schema and privacy controls](logging.md) describe `waf_block`, `waf_observe` and `waf_allow`, including timestamp, client IP, rule attribution, action and optional bounded/redacted request context. Enforcement/forwarding precede a nonblocking logging enqueue; a worker emits stdout and persists batches. Events can be lost under saturation or crashes. Scrape counters and inspect drop counts rather than treating the log as a guaranteed durable packet ledger.

MCP completion records add `event:"mcp_action"`, `timestamp`, bounded `tool`, `status`, `agent_key_id` and `duration_ms`. They omit arguments, response bodies, credentials and panic contents. A contained tool panic returns an error asking the agent to refresh state before retrying; it does not claim that an ambiguous preceding mutation was rolled back. Security-relevant management mutations retain their existing transactional PostgreSQL audit events. Container collectors can ship JSON to Loki, Fluent Bit, Datadog or a SIEM using their own retention/residency controls.

Instrumentation uses the pinned official [Prometheus Go client](https://github.com/prometheus/client_golang/releases/tag/v1.25.0). No inference, agent call or log-collector network operation runs on the forwarding path.
