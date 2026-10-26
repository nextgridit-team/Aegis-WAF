# Traffic logging and forwarding

The request path resolves identity, selects its cached policy, evaluates rules and protection, and applies the resulting block, redirect or upstream proxy action. It then attempts a nonblocking enqueue of the completed access event. PostgreSQL inserts are batched in a background worker. Database writes, country lookup and optional evidence redaction/JSON generation do not delay the forwarding decision.

When opt-in JSON evidence is enabled, a bounded tap copies bytes while the upstream consumes them; it never reads ahead just to prepare a log. If the upstream responds without consuming the body, evidence marks it unavailable. A JSON-body rule can still require bounded synchronous inspection to enforce that rule correctly. Metadata snapshots and the stream copy have bounded in-memory overhead; asynchronous logging is not a claim of zero CPU overhead.

The access queue holds up to 8192 events, and at most 64 optional evidence captures can be pending per replica. Saturation drops logs or samples rather than waiting or spawning an unbounded goroutine per request. `/api/status` exposes dropped access logs and evidence samples. Failed database batches also increment the dropped-log count. Logging is best effort; process crashes can lose queued events. This queue is separate from security-relevant administrative audit writes, which remain part of management transactions.

Long-running configuration, log, ACME and feed workers now run under a supervisor. A recoverable panic records a constant error and counter, unwinds deferred transaction/lock cleanup, and restarts after a cancellable one-second delay. Panic values are not logged because they may contain secrets. Pending evidence reservations are released when a log batch unwinds. A failed issuance heartbeat cancels its job rather than continuing without coordination. The status endpoint exposes `background_worker_panics`; this is not protection against fatal runtime errors such as out-of-memory termination. HTTP request panics also retain Go's standard server containment.

## Security event schema and collection

Aegis emits one-line JSON security decisions to application stdout from the bounded background logging worker, after applying the traffic action. This does not add a synchronous log-sink call to forwarding. Use `event` to distinguish security records from JSON application diagnostics. The machine-readable contract is [security-events.schema.json](security-events.schema.json).

```json
{"schema_version":1,"timestamp":"2026-10-25T12:00:00Z","event":"waf_block","action":"blocked","client_ip":"198.51.100.24","site_id":3,"policy_id":2,"policy_revision":4,"method":"GET","status":403,"response_source":"waf","rule_triggered":["crs:942100"],"matched_payload":null,"matched_payload_source":"disabled","payload_truncated":false,"rule_ids":[],"signature_ids":[942100],"signals":[]}
```

| Field | Meaning |
| --- | --- |
| `schema_version` | Contract version, currently `1`. |
| `timestamp` | Recorded request event time in UTC; stdout `time` is emission time. Legacy `request_at` remains available. |
| `event` / `action` | `waf_block` / `blocked`, `waf_observe` / `observed`, or explicit full bypass `waf_allow` / `allowed`. Upstream HTTP 403 responses alone are not WAF blocks. |
| `client_ip` | Resolved client identity after the configured trusted-proxy checks. |
| `site_id`, `policy_id`, `policy_revision` | Application and selected policy context. |
| `rule_triggered` | Deduplicated trigger/context identifiers: `custom:<id>`, `crs:<id>`, `signal:<name>`, `network:<decision>`, `inspection:<state>`, or `waf:unspecified` when no more precise block reason exists. Matched identifiers are context, not a claim that every match independently caused the final action. |
| `matched_payload` | Nullable text. Disabled/unavailable capture is always `null`. Opt-in retained, redacted request context is limited to 2 KiB. It is not a guaranteed exact matched-byte string. |
| `matched_payload_source` | `disabled`, `unavailable` (not sampled/not retained/invalid), or `redacted_request_context`. |
| `payload_truncated` | Whether the retained text was shortened. Treat payload as text, not necessarily complete embedded JSON. |
| `rule_ids`, `signature_ids`, `signals` | Stable arrays, including empty arrays. Legacy fields remain for collectors. |
| `response_source`, `status`, `duration_ms` | Actual response origin, HTTP status and recorded duration. |

For payload context, explicitly enable **Traffic → Capture settings → Include retained redacted samples in security events** (`security_samples`), plus evidence capture and field allowlists. Existing sampling budgets, redaction and retention still apply. No request bodies, authorization headers, cookies or credentials are added to stdout by default. `request_sample` remains a compatibility alias when context exists. Review [privacy and redaction limits](security-tuning.md#structured-events-and-privacy) before exporting samples.

The contract applies to every emitted block source: native rules, managed signatures, bot/flood decisions, CIDR/Geo rules and inspection bounds. Normal unmatched allowed requests remain in PostgreSQL access logs without generating a security stdout record. Administrators can disable stdout security events per application; that existing preference is respected.

For a local view:

```sh
docker compose logs --no-color --no-log-prefix app | jq -Rc 'fromjson? | select(.event == "waf_block")'
```

Point a Docker stdout collector, Filebeat, an OpenTelemetry log collector or your SIEM agent at the application container, decode JSON once, and filter on `event` / `action`. For Grafana Loki, apply `| json` then `| event="waf_block"` to your application stream. No collector or external destination is enabled automatically.

Delivery is best effort. Queue saturation and database/collector outages can lose events; the dashboard and `/api/status` expose dropped access-log counts. Stdout emission is attempted before the PostgreSQL batch write, so a database write failure does not suppress an already queued stdout record. Collectors manage their own transport, storage and data residency; PostgreSQL evidence retention does not delete exported stdout samples.

Prometheus request/inspection/MCP metrics and structured MCP completion events are documented in [observability](observability.md). They do not make queued log delivery lossless.
