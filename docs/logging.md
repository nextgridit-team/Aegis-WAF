# Logs, collection and retention

Aegis sends completed public requests, committed administrative audits, MCP tool completions and application diagnostics to container stdout as one-line JSON. Ordinary allowed requests are included. Use **System → Logs & retention** to choose how much history Aegis keeps in PostgreSQL: **six hours by default**, configurable from 1 to 8,760 hours, shared by all applications and replicas.

Database retention does not configure Docker, the host journal or a SIEM. Configure a collector and its own retention if you need longer history. No external destination is enabled automatically.

## Event types

| Record | Identification | Contents |
| --- | --- | --- |
| Ordinary request | `event:"http_access"` | Request ID, client IP, application/host, selected policy, status, response source, duration and available region/country. Includes upstream errors, redirects and ACME responses. |
| Security decision | `waf_block`, `waf_observe`, `waf_allow` | The same metadata plus rule/signature IDs, signals and the decision. Explicit full WAF bypass is `waf_allow`. An upstream 403 alone is not a WAF block. |
| Administrative audit | `event:"admin_audit"` | Stable audit ID, original timestamp, actor, action and resource; emitted only after its database transaction commits. |
| MCP completion | `event:"mcp_action"` | Tool, status, key ID and duration, without tool arguments, response bodies or credentials. |
| Application diagnostic | `level` and `msg` | Startup, runtime errors and background-worker diagnostics. These do not all have an `event` field. |

One access record is produced when a public request finishes; a long-lived stream is logged when it ends. Requests rejected before a site is selected have no site/policy assignment. This is HTTP request logging, not a packet ledger or a log of every management-page read. Malformed connections that never reach the public handler cannot produce a completed-request record.

The request path applies the policy and forwards, blocks or redirects before attempting a **nonblocking** logging enqueue. An asynchronous worker enriches metadata and emits stdout. A separate bounded database queue persists batches, so a slow database does not stall stdout processing. Neither sink is called synchronously from the forwarding goroutine. Optional JSON evidence uses a bounded tap while the upstream consumes the body; it does not read ahead to prepare a log. Actual inspection can still require bounded synchronous body reads.

## Security event schema and collection

Request records use [security-events.schema.json](security-events.schema.json), including ordinary `http_access` records. Audits use [audit-events.schema.json](audit-events.schema.json).

```json
{"schema_version":1,"timestamp":"2026-10-27T12:00:00Z","event":"waf_block","action":"blocked","request_id":"example-request-id","host":"app.example.com","site_id":3,"site_name":"Customer portal","client_ip":"198.51.100.24","policy_id":2,"policy_revision":4,"method":"GET","status":403,"response_source":"waf","duration_ms":1,"rule_triggered":["crs:942100"],"matched_payload":null,"matched_payload_source":"disabled","payload_truncated":false,"rule_ids":[],"signature_ids":[942100],"signals":[]}
```

| Field | Meaning |
| --- | --- |
| `schema_version` | Contract version, currently `1`. |
| `timestamp` | Original event time in UTC; stdout `time` is emission time. Historical exports can have much older timestamps. |
| `request_id` | Stable request correlation/deduplication ID. Also shown in request details. Legacy imported records use `access:<database ID>`. |
| `event` / `action` | `http_access` / `allowed`, `waf_block` / `blocked`, `waf_observe` / `observed`, or `waf_allow` / `allowed`. Allowed means the gateway permitted forwarding, not that the upstream succeeded. |
| `client_ip` | Resolved identity after configured trusted-proxy checks; an unrouted request has only the socket peer. |
| `host`, `site_id`, `site_name` | Requested hostname and application context, when available. Historical records may lack names. |
| `policy_id`, `policy_revision`, `policy_name` | Selected policy context. |
| `country`, `region_code`, `region_name` | Available enrichment; empty when unknown. |
| `rule_triggered` | Deduplicated identifiers such as `custom:<id>`, `crs:<id>`, `signal:<name>`, `network:<decision>` and `inspection:<state>`. Matches are context, not a claim that every match independently caused the action. |
| `matched_payload` | Nullable opt-in redacted request context, limited to 2 KiB; not a guaranteed exact matched-byte string. |
| `matched_payload_source` / `payload_truncated` | `disabled`, `unavailable` or `redacted_request_context`, and whether the text was shortened. Treat it as text, not necessarily complete embedded JSON. |
| `rule_ids`, `signature_ids`, `signals` | Stable arrays, including empty arrays. |
| `response_source`, `status`, `duration_ms` | Response origin, HTTP status and duration. A terminated stream can retain the status already sent. |

Audit records have `schema_version:1`, `event_id:"audit:<database ID>"`, `audit_id`, `timestamp`, `actor`, `action` and `resource`. Use deployment identity plus `event_id`/`request_id` for deduplication across replicas; IDs alone do not identify independent installations.

Metadata is always emitted. No raw URL path/query, request body, authorization header, cookie or private key is added to request stdout records by default. For optional payload context, enable **Traffic → Capture settings → Include retained redacted samples in security events**, plus evidence capture and field allowlists. Sampling, redaction and size caps still apply. The deprecated `security_events_disabled` API field no longer suppresses metadata; existing `true` values continue to suppress sample export until an administrator changes capture settings. Historical database backfill exports metadata only, never old content samples. See [privacy controls](security-tuning.md#structured-events-and-privacy).

For a local view:

```sh
# All JSON application records, including ordinary requests and audits.
docker compose logs --no-color --no-log-prefix app | jq -Rc 'fromjson?'

# Only WAF blocks.
docker compose logs --no-color --no-log-prefix app | jq -Rc 'fromjson? | select(.event == "waf_block")'
```

Point Filebeat, Fluent Bit, an OpenTelemetry collector or your SIEM agent at the container stream. Decode the application JSON after any Docker envelope your collector supplies. In Loki, apply `| json` then `| event="waf_block"` to the application stream. PostgreSQL container diagnostics remain a separate container stream in PostgreSQL's own format.

## Retention and upgrades

The global window covers access metadata, administrative audits and optional request evidence. Evidence uses the shorter of the application capture expiry and the current global window; APIs, replay and simulation cannot read samples beyond that window even if physical cleanup is delayed. Alert history and configuration revision history have separate lifecycles. Backups and exported copies are not deleted by this setting.

Reducing retention makes older records eligible for automatic deletion. It does not delete everything in the same management request. Dashboard history and replay depend on available retained data; choosing six hours does not provide a 24-hour investigation history.

Before deleting an access or audit record, Aegis requires a successful stdout export. Live access events are normally emitted before their database write. Committed audits and pending stored access records are exported in batches of 250 per type, coordinated with PostgreSQL row locks across replicas. Upgrading backfills existing stored metadata before it becomes eligible for deletion. Previously emitted records from older versions may be exported again because those versions did not track delivery.

Cleanup uses database coordination, bounded transactions and catch-up passes when a batch limit is reached. Normal checks settle to a five-second interval when caught up. Database outages, export failures, an upgrade backlog or insufficient storage throughput can extend physical retention. This is a retention target, not a guaranteed hard disk-size cap. Deleted PostgreSQL space becomes reusable; files do not necessarily shrink immediately.

**System → Logs & retention** shows export backlog, last checks, cleanup totals/errors, table size and current-replica drop counters. The management API exposes the same state at `GET /api/log-settings`; revision-checked changes use `PUT /api/log-settings`. [API contract](management-api.md#global-log-retention).

## Delivery and failure behavior

The access intake queue holds 8,192 events; the database queue holds eight batches of at most 1,000 events. At most 64 optional evidence captures can be pending per replica. Saturation drops records or samples instead of waiting in forwarding or starting unbounded goroutines. A database outage can lose dashboard history while already emitted stdout records remain available to collectors. Process crashes can lose queued records.

Stored export is at least once: a crash or database commit failure after a successful stdout write can cause a replay. Failed exports remain stored and ineligible for access/audit cleanup. A successful stdout write is **not** a Docker durability or SIEM receipt acknowledgement. Docker rotation, collector outages or a full disk can still lose exported history. There is no persistent local application spool.

Graceful shutdown drains HTTP handlers, access logging and a final bounded stored-log export. A permanently blocked OS stdout write is not cancellable by a Go context; Docker's stop deadline still applies. Transactional administrative mutations fail when their audit cannot commit. These guarantees differ from best-effort access logging.

`/api/status` reports dropped access persistence, stdout drops/failures and evidence samples. [Prometheus metrics](observability.md) expose the current replica's logging loss counters. A sink failure may later be recovered by stored export, so stdout failures are not an exact permanent-loss count. Supervised workers contain recoverable panics, log a constant diagnostic without panic contents and restart with backoff. Fatal runtime errors such as OOM remain outside this containment.

## Docker and SIEM history

The supplied Compose file uses Docker's `json-file` driver with `max-size:100m` and `max-file:5` for the app. This bounds local container history by size, not hours; busy systems can rotate through it quickly. Override `AEGIS_DOCKER_LOG_MAX_SIZE` / `AEGIS_DOCKER_LOG_MAX_FILES`, or configure your preferred supported logging driver and collector. Recreate the app container for driver/rotation changes to take effect.

Aegis's database window does not change those driver settings. Docker does not automatically archive rotated records into another system log. Ship them before rotation if you need long-term history. See Docker's [JSON-file driver](https://docs.docker.com/engine/logging/drivers/json-file/) and [logging configuration](https://docs.docker.com/engine/logging/configure/) for rotation, delivery mode and driver behavior.
