# Inspection bounds, exclusions and security telemetry

## Sensitivity and selection

In the policy editor, choose an original or curated managed set, start in Observe, then use the 1–5 **Sensitivity** slider. Standard preserves paranoia 1, inbound 5 and outbound 4. Advanced edits switch the label to Custom when no preset matches; selecting a preset overwrites those three fields only. Modes, response inspection, body limits and exclusions are independent. Aggressive and Maximum explicitly warn about legitimate traffic being blocked. See the [full preset table and curated-set workflow](managed-signatures.md#sensitivity-and-curated-sets).

A curated set removes unselected detection rules through Coraza's existing removal directives while retaining scoring and enforcement helpers. Sparse sets may never reach full-bundle anomaly thresholds; tune in Observe and test legitimate traffic before enforcing. Sensitivity does not shrink the compiled corpus and is not a latency guarantee. Source/version/digest and selected IDs stay frozen; upstream review creates another artifact rather than changing published policies.

## Request-body inspection

Body inspection uses bounded prefixes, not an unbounded `io.ReadAll` of visitor data. Custom JSON fact extraction reads at most 64 KiB + one sentinel byte, bounds nesting and token counts, and replays consumed bytes upstream. Managed signatures inspect 4 KiB–1 MiB per policy with 64 concurrent reservations per replica. Block defaults to rejecting oversized request bodies (413); an explicit **Inspect prefix and forward full body** action permits larger requests while leaving the tail uninspected. Parser errors and matched rules can still reject truncated JSON/multipart bodies. Observe forwards oversized requests with capped metadata. Saturated enforcing inspection returns 503; Observe marks busy and allows.

Response inspection is optional and off by default. It has separate Off/Observe/Block, outbound threshold, 4 KiB–1 MiB body limit (default 256 KiB) and reject/partial action controls. Web profiles buffer eligible text bodies before forwarding; matching or oversized rejecting responses return a generic 502 without forwarding upstream headers/body. SSE/streaming profiles forward immediately and inspect bounded overlapping windows after delivery. Block can terminate future output, often retaining the original status 200; it cannot retract sent bytes. WebSocket frames, binary gRPC and unsupported types have no body inspection. The five-second buffered-body deadline does not apply to streams. Request-only reservations release after prefix forwarding; buffered responses release after the prefix is consumed/closed. Streaming responses release the original request transaction after headers and reserve a slot only during each window check. [Full behavior and API fields](body-inspection.md).

A bounded prefix is buffered before forwarding so Block can decide before sending attack bytes upstream. Streaming data upstream while deciding whether to block would already expose the upstream. Uninspected data is never described as fully inspected. Evidence uses a bounded tap while the upstream reads, not a separate read-ahead operation. Configuring a larger body limit increases concurrent memory requirements; these bounds do not cap all HTTP/TLS/Coraza/process memory.

## False-positive tuning

Policy **Advanced signature tuning** supports global rule-ID exclusions and **Scoped signature exclusions (JSON)**. Settings persist through the dashboard/API in PostgreSQL; no configuration files need editing. For example:

```json
[
  {
    "rule_ids": [942100],
    "path_prefix": "/search",
    "parameters": ["q"],
    "client_cidrs": ["192.168.10.0/24"]
  }
]
```

This exempts argument `q` from rule 942100 only when both the path prefix and verified source range match. Other arguments, rules and paths still apply. Omitting parameters exempts those entire rules within the selected path/client scope. Parameter-only exceptions apply across paths. Client predicates cannot use an unreliable forwarded identity. Scopes are literal prefixes/CIDRs/argument names, not administrator-provided SecLang. Up to 32 entries, 20 IDs and 16 parameters/client CIDRs each; rule IDs must exist in the selected set and be request detection IDs 910000–948999 or response detection IDs 950000–958999. Response exclusions support path/client scopes, not request-parameter scopes. Scoring/control IDs cannot be conditionally excluded. Parameter names refer to Coraza ARGS (query/form and the corresponding parsed JSON argument names), not arbitrary HTTP headers or raw-body byte offsets.

Exceptions do not prove that a request is safe. Investigate allowed and blocked traffic, replay both attack and benign retained facts for custom rules, and use Observe before broadening exclusions.

## Structured events and privacy

Application diagnostics and security events use JSON on stdout. The bounded background access-log worker emits security metadata after the traffic decision, before attempting the PostgreSQL batch write. A failed database write therefore does not suppress an otherwise queued stdout event. Slow logging can fill/drop the bounded queue; it does not wait in forwarding. Events are best-effort, not a guaranteed SIEM delivery stream.

Security events use `event` values `waf_block`, `waf_observe`, or `waf_allow` (explicit full WAF bypass). Versioned fields include `schema_version`, UTC `timestamp`, `client_ip`, `rule_triggered`, nullable `matched_payload`, and `action`, plus site/policy/revision, status, legacy custom `rule_ids`, CRS `signature_ids`, signals, and network decision. See the [event contract and collection guide](logging.md). No raw matched payload, authorization/cookie headers, key or body is included by default. An unmatched allowed request remains in PostgreSQL access logs without producing a security stdout event.

In **Traffic → Capture settings**, administrators can disable security stdout events per application or explicitly include retained redacted request samples. `security_events_disabled` and `security_samples` are also TrafficSettings API fields. Samples require the existing opt-in sampling policy and field allowlists; only sampled retained facts are emitted, capped at 2 KiB. `request_sample` is context, not a guaranteed exact matched string. Truncation can leave a JSON-looking string incomplete. Redaction is best-effort; stdout collectors and agents may export personal data outside PostgreSQL retention controls. Audit events contain operation metadata, never sample values or credentials.

## Regression checks

The attack matrix includes SQL injection, XSS, traversal, encoding variants and benign controls through Coraza/CRS. Separate tests verify scoped exclusions, tiny transport chunk boundaries, bounded read-ahead, exact body replay, reservation release and telemetry privacy. A prompt-injection case exercises an explicitly configured native literal rule only: CRS is not a general semantic prompt-injection detector.

Go fuzzing checks JSON fact extraction, read bounds, malformed input and exact body preservation. Seed cases run with ordinary `go test`; CI additionally runs 20 seconds with two fuzz workers. Pull requests and branch pushes run the security workflow. Main pushes, nightly builds and manual image builds must pass this reusable workflow before the image publication job starts. Detection tests and fuzzing reduce regressions; they do not establish complete attack coverage or absence of bypasses.
