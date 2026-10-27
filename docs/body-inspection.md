# Request and response body inspection

Configure **Policies → Edit → Signature protection → Body and response inspection**. Settings are versioned in PostgreSQL with the policy and propagate through the normal snapshot refresh. There are no site configuration files to edit.

## Request inspection

| Setting                              | Default                                                     | Behavior                                                                                                                                                      |
| ------------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inspected body limit                 | 64 KiB for custom policies; 1 MiB for the included baseline | Configurable 4 KiB–1 MiB. Bodies exactly at the limit are accepted if no other rule rejects them.                                                             |
| Oversized request action             | Reject                                                      | In Block, return 413 without forwarding an oversized body.                                                                                                    |
| Inspect prefix and forward full body | Explicit alternative                                        | Inspect only the prefix, preserve the full original body upstream, and record `inspection: partial`. Header/query and prefix signature matches still enforce. |

Observe permits oversized bodies and marks partial inspection regardless of the configured oversize action. Request transport errors remain errors. An incomplete JSON or multipart prefix can fail structured parsing and be rejected in Block even with the partial action. This option is not a guarantee that every large upload is accepted. Tune the body limit for the application, test its actual upload format, and inspect recorded failures before enforcing.

Known oversized requests in rejecting Block mode can be rejected from Content-Length without reading the body. Otherwise, the connector reads at most the configured limit plus one sentinel byte before its decision, including chunked requests. Every consumed byte is replayed on an allowed request. The tail of a partial request is **not inspected**; this is an explicit protection tradeoff.

## Optional response inspection

Response inspection is **Off by default**, including existing policies and the included baseline. Enabling it compiles the bundled CRS response rules as well as request rules. These detect known disclosure patterns such as database errors; they are not a general data-loss prevention system.

| Setting                                  | Default              | Behavior                                                                                                                |
| ---------------------------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Response inspection mode                 | Off                  | Off streams normally. Observe records matches and forwards. Block withholds matching buffered responses; streaming matches stop future output.                        |
| CRS outbound anomaly threshold           | 4                    | Configurable 1–100, independent of the inbound threshold.                                                               |
| Response inspection limit                | 256 KiB              | Configurable 4 KiB–1 MiB.                                                                                               |
| Oversized response action                | Reject               | In response Block, return a generic 502 for an oversized eligible response.                                             |
| Inspect prefix and forward full response | Explicit alternative | Inspect the bounded prefix, forward the original full response if permitted, and record `response_inspection: partial`. |

Policy Observe or signature Observe caps response Block at Observe. Policy/signature Off disables it. Response errors are represented as WAF-sourced 502 responses; the original upstream body and headers are withheld on rejection. Response inspection cannot undo a request that has already reached its upstream.

Eligible media types are `text/plain`, `text/html`, `text/xml`, `application/json`, `application/xml` and `application/xhtml+xml`. MIME parameters such as charset are allowed. Binary/other types record `skipped_content_type`; SSE uses the bounded streaming windows described below; protocol upgrades record `skipped_upgrade`. HEAD, 204, 304 and empty-body responses record `no_body`. Response header rules run before these body exemptions. Correct upstream Content-Type is required; unsupported types are not body-inspected.

Aegis requests identity encoding upstream when response inspection is enabled. If the upstream still returns encoded eligible content, response Block returns 502 and Observe forwards it with `unsupported_encoding`. It does not decompress arbitrary upstream encodings into unbounded memory.

Eligible responses are buffered to EOF or the limit plus one byte **before client headers/body are sent**, allowing a blocking decision. This adds time to first byte and makes response inspection inappropriate for arbitrary text streams. A five-second read deadline cancels stalled eligible bodies and returns 502 in either mode; transport/read failures cannot be treated as clean responses. SSE/explicit streaming profiles and WebSockets bypass buffering before this timer starts. Partial responses stream their remaining bytes after inspection.

## Bounds and lifecycle

There are 64 shared inspection reservations per replica. Request-only transactions close after inspection; their replay prefix releases its reservation when consumed or closed. Response-enabled transactions carry request state into the response phases and hold a reservation until the response prefix is forwarded/closed. Streaming responses release the request transaction after headers and reserve a slot only during each window check; idle streams and WebSockets do not retain an inspection slot. Early errors, redirects and cancellation also release reservations.

Memory includes bounded connector prefixes and Coraza's own bounded buffers/collections. A body limit is not a total process-memory limit. Enabling response inspection increases memory residency and can reduce available inspection concurrency while upstreams are responding. There is no disk body spooling or new persistent volume. At most eight distinct active managed configurations are supported per replica.

## Investigation and exclusions

Request details and access logs contain separate request/response inspection statuses, effective response mode and detected CRS IDs. Signature inventory labels response rules as optional. Global rule exclusions can select response rules; path/client scoped response exclusions are supported, but request-parameter exclusions do not apply to response bodies. Raw response bodies are not saved as evidence or exposed in normal logs.

Existing custom-rule replay uses retained request facts and does not replay response CRS rules. Updating to this build does not silently enable response inspection or change existing oversized-request actions. Disable response inspection before rolling back to a build that does not support it.

The implementation uses the established Coraza transaction phases and [body-limit directives](https://www.coraza.io/docs/seclang/directives/); Aegis applies its own bounded read/replay and error handling around those phases.

## Endpoint profiles

Choose **Proxy hosts → Add/Edit → Endpoint type**. This is a host setting; the assigned policy still controls CRS, body ceilings, rates, network rules and exclusions. The profile is not authentication or automatic API-schema validation. Policies own accepted methods, inspection windows and connection safeguards; the host owns routing, endpoint type and upstream TLS.

| Profile                               | Bot handling                                                                                | Response handling when inspection is enabled                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| **Website** (`web`, default)          | Browser-header signals and optional selective CAPTCHA                                       | Eligible bounded bodies inspected before delivery                     |
| **API** (`api`)                       | No browser-header mismatch signal or CAPTCHA; high suspicion blocks with JSON in Block mode | Eligible bounded bodies inspected before delivery                     |
| **SSE / streaming API** (`streaming`) | Same machine-client bot handling as API                                                     | Immediate flushing with bounded overlapping inspection after delivery |

API/SSE gateway denials and upstream-connect/response-inspection failures use JSON error codes with the original HTTP status. They issue no challenge cookies and do not accept browser-clearance bypasses; reserved challenge URLs return 404. Observe records suspicion without blocking. Scanner, headless, optional empty-User-Agent, path and frequency signals remain enabled according to the policy. Explicit CIDR/exemption rules still apply.

CRS request parsing remains content-type based for all profiles, including JSON bodies. API does not require JSON for every request: uploads and other supported formats retain the selected policy's bounds. Upstream status/body/content-type and CORS behavior are preserved; selecting API does not create API keys or make an unauthenticated upstream private. Mixed websites/API paths should use separate proxy hosts when different profiles are required; per-path profile overrides are not implemented.

## SSE and streaming API profiles

In **Proxy hosts → Add/Edit → Endpoint type**, choose **Website** (default), **API**, or **SSE / streaming API**. The endpoint type is stored per host in PostgreSQL. Streaming window tuning is in **Policies → Signature protection → API methods and stream inspection**. Streaming profiles flush every upstream read immediately and allow up to two minutes for upstream response headers (Website/API default to 30 seconds). They do not buffer the entire response or impose the five-second buffered-body timer. A correct `text/event-stream` response receives streaming handling automatically, including on Web hosts. Other streaming text/NDJSON endpoints should explicitly select the streaming profile.

Response inspection remains policy-controlled and Off by default. When enabled, streaming text uses overlapping, bounded windows instead of buffering to EOF. The policy window is 4096–65536 bytes, capped by its response-body limit. New dashboard policies start with an explicit 8192-byte policy window. Existing policies without an override preserve the legacy host window (default 8192) until explicitly changed. Reads are at most half a window; a response-only CRS transaction inspects each delivered chunk together with preceding window bytes before the next read. The final chunk is inspected before EOF. Windows have independent anomaly scores, use response/path/client exclusions and do not recreate the original request-body transaction. Patterns longer than a window, cross-window score accumulation, protocol semantics and prompt-injection intent are not covered.

**Delivery precedes window inspection.** This preserves immediate first-chunk delivery, but matching bytes can reach the client. In response Block, a match stops subsequent output: the client can receive a truncated stream/transport error with the original status (often 200), not a retroactive 502. Observe records detection and preserves every byte. Use Web with buffered inspection where withholding sensitive content is required. Window checks consume CPU and can add spacing between chunks; no zero-overhead or fixed TTFT guarantee is claimed.

Eligible streaming types are SSE, NDJSON and the text/JSON/XML types above. Binary gRPC messages, WebSocket frames and arbitrary encodings have no body inspection. Identity encoding is requested; unsupported encoding follows the existing Block/Observe behavior before streaming begins. Headers still undergo the existing response-header checks. The request-body ceiling/oversize choice remains the selected policy's setting; streaming does not silently waive request protection.

Logs include `stream_bytes`, `stream_windows` and `response_inspection` (`stream_windows`, `stream_observed_match`, `stream_match`, `stream_busy`, `stream_error`, `stream_unavailable`). Byte counts exclude duplicate overlap; windows overlap and counts are not unique detections. Logs are emitted when the request ends, and client cancellation may end a stream before its last delivered chunk is inspected. Busy/error/unavailable checks terminate in Block and mark incomplete coverage in Observe; there is no unbounded pending inspection queue. Stream bodies are not retained as evidence.

## Accepted HTTP methods and API starting settings

With automatic method defaults, Website uses the CRS source’s method list (GET, HEAD, POST and OPTIONS in the bundled set). API and SSE additionally allow PUT, PATCH and DELETE, so normal REST updates do not trigger CRS911100 merely because of their method. TRACE and CONNECT are not part of the automatic defaults. The policy can specify up to 16 explicit methods under **API methods and stream inspection**; explicit lists override endpoint defaults and match complete method tokens. These controls feed CRS method enforcement: deliberately excluding or curating out rule911100 disables that check. Other attack signatures remain active.

**Use API starting settings** explicitly fills the unsaved policy form with Observe, Standard sensitivity, a 1 MiB request ceiling, common API methods, an 8 KiB policy stream window, response inspection Off and bot/empty-User-Agent checks Off. It keeps selected rules, assignments, flood budgets and connection limits. Review and Save to apply. It does not create upstream credentials or distinguish harmless programming examples from attacks: keep new AI services in Observe while tuning targeted exceptions. SQLi/XSS checks are not silently removed.

## Policy connection and streaming safeguards

Under **Policies → Bot & flood protection → Connection and stream limits**, enable limits and configure:

| Setting | Starting value | Range |
| --- | --- | --- |
| Concurrent requests per application | 100 | 1–10000 |
| Concurrent requests per client | 10 | 1–application cap |
| Maximum upstream request duration | 900 seconds | 1–86400 seconds |
| Idle time without upstream/upload/delivery progress | 60 seconds | 1–3600 seconds |

Existing policies have these safeguards disabled. They count admitted upstream requests, including SSE and ordinary API calls, per application, selected policy and replica. **They remain local even when request-rate counters use Redis.** Multiply the per-replica budget when sizing an installation; these are replica safeguards, not a global backend quota. Client caps use resolved IPs, so users sharing an egress address can share a budget. Unresolved trusted-proxy identities fall back to the peer for limiting.

Block enforces. Observe records exceedances without cutting off otherwise allowed requests; Off disables the limits. Full WAF bypass skips them. A new request above an enforcing connection cap receives 429 and Retry-After. Duration/idle cancellation before response headers returns 504 (JSON for API/SSE); after streaming starts it terminates the stream with its original status, commonly 200. An expired upstream error response is subject to the same cutoff. Only a gateway-generated timeout before headers gets a fixed, bounded error-reporting allowance.

Uploads reset idle progress as their body is forwarded; this does not remove the listener’s existing request-read bounds. WebSocket upgrades retain their read/write transport and are not timed as idle from unobserved frames; maximum duration still closes them. Durations include waiting for the upstream response. Client disconnects, errors and completion release admission slots. Reloading a policy does not reset active connection counts; requests already admitted retain their original settings, and new requests use the refreshed policy. No PostgreSQL lookup is added to request admission.

Request signals include `connection_limit_exceeded`, `upstream_duration_exceeded` and `upstream_idle_timeout`. Stream requests are still logged when they end. Offline simulation warns that live connection counts and duration/idle behavior cannot be reconstructed from recorded request metadata; validate them with live test streams.
