# Request and response body inspection

Configure **Policies → Edit → Managed signatures → Signature tuning**. Settings are versioned in PostgreSQL with the policy and propagate through the normal snapshot refresh. There are no site configuration files to edit.

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
| Response inspection mode                 | Off                  | Off streams normally. Observe records matches and forwards. Block withholds a matching response.                        |
| CRS outbound anomaly threshold           | 4                    | Configurable 1–100, independent of the inbound threshold.                                                               |
| Response inspection limit                | 256 KiB              | Configurable 4 KiB–1 MiB.                                                                                               |
| Oversized response action                | Reject               | In response Block, return a generic 502 for an oversized eligible response.                                             |
| Inspect prefix and forward full response | Explicit alternative | Inspect the bounded prefix, forward the original full response if permitted, and record `response_inspection: partial`. |

Policy Observe or signature Observe caps response Block at Observe. Policy/signature Off disables it. Response errors are represented as WAF-sourced 502 responses; the original upstream body and headers are withheld on rejection. Response inspection cannot undo a request that has already reached its upstream.

Eligible media types are `text/plain`, `text/html`, `text/xml`, `application/json`, `application/xml` and `application/xhtml+xml`. MIME parameters such as charset are allowed. Binary/other types record `skipped_content_type`; SSE records `skipped_stream`; protocol upgrades record `skipped_upgrade`. HEAD, 204, 304 and empty-body responses record `no_body`. Response header rules run before these body exemptions. Correct upstream Content-Type is required; unsupported types are not body-inspected.

Aegis requests identity encoding upstream when response inspection is enabled. If the upstream still returns encoded eligible content, response Block returns 502 and Observe forwards it with `unsupported_encoding`. It does not decompress arbitrary upstream encodings into unbounded memory.

Eligible responses are buffered to EOF or the limit plus one byte **before client headers/body are sent**, allowing a blocking decision. This adds time to first byte and makes response inspection inappropriate for arbitrary text streams. A five-second read deadline cancels stalled eligible bodies and returns 502 in either mode; transport/read failures cannot be treated as clean responses. SSE and WebSockets are exempt before this timer starts. Partial responses stream their remaining bytes after inspection.

## Bounds and lifecycle

There are 64 shared inspection reservations per replica. Request-only transactions close after inspection; their replay prefix releases its reservation when consumed or closed. Response-enabled transactions carry request state into the response phases and hold a reservation until the response prefix is forwarded/closed. Exempt streams release it immediately after headers, so a long-lived SSE/WebSocket does not retain a transaction or inspection slot. Early errors, redirects and cancellation also release reservations.

Memory includes bounded connector prefixes and Coraza's own bounded buffers/collections. A body limit is not a total process-memory limit. Enabling response inspection increases memory residency and can reduce available inspection concurrency while upstreams are responding. There is no disk body spooling or new persistent volume. At most eight distinct active managed configurations are supported per replica.

## Investigation and exclusions

Request details and access logs contain separate request/response inspection statuses, effective response mode and detected CRS IDs. Signature inventory labels response rules as optional. Global rule exclusions can select response rules; path/client scoped response exclusions are supported, but request-parameter exclusions do not apply to response bodies. Raw response bodies are not saved as evidence or exposed in normal logs.

Existing custom-rule replay uses retained request facts and does not replay response CRS rules. Updating to this build does not silently enable response inspection or change existing oversized-request actions. Disable response inspection before rolling back to a build that does not support it.

The implementation uses the established Coraza transaction phases and [body-limit directives](https://www.coraza.io/docs/seclang/directives/); Aegis applies its own bounded read/replay and error handling around those phases.
