# Performance measurements

## Current forwarding and CRS baseline — 2026-10-25

| Workload | Requests/sec | Mean ms | p50 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: |
| Direct upstream | 16,206 | 0.978 | 0.787 | 3.431 |
| Aegis · no rules | 13,676 | 1.163 | 0.959 | 3.995 |
| Aegis · 10 custom rules | 13,578 | 1.169 | 0.947 | 4.069 |
| Aegis · 100 custom rules | 13,359 | 1.188 | 0.979 | 4.053 |
| Aegis · bundled CRS baseline | 10,579 | 1.501 | 1.351 | 3.802 |

Linux/amd64, AMD Ryzen 9 7950X3D (32 available CPUs), Go 1.26.10; medians of three sequential runs of 64,000 small HTTP/1.1 keep-alive GETs per phase with 16 client threads. PostgreSQL access logging was enabled; evidence capture and bot/flood controls were off. The CRS row used the bundled PL1 baseline in Block mode, anomaly threshold 5, with no signature exclusions.

Client, gateway, upstream and PostgreSQL shared the Docker host. These short closed-loop measurements include client scheduling and Docker networking; repeat them on target hardware. TLS handshakes, uploads, expensive custom regexes and adversarial mixed workloads require separate measurements. Tail values vary by run. Median paired mean-latency deltas were 0.185 ms for forwarding without rules and 0.526 ms for CRS. Every measured response was successful, with zero dropped access logs and worker panics. The fixture verifies a real XSS canary is blocked by CRS on both replicas before measuring benign traffic, and validates its actual JSON stdout block event.

Exact measured implementation: [bf53d68](https://github.com/nextgridit-team/Aegis-WAF/commit/bf53d68071569ccd4c96aa42bf5f4401ba06af03), image ID and host details in [run 1](benchmarks/2026-10-25/adoption-1.json), [run 2](benchmarks/2026-10-25/adoption-2.json) and [run 3](benchmarks/2026-10-25/adoption-3.json). Custom-rule cases use nonmatching Observe path conditions. Assigning the CRS baseline selects that policy instead of the standalone custom rules. Phases last approximately 4–6 seconds; this is a local reference, not a saturation result or production capacity guarantee.

Reproduce sequentially after building an image:

```sh
AEGIS_BENCHMARK_REPORT=/tmp/aegis-result.json python3 tests/container-smoke.py <image>
```

The disposable fixture also verifies non-root/read-only deployment, real stdout security schema, database loss/recovery, optional sealed snapshots, native management TLS and graceful shutdown. It stops/removes only its own test stack. Do not run competing benchmarks on the host while measuring.

## Earlier forwarding and engine measurements

Run engine measurements with `go test ./internal/app -run '^$' -bench 'BenchmarkRuleEvaluation|BenchmarkResolvedProtection' -benchmem -count=3`. The engine fixtures use simple nonmatching path conditions and reuse a request, with a virtual clock for protection. They isolate matching/allocation cost rather than reporting proxy latency. The 1000-rule case is synthetic engine scaling; the supported standalone per-application limit is 100.

For external HTTP latency, build an image and set `AEGIS_BENCHMARK_REPORT=/tmp/aegis-latency.json` when running `python3 tests/container-smoke.py <image>`. The disposable fixture measures a direct upstream and the gateway with 0, 10 and 100 active nonmatching Observe rules. It uses 64,000 successful HTTP/1.1 keep-alive GETs per phase, sixteen concurrent client threads and a small fixed response. PostgreSQL access logging is active; evidence capture and flood protection are off. The report includes percentiles, throughput, configuration health and dropped-log counts. Only its test stack is stopped/removed.

A 2026-10-25 local Linux/amd64 Docker run on an AMD Ryzen 9 7950X3D host (32 available CPUs), Go 1.26, image `aegis-waf:review-hardening-test`, produced:

| Path | p50 ms | p99 ms | Requests/s |
| --- | ---: | ---: | ---: |
| Direct upstream | 0.771 | 3.394 | 16,592 |
| Gateway, no rules | 0.987 | 4.174 | 13,200 |
| Gateway, 10 rules | 0.984 | 4.194 | 13,149 |
| Gateway, 100 rules | 0.999 | 4.293 | 12,910 |

All responses succeeded; dropped access logs and worker panics were zero. Each phase lasted approximately 4–5 seconds. Client, gateway, database and upstream share the test host, so this closed-loop test includes client scheduling, Docker networking and database contention. It is a reproducible baseline, not a capacity claim or a production p99 guarantee. It does not cover TLS handshakes, large uploads, WebSockets, expensive regexes, coordinated rate limiting or adversarial mixed workloads.

Three one-second engine runs measured 10 rules at 697–703 ns/op, 100 at 5.88–5.92 µs/op and the synthetic 1000 at 58.3–58.4 µs/op. Local resolved-IP/flood/bot protection measured 186–187 ns/op. Those microbenchmarks exclude network, PostgreSQL and response handling. Repeat the full workload on target hardware and compare before/after coordination or signature-engine changes.

## Measured allocation changes

Forwarding profiles found 79.6% of allocated bytes in the reverse proxy's new 32 KiB response-copy buffer. Reusing cleared buffers changed three two-second real-upstream microbenchmarks from 34.95–35.84 µs / about 41.1 KiB per operation to 29.21–29.86 µs / 8.35–8.41 KiB. Keeping fact-cache hit lookup separate from stored selector allocation changed the 100-rule matcher from about 5.9 µs / 103 allocations to 5.34–5.37 µs / 4 allocations. These changes were measured individually and retained; neither disables protections. Full-network measurements remain noisy and do not establish a material production p99 gain. See [the repeated forwarding comparisons](proxy-comparison.md) for measured reference ranges.

## Platform hardening verification (2026-10-25)

A final small-response HTTP/1.1 keep-alive run used 64,000 requests per phase and concurrency 16 on the same Ryzen 9 7950X3D host. The new build includes selective CAPTCHA support, simulation enforcement, streaming profiles, optional shared counters and Prometheus instrumentation; this workload uses local counters, no challenges and response inspection Off. Results are in [the raw report](benchmarks/platform-hardening-20261025.json).

| Path | Requests/sec | Mean ms | p99 ms |
| --- | ---: | ---: | ---: |
| reference_haproxy | 15,187.9 | 1.046 | 4.046 |
| reference_nginx | 14,402.0 | 1.097 | 4.314 |
| direct_upstream | 15,449.7 | 1.025 | 3.955 |
| gateway_0_rules | 13,029.0 | 1.218 | 4.401 |
| gateway_10_rules | 14,430.3 | 1.098 | 3.894 |
| gateway_100_rules | 13,551.0 | 1.167 | 4.256 |
| gateway_crs_baseline | 10,807.5 | 1.471 | 3.793 |

These are single-phase fixture measurements on a shared local host, not sustained production capacity or a security-equivalent comparison. The CRS baseline's mean was approximately 0.45 ms above the direct path; its total mean was 1.47 ms. Do not subtract independent p99 values to claim overhead. The 10-rule run being faster than the 0-rule run illustrates measurement variation. HAProxy/NGINX references are their routing dataplanes, not NGINX Proxy Manager's complete management product or SafeLine. Shared Redis lookup, active CAPTCHA, larger bodies and streaming-window inspection need separate workload-specific measurements. No access logs/evidence were dropped and no background worker panics were recorded during this run.
