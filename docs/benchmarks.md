# Performance measurements

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
