# Aegis and forwarding/WAF references

The relevant comparisons differ: HAProxy is a mature load balancer/proxy; NGINX Proxy Manager supplies a certificate/routing administration workflow around NGINX; SafeLine is a dedicated WAF. Aegis combines a Go gateway with application policies, certificate management and a bounded evidence/replay workflow, but is an early implementation.

## Same-host forwarding measurements

Three isolated 64,000-request runs per phase, sixteen concurrent HTTP/1.1 keep-alive clients, small fixed response, Linux/amd64 Ryzen 7950X3D host. Medians of the three runs:

| Forwarding path | p50 ms | p99 ms | Requests/s |
| --- | ---: | ---: | ---: |
| Direct test upstream | 0.771 | 3.319 | 16,760 |
| HAProxy 3.2.26 | 0.820 | 3.916 | 15,026 |
| Raw NGINX 1.30.6 | 0.889 | 4.178 | 14,138 |
| Aegis, no custom rules | 0.984 | 4.135 | 13,280 |
| Aegis, 100 simple nonmatching rules | 0.966 | 4.268 | 13,319 |

Aegis kept PostgreSQL access logging enabled and dropped zero logs. Reference access logging was disabled. Both reference configurations used streaming proxying and upstream keep-alive. These are basic forwarding references, not equivalent full-security configurations. The client, proxies, database and upstream share a host; the test is not a saturation or production capacity benchmark. Noise explains small inversions such as 100-rule throughput exceeding zero-rule throughput. Aegis zero-rule p99 ranged 4.009–4.432 ms; HAProxy ranged 3.837–4.080 ms; raw NGINX ranged 4.142–4.385 ms. Differences in those ranges should not be marketed as a general winner.

This did **not** run NGINX Proxy Manager itself or SafeLine's complete stack. Raw NGINX shows its forwarding engine's reference behavior; it is not an NPM result. SafeLine's semantic inspection and bot controls require a separately configured workload before making a latency comparison. Vendor QPS figures are not comparable to this fixture. Raw reports, image IDs and source revision are in [the measurement artifacts](benchmarks/2026-10-25/). Reproduce with `AEGIS_COMPARE_PROXIES=1 AEGIS_BENCHMARK_REPORT=/tmp/result.json python3 tests/container-smoke.py <image>`.

## Product and engineering position

| Product | Established emphasis | Implication for Aegis |
| --- | --- | --- |
| HAProxy Community | L4/L7 routing, load balancing, ACLs and stick-table counters/peer synchronization | A useful forwarding and operational-maturity reference; its configuration model is not our dashboard/policy/evidence workflow. |
| NGINX Proxy Manager | Browser-managed proxy hosts, TLS certificates, access lists/basic authentication and advanced NGINX configuration | Closest comparison for setup simplicity. Its documented core workflow is proxy administration; a raw NGINX benchmark does not measure its full configuration. |
| SafeLine | Semantic web-attack detection, bot challenges and additional protection features | A broader dedicated WAF reference. Aegis's basic bot signals and custom DSL do not establish comparable attack coverage. |
| Aegis today | Embedded dashboard, PostgreSQL configuration, certificate automation, scoped policies, opt-in redacted evidence and deterministic custom-rule replay | Useful application-aware controls; now includes opt-in Coraza/CRS request signatures; still needs coordinated rate budgets and broader attack/benign testing before claiming mature WAF parity. |

The measured buffer reuse and fact-cache changes reduce allocations and matcher CPU without removing inspection, TLS verification, audit writes or forwarding safeguards. End-to-end p99 remains around four milliseconds in this lab; the measurements do not prove a significant production tail-latency reduction. The opt-in Coraza/CRS integration adds established request-signature coverage, but body buffering, tuning, exclusions, resource limits and replay completeness still require explicit handling.

Sources: [HAProxy 3.2 configuration manual](https://docs.haproxy.org/3.2/configuration.html), [NGINX Proxy Manager guide](https://nginxproxymanager.com/guide/), [SafeLine project description](https://github.com/chaitin/SafeLine/blob/main/README.md), [Coraza body processing](https://www.coraza.io/docs/reference/body-processing/). Product-position conclusions above are our assessment from these documented features and the local tests, not independent certification.
