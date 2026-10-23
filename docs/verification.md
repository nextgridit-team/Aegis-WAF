# Verification evidence

Verified locally on 2026-10-20 using Go 1.26.2, Node 22.23.3, PostgreSQL 18.4, and a headless Chromium-family browser. PostgreSQL was an isolated local test instance; no public CA accounts or production certificates were created.

| Check                                                                                                           | Result                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TypeScript strict typecheck and minified production asset build                                                 | Passed; production assets embedded in Go                                                                                                                              |
| Go build and `go vet ./...`                                                                                     | Passed                                                                                                                                                                |
| `go test -race -count=1 ./...` with real PostgreSQL                                                             | Passed, including concurrent schema/bootstrap initialization                                                                                                          |
| Bootstrap exclusivity, password/session persistence, cross-replica session use and logout                       | Passed                                                                                                                                                                |
| CSRF/origin rejection and unauthenticated mutation header checks                                                | Passed                                                                                                                                                                |
| Upload/key matching, date validation, hostname coverage, encryption authentication, no key readback             | Passed                                                                                                                                                                |
| Real TLS replacement without restart; failed replacement and audit-write rollback preserve previous certificate | Passed                                                                                                                                                                |
| Version polling applies a committed certificate update on another replica                                       | Passed                                                                                                                                                                |
| Real upstream HTTP proxying, response streaming, protocol upgrade echo and HTTP 101 access logging              | Passed                                                                                                                                                                |
| Untrusted upstream TLS, unknown SNI, expired SNI and unknown host rejection                                     | Passed                                                                                                                                                                |
| Real ACME client against a local RFC 8555 fixture                                                               | Registration, orders, authorizations, CSR/certificate retrieval, and persisted job/order state passed                                                                 |
| Two-replica ACME coordination                                                                                   | One order created; HTTP-01 response retrieved successfully through both replicas                                                                                      |
| Renewal failure/backoff/manual retry and abandoned-running-job recovery                                         | Passed; old certificate material retained on failure                                                                                                                  |
| Real browser flows                                                                                              | Setup, sign-in, upload, site creation, persisted reload, upstream routing, rejected replacement/input preservation, CA acceptance guard, disable/delete/logout passed |
| Responsive and rendered review                                                                                  | 15 page/viewport checks at 390, 768 and 1440 px; no document overflow or browser exceptions; desktop and mobile screenshots inspected                                 |
| Actual PostgreSQL stop/start with compiled app processes                                                        | Existing HTTP/TLS serving and readiness continued; management writes failed with 503; a fresh replica remained unready and became ready after database recovery       |
| Compiled healthcheck command and graceful SIGTERM exit                                                          | Passed                                                                                                                                                                |
| `docker compose config --quiet`                                                                                 | Passed                                                                                                                                                                |

The browser test uses synthetic certificates and an isolated deployment. Screenshots were inspected under `/tmp/aegis-waf-browser`; these are local test artifacts, not shipped assets. The mobile operational tables scroll horizontally to preserve readable hostnames and actions.

## Reproduce

Backend instructions are in the [README](../README.md). Integration tests create/drop isolated schemas, so `TEST_DATABASE_URL` must point at a dedicated test database with schema-creation permission. Ordinary `go test` reports skipped integration tests when that variable is absent.

Browser tests are in `tests/browser.cjs`. They create/delete application records and bootstrap a test administrator if necessary. Use a dedicated local deployment on management 19090 / public HTTP 18080. The test upstream uses 127.0.0.1:18081. A private JSON credentials file supplies `secret` and `password` for a test-only `browser-admin` account. Do not use production administrator credentials.

```sh
cd tests
npm ci
npx playwright install chromium
BROWSER_CREDENTIALS_FILE=/absolute/path/test-credentials.json npm test
```

`BROWSER_EXECUTABLE` can select an installed Chromium-compatible binary. `BROWSER_BASE_URL`, `BROWSER_PROXY_URL`, and `BROWSER_ARTIFACT_DIR` override the test endpoints/artifact directory.

`tests/process-outage.py` stops and restarts a dedicated local PostgreSQL cluster. It expects the compiled test app on 18080/18443/19090, PostgreSQL on 55432, and the `browser-admin` account from the browser test. Set `AEGIS_WAF_TEST_CREDENTIALS_FILE` to a private JSON file containing test deployment `key`, `secret`, and administrator `password`, and set `PG_CTL` and `PG_DATA` to that isolated PostgreSQL installation/data directory. It starts a second application replica, verifies recovery, stops that replica gracefully, and removes its site/certificate records.

## Docker runtime verification and remaining deployment checks

Docker runtime verification passed on **2026-10-23** using Docker Engine 29.9.2 and Compose 5.6.0. The Dockerfile built successfully from the checked-in source, and the resulting image is tagged locally as `aegis-waf:verification`. The application source did not require changes.

`tests/container-smoke.py` runs the production Compose configuration with an isolated project, temporary secret-file overrides, random localhost ports, a disposable PostgreSQL volume, and a test HTTP upstream. It verified:

- Healthy application startup as UID 10001 and platform-assigned UID/GID 23456.
- Read-only root filesystem (including a failed write probe), writable temporary directory, readable mounted secrets, and packaged CA certificates.
- All Linux capabilities dropped, no privileged mode or host networking, no Docker socket, and no persistent application volume.
- First-run setup, cross-replica sessions, certificate uploads without private-key readback, and cached HTTP/TLS proxying through both replicas.
- A successful HTTPS request to the Let's Encrypt staging directory using the packaged CA bundle; no CA account or certificate was created.
- HTTP/TLS serving through a real PostgreSQL-container outage, accurate management failure responses, and a fresh third replica remaining unready until database recovery.
- Configuration, certificates, and sessions reloading after application restart.
- All three application containers exiting with status 0 on graceful shutdown.

The test cleans up its own containers, network, volume, and temporary secrets; unrelated services are left untouched. Reproduce with:

```sh
make container-test
# Or test an already-built image:
python3 tests/container-smoke.py aegis-waf:verification
```

Public ACME staging/production issuance also remains unverified. The local CA fixture establishes application protocol flow and database coordination, but cannot establish public DNS, external load-balancer behavior, CA policy, or real-world HTTP-01 reachability. Run a staging issuance through the target load balancer before requesting production certificates. Online encryption-key rotation, automated log retention, MFA and additional administrator roles are explicitly outside the implemented foundation.

## Repository import verification

The Aegis WAF branding import was rebuilt and checked with TypeScript, `go build`, `go vet`, real-PostgreSQL race-enabled tests, and the browser acceptance suite. The Go module uses `github.com/nextgridit-team/Aegis-WAF`; the executable is `aegis-waf`. The repository’s original MIT license and initial commit were preserved. Docker runtime verification has since passed as documented above; public-CA issuance remains unverified.
