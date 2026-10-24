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

Docker runtime verification passed on **2026-10-23** using Docker Engine 29.9.2 and Compose 5.6.0. The Dockerfile built successfully from the checked-in source, and the resulting image is tagged locally as `aegis-waf:verification`. That initial runtime verification required no application-source changes.

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

## Certificate-first console and real ACME verification — 2026-10-23

The dashboard was redesigned with a light workspace, focused certificate inventory, guided authority/domain forms, automatic issuance status, and a prefilled Connect site handoff. Existing API authentication, CSRF, encrypted storage, and the two-container production architecture remain in use.

The complete browser suite passed against the official Pebble image with validation enabled. Pebble resolved `app.example.test` to the second gateway replica and performed three real HTTP-01 validation requests; no always-valid bypass was configured. The browser registered the account, explicitly accepted its terms, queued issuance, observed a valid certificate through automatic polling, configured its upstream, and received trusted HTTPS responses through both replicas. The test then verified upload/coverage failures, form preservation, Escape/focus behavior, session logout, and 16 layout checks across 320, 390, 768 and 1440 px. Desktop and mobile screenshots were inspected; selected captures with synthetic local-test data are in `docs/screenshots/`.

This real CA test exposed a finalization compatibility bug absent from the earlier synchronous fixture: an authority can return `processing` without repeating the order URL in Location. Aegis now supplies the previously authenticated order URL only for that finalization response so the existing ACME library can poll and fetch the certificate. The PostgreSQL integration fixture now reproduces this asynchronous response. Race-enabled Go tests and `go vet` passed in isolated containers. Issuance failures now identify the failed phase without logging raw CA messages or secrets.

CA terms support HTTPS links and safely escaped inline plain text. Changing the authority or its URL clears acceptance and ignores obsolete lookup results. Non-submit controls cannot accidentally submit a form. Status refresh pauses while an editor is open, and modal dialogs preserve native keyboard behavior.

Reproduce with the README’s `make browser-test` instructions, or run `python3 tests/acme-browser.py <built-image>`. Browser dependencies and a Chromium-compatible executable must be installed. Screenshots and Pebble validation logs are stored in `/tmp/aegis-ui-review`; test containers, network, database volume, and temporary key material are cleaned up. Public Let’s Encrypt issuance remains a deployment check requiring the administrator’s actual hostname and port-80 reachability.

## Declarative rules and bounded evidence — 2026-10-24

The Go rule engine, PostgreSQL migration, rule lifecycle APIs, and Rules/Traffic dashboard views were added to the existing application image. No model, behavioral learning, CAPTCHA, external signature feed, or automatic activation was added. Capture is opt-in and new/edited/imported rules remain drafts.

Race-enabled tests against isolated PostgreSQL passed, including the original certificate/ACME/proxy tests and new coverage for:

- Validation of operators, scope, protected field selectors, RE2 syntax and activation bounds.
- Single decoding, repeated query values, direct-peer CIDRs (including mapped IPv4), incomplete inspection and tri-state AND evaluation.
- JSON inspection preserving exact upstream request bytes for valid, duplicate-key, malformed, oversized and chunked bodies.
- Evidence allowlists, common-secret/path redaction, bounded values, sampling caps, and unknown replay results for uncaptured facts.
- Draft/observe/block behavior through two replicas, site isolation, CSRF rejection, rejected edits preserving enforcement, and editing an active rule returning it to draft.
- Offline replay with zero upstream requests, rejection of foreign-site evidence, revision history and rollback preserving the original expiry.
- Cached rules enforcing and expiring after the database pool is closed, and accurate management failure responses.
- Failed audit inserts rolling back the rule and configuration version; stale deleted-site samples not poisoning log batches.
- Upgrading the actual previous schema with existing access-log rows and repeating migration safely.

The production image built successfully and strict TypeScript checks passed. The container smoke suite passed with the new backend: default/arbitrary non-root UIDs, read-only root, tmpfs, secret/CA readability, no capabilities/privilege/socket/application volume, shared sessions, HTTP/TLS, a real PostgreSQL outage, fresh-replica readiness, restart persistence and graceful shutdown. Repeat with `python3 tests/container-smoke.py aegis-waf:ui-verification` after building that tag.

Use `python3 tests/go-integration.py` for a disposable PostgreSQL container plus Dockerized Go race tests and vet. It publishes no database port and removes its isolated resources. See [rules documentation](rules.md) for inspection, privacy, propagation, retention and replay limitations. HTTP-01 remains the implemented ACME method; automated DNS-01 still needs a selected DNS provider/integration.

The real Pebble/two-replica browser suite passed with the new dashboard. It verified redacted bounded capture, draft creation, observe/block/disable/rollback, edit-to-draft behavior, scoped offline replay, JSON export/import (including invalid-input preservation), visible observe results in Activity, and 24 responsive page/viewport checks at 320/390/768/1440 pixels. It also reverified the complete account/HTTP-01/certificate-to-proxy workflow and trusted HTTPS through both replicas. Import testing exposed an accessible-label issue that was fixed; dialog titles now escape user-provided names, with a literal-HTML-name regression check. A final unit check rejects null capture allowlists so API settings round-trip through the dashboard. Desktop/mobile screenshots were inspected, and a synthetic rules capture is checked in as `docs/screenshots/rules.png`.
