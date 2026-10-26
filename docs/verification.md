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

Backend instructions are in the [development guide](development.md). Integration tests create/drop isolated schemas, so `TEST_DATABASE_URL` must point at a dedicated test database with schema-creation permission. Ordinary `go test` reports skipped integration tests when that variable is absent.

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

## Cloudflare DNS-01, dark mode, and pasted setup codes — 2026-10-24

Cloudflare DNS credentials and TXT record IDs are encrypted/tracked through PostgreSQL, and the certificate request form now selects HTTP-01 or Cloudflare DNS-01. The DNS path reuses lego's provider with the existing ACME job coordination and supports wildcard certificates. Provider read APIs omit tokens. The DNS-01 integration fixture covers issuance, coordination, cleanup/recovery and failed-renewal preservation without touching public DNS. Real Cloudflare issuance requires the user's scoped token and domain; see [Cloudflare setup](cloudflare.md).

Theme selection follows the system by default; the manual toggle persists in browser storage. Both authenticated and setup/login screens include the toggle. Screenshot review identified and corrected a light-only certificate inventory surface in dark mode.

Pasted bootstrap codes now trim surrounding whitespace on the server and in the browser. A new integration check first failed with the previous HTTP 403 rejection, then passed after normalization. The setup code is visible to avoid password-manager substitution; administrator passwords retain their exact contents.

The final candidate passed `go test -race -count=1 ./...` and `go vet` against disposable PostgreSQL on Nexus, strict TypeScript checks, and the browser suite with real Pebble HTTP-01 validation. Added browser assertions cover system-theme following, manual override persistence across reloads, dark inventory contrast, token write-only behavior, invalid credential input, DNS-01 selection without a port-80 checkbox, and inline Cloudflare connection preserving the certificate request. The original 24 responsive layout checks and certificate/proxy/rule flows also passed. Synthetic Cloudflare/DNS-01 integration tests passed; no live Cloudflare credentials were used by those tests.

## Single-form certificate requests

Reviewed the Cloudflare workflows documented by acme.sh, Certbot and lego. The dashboard now collects domains, email and a Cloudflare API token in one form. Let's Encrypt production and DNS-01 are the defaults; saved contact/credential metadata is reused. Staging/custom CAs, HTTP-01 and naming live under Advanced options. Account registration and encrypted credential persistence run on submit, with explicit CA terms acceptance and preserved form state on failure.

`npm --prefix tests run test:onboarding` passed with intercepted APIs: first request without prerequisite setup, existing setup reuse, credential-save retry, certificate-queue retry without recreating confirmed credentials, ambiguous registration-response recovery, no side effects before terms acceptance, invalid token input before account creation, responsive form widths at 320/390/1440 pixels, and closing the form during delayed registration stopping subsequent credential/issuance steps. This test creates no public CA accounts or DNS records.

The Nexus candidate image passed strict TypeScript compilation and the full browser suite using real Pebble account registration/HTTP-01 validation, issuance and trusted HTTPS through both replicas. Existing Cloudflare configuration, dark-mode persistence, 24 responsive page checks and proxy/rule flows passed. Live Cloudflare issuance still requires the user's token and domain. No backend API/schema changes were needed for this UX update.

## Traffic dashboard, bot/flood protection and URL feeds — 2026-10-24

Passed strict TypeScript build, production image build, real PostgreSQL race
checks and go vet. New backend tests cover concurrent token budgets, client
and application isolation, observe/block behavior, trusted-proxy spoofing
resistance, public socket/in-flight accounting, aggregated replica reports,
application/time filters, transactional app/protection creation and rejected
edits, feed format validation, public-address/SSRF checks, ETag requests,
12-hour due-time checks, competing-replica sync coordination, draft-only
imports, duplicate prevention and preservation of enabled rules on updates.

The real Pebble browser suite passed with two replicas: ACME validation,
trusted HTTPS proxying, dashboard/application filters, user-configurable
protection at application creation, bot observation/blocking, a real DB-IP
country database download and lookup with a trusted forwarded client, and
32 responsive page checks. The standalone feed UI fixture covers source
creation, starter URL, sync error/retry, escaped candidate JSON, draft import,
removal and four responsive layouts. The certificate onboarding regression
fixture remains covered separately.

The downloaded DB-IP country file also passed reader verification and real
IPv4/IPv6 lookups; private addresses remain unlocated. No visitor traffic was
sent to a geolocation API. The container smoke suite passed with the new
workers/telemetry: default/arbitrary non-root UIDs, read-only root, tmpfs,
CA/secret readability, shared sessions and HTTP/TLS, database outage/cache
survival, fresh-replica readiness, restart persistence and graceful shutdown.
These checks use disposable databases/projects and leave user data intact.

Natural Earth map boundaries are public domain. Synthetic local test
screenshots are included as traffic-dashboard.png and
traffic-dashboard-mobile.png. Basic user-agent bot signatures are not
advanced bot classification. Flood budgets are per replica and statistics
are derived from best-effort access logs; the dashboard exposes dropped-log
warnings. See dashboard.md and rule-feeds.md for operational limits.

The application/group/rule mapping requested next is researched in
cloudflare-rule-design.md using Cloudflare's primary documentation.
Reusable versioned rule groups and attachments are a proposed next schema
increment, not part of this implementation; current rule/feed imports remain
site-scoped and require explicit activation.

## Standalone HTTPS management regression

Added native management-listener TLS for deployments that remove their HTTPS
management proxy. Stored certificates are cached independently of application
routes; a wildcard can cover management without any protected site configured.
Tests cover absent/uncovered/expired certificates, separation from public SNI
routing, retained cached TLS during database failure, real PostgreSQL password
login and cross-replica session/logout over verified TLS. Remote session
cookies remain Secure; plain-HTTP private-IP sign-in is not enabled. The
container readiness probe supports local HTTPS without requiring the DNS
certificate to cover the loopback IP.

## Header controls and component CIDR exceptions

Added regression coverage for resolved identity forwarding, forwarding disabled,
request Set/Remove, response Set/Remove on normal and blocked responses,
invalid/reserved/credential header rejection, duplicate operations and CRLF
rejection. CIDR tests cover per-component isolation, individual addresses,
IPv6/mapped IPv4, external throttling, budgets unconsumed by exempt traffic,
malformed/untrusted proxy identity and retained declarative WAF enforcement.
PostgreSQL coverage includes application settings persistence, two replicas,
exemption logs/totals, invalid edits retaining working settings and cached
behavior without database access. Browser coverage adds header editor retries,
CIDR/source persistence, real upstream echo of forwarding/custom headers,
external 429 responses, forwarding disabled and four header-form viewports.

## Policies, provider configuration, deferred logging and resources

PostgreSQL integration tests and `go test -race`/`go vet` passed for policy selection across two replicas, trusted client identity, frozen signature snapshots, explicit refresh, rollback, stale edits, default reassignment and fallback validation. Provider tests verify bounded model discovery, redirect refusal, authentication failure handling, encrypted write-only keys, endpoint changes and saved-setting preservation. Resource tests verify CPU/RAM samples from both replicas remain global under application filtering. Logging tests prove saturated queues do not block forwarding or blocking and evidence capture never reads a body ahead of the upstream.

The candidate image passed the container smoke suite, including arbitrary non-root UIDs, read-only filesystems, cached HTTP/TLS during actual database outages, fresh-replica readiness, reload and direct management HTTPS. The real Pebble/browser suite passed certificate issuance and HTTPS proxying through both replicas, provider discovery/model persistence against an isolated keyless fixture, policy creation/assignment/enforcement, the CPU/RAM panel and its refresh behavior, and forty responsive page checks. Rule feed fixture tests, strict TypeScript build and npm security audit also passed. These fixtures do not establish inference quality or production attack coverage.

## Review hardening and measured optimization checkpoint

Full PostgreSQL integration/race/static checks passed after worker containment, configurable evidence redaction, optional sealed-cache recovery and forwarding changes. The container fixture passed actual stop/start recovery with an explicitly cached arbitrary-UID replica serving HTTP/TLS while PostgreSQL was stopped; sessions still returned 503 and an uncached new replica remained unready. Failed/tampered/stale cache cases, wrong key/database context and rule-expiry preservation passed unit/integration checks. The Pebble/browser suite passed all forty responsive checks and certificate, provider, policy and custom-redaction form workflows.

Forwarding allocation profiling identified the standard reverse-proxy 32 KiB copy allocation as about 80% of allocated bytes. An individually measured cleared buffer pool reduced a real-upstream forwarding microbenchmark from 34.95–35.84 µs and about 41.1 KiB/op to 29.21–29.86 µs and 8.35–8.41 KiB/op. Separating fact-cache hits from stored selector allocation reduced the 100-rule matcher from about 5.9 µs/103 allocations to 5.34–5.37 µs/4 allocations. These are microbenchmark improvements; tail latency is measured separately and no production p99 reduction is claimed.

The isolated, separately pinned Coraza/CRS experiment passed its benign/attack/Observe fixtures. Managed production signature-set loading and policy attachment are a subsequent integration; the experiment alone is not active protection.

## Scoped agent control, address objects, Geo and security tuning — 2026-10-25

The scoped MCP implementation and portable skill were checked using a real official Go SDK client over TLS and isolated PostgreSQL. Tests verified operation discovery, general management through existing API handlers, read-only restrictions, account/new-key creation denial even with every scope (including encoded-path attempts), disabled proposals, authorized activation/disable, audit records, source-object edits, revocation, Origin rejection and disabled access. Skill tests compare embedded files, MCP retrieval and ZIP contents; the Agent Skills format validator passed. This verifies protocol/API behavior, not an external model's reasoning or the behavior of every MCP client/importer.

The complete PostgreSQL-backed `go test -race -count=1 ./...` and `go vet ./...` passed (90.928s package test time). Strict TypeScript/esbuild passed. The real browser/Pebble acceptance run passed 52 responsive checks plus address/group and scoped-key workflows, the authenticated skill download, state-map drill-down, evidence/replay, and trusted certificate/proxy traffic through both replicas. Image `aegis-waf:agent-access-test` (`eb7b332cdfc1`) includes the final skill; artifacts were captured under `/tmp/aegis-agent-skill-final` in the implementation environment.

The runtime smoke suite also passed non-root and arbitrary-UID operation, read-only root, temporary storage, CA/secret readability, shared sessions, encrypted certificate handling, routing/TLS on both replicas, database loss/recovery, optional sealed-cache recovery, graceful shutdown and native management HTTPS. CI repeats runtime checks against the exact image before publishing.

Geo tests exercise local country/region lookup with a small licensed MMDB, two-worker job claiming, cache reuse, failure retention/retry, disabling enrichment and regional aggregates. The browser downloaded/used a real Country database. A full production City dataset was not downloaded; its accuracy, deployment memory and public geolocation coverage remain deployment checks. Geo enforcement and external downloads remain opt-in.

Security regressions cover SQLi/XSS/traversal/encoding and benign controls, targeted path/argument/verified-source exclusions, transport chunk boundaries, bounded body reads, byte-preserving forwarding, reservation release and telemetry privacy. The 20-second two-worker fuzz run passed (2,656 executions in that run); seed cases also run with normal tests. Prompt-injection coverage is explicitly a custom literal-rule example, not a general semantic detector. Security CI now gates image publication and also runs on pull requests/branch pushes. No benchmark improvement or complete bypass resistance is claimed.

## Response attribution, address labels and live map — 2026-10-25

Full PostgreSQL race/vet checks passed (92.277s package test time). Tests distinguish actual upstream 403/502 responses from gateway rejections, HTTPS redirects and transport errors; verify per-proxy/source/status aggregation, deleted-host history, legacy unknowns, application filters, most-specific IPv4/IPv6 object labels and name changes without log rewrites. The live API returns bounded recent recorded traffic with the selected host and current object labels.

Final real-browser/Pebble checks passed 56 responsive checks, including all response-table column labels fitting desktop width, object names plus original IPs in request lists/details, actual green/red live effects after allowed/blocked proxy requests, application filtering, pause/resume and reduced-motion cleanup. Source image `aegis-waf:status-labels-test` (`9b2291f45ad3`) contains the final layout. The map is a best-effort view of completed logged requests, with a bounded one-second polling tail and explicit logical unknown/gateway positions; it does not claim active TCP counts or precise visitor coordinates.

## Local network display location — 2026-10-25

Full PostgreSQL integration, race detection and vet passed (89.675s). Regressions cover most-specific IPv4/IPv6 object matching, conservative equal-prefix handling, optional-flag update compatibility, replica refresh, public-IP validation, encrypted snapshot round-trip, idempotent post-forward enrichment, region enrichment, stored/live provenance, and unchanged client identity/Geo decisions. TypeScript production build passed. Browser/Pebble passed 56 responsive checks including saving the shared reference, marking a local IP object, the prominent Dashboard live-map button, and certificate/proxy flows across two replicas. All services and credentials used for these tests were disposable; production local objects/reference remain opt-in.

## Gateway public-IP detection — 2026-10-25

PostgreSQL integration/race/vet passed (89.331s); strict TypeScript build and final browser/Pebble suite passed (56 responsive checks). Detection tests cover IPv4/IPv6, invalid/private/empty/oversized responses, non-200 responses, redirects, cancellation, session/CSRF checks, and detection without changing the saved reference. Browser checks cover successful field population, failed lookup preserving manual input, and explicit save. The fixed HTTPS provider was reachable from the Nexus runtime network without changing any settings. Browser artifacts are in `/tmp/aegis-detect-public-ip` on the build host.

## Regional live map and local route flow — 2026-10-25

PostgreSQL integration/race/vet passed (89.876s), including real-MMDB Washington coordinates, country mismatch/private-IP rejection, local reference lookup without rewriting identity, and gateway/per-event coordinates in the live API. TypeScript production build passed. Final browser/Pebble passed 56 responsive checks plus projected regional gateway positioning, local-flow host filtering, direct application links, global reset, detection success/failure, and actual allowed/blocked animations. Browser regional coordinate fixtures validate the projection; backend tests use the real City MMDB fixture. Artifacts: `/tmp/aegis-regional-flow`; final local image `873e46458d07`. No per-client external Geo lookup or forwarding-path work was added. Local-flow counts are labeled bounded feed samples and do not claim health status.

## Shared local-traffic map filter — 2026-10-25

PostgreSQL integration/race/vet passed (91.095s). Regression checks confirm external live events are selected before the tail limit, regional data excludes recorded local traffic, and the dashboard map can exclude local events while overview totals retain all requests. Invalid filter values are rejected. TypeScript build and the browser/Pebble suite passed (56 responsive checks), including local-note removal from the live view, retained Activity logs, and the shared preference on returning to Dashboard. Artifacts: `/tmp/aegis-hide-local`; final local image `1cadba19c75a`. This is a view preference and does not change classification, logging or enforcement.

## Manual ACME rotation and animated host flow — 2026-10-25

Full PostgreSQL integration/race/vet passed (89.899s). Manual-renewal tests cover early HTTP-01 reissuance, session CSRF, uploaded/missing certificate rejection, active-job conflicts, and preservation of current certificate material before issuance. Cloudflare DNS fixture tests force a failed early renewal, confirm the existing chain remains, retry through the other replica with the saved credential, and confirm the renewed TLS public key changes.

Final browser/Pebble passed 56 responsive checks, actual certificate fingerprint replacement on both replicas without restarting, continued trusted HTTPS, absence of Renew now for uploaded certificates, direct host filtering via keyboard, host-only flow cards, moving green/red request pulses, no idle pulses and reduced-motion cleanup. Existing local map filters and regional positioning also passed. Artifacts: `/tmp/aegis-flow-renew-final`; local image `6c97119bc3b7`. Production certificates were not used for these tests.

A focused browser follow-up verified simultaneous allowed/blocked pulses remain visually distinct, the 16-pulse bound, no idle pulses, reduced-motion cleanup, disposal, hidden upstreams and 320/390/768/1440 px sizing. Screenshot: `/tmp/aegis-flow-renew-final/flow-outcomes-separated.png`.

## README adoption baseline and security schema — 2026-10-25

Full PostgreSQL integration/race/vet passed (89.879s) for security-event schema v1. Tests cover custom/CRS/flood/network/inspection/fallback blocks, UTC timestamps, stable arrays, nullable payloads, bounded opt-in context, legacy aliases, managed Observe events and upstream-403 separation. JSON Schema and both documented JSON examples were checked for required fields; no new validation dependency is required by the application.

Three sequential 64,000-request/phase runtime fixtures passed on exact implementation `bf53d68071569ccd4c96aa42bf5f4401ba06af03`, image `5d6157271548`. Each validated a real CRS block stdout event, active CRS on both replicas, non-root/read-only execution, certificate/session behavior, database outage/recovery, optional sealed snapshots, native management TLS and graceful shutdown. All measured responses succeeded, with zero dropped logs and worker panics. Raw reports and hardware details are in `docs/benchmarks/2026-10-25/adoption-{1,2,3}.json`. The README uses medians and explicitly separates forwarding, custom rules and CRS; its Compose block matches the checked-in deployment and `docker compose config --quiet` passed.

## Bounded response inspection and per-host HSTS — 2026-10-25

Final PostgreSQL integration/race/vet passed (100.933s), including two-replica policy persistence and sealed-cache restoration with response protection enabled. Real CRS disclosure signatures withhold the upstream body and headers in Block (502), remain visible while preserving bytes in Observe, honor outbound thresholds and path-scoped response exclusions, and never retain raw response content. Tests cover exact request/response boundaries, chunked partial replay, structured-prefix parser failures, unsupported encodings, five-second upstream-read cancellation, HTTP/2 SSE and 65 concurrent WebSocket upgrades without retained inspection slots.

HSTS regressions cover bounded max age, max-age=0, conflicting manual header rejection, native TLS and trusted TLS offload, untrusted forwarded-proto rejection, WAF block headers, and redirect-loop prevention. Enabling HSTS does not disable upstream certificate verification; an untrusted self-signed test backend remains rejected. Fresh baselines store normalized defaults with response inspection off and the existing rejecting request action. Existing installations' policies are not rewritten.

Strict TypeScript build and final browser/Pebble suite passed with 56 responsive checks, final local image `acb2e68747de`. The browser verifies new inspection settings survive policy editing, HSTS settings survive host editing and appear in real HTTPS responses, searchable optional response signatures, certificate rotation and trusted TLS through both replicas, and mobile request-detail wrapping. Artifacts: `/tmp/aegis-response-browser-final`. Container smoke on the preceding combined implementation image (`873907af133c`) passed non-root/arbitrary UID, read-only filesystem, cross-replica sessions, encrypted certificate storage, outage/recovery, optional sealed snapshots, native management HTTPS and graceful shutdown. Its load measurements ran alongside other checks and are not published as new capacity figures.

Response inspection and HSTS are opt-in. Inspection caps remain finite; partial actions explicitly leave tails uninspected and truncated structured request bodies can still be rejected. No complete request-body bypass or dashboard-managed upstream trust store was introduced.

## Selective self-hosted CAPTCHA — 2026-10-25

Full PostgreSQL integration/race/vet passed (113.481s). Focused real-PG/race tests passed for selective scoring, PNG/audio across replicas, server-side one-time answer verification, scoped clearance, replay/concurrent redemption, five-attempt bounds, CSRF/origin checks, expiry, open-redirect rejection and independent flood/signature enforcement. A final focused PostgreSQL/race regression passed (6.878s) proving application header rewrites cannot remove CAPTCHA cookies/CSP/no-store behavior while host HSTS is retained.

The real browser/Pebble fixture passed its existing 56 responsive checks plus ordinary-browser forwarding without proof cookies, suspicious-browser verification at mobile/desktop widths, real PNG rendering, a real encrypted-answer solve through the form and clearance on the second replica. Test answers are obtained only by the isolated fixture's direct database/key access; the application has no answer-reading or always-pass endpoint. Artifacts: `/tmp/aegis-bot-browser`. Frontend TypeScript build and npm audit passed (zero reported vulnerabilities). The implementation uses local `dchest/captcha` v1.1.0, with its MIT notice included.

No provider keys or external challenge calls are required. CAPTCHA is opt-in and does not imply verified-bot identity, adaptive learning or complete bot prevention. Challenge answers/proofs are not captured in normal evidence. PostgreSQL is authoritative; cached clearance remains bounded and new verification fails accurately during database loss.

## MCP simulation safety gate (2026-10-25)

The complete Go suite passed with real isolated PostgreSQL, race detection and `go vet` (121.581 s for the application package). Focused authenticated MCP tests cover both generic and convenience routes. Offline simulation leaves rule/config/audit state and the active snapshot unchanged, sends no upstream requests, keeps missing facts unknown, withholds receipts after failed assertions, and rejects missing, altered, reused, expired, stale and cross-key receipts. Concurrent use of one receipt permits exactly one committed mutation. This verifies the bounded harness and authorization contract, not production false-positive rates or the legitimacy of recorded allowed traffic.

## Streaming profile verification (2026-10-25)

Focused real-PostgreSQL/race tests passed (15.443 s), covering profile defaults/validation/API persistence and activation, immediate HTTP/2 SSE first-chunk delivery, WebSocket upgrades, a real CRS SQL disclosure split across two chunks, termination after detection, Observe byte preservation, bounded 4 KiB rolling-window memory across a 256 KiB stream, busy handling and concurrent Close unblocking Read. Frontend strict typecheck/embedded production build passed. Tests explicitly retain status 200 for an already-started stream that is subsequently terminated; this is not a pre-disclosure blocking guarantee.

The complete PostgreSQL-backed `go test -race -count=1 ./...` suite and `go vet ./...` also passed after streaming changes (147.196 s for the app package).

## Optional shared counter verification (2026-10-25)

The complete PostgreSQL/Redis-backed Go race suite and vet passed (132.457 s for the app package). The same focused state contract passed against Dragonfly 2.0.0 (7.271 s). Coverage includes independent replica budgets, concurrent server-time token consumption, bot-frequency coordination, the namespace bucket cap, refill-safe TTLs, explicit 503/Observe failure behavior, independent bot enforcement during a flood Observe outage, recovery, encrypted password storage/no readback, verified TLS defaults, credential destination changes, ciphertext tamper preservation, retired-pool lifecycle and sealed snapshot recovery. Dashboard strict typecheck/build passed. CI now runs Redis-backed regressions alongside PostgreSQL. The optional Compose overlay publishes no backend port and does not alter the default two-container deployment.

After removing avoidable dispatch allocations, the focused local/shared protection regressions passed again (11.221 s). One local protection microbenchmark measured 210.5 ns/op, 16 B/op and one allocation; the preceding committed baseline measured 192.1 ns/op with the same bytes/allocation count. These single-run engine timings exclude network forwarding and do not establish production latency.

## Atomic reload continuity (2026-10-25)

The real-PostgreSQL/race reload test passed (7.057 s for the focused package run). HTTP/1.1 and HTTP/2 SSE streams and an upgraded bidirectional connection remained open across compiled rule/policy/CIDR and TLS-certificate changes. Both replica snapshots enforced new path, native resolved-client-IP and network-CIDR blocks; a fresh network TLS handshake presented serial 222 while existing streams retained negotiated serial 111. A deliberately invalid stored header configuration caused refresh failure without replacing the last working snapshot. No production code rewrite or listener restart was needed: the existing atomic snapshot swap already supplies the requested behavior.

## Platform telemetry and limitations review (2026-10-25)

The combined PostgreSQL/Redis-backed Go race suite and vet passed after the final simulation-hostname fix and HTTP/2 library patch (140.224 s for the application package). Focused telemetry/MCP/streaming tests passed (11.987 s), covering standard Prometheus parsing, bounded request series, concurrent exact counting, log-queue independence, session/read-key authentication, immediate revocation, management/public listener separation, and secret-free JSON MCP success/error/panic completion. Tool panics and typed-nil SDK results are contained safely.

`govulncheck` v1.9.0 with Go 1.26.10 found zero reachable vulnerabilities and zero vulnerable imported packages. Five module-only HTTP/2 advisories were eliminated by updating `golang.org/x/net` to v0.60.0. The remaining module-only GO-2026-5932 concerns unmaintained `golang.org/x/crypto/openpgp`; Aegis does not import that package and no fixed version is available. Its bcrypt/other used crypto packages are not affected by that advisory. Re-review this unused-package finding by 2026-11-25 or on a dependency/import change. Frontend lockfile audit found zero vulnerabilities. Distributed dependency notices were regenerated with go-licenses v2.0.1; its warnings concern assembly dependency inspection, not missing license attribution.

The [limitations review](limitations-review.md) prioritizes automatic access/audit retention and administrator MFA next, while retaining explicit bounded-inspection, streaming, logging-durability and network-DDoS boundaries. The user's new README motivation section and demo graphics remain untouched.

The final production-container browser/Pebble acceptance passed after correcting the System selector's explicit accessible label and protecting inline form drafts from background polling. It exercised local/shared state controls (including an accurately reported failed draft connection), session-authenticated Prometheus exposition, streaming-profile selection, baseline assignment, self-hosted CAPTCHA image/answer verification and clearance on a second replica, plus the existing certificate/routing/policy/map flows. Artifacts were saved to `/tmp/aegis-platform-browser-final`.

The final container smoke/latency fixture passed: UID 10001 and arbitrary UID 23456, read-only root/tmpfs and packaged CA access, cross-replica sessions/certificates/routing, default and sealed-cache database-outage behavior, cold-start readiness, accurate failed writes, restart reload, native management HTTPS and graceful shutdown. The optional Redis Compose overlay separately passed health/non-root/read-only/no-published-port checks. The measured CRS baseline was 10,807.5 requests/sec, mean 1.471 ms and p99 3.793 ms in the fixed local fixture, with zero dropped logs/evidence and zero worker panics. [Raw results and comparison limits](benchmarks.md#platform-hardening-verification-2026-10-25).

## Configurable alerts and endpoint profiles — 2026-10-26

Website/API/SSE profiles were verified with the complete PostgreSQL/Redis race/vet suite (146.884 seconds), focused profile-aware MCP simulation/skill tests, and browser/Pebble acceptance (`/tmp/aegis-api-browser`). API retains SQLi/body-limit/response-leak enforcement while producing JSON denials and blocking high bot suspicion without browser CAPTCHA.

Alerting checks exercise encrypted write-only destinations, HMAC signatures, seven provider payloads against isolated HTTP receivers, metadata/link-local restrictions, disabled redirects, cross-replica cooldown and delivery claims, acknowledgement, retry limits/redaction, all four trigger queries and ascending backlog cursors. Notification administration is verified not to change WAF configuration versions or invalidate simulation receipts. The frozen release passed the full PostgreSQL/Redis race/vet suite (153.307 seconds), focused final alert/migration/skill checks (11.279 seconds), and container smoke checks for non-root/read-only operation, encrypted certificates, replica sessions, outages, sealed-cache recovery, native management TLS and graceful shutdown; initial migration expectations were updated from schema 18 to 19.

The browser/Pebble flow (`/tmp/aegis-alerts-browser-final`) passed destination creation/test-send, application-scoped trigger creation, a real CRS-triggered inbox entry and acknowledgement at 390px/1440px, alongside the existing full acceptance flow. The isolated test receiver returned HTTP 2xx; external provider accounts and agent reasoning/startup were not tested. Actual AI wake-up requires the operator's configured receiver/orchestrator. The root README links the current alert guide; [screenshot provenance](screenshots/README.md) records the fixture image scope.

## Local traffic flow UX — 2026-10-26

The compact host-pill layout passed the strict TypeScript/embedded-asset build and the focused Playwright fixture (`tests/local-flow-ui.cjs`, artifacts `/tmp/aegis-local-flow-ux`). Checks cover 0/1/4/60/500 hosts, bounded DOM rendering, name/domain search, pagination, keyboard focus across selection, direct links, truthful out-of-filter counts, long/escaped names, disabled/wildcard routes, light/dark themes, 320/390/768/1440px widths, 200% zoom, moving pulses, reduced motion and disposal. The production-container browser/Pebble fixture also passed actual feed integration, allowed/blocked pulse movement, application filtering and shared local-traffic hiding (`/tmp/aegis-local-flow-browser`). No backend or forwarding behavior changed.

## Shared mitigation catalogue — 2026-10-26

The complete real-PostgreSQL/Redis Go race suite passed (162.251 seconds), followed by vet. Catalogue integration covers separate checksummed downloads, no automatic activation, cross-replica compilation, frozen provenance, explicit targeted refresh, revision-conflict rollback with visible errors, source removal without losing policy snapshots, and persistent removal of the provisioned subscription. Manifest/regression validation and the TypeScript asset build passed. Legacy feed Playwright checks passed, including failure/retry and draft import.

The production-container browser/Pebble acceptance passed (`/tmp/aegis-catalogue-browser`), including catalogue CVE search and pack selection, applying to an existing policy without losing other groups/assignments, and enforcement on both replicas. Declared Brotli request encoding was blocked while ordinary response negotiation remained allowed. These were harmless header tests, not live vulnerability exploitation or proof of complete CVE coverage. [Operator workflow and limits](rule-feeds.md).

## Policy-owned community controls and reviewed submissions — 2026-10-26

The full PostgreSQL/Redis race suite passed (170.990 seconds) with vet, followed by focused community/baseline/capacity/investigation/MCP regressions (45.238 seconds). Tests verify bundled offline catalogue availability, baseline all-enabled defaults, one-time upgrade preserving other settings, persistent disabling, individual selection, invalid IDs and legacy scoped groups on two replicas. A fully customized baseline at capacity retains its working protection instead of receiving an unloadable snapshot.

The final browser/Pebble run passed (`/tmp/aegis-policy-community-browser`): policy-owned all/individual/off selection, CVE search, persistence and enforcement on two replicas while preserving other groups/assignments. CRS was temporarily disabled for the community on/off probes because its independent encoding rules can also reject the sample header, then restored. Feed review is read-only. Docker compilation includes the bundled rule package, and TypeScript/embedded assets build cleanly.

Submission-gate tests verify unchanged files pass, same-revision edits fail, stable-ID edits fail, missing manifest increments fail and coordinated revision/manifest updates pass. Manifest checks and workflow/issue-form YAML parsing passed. CODEOWNERS and an exact protection payload are checked in; a GitHub administrator must activate required review. Files and green CI alone do not enforce it. No live third-party exploit scanning was performed.

## Single community source — 2026-10-26

The focused PostgreSQL/race/vet suite passed (49.344 seconds), including one-time official starter retirement, preservation of imported native rules and custom sources, policy selection, baseline upgrade, investigation and MCP simulation. The custom-source Playwright fixture passed error/retry, escaped review, legacy import and four responsive layouts after removal of the starter shortcut. Historical starter JSON remains only for compatibility. No new vulnerability signatures were published as part of this consolidation.
