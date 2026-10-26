# Development and verification

Run commands from the repository root. Requirements: Go 1.26+, Node 22+, and PostgreSQL 18 for integration tests. Focused certificate-form tests run with `npm --prefix tests run test:onboarding` after installing browser dependencies; they intercept API calls and never contact a public CA or DNS provider.

```sh
cd web && npm ci && npm run build && cd ..
go test -race ./...
go vet ./...
go build -trimpath -o bin/aegis-waf ./cmd/aegis-waf

# Use a test database where the supplied user may create/drop schemas.
TEST_DATABASE_URL='postgres://user:password@localhost:5432/testdb?sslmode=disable' \
  go test -race -count=1 ./...
```

`python3 tests/go-integration.py` runs race-enabled tests and vet in Docker against a disposable, unexposed PostgreSQL instance and removes its resources. Tests use isolated schemas and exercise a real PostgreSQL database. The local ACME fixture exercises the real `golang.org/x/crypto/acme` client, registration, orders, CSR submission, shared HTTP-01 responses, two-replica issuance coordination, failed renewal preservation, backoff/manual retry, and crashed-worker recovery. It does not establish compatibility with every public CA. Other tests cover bootstrap exclusivity, cross-replica sessions/revocation, CSRF, encrypted storage/no key readback, transactional audit failures, live TLS replacement, snapshot propagation, proxy forwarding-header trust, streaming, unknown/expired SNI, and database failure behavior.

Production assets are checked in for convenient Go-only development; rebuild them after dashboard edits. The Docker build always regenerates them from TypeScript. `make build`, `make test`, and `make integration` wrap the commands above. See [verification evidence](verification.md) for checks performed in the implementation environment and remaining deployment checks.

Verify the built image and its runtime constraints with Docker, Compose, Python 3, and OpenSSL:

```sh
make container-test
```

This builds `aegis-waf:verification` and runs `tests/container-smoke.py` against an isolated Compose project. It generates temporary secrets, binds random localhost ports, starts two replicas (including a platform-assigned UID) and a disposable PostgreSQL database, and verifies HTTP/TLS routing, shared sessions, CA connectivity, database outage/recovery, restart persistence, and graceful shutdown. A temporary Node HTTP server acts as the test upstream. Test containers, networks, volumes, and secrets are removed on exit; the application image is retained. No public ACME account or certificate is created.

### Verify the certificate-to-proxy browser flow

The browser suite provisions a real [Pebble ACME test authority](https://github.com/letsencrypt/pebble), PostgreSQL, two gateway replicas, and a test upstream in an isolated Docker network. It performs real HTTP-01 validation through the second replica, requests a certificate through the dashboard, and verifies HTTPS proxy responses against the issued certificate’s trusted test root. It also checks PEM errors, modal focus, input preservation, bounded/redacted traffic capture, draft/observe/block/disable/rollback workflows, offline replay, and responsive layouts. Pebble is used only by tests; production deployment remains one application image plus PostgreSQL.

```sh
npm --prefix tests ci
(cd tests && npx playwright install chromium) # or set BROWSER_EXECUTABLE
make browser-test
```

The suite generates temporary credentials and certificates, uses random localhost ports, and removes its test resources on exit. Screenshots are written to `/tmp/aegis-ui-review` by default. Real Let’s Encrypt staging/production issuance still requires your public DNS and port forwarding.

For a source-built deployment, use `docker compose -f compose.yaml -f compose.build.yaml up -d --build` after generating bootstrap secrets. This overlay uses `aegis-waf:local` and disables registry pulls.

Without `TEST_DATABASE_URL`, database integration tests are skipped. Shared-backend tests additionally require `TEST_REDIS_ADDRESS`; set `TEST_REDIS_PASSWORD` when authentication is required. Use the isolated commands below to exercise these paths.

## README maintenance

Keep implemented behavior separate from proposals, verify setup commands against Compose, and link detailed operations/API material rather than expanding the front page indefinitely. Use relative repository links, descriptive image text and real synthetic-data screenshots. The structure follows [GitHub README guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes), [Write the Docs](https://www.writethedocs.org/guide/writing/beginners-guide-to-docs/) and [GitHub diagram support](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams). Refresh images using the [screenshot guide](screenshots/README.md).

Security regression and fuzz targets are documented in [inspection and telemetry](security-tuning.md). Run `go test ./internal/app -run '^$' -fuzz '^FuzzRequestBodyReplay$' -fuzztime=20s -parallel=2` for the bounded local fuzz check. MCP integration uses a real official-SDK client over TLS against an isolated database, without an external model.

## Shared counters, simulation and streaming regressions

```sh
# Full PostgreSQL/race/vet suite with a disposable authenticated Redis backend.
AEGIS_TEST_RATE_STATE_IMAGE=redis:8-alpine python3 tests/go-integration.py

# Run the same suite with the supported Dragonfly fixture instead.
AEGIS_TEST_RATE_STATE_IMAGE=docker.dragonflydb.io/dragonflydb/dragonfly:v2.0.0 \
  python3 tests/go-integration.py
```

The runner cleans up its own containers/network. These are test-only services, not new production requirements. CI's image job also supplies Redis alongside PostgreSQL. Tests cover cross-replica budgets, outage/recovery, capacity/TTL bounds, encrypted credentials, simulation receipt binding and rollback, unknown evidence, streaming-window matches, and active HTTP/1.1/HTTP/2/upgraded connections through rule/CIDR/TLS reloads.

The browser/Pebble flow also checks System settings, authenticated metrics, Web/SSE selection and selective CAPTCHA with cross-replica clearance. Its CAPTCHA answer access reads only the isolated test database/key; no production bypass endpoint is built into Aegis. Prometheus tests validate exposition, bounded labels, authentication, queue-independent counting and secret-free MCP success/error/panic events.

## Local traffic flow UX fixture

Run `BROWSER_EXECUTABLE=/path/to/chromium node tests/local-flow-ui.cjs` after installing the web/test dependencies. This serves the production local-flow component and CSS with explicitly synthetic host/event fixtures; it does not contact a real Aegis deployment. It verifies 0/4/60/500-host inventories, search/paging, keyboard focus, scoped-count semantics, disabled/wildcard/long-name handling, themes, 320–1440px widths, 200% zoom, moving pulses, reduced motion and cleanup. Screenshots default to `/tmp/aegis-local-flow-ux`; set `BROWSER_ARTIFACT_DIR` to override. The full browser/Pebble fixture separately verifies actual feed integration.
