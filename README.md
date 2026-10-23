# Aegis WAF foundation

A self-hosted Go reverse proxy with a TypeScript management console embedded in the application binary. PostgreSQL is the sole persistent application store. Each replica runs the API, proxy, configuration refresher, log writer, and ACME worker. This milestone implements TLS and routing; it contains no AI integration, traffic learning, CAPTCHA, or WAF detection.

## Run with Compose

Prerequisites: Docker with Compose and Python 3 for one-time bootstrap secret generation.

```sh
python3 scripts/bootstrap-secrets.py
docker compose up --build -d
```

Open **http://localhost:9090**, read `secrets/bootstrap_secret` locally, and complete first-run setup. Choose your own username and a unique 14–72-byte password. Then sign in. There are no default administrator credentials. Setup is transactionally limited to the first administrator across all replicas; the bootstrap secret cannot reset an existing administrator.

The application maps public HTTP **80 → 8080**, HTTPS **443 → 8443**, and management **127.0.0.1:9090 → 9090**. If public ports are occupied, use `HTTP_PUBLISH=127.0.0.1:18080 HTTPS_PUBLISH=127.0.0.1:18443 docker compose up -d`; HTTP-01 still requires an external mapping from public port 80. TLS redirects use the standard public HTTPS port 443. Secrets are generated only once; keep the encryption key and PostgreSQL backups together in your recovery process, but store the key outside the database.

Manage all sites, certificates, and ACME accounts through the dashboard or management API. No site configuration files, image rebuilds, or restarts are needed. Deployment bootstrap scripts do not manage application configuration.

### Protect an application

1. Upload a currently valid PEM certificate chain and its matching private key in **Certificates**, or issue one through **ACME & renewal**.
2. In **Protected sites**, enter exact DNS hostnames, an HTTP(S) upstream URL, and the certificate. Choose whether to preserve the incoming Host header and redirect HTTP to HTTPS. HTTP-only sites are supported without a certificate.
3. Point DNS and your port mappings or load balancer at the public listeners. Allow up to **2 seconds** for each replica to load the committed version.

Unknown hosts and mismatched TLS SNI/Host requests receive HTTP 421. Unknown or expired SNI certificates fail the TLS handshake. Uploaded certificates may use private PKI; upload validation checks format, dates for the supplied chain, signatures between adjacent certificates, server-auth usage, key correspondence, and coverage of every attached site. It does not assert public trust or perform revocation checks. Upload the leaf first, followed by intermediate certificates. PKCS#8, PKCS#1 RSA, and SEC1 EC unencrypted keys are supported. RSA, EC and Ed25519 keys are handled by Go TLS. Certificate replacement is transactional; invalid coverage, mismatched keys, or failed audit writes preserve the previous certificate.

### ACME

Register an account using the staging, production, or custom **HTTPS ACME directory URL**. Load and review the CA terms and explicitly accept them. The application stores the account key encrypted and records acceptance. Start with Let's Encrypt staging to test reachability, then use a production account for browser-trusted certificates. Private CAs must be trusted by the application's system CA bundle; mount a suitable read-only CA bundle and set `SSL_CERT_FILE` if needed.

Request certificates for administrator-provided exact DNS hostnames. Public port **80** must reach the HTTP listener on every replica; DNS A/AAAA records must resolve correctly. Challenges bypass site routing and HTTPS redirects, including before any site exists, and are served from PostgreSQL by all replicas. HTTP-01 cannot issue wildcard certificates. A `ChallengeProvider` interface leaves room for DNS-01 later; no DNS provider is included.

Workers poll every **5 seconds**. Renewals begin when remaining validity is less than **30 days or one-third of the certificate lifetime**, whichever is shorter. Jobs retain attempts, next-run time, sanitized errors, and order URLs/status. Failures retry with exponential backoff from 1 minute to 24 hours, indefinitely. **Retry now** advances a failed job. Five-minute execution limits bound stuck orders. A crashed worker's running job is eligible for another worker once its database advisory lock is released. Each attempt starts a fresh ACME order; interrupted orders remain in history. A valid active certificate is retained during failures.

## Deployment properties

- One application image plus PostgreSQL; no Redis, separate workers, privileged mode, host networking, Docker socket, or Linux capabilities.
- App image runs as UID/GID **10001** and also supports a platform-assigned non-root UID. All application files and CA certificates are world-readable; mount secret files readable by the assigned UID. The bootstrap script uses a host directory mode of 0700 and files mode 0444 so container bind-mounted secrets work with arbitrary UIDs. Restrict secret exposure to the relevant container and keep the host directory private.
- Compose drops all application capabilities, sets `no-new-privileges`, uses a read-only root filesystem, and mounts a 32 MiB ephemeral `/tmp`. No persistent application volume is used. Only PostgreSQL has a persistent volume.
- `/livez` and `/readyz` are available **only on management**. Readiness stays 503 until a full snapshot is loaded. After that, a database outage preserves readiness and cached proxy/TLS service. API status exposes database refresh degradation separately. No new administration or sign-in can succeed without PostgreSQL. HTTP-01 challenge responses require PostgreSQL and return 503 during outages.
- Public listeners have bounded header, request-read, upstream connection, TLS handshake, and upstream-response-header timeouts. Response streams have no write timeout. WebSockets, streaming responses, and upstream HTTPS verification use Go's reverse proxy. Client-supplied forwarding headers are discarded and rebuilt from the direct peer; an external load balancer's forwarded identity is not trusted in this milestone.
- SIGINT/SIGTERM stop accepting requests, drain HTTP for up to 15 seconds, cancel ACME operations, and flush pending access logs. Compose allows 25 seconds before termination. Long-lived upgraded WebSocket connections are terminated when the process exits.

### Multiple replicas

Run the same image with identical database URL, encryption key, and key identifier. Every replica has the complete application. Place the public listeners behind a TCP load balancer for end-to-end TLS termination at the app. Port 80 challenge requests must also reach the app. Management may use a separate HTTPS reverse proxy; forward Host accurately and do not expose management paths on protected application listeners. Browser sessions work across replicas without stickiness.

The single-host Compose file publishes fixed host ports, so it intentionally starts one replica. To run more replicas on one Docker host, remove the app `ports` mappings in your deployment configuration and use an external load balancer on the internal ports. On separate hosts, map each replica's ports as usual. PostgreSQL advisory locks require **direct or session-pooled connections**; transaction-pooling middleware is not supported. Each replica permits up to 20 PostgreSQL connections, including one reserved by an active issuance operation. Size PostgreSQL connection capacity accordingly.

### Bootstrap environment

| Setting                                                          | Required / default                                                                                                         |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL` or `DATABASE_URL_FILE`                            | Required PostgreSQL connection URL including credentials; use `sslmode=verify-full` and a trusted CA for remote PostgreSQL |
| `ENCRYPTION_KEY` or `ENCRYPTION_KEY_FILE`                        | Required base64 encoding of exactly 32 random bytes                                                                        |
| `ENCRYPTION_KEY_ID`                                              | `primary`; must match across replicas                                                                                      |
| `BOOTSTRAP_SECRET` or `BOOTSTRAP_SECRET_FILE`                    | Required, at least 32 characters; used only for first-run setup                                                            |
| `HTTP_ADDR`                                                      | `:8080`                                                                                                                    |
| `HTTPS_ADDR`                                                     | `:8443`                                                                                                                    |
| `MANAGEMENT_ADDR`                                                | `:9090`                                                                                                                    |
| `TMPDIR`                                                         | `/tmp` in the container                                                                                                    |
| `SSL_CERT_FILE`, `SSL_CERT_DIR`, standard Go networking settings | Optional operational trust/network bootstrap                                                                               |

Defining both a sensitive variable and its `_FILE` variant is an error. No application setting depends on local storage. The image includes CA certificates. The Compose database connection uses the isolated Docker network without TLS; use verified TLS outside that host/network trust boundary.

## Security and persistence

Passwords use bcrypt cost 12. Session tokens contain 256 random bits; only SHA-256 token hashes, expiry, and CSRF state are stored server-side. Sessions expire after 12 hours and logout revokes them centrally. Cookies are HttpOnly and SameSite=Strict. Secure cookies are mandatory for non-loopback management hosts; HTTP cookies are permitted only on localhost/loopback so the default private Compose console works. For remote access, use an HTTPS management proxy or an SSH localhost tunnel. The app ignores client-supplied `X-Forwarded-Proto` for cookie decisions.

Mutations require `X-Requested-With: aegis-waf`, a same-origin Origin when present, and the session's `X-CSRF-Token`. JSON content types and request sizes are enforced. Setup and sign-in have database-backed direct-peer and global throttles. No cross-origin API access is enabled. All administrators currently share full management authority; additional roles, password reset/recovery, and MFA are outside this milestone.

AES-256-GCM encrypts private keys and ACME account keys with random nonces and associated data identifying the key ID and material purpose. Key IDs are stored alongside ciphertext; normal read APIs never return ciphertext or private keys. An unknown key ID or authentication failure rejects a new snapshot. **Online key rotation is not implemented**: retain the current external key. Changing the key or identifier alone makes encrypted records unreadable. Database backup alone is insufficient for recovery.

Routing and certificates load in one repeatable-read transaction and are published as an immutable in-memory snapshot. Configuration writes serialize on a database version row, commit changes plus audit records atomically, and increment that version. Replicas check it every 2 seconds. Refresh failures keep the complete previous snapshot. A fresh replica never invents a fallback configuration. Schema initialization uses a database transaction and advisory lock across replicas; migrations are embedded in the binary.

ACME issuance uses a per-certificate PostgreSQL session advisory lock, one active job per certificate, connection-health monitoring that cancels work on lock-connection loss, and per-attempt owner tokens fencing stale completion writes. HTTP-01 challenge records commit before asking the CA to validate. CA network requests cannot be committed atomically with PostgreSQL: a process failure at the boundary can leave an orphaned CA account/order; it cannot expose private keys or replace a stored certificate with partial material.

Access logs contain timestamp, site ID, direct peer IP, HTTP method, response status, and duration. They intentionally omit request/response bodies, path/query, authorization, and cookies. Logs are batched to PostgreSQL once per second or per 1,000 records. An 8,192-event in-memory queue avoids blocking proxy traffic. Outages or saturation can drop access logs; a per-replica counter is exposed at `/api/status`. Audit writes are synchronous and transactional with administrative changes. No secrets are included in audit events or normal service logs. Access/audit retention is currently manual in PostgreSQL; plan disk capacity and a retention policy before high-volume deployment.

## Management API

All authenticated paths live under `/api` on the management listener. There are no bearer-token or private-key export APIs. Use the dashboard for interactive management, or a cookie jar for automation:

- `GET /setup`, `POST /setup` (`username`, `password`, `secret`): one-time administrator bootstrap.
- `POST /login` (`username`, `password`): returns username and CSRF token and sets the session cookie. `GET /me` returns the current CSRF token. `POST /logout` revokes the session.
- `GET /status`: this replica's loaded version, database refresh health, propagation interval, and access log drop count.
- `GET /sites`, `POST /sites`, `PUT /sites/{id}`, `DELETE /sites/{id}`: site management. Write fields: `name`, `hostnames`, `upstream`, nullable `certificate_id`, `redirect_https`, `preserve_host`, `enabled`. Send all fields on PUT.
- `GET /certificates`: metadata, validity, and assignments. `POST /certificates`, `PUT /certificates/{id}`: `name`, `chain_pem`, `private_key_pem`. PUT replaces an uploaded certificate only. `DELETE /certificates/{id}` requires no assignments or active jobs.
- `GET /acme/directory?url=staging|production|<encoded HTTPS URL>`: discover CA terms.
- `GET /acme/accounts`, `POST /acme/accounts`: registration fields `directory` (`staging`, `production`, or HTTPS URL), `email`, `accept_terms: true`.
- `POST /acme/certificates`: `name`, `domains`, `account_id`; returns 202 after queuing issuance. Attach it to sites after issuance succeeds.
- `GET /acme/jobs`, `POST /acme/jobs/{id}/retry`: newest 100 jobs with order history; retry only accepts jobs in `retry` state.
- `GET /audit`, `GET /access-logs`: latest 200 records.

For mutations, send `Content-Type: application/json`, `X-Requested-With: aegis-waf`, and the current `X-CSRF-Token` (except setup/login, which have no session yet). Errors return JSON with an `error` field. Database failures return 503 without claiming success; invalid input returns 400; conflicts return 409. A connection loss exactly at commit can leave an ambiguous result; refresh state before repeating a create operation.

## Development and verification

Requirements: Go 1.26+, Node 22+, and PostgreSQL 18 for integration tests.

```sh
cd web && npm ci && npm run build && cd ..
go test -race ./...
go vet ./...
go build -trimpath -o bin/aegis-waf ./cmd/aegis-waf

# Use a test database where the supplied user may create/drop schemas.
TEST_DATABASE_URL='postgres://user:password@localhost:5432/testdb?sslmode=disable' \
  go test -race -count=1 ./...
```

Tests use isolated schemas and exercise a real PostgreSQL database. The local ACME fixture exercises the real `golang.org/x/crypto/acme` client, registration, orders, CSR submission, shared HTTP-01 responses, two-replica issuance coordination, failed renewal preservation, backoff/manual retry, and crashed-worker recovery. It does not establish compatibility with every public CA. Other tests cover bootstrap exclusivity, cross-replica sessions/revocation, CSRF, encrypted storage/no key readback, transactional audit failures, live TLS replacement, snapshot propagation, proxy forwarding-header trust, streaming, unknown/expired SNI, and database failure behavior.

Production assets are checked in for convenient Go-only development; rebuild them after dashboard edits. The Docker build always regenerates them from TypeScript. `make build`, `make test`, and `make integration` wrap the commands above. See [verification evidence](docs/verification.md) for checks performed in the implementation environment and remaining deployment checks.

Verify the built image and its runtime constraints with Docker, Compose, Python 3, and OpenSSL:

```sh
make container-test
```

This builds `aegis-waf:verification` and runs `tests/container-smoke.py` against an isolated Compose project. It generates temporary secrets, binds random localhost ports, starts two replicas (including a platform-assigned UID) and a disposable PostgreSQL database, and verifies HTTP/TLS routing, shared sessions, CA connectivity, database outage/recovery, restart persistence, and graceful shutdown. A temporary Node HTTP server acts as the test upstream. Test containers, networks, volumes, and secrets are removed on exit; the application image is retained. No public ACME account or certificate is created.

## License

[MIT](LICENSE), copyright nextgridit-team.
