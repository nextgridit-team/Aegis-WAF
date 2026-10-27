# Deployment and operations

Start with the [README quick start](../README.md#deploy-with-docker-compose). This guide covers the deployment settings that live outside PostgreSQL. Sites, upstreams, certificates and policies are configured through the web interface or management API.

## Requirements and image

The standard deployment runs the public `ghcr.io/nextgridit-team/aegis-waf:latest` image and PostgreSQL 18 using Docker Compose v2+. Bootstrap secret generation requires Python 3; cloning the repository requires Git. The publishing workflow currently builds Linux/amd64 images. Go and Node are needed only for development or source builds.

```sh
git clone https://github.com/nextgridit-team/Aegis-WAF.git
cd Aegis-WAF
python3 scripts/bootstrap-secrets.py
docker compose up -d --wait
```

Run commands in this directory so Compose finds the intended configuration, secret files and project. Retain its directory/project identity when updating; changing the Compose project name can select a different database volume. See [image publishing](image-builds.md) for build tags and digests.

For a source build instead of the published image:

```sh
docker compose -f compose.yaml -f compose.build.yaml up -d --build --wait
```

## Bootstrap secrets

The bootstrap script creates four files in `secrets/`: `database_url`, `postgres_password`, `encryption_key` and `bootstrap_secret`. It refuses to overwrite a nonempty directory. Keep existing material when restarting or updating an installation.

The host secret directory has mode 0700; individual mounted files have mode 0444 so a platform-assigned non-root UID can read its container mounts. Keep the host directory private and mount only the secrets each service needs. No persistent application volume is required by the default deployment; PostgreSQL uses the named `postgres` volume.

Open `http://localhost:9090` on the Docker host, read `secrets/bootstrap_secret` locally and complete browser setup. There are no default credentials. Setup creates only the first administrator across replicas; the code cannot reset an existing administrator. Use a unique 14–72-byte password.

## Listener mappings

| Listener          | Inside app container | Default published address |
| ----------------- | -------------------- | ------------------------- |
| Application HTTP  | `8080`               | `0.0.0.0:80`              |
| Application HTTPS | `8443`               | `0.0.0.0:443`             |
| Management        | `9090`               | `127.0.0.1:9090`          |

Set the non-secret `HTTP_PUBLISH`, `HTTPS_PUBLISH` and `MANAGEMENT_PUBLISH` Compose variables to change host bindings. For example, a local test installation using alternative public ports:

```sh
HTTP_PUBLISH=127.0.0.1:18080 HTTPS_PUBLISH=127.0.0.1:18443 docker compose up -d --wait
```

Keep those overrides for subsequent commands, or store them in the deployment's `.env` file. `.env` controls Compose substitutions; it does not automatically pass arbitrary application variables into the container. The base Compose file does not forward `MANAGEMENT_TLS` from `.env`.

HTTP-to-HTTPS redirects target the standard public HTTPS port 443. With alternative test ports, access HTTPS explicitly using its mapped port or provide an external 443 mapping. HTTP-01 always requires public port 80 to reach Aegis's HTTP listener; changing the local mapping alone does not satisfy that requirement. Cloudflare DNS-01 does not need inbound port 80. HTTPS application traffic still needs an appropriate reachable mapping/load balancer.

PostgreSQL is not published on a host port by the supplied Compose file. The application-to-database connection uses the Docker network without TLS. For a remote PostgreSQL service, use verified TLS and an appropriate trusted CA.

## Remote HTTPS management

The default loopback binding is for a browser on the Docker host. A browser on another computer cannot reach it through that computer's `localhost` address. Remote management requires HTTPS: Aegis sets Secure session cookies for every non-loopback management hostname/IP. A plain HTTP LAN URL may display the sign-in page but cannot retain the session.

There are two supported paths:

1. **An existing HTTPS reverse proxy.** Give management its own DNS hostname and trusted certificate. Route it directly to the separate management listener on port 9090, preserving the browser's Host header, including its port when applicable. Keep the backend private and reachable only by that proxy. The browser must use the HTTPS hostname. Do not publish management paths through Aegis's protected application listeners. This path can provide HTTPS for first-run setup.
2. **Native management HTTPS.** First complete setup through the local browser or the existing HTTPS management proxy. In Certificates, upload or request a valid certificate covering the management DNS name. A public CA certificate can be obtained using Cloudflare DNS-01 without an existing public application route. Then enable native management TLS as described below.

Native TLS selects a valid certificate from PostgreSQL by management SNI, independently of proxy-host assignments. It does not mint an automatic bootstrap/self-signed certificate. Keep your initial management access available until a matching certificate is stored and the HTTPS listener has been verified.

Create a deployment-local overlay named `compose.management-tls.yaml`:

```yaml
services:
  app:
    environment:
      MANAGEMENT_TLS: "true"
```

Set a LAN binding in the deployment's `.env`, replacing the example with the Docker host's actual address:

```dotenv
MANAGEMENT_PUBLISH=192.168.1.10:9090
```

Point your management DNS hostname, for example `waf.example.com`, at that address. Start with the overlay:

```sh
docker compose -f compose.yaml -f compose.management-tls.yaml up -d --wait app
```

Open `https://waf.example.com:9090` using the hostname covered by the stored certificate. A certificate for a domain does not validate an IP-address URL. Certificate replacements refresh without restarting the application. Continue using the overlay and `.env` when updating. In Dockge, apply the equivalent environment/binding changes to its deployment configuration and use its pull/recreate controls.

## Certificate and upstream connectivity

Aegis uses established Go ACME/DNS libraries inside the application; no Certbot sidecar or shared certificate filesystem is needed. Private keys, account material, jobs and challenge state live in PostgreSQL; secret values are encrypted before storage.

- **Cloudflare DNS-01:** Cloudflare must host the authoritative zone. Supply a scoped API token with Zone Read and DNS Edit through the dashboard. Outbound HTTPS to Cloudflare/the CA and public DNS resolution/propagation checks must work. Exact names and wildcard certificates are supported. See [Cloudflare setup](cloudflare.md).
- **HTTP-01:** Public A/AAAA records and port 80 must reach the HTTP listener. Challenges are available through every replica, before any proxy host exists, and bypass application redirects/protection. HTTP-01 does not issue wildcards.
- **Private upstream CAs:** Configure per-host trust in **Applications → Upstream TLS**, then click **Test upstream**. [Trust and diagnostic guide](upstreams.md). Private ACME CAs or deployment-wide operational trust can still use a read-only combined CA bundle and `SSL_CERT_FILE`. Upstream HTTPS verification remains enabled.
- **Upstreams:** Supply an HTTP(S) URL reachable from the app container. Container `localhost` is the app itself. Use a reachable host/service address or attach the app to the upstream's Docker network. Exact route hostnames are configured in Applications; wildcard certificate coverage does not create wildcard routes.

Renewals begin before expiry using the shorter of 30 days or one-third of certificate lifetime. Failed jobs retain the existing certificate and retry with backoff from one minute to 24 hours. Issuance errors and Retry now are visible in the dashboard. A certificate that eventually expires is no longer eligible for TLS selection.

## Multiple replicas

Every replica runs the same complete application image. Give replicas the same database URL, external encryption key and key identifier. Sessions are server-side in PostgreSQL and work across replicas without sticky sessions. Database-backed locks coordinate certificate issuance and feed jobs; HTTP flood budgets use local memory by default or optional Redis/Dragonfly shared counters.

The supplied Compose file publishes fixed host ports and starts one app replica. Running `--scale app=2` against those unchanged bindings causes port conflicts. For multiple replicas on one host, use a deployment configuration without per-replica fixed public port bindings and place an external load balancer in front. On separate hosts, map ports for each replica normally.

For TLS termination at Aegis, use TCP pass-through on public HTTPS. HTTP-01 requests must also reach Aegis over public port 80. Keep management on a separately controlled listener. When a proxy supplies client-IP headers, configure only its actual trusted IPs/CIDRs per application; trust is not inferred from private address ranges.

PostgreSQL advisory locks require direct or session-pooled connections; transaction pooling is not supported. Each replica permits up to 20 database connections, including one reserved by active issuance. Size PostgreSQL capacity for the replica count. Keep replica clocks synchronized for certificate/rule expiry checks. See [snapshot behavior](#health-and-database-outages) and [identity settings](headers-and-cidrs.md).

## Runtime and bootstrap settings

The image runs as UID/GID 10001 by default and supports platform-assigned non-root UIDs. Internal listeners use unprivileged ports. Compose sets a read-only application root, a 32 MiB `/tmp` tmpfs, `cap_drop: [ALL]`, `no-new-privileges` and a 25-second stop grace period. No privileged mode, host networking, Docker socket or separate worker image is required.

| Application environment                       | Required / default                                                         |
| --------------------------------------------- | -------------------------------------------------------------------------- |
| `DATABASE_URL` or `DATABASE_URL_FILE`         | Required PostgreSQL URL; use `sslmode=verify-full` for verified remote TLS |
| `ENCRYPTION_KEY` or `ENCRYPTION_KEY_FILE`     | Required base64 encoding of exactly 32 random bytes                        |
| `ENCRYPTION_KEY_ID`                           | `primary`; must match the stored key identifier and other replicas         |
| `BOOTSTRAP_SECRET` or `BOOTSTRAP_SECRET_FILE` | Required; at least 32 characters, used for first-run setup                 |
| `HTTP_ADDR`                                   | `:8080`                                                                    |
| `HTTPS_ADDR`                                  | `:8443`                                                                    |
| `MANAGEMENT_ADDR`                             | `:9090`                                                                    |
| `MANAGEMENT_TLS`                              | `false`; native HTTPS requires a previously stored matching certificate    |
| `TMPDIR`                                      | `/tmp` in the image                                                        |
| `SSL_CERT_FILE`, `SSL_CERT_DIR`               | Optional operational CA trust settings                                     |
| `SNAPSHOT_CACHE_FILE`                         | Unset; opt-in absolute path to encrypted recovery snapshot                 |
| `SNAPSHOT_CACHE_MAX_AGE`                      | `24h`; positive and no more than `168h`                                    |

Set these in the container environment through your deployment configuration. Defining both a secret variable and its `_FILE` variant is an error. Only bootstrap/operational configuration belongs here; application settings belong in PostgreSQL. Online encryption-key rotation is not implemented: changing the key or key identifier alone makes existing encrypted records unreadable.

## Administrator and certificate security

Passwords use bcrypt cost 12. Sessions contain 256-bit random tokens; PostgreSQL stores their SHA-256 hashes, expiry and CSRF state. Sessions expire after 12 hours, and logout revokes them centrally. Cookies are HttpOnly and SameSite=Strict, with Secure required outside loopback. Management mutations require a same-origin request header and the current CSRF token; setup/sign-in have database-backed throttling. All administrators share full management authority. Password recovery, MFA and granular roles are not implemented.

PEM upload checks supported key format, key/certificate correspondence, certificate dates, adjacent chain signatures, server-auth usage and hostname coverage on assignment. Upload the leaf first, followed by intermediate certificates. PKCS#8, PKCS#1 RSA and SEC1 EC unencrypted private-key PEM formats are supported. Upload validation does not establish public trust or check revocation. Replacements commit transactionally and failed validation preserves the active certificate. Private keys are encrypted with AES-256-GCM before PostgreSQL storage and are never returned by normal read APIs. Public certificate chains and ordinary configuration/logs are not encrypted by this application layer.

ACME workers poll every five seconds, coordinate using per-certificate session advisory locks and fence stale completion writes. Attempts have a five-minute execution bound; interrupted orders remain in history and retries start fresh orders. External CA/DNS requests cannot be made atomic with database commits, so abandoned external operations can require recovery. Existing valid certificates remain active when renewal fails.

## Health and database outages

`/livez` and `/readyz` exist only on the management listener. The image's built-in healthcheck supports its HTTP and native HTTPS modes. Authenticated `/api/status` reports refresh health, loaded version, log drops, worker panic counts and optional cache state.

| Condition                                           | Behavior                                                                                                                                                                |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initial startup with PostgreSQL available           | Embedded additive schema initialization runs under a database lock; readiness succeeds after a complete snapshot loads.                                                 |
| Database loss after configuration loads             | Cached routes, TLS certificates and rules continue; failed refreshes preserve the complete last snapshot. Readiness remains available.                                  |
| Administration/sign-in/HTTP-01 during database loss | These still depend on PostgreSQL and report failures; they cannot be served from a proxy snapshot.                                                                      |
| New/restarted default replica during an outage      | Remains unready until PostgreSQL becomes available.                                                                                                                     |
| Explicitly enabled sealed recovery cache            | May restore a valid, recent encrypted snapshot and become ready before database recovery; stale/invalid files are ignored. See [cache requirements](snapshot-cache.md). |

Replicas poll configuration versions every two seconds. Loading/compiling a changed snapshot can add time, particularly for a new managed signature configuration. Expired certificates are rejected and standalone rule expiry is checked on the request path even if refresh is unavailable.

SIGINT/SIGTERM stop accepting requests, allow up to 15 seconds for HTTP draining, cancel ACME work and attempt to flush queued access logs. Long-lived upgraded connections end when the process exits. Recoverable background-worker panics are contained and retried; fatal runtime failures such as out-of-memory termination still require process restart.

## Backups and recovery

Back up PostgreSQL plus the deployment's external encryption key, secret files and Compose/overlay settings. Protect the recovery copy of the encryption key separately from the database backup. Database dumps also contain unencrypted configuration, metadata and any retained evidence; protect them accordingly.

An example logical database backup, from the deployment directory:

```sh
umask 077
docker compose exec -T db pg_dump -U aegis_waf -d aegis_waf -Fc > aegis-waf.dump
```

Use your normal PostgreSQL backup/restore process and test restoration into an isolated deployment with the original encryption key and matching key identifier. Restore database state and deployment secrets together. A database dump alone cannot recover private keys; an optional snapshot cache is not a substitute for database backups. Do not rerun bootstrap generation to replace lost keys.

Access/audit log retention is manual in PostgreSQL. Optional sampled evidence expires automatically, but outages and backups affect physical retention. Plan storage capacity and retention for your workload. See [logging](logging.md), [privacy](evidence-privacy.md) and [encryption](encryption-at-rest.md).

For updates, pull/recreate only the app while retaining the database and secrets. Pin a unique build tag/digest for reproducible rollback, check schema/feature compatibility before downgrading, and keep all replicas CRS-capable before enabling a managed set. A build that predates managed signatures cannot enforce those policy settings. [Image builds](image-builds.md) describes the publishing schedule and tags.

## Troubleshooting

| Symptom                                                            | Check                                                                                                                                        |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-in page loads but login does not persist on a LAN IP          | Use the HTTPS management hostname. Plain remote HTTP cannot retain Secure cookies.                                                           |
| Bootstrap code rejected                                            | Use the file from this deployment and check whether an administrator already exists. The code does not reset an account.                     |
| Port already allocated                                             | Change the deployment's publish variables or remove the conflicting listener. Preserve public port 80 reachability if using HTTP-01.         |
| Public HTTP returns 421 or TLS handshake fails for an unknown name | Configure the exact proxy hostname and a valid covering certificate. Unknown hosts are intentionally rejected.                               |
| HTTPS upstream cannot be reached                                   | Check container DNS/network access, upstream hostname/certificate trust and the URL. Do not use container localhost for a different service. |
| CRS blocks uploads or ordinary requests                            | Start in Observe, inspect rule IDs and tune the selected policy. Enforcing oversized bodies returns 413.                                     |
| Fresh deployment never becomes ready                               | Check database access, secret-file readability and app logs. The default startup needs PostgreSQL.                                           |

Use `docker compose ps` and `docker compose logs --tail 100 app` to inspect operational status. Sanitize any logs before sharing them in an issue.

## Optional shared counters

The default Compose deployment remains two containers. For cluster-wide flood and bot-frequency budgets, use an existing private Redis/Dragonfly endpoint or add `-f compose.redis.yaml`, then configure **System → Rate-limit state**. PostgreSQL remains authoritative for configuration and protection definitions. See [shared counters, failure behavior and latency](shared-rate-state.md).
