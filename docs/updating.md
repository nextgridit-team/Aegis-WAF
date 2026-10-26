# Update and recover

Back up PostgreSQL and retain the external encryption key before updating. From your deployment directory:

```sh
docker compose pull app
docker compose up -d --no-deps --wait app
```

Use the same Compose overlays and environment overrides you used for deployment. In Dockge, use its update/pull-and-recreate action. CI publishes on main pushes, nightly at **07:17 UTC**, and on manual runs; publishing does not restart your installation.

For reproducible deployment or rollback, pin `AEGIS_IMAGE` to a unique build tag or digest. Preserve the database and secret files, and check schema/feature compatibility before downgrading. See [image publishing](image-builds.md) and [backups](deployment.md#backups-and-recovery). Loaded CRS sets stay pinned until you explicitly select a different stored version.

For database, encryption-key and storage recovery details, see [deployment and operations](deployment.md#backups-and-recovery) and [encryption at rest](encryption-at-rest.md).

## Platform hardening upgrade notes

The 2026-10-25 changes add selective self-hosted CAPTCHA, streaming profiles, optional shared counters, enforced MCP simulation and Prometheus metrics. Existing applications retain their saved profiles, an 8192-byte default stream window and local counters. Hosts without a profile default to Website (`web`). API/SSE profiles use JSON gateway errors and block high bot suspicion without browser CAPTCHA; review bot settings when updating existing streaming hosts. CAPTCHA and response inspection remain opt-in; existing policy definitions, assignments and loaded signature versions are preserved.

Update every serving replica before enabling new shared policy fields or selecting API. Older builds reject the `api` profile; change affected hosts back to `web` before a downgrade. MCP clients must adopt `simulate_rule_impact` and pass its short-lived `simulation_id` for live protection mutations; earlier direct enforcement calls fail without a receipt. Import the updated bundled agent skill. Simulation is not a separate human-approval workflow and does not expand key scopes.

The default Compose file still starts only the app and PostgreSQL. Add the optional Redis overlay or use an existing backend only when choosing shared budgets in System. Shared enforcing counters return 503 on backend failure; there is no silent local fallback. [Shared-state deployment](shared-rate-state.md).

Configuration reloads use atomic snapshots without restarting listeners. Updating the container is a separate operation: a single-replica deployment can be interrupted during replacement. Keep the database and external key backed up, and verify readiness, routing and new requests after the update. [Change history](../CHANGELOG.md) · [Current limits](limitations.md).

## Alerting upgrade

Schema 19 adds encrypted notification destinations, alert rules, an inbox and delivery leases. No destinations, external sends or trigger rules are created automatically. Update all replicas before configuring Alerts; a prior binary does not run the new workers. Notification acknowledgement/configuration is independent of the WAF configuration version and does not invalidate protection simulations. The existing database/external-key backup covers notification configuration too. [Setup and retention](alerts.md).
