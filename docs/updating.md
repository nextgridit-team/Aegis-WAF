# Update and recover

Back up PostgreSQL and retain the external encryption key before updating. From your deployment directory:

```sh
docker compose pull app
docker compose up -d --no-deps --wait app
```

Use the same Compose overlays and environment overrides you used for deployment. In Dockge, use its update/pull-and-recreate action. CI publishes on main pushes, nightly at **07:17 UTC**, and on manual runs; publishing does not restart your installation.

For reproducible deployment or rollback, pin `AEGIS_IMAGE` to a unique build tag or digest. Preserve the database and secret files, and check schema/feature compatibility before downgrading. See [image publishing](image-builds.md) and [backups](deployment.md#backups-and-recovery). Loaded CRS sets stay pinned until you explicitly select a different stored version.

For database, encryption-key and storage recovery details, see [deployment and operations](deployment.md#backups-and-recovery) and [encryption at rest](encryption-at-rest.md).
