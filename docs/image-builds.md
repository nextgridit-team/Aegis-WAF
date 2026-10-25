# Published application image

GitHub Actions rebuilds the single application image on main pushes, nightly
at 07:17 UTC, and through Actions > Build and publish application image > Run
workflow. It runs formatting/vet, PostgreSQL race tests, the dashboard build
and dependency audit, then verifies the exact image with the container smoke
suite, including direct HTTPS management, before publishing.

Image: `ghcr.io/nextgridit-team/aegis-waf:latest`. Each run also publishes a
unique `sha-<commit>-<run-id>-<attempt>` tag. The commit alone is insufficient
as an immutable nightly identifier because base images can change. Use the
unique build tag or image digest for rollback. The workflow refreshes base
images and uses official actions pinned to immutable commits.

Publishing uses the repository's GITHUB_TOKEN with packages:write; no registry
password needs to be stored as a repository secret. GitHub creates new GHCR
packages private by default. For anonymous Compose/Dockge pulls, an organization
package administrator must change the package visibility to Public in GitHub's
package settings. A private package instead needs registry authentication on
the Docker host; do not put credentials in Compose or the image.

Compose defaults to the registry's latest tag and pulls when deploying.
In Dockge use the update/pull-and-recreate action to install a new image.
Publishing a nightly image does not restart a running deployment. No updater,
Docker-socket mount or extra worker container is installed.

Set `AEGIS_IMAGE` to a unique build tag/digest for a rollback. Keep the current
PostgreSQL data and secret files. The optional compose.build.yaml overlay is
for development source builds; it is not required for normal deployment.
