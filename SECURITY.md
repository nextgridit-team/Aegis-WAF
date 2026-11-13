# Security policy

Aegis is a security product, so please report suspected vulnerabilities privately rather than in a public issue.

## Reporting a vulnerability

Use GitHub's private advisory form:

https://github.com/nextgridit-team/Aegis-WAF/security/advisories/new

Include, where you can:

- the image tag or digest (`ghcr.io/nextgridit-team/aegis-waf:latest`, a `sha-<commit>-<run>-<attempt>` tag, or a digest), and whether the deployment is the stock `compose.yaml`;
- the affected component and the relevant configuration (policy mode, trusted proxies, optional features enabled);
- reproduction steps or a proof of concept, using synthetic data;
- the observed impact and any preconditions.

Do not include production credentials, private keys, customer traffic or personal data. Redact anything you must show.

## What to expect

Aegis is maintained on a best-effort basis. There is no bug bounty and no guaranteed response time; we aim to acknowledge a complete report within five business days, confirm or dispute the finding, and agree on disclosure timing before any public write-up. Please allow a reasonable window to ship a fix before publishing details.

## Scope

In scope: the application image, the supplied Compose deployment, the management API and MCP endpoint, the shipped dashboard, and the rule-feed tooling in this repository.

Out of scope: findings that require a compromised host or Docker daemon; vulnerabilities in upstream dependencies without an Aegis-specific impact (report those upstream); and configuration the documentation already warns about, such as publishing the management listener as plain HTTP on a non-loopback address or assigning the baseline policy to an upload-dependent application without reviewing the community guards.

## Supported versions

There is no semantic-version release series yet. Security fixes ship in the current `latest` image and in new `sha-<commit>-<run>-<attempt>` builds; older images are not patched. Reproduce against the newest published image or `main` when you can.

See the [security model](docs/security.md) for protection boundaries and [current limitations](docs/limitations.md) for known constraints.
