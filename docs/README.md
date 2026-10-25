# Aegis documentation

[Project overview and quickstart](../README.md) · [Current limitations](limitations.md) · [Security model](security.md)

## Install and operate

| Goal                                                                         | Guide                                                                                     |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Protect your first application                                               | [Guided setup](getting-started.md)                                                        |
| Deploy with Compose or Dockge, configure HTTPS management, scale and back up | [Deployment and operations](deployment.md)                                                |
| Pull images and plan upgrades or rollback                                    | [Update and recover](updating.md) · [Image publishing](image-builds.md)                   |
| Understand replicas, cached configuration and database failure               | [Architecture](architecture.md) · [Optional sealed recovery cache](snapshot-cache.md)     |
| Set up TLS and renew certificates                                            | [Certificate lifecycle and storage](certificates.md) · [Cloudflare DNS-01](cloudflare.md) |

## Protect applications

| Goal                                                   | Guide                                                                                  |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| Assign policies and source-specific protection         | [Policies](policies.md)                                                                |
| Load OWASP CRS and select signatures or exclusions     | [Managed signatures](managed-signatures.md)                                            |
| Author rules and synchronize external rule sources     | [Custom rules](rules.md) · [Rule feeds](rule-feeds.md)                                 |
| Tune inspection bounds and false positives             | [Body inspection controls](body-inspection.md) · [Security tuning](security-tuning.md) |
| Configure trusted proxies, headers and CIDR exemptions | [Headers and client identity](headers-and-cidrs.md)                                    |
| Reuse addresses and groups                             | [Address objects](address-objects.md)                                                  |
| Download Geo data and apply geographical decisions     | [Geolocation](geolocation.md)                                                          |

## Observe and investigate

| Goal                                            | Guide                                                                                   |
| ----------------------------------------------- | --------------------------------------------------------------------------------------- |
| Understand dashboard metrics and traffic views  | [Dashboard](dashboard.md)                                                               |
| Inspect an individual request                   | [Request investigation](request-investigation.md)                                       |
| Collect structured security events              | [Logging and SIEM integration](logging.md) · [JSON Schema](security-events.schema.json) |
| Control request-content retention and redaction | [Evidence privacy](evidence-privacy.md)                                                 |
| Evaluate performance                            | [Benchmarks](benchmarks.md) · [Proxy comparison and its limits](proxy-comparison.md)    |

## Security, automation and development

| Goal                                                           | Guide                                                                          |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Understand protection boundaries and operator responsibilities | [Security model](security.md) · [Encryption at rest](encryption-at-rest.md)    |
| Connect your own agent                                         | [Management MCP, scoped keys and portable skill](agent-access.md)              |
| Use the management API                                         | [API reference](management-api.md)                                             |
| Build, test and inspect verification results                   | [Development](development.md) · [Verification](verification.md)                |
| Understand the interface and reproduce screenshots             | [Dashboard design](design.md) · [Screenshot provenance](screenshots/README.md) |
| Maintain accurate public documentation                         | [Documentation guidelines](maintaining-documentation.md)                       |

## Proposals and research

These documents record ideas or design research; their inclusion does not mean the features are implemented. Use the project README and current feature guides to assess available behavior.

- [Proposed AI endpoint and external MCP protection profiles](ai-gateway-proposal.md), including Ollama and the **LiteLLM gateway**.
- [AI use cases](ai-use-cases.md) and [implementation review](ai-use-cases-review.md): earlier investigation ideas.
- [Legacy AI-provider settings](ai-provider.md): historical configuration surface; it does not run an inference workflow.
- [Cloudflare rule design research](cloudflare-rule-design.md).
