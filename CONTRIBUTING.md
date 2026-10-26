# Contributing to Aegis

Anyone can propose a community mitigation through a fork and pull request, or
[request a rule](https://github.com/nextgridit-team/Aegis-WAF/issues/new?template=rule-request.yml).
No repository write access is needed. A maintainer reviews submissions before they
are accepted; passing automated checks alone is not approval.

See the **[rule contribution workflow](docs/rule-contributions.md)** for authoring,
local checks, review criteria, false-positive reports and publication. The
[community rule PR template](.github/PULL_REQUEST_TEMPLATE/community-rule.md)
provides the information reviewers need. Prefer one rule per PR; closely related
rules may share a submission when that makes review clearer.

For application changes, follow [development and verification](docs/development.md).
Use synthetic or sanitized fixtures. Do not submit credentials, personal traffic
or code copied without compatible licensing. Report security issues using the
[security guidance](docs/security.md).
