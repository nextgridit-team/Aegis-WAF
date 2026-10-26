## Rule submission

Rule ID / revision:
CVE(s) or attack class:
Technology and affected versions:
Primary upstream advisory/reference:

## Coverage and compatibility

What exact traffic does this match? Which attack paths remain uncovered?
Which legitimate requests could it block? Is this a broad delivery-path guard?

## Verification

Describe matching, nonmatching and near-match/case/encoding fixtures. Use synthetic
or sanitized requests only; never include live credentials, personal data or
unapproved third-party targets.

- [ ] One rule per JSON file, with a stable ID and increasing revision.
- [ ] Metadata distinguishes partial mitigation from exploit detection.
- [ ] At least one matching and one legitimate nonmatching test; regression cases pass.
- [ ] Package and release descriptor regenerated; checksums and revision checks pass.
- [ ] Changes are limited to the rule and necessary package/release descriptor/docs/tests.
- [ ] I have the right to contribute this under the repository's MIT license; any adapted work is attributed and license-compatible.
- [ ] I understand this requires maintainer review and is not automatically published or enabled for operators.
