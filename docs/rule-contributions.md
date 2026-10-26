# Contribute a community rule

Anyone can submit rules. Submission does not publish a rule: a maintainer checks
its coverage, compatibility and tests before merging it into the reviewed feed.
Aegis uses declarative WAF matchers, not executable Nuclei templates.

## Submit through a fork and pull request

1. Fork the repository and create a branch from current `main`.
2. Add one `<stable-id>.json` file under `rules/community/`, or update an existing
   file and increase its revision. Prefer one rule per PR. Follow the
   [file-format authoring guide](../rules/community/README.md).
3. Include an upstream advisory, affected versions, exact coverage, remaining
   attack paths and likely false positives. Broad guards must explicitly say
   which legitimate request types they reject. Do not claim complete CVE coverage
   from a content-type/header guard.
4. Add matching, legitimate nonmatching and useful near-match/case/encoding
   regression fixtures. Use harmless synthetic requests, not live exploit tests
   against third parties. Preserve attribution and license compatibility.
5. Run the checks below, commit the individual rule, regenerated package and release descriptor,
   then open a PR using the [community-rule template](../.github/PULL_REQUEST_TEMPLATE/community-rule.md).
   Include the command output and explain compatibility tradeoffs. CI runs
   isolated validation without production credentials or external target scans.
6. Address review comments. A changed rule needs a higher revision; changes after
   approval require fresh review when the documented branch protection is active.

```sh
python3 scripts/build-rule-feed.py
python3 scripts/build-rule-feed.py --check
python3 scripts/check-rule-revisions.py --base-ref origin/main
go test ./internal/app -run 'TestCommunityCatalogue|TestCatalogue'
```

For a new file, start revision 1. For any edit to an existing rule's bytes,
including formatting or metadata, increment its revision. The generator updates
package checksum and increases the release revision. Rebase competing feed PRs and
regenerate the package and descriptor when necessary. Existing entries keep their stable IDs.
Checks cover bounded rules, required metadata, SHA-256, revisions and positive /
negative regression cases. They do not prove exploit coverage or low false-positive
rates for every application.

## Maintainer review and publication

Review the actual declarative definition and all compatibility notes. Check the
advisory against primary sources, matcher specificity and bypass/unknown-fact
boundaries, legitimate traffic fixtures, attribution and license. Review CI or
validator changes as carefully as rules. Request changes when the coverage claim
exceeds the matcher or a broad block is not adequately explained.

A maintainer approval is separate from green CI. Merge accepted rules through a
pull request; do not auto-merge submissions solely because tests pass. Merged
individual JSON files, generated package and release descriptor become available at the main-branch
community URL. Image publication also depends on community validation. Rejected,
open and unmerged PRs never enter that feed. Fork owners can publish a separate
feed, but that is not the reviewed Aegis community source.

The feed syncs every 12 hours or manually. Operators enable/select rules in
**Policies → Edit → Community mitigations**. The shipped baseline enables every
shipped community mitigation, while custom policies choose their own selection.
Published definitions are pinned; sync alone does not change existing copies.
Updates require an explicit policy snapshot refresh/save. New baseline deployments
receive the bundled reviewed rules before their first network sync.

## Requests and corrections

No Go setup is needed to [request a rule](https://github.com/nextgridit-team/Aegis-WAF/issues/new?template=rule-request.yml)
or [report a false positive / missed match](https://github.com/nextgridit-team/Aegis-WAF/issues/new?template=rule-false-positive.yml).
Include the rule ID/revision, Aegis image version, expected behavior and minimal
sanitized fixtures. A maintainer or another contributor can turn the report into
a reviewed PR. Never publish credentials or private customer traffic.

## Required GitHub administration

**CODEOWNERS and CI files do not enforce review by themselves.** A repository
administrator must protect `main`. The checked-in
[branch-protection payload](../.github/branch-protection/main.json) specifies:

- Pull request required; at least one approval and required code-owner review.
- Dismiss stale approvals, require approval after the last push, and resolve conversations.
- Require the **Community rule validation** status check and an up-to-date branch.
- Enforce for administrators; disallow force pushes and branch deletion.

In **Settings → Branches → Add branch protection rule**, target `main` and enable
those options. The payload can alternatively be applied with the authenticated
GitHub REST `PUT /repos/nextgridit-team/Aegis-WAF/branches/main/protection` endpoint.
Review/preserve any existing protection settings before replacing them.

`CODEOWNERS` names `@sparksbenjamin` for the community files and review/validation
controls. The owner must have write access; replace this with a maintained team
as the project grows. A PR author cannot supply their own required approval.
Keep a second eligible maintainer for rules authored by the owner. Verify the
protected state in GitHub after applying it. Until it is enabled, trusted users
with direct push permissions can bypass this documented workflow.

## Design references

This workflow adapts the open-submission, focused-PR, validation and moderator
review practices in the [Nuclei contribution guide](https://github.com/projectdiscovery/nuclei-templates/blob/main/CONTRIBUTING.md)
and [template review guide](https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATE-REVIEW-GUIDE.md).
Their templates scan targets; Aegis rules inspect proxied requests, so the test
inputs and compatibility review differ. GitHub documents [required branch reviews
and checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
