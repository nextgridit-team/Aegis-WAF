# November 10, 2026 community release

Release 9 adds five guards to the 95-rule catalogue. Each carries positive and negative request fixtures, affected versions, primary references and explicit compatibility limits. These tests establish matcher behavior and WAF enforcement, not exploitation or complete remediation of a vulnerable product.

| CVE | Guard | Coverage and remaining exposure |
| --- | --- | --- |
| CVE-2026-119977 | `wordpress-upgrade-staging-guard` | External access to the default WordPress upgrade staging directory. Relocated content directories and other installer paths are outside coverage. |
| CVE-2026-102895 | `gpustack-client-ip-header-guard` | Client-supplied `X-GPUStack-Real-IP`, regardless of address spelling. The independent same-host proxy loopback bypass remains; require authentication and patch GPUStack. |
| CVE-2026-114432 | `contact-form-7-upload-directory-guard` | HTTP retrieval/listing of the default temporary upload directory. Does not stop the initial upload or cover custom upload locations. |
| CVE-2026-97229 | `gitlab-project-ci-lint-guard` | Project CI-lint HTTP route, including GET and namespaced project IDs. Does not inspect stored CI configuration or protect other evaluation paths. |
| CVE-2026-110264 | `gitlab-org-mode-render-guard` | Org-mode blob views and all blob previews, including previews forcing the renderer through request parameters. Other rendering paths, including automatic README rendering, remain outside coverage. |

The WordPress and Contact Form 7 rules use the directories confirmed in [WordPress's upgrader](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-admin/includes/class-wp-upgrader.php) and [Contact Form 7's upload implementation](https://github.com/rocklobster-in/contact-form-7/blob/v6.2.3/includes/file.php). They preserve ordinary admin update requests, form submissions and unrelated media retrieval. The [Contact Form 7 advisory](https://contactform7.com/2026/10/29/contact-form-7-624/) describes the affected upload behavior.

[GPUStack's advisory](https://github.com/gpustack/gpustack/security/advisories/GHSA-gj9m-f8ph-pmhr) distinguishes header spoofing from a loopback TCP peer. A header-only guard cannot repair the latter. This release deliberately makes no full authentication-bypass coverage claim.

[Rapid7's first-hand analysis](https://www.rapid7.com/blog/post/ra-gitlab-ci-cd-regex-integer-overflow-technical-analysis-cve-2026-97229/) identifies the project CI-lint trigger. [GitLab's detection guidance](https://gitlab.com/gitlab-security-oss/tldr/-/raw/main/Detections/platforms/GitLab/Vulnerability%20Detections/org_mode_render_error_burst.md) identifies blob rendering and preview renderer selection. Blocking these routes restricts legitimate CI linting, Org-mode viewing and editor previews. Follow the [GitLab patch guidance](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/), including the Ruby update for custom runtimes.

Paths are matched against Go's decoded URL path, with single-encoding, prefix, boundary and benign controls in each file. Repeated upstream decoding, path aliases, internal jobs and direct-origin access are outside this evidence. No exploit programs were executed and no live third-party endpoints were tested.

Following policies adopt a validated release atomically, including withdrawals. Pinned selections stay unchanged. Tests exercise the actual scheduler, policy history, two independently refreshed WAF instances, blocking and benign controls, Observe/Off/disabled behavior, rollback pinning, ETags and last-good retention on capacity failure. See [feed behavior and upgrade requirements](../rule-feeds.md).
