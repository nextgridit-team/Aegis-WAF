# Maintaining project documentation

The root README is the landing page: explain who Aegis helps, what works, what it looks like and how to start. Keep operational reference material in linked guides. Screenshots, measured performance and clear limitations support the product description.

## Editorial basis

- [GitHub's README guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes) identifies the reader's main questions: purpose, usefulness, getting started, help and maintainers. It also documents relative links and heading navigation.
- [Google's README guidance](https://google.github.io/styleguide/docguide/READMEs.html) emphasizes a short summary, usage, project status, contacts and links to detailed documentation.
- [Diátaxis](https://diataxis.fr/) distinguishes tutorials, task instructions, reference and explanation. The docs index groups Aegis guides by reader task; a getting-started guide should not need to teach the entire architecture.

## Keep claims reviewable

1. Check feature claims against the current code and interface. Label proposals explicitly and keep them out of shipped-feature lists.
2. Link the canonical Compose file rather than maintaining a second copy. Check commands, prerequisites, listener defaults and browser setup against it and the bootstrap script.
3. State encryption scope precisely: application-encrypted private keys and credentials do not imply encrypted public certificate chains, all database columns or host disks.
4. Give benchmark conditions, source revision and raw measurements. Do not imply capacity or performance parity from unmatched workloads.
5. Use real application screenshots with provenance and synthetic fixtures. Do not expose production credentials or traffic, or present test-CA issuance as public-CA verification.
6. Preserve material limits, including per-replica flood budgets, bounded/optional response inspection, optional content evidence, best-effort telemetry and database recovery boundaries.
7. Check relative links, anchors and image paths after moving content. Preserve established root README anchors where practical.

A documentation-only edit needs relevant command, link and factual review. Runtime changes require the checks in the [development guide](development.md).
