# Community mitigation catalogue

This directory is the public Aegis workspace feed. `manifest.json` is a small index; each other JSON file defines one independently versioned rule. Rule packs are labels used for selecting related rules together, not executable plugins.

Rules are opt-in partial mitigations. They include compatibility risks and links to upstream advisories. Runtime patching remains necessary. See [operator workflow and coverage limits](../../docs/rule-feeds.md).

Anyone may submit a fork/PR or request a rule. Follow the [reviewed contribution workflow](../../docs/rule-contributions.md); tests do not replace maintainer approval.

## Add or update a rule

1. Copy an existing individual rule file. Use a stable unique ID and matching `<id>.json` filename. New rules start at revision 1; increment an existing rule's revision whenever its bytes change, including metadata or formatting.
2. Describe applicability, coverage, limitations and false positive risk honestly. Include CVEs, technology and public HTTPS primary advisory references. Do not imply full vulnerability coverage from a broad header guard.
3. Use the [bounded native rule format](../../docs/rules.md). The placeholder scope is replaced for assigned applications; the proposed action is Observe. Policy mode controls enforcement.
4. Include 2–16 regression cases with matching **and** nonmatching requests. Test normal traffic, case variants and near matches. These are harmless matcher inputs, not live exploit attempts.
5. Regenerate the manifest and run validation:

```sh
python3 scripts/build-rule-feed.py
python3 scripts/build-rule-feed.py --check
go test ./internal/app -run 'TestCommunityCatalogue|TestCatalogue'
```

The script reads individual JSON files, preserves a stable rule ordering and hashes their exact bytes. It increases the manifest revision when its generated entries change. Commit the rule file and regenerated manifest together. CI checks the manifest, increasing revisions and regression vectors. Maintainer review is required by the documented repository protection configuration. Aegis rejects downgraded revisions, mismatched checksums and changed content that reuses an already downloaded rule revision.

To publish elsewhere, host this directory over public HTTPS and subscribe to the manifest URL. Keep rule files beneath the manifest directory; this feed uses sibling JSON filenames. SHA-256 provides consistency with the manifest; it is not an independent publisher signature. Review the publisher and the actual rules before activation.
