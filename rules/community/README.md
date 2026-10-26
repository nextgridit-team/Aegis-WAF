# Community mitigation catalogue

This directory is the public Aegis workspace feed. `release.json` is a small release descriptor pointing to `community-rules.zip`. Each source JSON file defines one independently versioned rule. The archive contains separate rule files, not one combined rule. Rule packs are labels used for selecting related rules together, not executable plugins.

Rules are partial mitigations selected in policies; the shipped baseline selects all bundled rules. They include compatibility risks and links to upstream advisories. Runtime patching remains necessary. See [operator workflow and coverage limits](../../docs/rule-feeds.md).

Anyone may submit a fork/PR or request a rule. Follow the [reviewed contribution workflow](../../docs/rule-contributions.md); tests do not replace maintainer approval.

## Add or update a rule

1. Copy an existing individual rule file. Use a stable unique ID and matching `<id>.json` filename. New rules start at revision 1; increment an existing rule's revision whenever its bytes change, including metadata or formatting.
2. Describe applicability, coverage, limitations and false positive risk honestly. Include CVEs, technology and public HTTPS primary advisory references. Do not imply full vulnerability coverage from a broad header guard.
3. Use the [bounded native rule format](../../docs/rules.md). The placeholder scope is replaced for assigned applications; the proposed action is Observe. Policy mode controls enforcement.
4. Include 2–16 regression cases with matching **and** nonmatching requests. Test normal traffic, case variants and near matches. These are harmless matcher inputs, not live exploit attempts.
5. Regenerate the package and release descriptor and run validation:

```sh
python3 scripts/build-rule-feed.py
python3 scripts/build-rule-feed.py --check
go test ./internal/app -run 'TestCommunityCatalogue|TestCatalogue'
```

The script discovers individual JSON files recursively, preserves their exact bytes, and generates an archive with stable ordering, timestamps and file modes. It increases the release revision when the package changes. Commit the rule file, `community-rules.zip` and `release.json` together; do not maintain a master rule list. CI validates source/package agreement, independent revisions and regression fixtures. Existing unchanged archives are reused so checks do not depend on the producer's zlib version.

For another host, publish `release.json` and `community-rules.zip` together over public HTTPS and subscribe to the release URL. Keep the relative archive path beneath the release directory. SHA-256 provides consistency, not an independent publisher signature. See [distribution and compatibility](../../docs/rule-feed-distribution.md). `manifest.json` is a frozen legacy v2 snapshot and must not be extended for new releases.
