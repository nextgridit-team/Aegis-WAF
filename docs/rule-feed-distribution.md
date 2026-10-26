# Packaged rule distribution

Authors and reviewers work on one JSON file per rule. Clients download a compact release descriptor and a compressed package of those files, then store individual entries in PostgreSQL. Discovery, delivery and policy activation are separate operations.

## What we took from established feeds

[Tenable's offline plugin distribution](https://docs.tenable.com/security-center/Content/OfflineNessusPluginUpdate.htm) uses a compressed plugin package. Its [custom plugin guide](https://docs.tenable.com/security-center/6_2/Content/manage-custom-plugins.htm) describes individual text plugins and feed metadata inside an archive. This separates small update metadata from the plugin corpus.

[Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running) keeps separate templates, checks for template releases, downloads updates and supports selection by directory, tags and other metadata. Its repository also contains generated checksum metadata. Individual source files support focused reviews; release distribution avoids asking operators to maintain a growing combined document.

Aegis follows that separation. It does not import or execute NASL plugins or Nuclei scanner templates.

## Release format and sync

`rules/community/release.json` contains schema version, feed name, increasing revision, package path, SHA-256, rule count and compressed size. It contains no per-rule listing. The current descriptor is 273 bytes for 95 rules; the package is approximately 123 KiB. Adding rules grows the archive and PostgreSQL catalogue, rather than a master list in the descriptor.

A sync checks the descriptor using its ETag. If changed, it downloads the one ZIP, verifies its size/hash, validates bounded ZIP directory records, and reads the individual rule files without extracting them. All metadata, matchers and embedded regression fixtures must pass before a single transaction updates the catalogue. A failed update leaves the last-good catalogue and policy snapshots intact. PostgreSQL coordinates workers across replicas; normal checks run every 12 hours or manually.

The authoring script discovers rule JSON recursively and generates the archive and descriptor. Reviewers see changes to the source rule plus generated artifacts. Run the [contribution checks](rule-contributions.md); never edit only the archive.

## Boundaries

The package is limited to 2000 rules, 8 MiB compressed and expanded, and 64 KiB per member. Duplicate IDs, unsafe paths, links, unknown file types and corrupt members are rejected. Only individual rule JSON and the documented license notices are accepted. The descriptor is capped at 4 KiB. Validation happens outside the forwarding path.

SHA-256 authenticates the archive against the downloaded descriptor, not an independent publisher identity. HTTPS and publisher trust still matter. Signed releases and differential packages are future work. Aegis downloads a complete changed package; it does not claim Tenable- or Nuclei-scale capacity. Catalogue capacity and execution budgets are separate: 100 effective policy rules and 1000 assigned rules globally remain enforced. Beyond those budgets, expand applicability/selection and capacity deliberately rather than enabling an unlimited corpus on every request.

Policy saves freeze the selected definitions and their provenance. Sync does not replace those copies; operators review and explicitly refresh policy snapshots. The shipped baseline includes all bundled rules on a fresh installation, while existing baseline selections remain unchanged.

## Existing installations

New binaries read schema 3 releases and legacy schema 2 custom manifests. Startup upgrades only the exact official workspace URL, preserving source identity and policy selections. Deleted subscriptions stay deleted. Upgrade replicas before relying on the new format; an older binary cannot parse it, but retains its last-good runtime snapshot. The official `manifest.json` is frozen for compatibility and is no longer the update channel. Custom v1 application imports remain supported separately.
