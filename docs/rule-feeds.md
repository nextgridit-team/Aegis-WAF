# Rule catalogues and source subscriptions

Workspace catalogues share independently versioned rules across policies. Each rule remains an independently versioned JSON file. A small release descriptor points to a checksummed ZIP containing those files; there is no growing hand-maintained rule index. Administrators choose individual rules or packs; downloading updates never changes published protection automatically.

## Enable mitigations in a policy

1. Open **Policies → Edit → Community mitigations**.
2. Turn on **Enable community mitigations**, then check **All available mitigations** or select individual rules. Search by CVE or name and expand coverage/compatibility notes before enforcing.
3. Save the policy. Turning the switch off preserves its selection but disables all catalogue mitigations for that policy; turning it back on restores the selection. Policy Off/Observe/Block still governs enforcement.
4. To adopt downloaded revisions, check **Refresh selected mitigation snapshots** and save. An ordinary save preserves frozen definitions. Selecting all captures the currently available rules; later feed additions do not silently enable themselves.

The shipped **Baseline protection** policy enables every shipped community mitigation, alongside CRS. The reviewed initial rules are bundled into the application, so this does not depend on a successful first network sync. On upgrade, the baseline receives this field once if absent; its other settings and assignments are preserved. Subsequent administrator selections or disabling are never overwritten on restart. Custom policies start with community mitigations off.

**Review compatibility before assigning the baseline:** the current 95 rules include broad endpoint-containment guards that disable legitimate operations, plus multipart and Brotli upload guards. Select only compatible mitigations for each application. The [100-CVE research inventory](research/kev-20261026/README.md) distinguishes request patterns from containment options and records coverage limits. Existing policies retain their previously selected snapshots when new rules are downloaded.

**Rules → Rule feeds** manages subscription URLs, sync and read-only catalogue review. It does not apply rules to policies. The Aegis community subscription is provisioned once; deletion persists, and **Use Aegis community feed** can add it again. Removing the source retains published copies, including the baseline's copies.

The catalogue contains 93 KEV-researched rules covering request patterns or endpoint containment for 100 distinct CVEs, alongside the original Node.js Brotli and PHP multipart guards. These are **partial mitigations, not substitutes for vendor fixes**. Review coverage and false-positive notes in the policy picker; inclusion in KEV does not prove that a WAF can prevent every exploitation path.

Public subscription URL:

```text
https://api.github.com/repos/nextgridit-team/Aegis-WAF/contents/rules/community/release.json
```

![Community catalogue showing individual rule revisions, CVEs and compatibility risks](screenshots/rule-catalogue.png)

## Sync and policy updates

The first scheduled check runs within 30 seconds, then every 12 hours. **Sync now** checks immediately. PostgreSQL coordinates checks across replicas; no extra worker container is required. The page shows errors, last success and next check. Failed downloads, checksum failures, invalid rules, failed regression vectors and revision conflicts preserve the complete last successful catalogue. Checks use ETags when available.

Policies store frozen rule definitions and feed provenance: source, entry ID, revision, checksum, pack and CVEs. An ordinary policy edit preserves these copies. Review shows **Update available** beside policies using an older definition. In the policy editor, use **Refresh selected mitigation snapshots** to refresh the current community selection. **Refresh selected rule snapshots from the library** refreshes all selected library snapshots on save. Existing history/rollback retains its frozen definitions. Removed feed entries disappear from the available picker; existing policy copies keep working. Removing a source also retains published policy copies and legacy imported rules, but prevents refreshing them from that source.

A changed catalogue increments the configuration version to invalidate stale MCP simulation receipts; it does not replace live policy copies. Policy changes propagate through the usual two-second snapshot refresh. MCP agents must simulate the exact policy mutation before publishing it.

## Publish your own per-rule feed

Choose **Add source**, a name and public HTTPS URL, and **Workspace catalogue · all policies**. Publish `release.json` and its ZIP in the same directory. Authors keep separate rule JSON files in the repository; the generated archive carries them to clients. See the [authoring guide](../rules/community/README.md) and [distribution design](rule-feed-distribution.md).

```json
{
  "schema_version": 3,
  "name": "Example application guards",
  "revision": 1,
  "package": {
    "path": "community-rules.zip",
    "sha256": "<64 lowercase hexadecimal SHA-256 characters>",
    "rule_count": 95,
    "size_bytes": 126093
  }
}
```

The package has individual `rules/<id>.json` files, optionally organized into subdirectories. Supported license notices are `LICENSE` and `LICENSES/nuclei-templates.txt`. Aegis reads the archive in memory without extracting files or running scripts. IDs must be unique across directories. A changed release costs two HTTP requests: descriptor plus package. An unchanged ETag costs one.

Every rule file contains `schema_version: 1`, stable `id`, increasing `revision`, `pack`, `technology`, `cves`, `description`, `affected_versions`, `coverage`, `limitations`, `false_positive_risk`, public HTTPS `references`, a native declarative `rule`, and `tests`. Tests include at least one matching and one nonmatching case, with bounded method/path/headers/body and `expected_match`. All cases must pass before a sync commits. The download normalizes action to Observe, clears external evidence IDs and replaces the placeholder application scope when compiling into assigned policies. Policy mode determines enforcement.

Increment a rule's revision whenever its bytes change; run `python3 scripts/build-rule-feed.py` and commit the rule, generated ZIP and descriptor together. Lower revisions and changed bytes reusing an existing revision are rejected. IDs use 1–64 letters, digits, dots, underscores or hyphens. Package paths must be relative ZIP paths beneath the descriptor directory, without traversal or query parameters. Unknown fields and malformed documents are rejected.

Limits: 20 sources, 4 KiB descriptor, 2000 rules/package, 8 MiB compressed and expanded package, 64 KiB/member, 2000 stored catalogue entries, 2–16 regression cases/rule, 30-second overall download and 20-second individual requests. Removed entries still consume catalogue capacity until their source is removed. Policy execution remains separately bounded at 100 effective rules/policy and 1000 assigned rules globally; a larger catalogue does not raise those execution budgets. Full packages are downloaded when changed; delta updates are not implemented.

Checksums verify package bytes against the downloaded descriptor. **They are not publisher signatures**: trust the publisher and HTTPS source. This format carries bounded declarative signatures, never executable plugins or remote scripts. NASL, Nuclei, ModSecurity/CRS, Suricata, YARA and arbitrary vendor feeds need an explicit converter.

## Upgrade compatibility

Upgrade the application before using a schema 3 URL. The exact official workspace subscription is migrated from `manifest.json` to `release.json`, preserving its ID, name and pinned policy copies. Custom URLs and deleted subscriptions are preserved. New binaries retain custom version 2 manifest support (100 entries, 1 MiB manifest, one request/file). The official version 2 manifest is a frozen compatibility snapshot, not the ongoing update channel; older clients should upgrade. Runtime last-good configuration remains available if an older replica cannot read a new feed format.

## Legacy application feeds

The community catalogue is the single shipped source. The official starter shortcut is removed, and its old subscription is retired once on upgrade while retaining imported native rules and their state. The historical `rules/starter.json` document remains available for compatibility, but is not offered as a second built-in feed. Custom application-bound version 1 subscriptions continue working. Choose an application labelled **legacy v1** to use a single JSON document such as [rules/starter.json](../rules/starter.json). Review and **Import pending as drafts** creates disabled, application-scoped local rules with proposed Observe action. Changed candidates import as new drafts; unchanged imports create no duplicate. Older imported rules are not automatically replaced or disabled. These subscriptions do not populate the workspace catalogue.

## URL and network constraints

Public HTTPS on port 443 only. Credentials, query parameters, fragments and redirects are rejected. The downloader validates DNS results for every new connection and connects to the validated IP while retaining hostname TLS verification. Environment proxies cannot bypass these checks. Private-network and authenticated feeds are unsupported. GitHub Contents API URLs use GitHub's raw-content media type; public API rate limits still apply.

## API and permissions

- `GET /api/rule-feeds`, `POST /api/rule-feeds` (`name`, `url`, optional `site_id`; omit or use `0` for workspace, positive ID for legacy)
- `GET /api/rule-catalog`: available workspace rules and stable IDs for policy group selection
- `GET /api/rule-feeds/{id}/items`: definitions, metadata, availability and pinned-policy/update information
- `POST /api/rule-feeds/{id}/sync`, `DELETE /api/rule-feeds/{id}`
- `POST /api/rule-feeds/{id}/import`: legacy sources only
- Policy writes accept `spec.community_mitigations: {"enabled": true, "rule_ids": [catalogue_rule_id]}`. `refresh_rule_ids` targets snapshot updates; send the current policy revision and complete specification/assignments.

Administrator authentication and write CSRF checks apply. Source creation, successful sync, import and removal are audited without recording rule contents or credentials. MCP exposes the catalogue through the existing scoped management interface; it cannot bypass the required policy simulation gate. See [management API](management-api.md) and [agent access](agent-access.md).
