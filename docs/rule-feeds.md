# Rule source subscriptions

Open **Rule feeds**, choose **Add source**, enter a name and a public HTTPS URL, and choose an application. **Use Aegis starter feed** pre-fills this repository's small example feed. The first scheduled check runs within 30 seconds, then every 12 hours. **Sync now** starts a manual check. The page displays last success, next check, errors, available rules and pending imports.

Sync stores candidate signatures separately from live rules. **Review** shows each rule's JSON, whether it is pending/imported/removed, and its last imported local rule ID. **Import pending as drafts** creates application-scoped, disabled rules with a proposed Observe action. Open **Rules** to test, observe and explicitly activate them. Candidate updates never change or disable existing local rules. A changed candidate imports as a new draft; review it and disable any superseded rule yourself. Re-importing an unchanged candidate creates no duplicate. Deleting a source retains its previously imported rules.

A failed download or an invalid document preserves the previous successful candidates and imported rules. Updates are applied atomically. HTTP ETags avoid downloading unchanged documents. PostgreSQL advisory locks coordinate sync across replicas; there is no extra worker container or cache service. Failed checks show an error and schedule another check in 12 hours; manual retry is always available.

## Feed format

A public feed is a single JSON document, at most 1 MiB and 100 entries:

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "environment-file-probes",
      "rule": {
        "schema_version": 1,
        "name": "Environment file probes",
        "scope": { "site_id": 1 },
        "all": [ { "field": "path", "op": "equals", "value": "/.env" } ],
        "action": "observe",
        "ttl_seconds": 3600
      }
    }
  ]
}
```

Entry IDs are stable, unique names using 1–64 letters, digits, dots, underscores or hyphens. Rules use the existing [bounded declarative signature format](rules.md). Unknown fields, invalid expressions, malformed JSON, duplicate IDs and over-limit documents are rejected as a whole. The application scope is remapped to the selected local application. Remote evidence references are discarded and proposed action is normalized to Observe. Existing per-application and global rule capacities also apply to imports; an over-capacity import rolls back entirely.

This is an Aegis JSON feed, not a ModSecurity/CRS, Suricata, YARA, IP blocklist or arbitrary vendor format. Such sources need an explicit converter. There is no remote script execution or automatic activation. The repository's [starter feed](../rules/starter.json) is a small example, not a comprehensive curated WAF ruleset.

## URL and network constraints

Only public HTTPS on standard port 443 is supported. Credentials, query parameters and fragments are rejected. Redirects are not followed. The downloader validates DNS results for every new connection and connects to the validated IP while retaining hostname TLS verification, preventing private-target requests and DNS rebinding. Proxy environment variables cannot bypass these checks. Response sizes and download duration are bounded. Private-network feeds and authenticated feeds are not supported in this version. GitHub Contents API URLs are supported with GitHub’s raw-content media type; the starter feed uses this first-party endpoint so networks that block raw.githubusercontent.com can still use it without DNS-policy changes. GitHub rate limits still apply.

## API

- `GET /api/rule-feeds`, `POST /api/rule-feeds` (`name`, `url`, `site_id`)
- `GET /api/rule-feeds/{id}/items`
- `POST /api/rule-feeds/{id}/sync`
- `POST /api/rule-feeds/{id}/import`
- `DELETE /api/rule-feeds/{id}`

Administrator authentication and write CSRF checks apply. Source creation, successful sync, draft import and removal are audited without recording rule contents or remote credentials. At most 20 sources may be configured.
