# Playbooks to use or adapt

Replace example IDs and ranges with discovered resources. Read the current contract before supplying a body. These are workflow templates, not standing authorization to alter production.

## Investigate a flagged or allowed request

1. Read the dashboard and latest access logs, identify the application and request ID.
2. With Evidence permission, call `get_request_details` for that ID. Separate the recorded policy/version and matches from any explicitly labeled current-library fallback.
3. Explain the rule/signature, decision, verified client identity, source-policy selection, exemptions and Geo decision. Quote only approved redacted facts.
4. If samples are unavailable, report the metadata and uncertainty. Do not silently enable broader collection or claim to have seen the raw request.

## Tune a false positive

1. Identify the exact detection IDs, affected paths/arguments and legitimate clients. Read current policy and assignments; record its revision and rollback target.
2. Propose a narrow scoped exclusion or custom-rule change. An example scoped exclusion is:

```json
{"rule_ids":[942100],"path_prefix":"/search","parameters":["q"],"client_cidrs":["192.168.10.0/24"]}
```

3. Confirm the combination matches operator intent: path and client predicates combine, and parameter targets exempt only those arguments for those IDs. This example is an exception entry, not a complete policy-update body.
4. For custom rules, replay retained suspicious and benign samples before activation. Missing facts produce unknown. For CRS settings, use approved isolated transaction tests; selected fact replay cannot reconstruct a full CRS transaction.
5. Apply the authorized change using the current revision and complete intended assignment list. Verify readback, observe subsequent traffic and retain rollback information.

## Propose a custom rule from evidence

Read `get_rule_schema`, inspect permitted retained samples, create a minimal application-scoped rule and call `propose_rule` with the RuleSpec as `input`. Example shape, using an actually discovered site ID:

```json
{"input":{"schema_version":1,"name":"Observe sensitive environment-file probes","scope":{"site_id":123},"all":[{"field":"path","op":"equals","value":"/.env"}],"action":"observe","ttl_seconds":900}}
```

Read the returned rule ID, replay the same definition with selected event IDs, review benign matches/unknowns, then activate under the playbook's authorization. A proposal is disabled. If the application uses a policy, its frozen rule groups determine enforcement; add the rule to the intended policy group rather than assuming standalone activation changes policy-bound traffic. Policy rule refresh is explicit; inspect the management contract before replacing frozen definitions.

## Add an application and certificate

1. Discover exact hostnames, approved upstream, certificate coverage, existing policies and proxy topology.
2. Choose an existing ACME account (account registration is console-only) and approved DNS credential, or upload operator-supplied PEM material using the certificate scope. Follow current issuance/upload payloads; never echo credentials. Poll jobs and inspect errors. Preserve existing valid certificates if issuance/renewal fails.
3. Create/update the application through `management_operation`. Validate hostname coverage, upstream reachability and intended HTTPS redirect behavior. Configure only known proxy source addresses and the sanitized client-IP header if behind a proxy.
4. Select a baseline or custom policy explicitly. Preserve intended application assignments. Add reusable address objects/groups for trust/exemptions only when authorized.
5. Verify certificate metadata and application readback, wait for propagation and run an approved benign HTTP/HTTPS check. Do not claim public DNS validation from local test results.

## Maintain feeds, Geo and network controls

Read feed candidate changes before import; a synced candidate is not automatically an active protection. Keep existing application scope and review the resulting rules/policies. For Geo sync, obtain the operator's license acceptance before setting `accept_license:true`; do not accept legal terms on their behalf without authorization. Queue sync, poll status, and retain previous valid data on errors. Country and optional City data are local lookups, not per-visitor API calls.

For CIDR controls, create one IP/subnet per object, group objects and reference them in the intended host/policy control. Keep explicit block precedence and the selected Geo-only/full-WAF allow behavior. Unknown location behavior must remain the operator's choice. Do not convert a flood exemption into a full bypass.

## Roll back an authorized change

Read current policy/rule history and current revision. Select the recorded target and call the discovered rollback operation with its required concurrency fields. Verify assignments as well as definitions; do not assume rollback recreates deleted address objects or reinstates application bindings. If a referenced object no longer exists, reconcile explicitly rather than applying a partial policy. Verify resulting logs/behavior and report the new revision.

## Autonomous-operation template

Record these in the operator's own playbook before autonomous enforcement:

- Applications/hostnames, permitted actions and maintenance windows.
- Evidence sharing destination, retained fields and lookback limits.
- Allowed scopes, change-rate budget, rule TTL bounds and maximum blast radius.
- Benign/attack replay criteria, handling of unknown facts and acceptance thresholds.
- Changes requiring human review, emergency stop and rollback triggers.
- Verification method, reporting destination and audit references.

Operate within that standing authorization without requesting approval repeatedly. Stop dependent mutations when a limit is exceeded or an essential fact is missing; present the concrete unresolved change. Aegis validates API contracts and key scopes; the agent/operator owns these additional automation limits.
