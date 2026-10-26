# Limitations review

Reviewed against release `ccdc48e` on 2026-10-26, including the real-PostgreSQL/Redis race suite, focused catalogue/MCP checks and two-replica browser/Pebble acceptance. This is a documentation and capability review, not a new independent penetration test. [Current limitations](limitations.md) contains the remaining operator-facing boundaries.

Most of the earlier feature gaps have been addressed. They should no longer be described as absent. Optional controls still need to be enabled, and their implementation does not remove their documented bounds.

## Completed improvements

| Earlier gap | Current implementation | Evidence / guide |
| --- | --- | --- |
| Only bespoke signatures | Coraza with bundled OWASP CRS, browsable signatures, policy assignment and exclusions | [Managed signatures](managed-signatures.md); `TestManagedSignaturesIntegration` |
| Request-only CRS and fixed oversized-body rejection | Optional response inspection and explicit reject/prefix actions for request/response bounds | [Body inspection](body-inspection.md); `TestManagedResponseSignatures`, `TestManagedRequestPartialAndBoundary` |
| Streaming endpoints could be buffered | Website/API/SSE profiles and immediate streaming with bounded overlapping response windows | [Streaming behavior](body-inspection.md#sse-and-streaming-api-profiles); `TestStreamingWindowDetectionAndPreservation`, `TestStreamingProfileIntegration` |
| Bot detection could only observe or block | Selective self-hosted image/audio CAPTCHA with expiring, scoped clearance across replicas | [Bot protection](bot-protection.md); `TestCaptchaSelectiveCrossReplicaAndBoundaries` |
| No coordinated rate budgets | Optional Redis/Dragonfly counters with bounded failure and recovery behavior | [Shared state](shared-rate-state.md); `TestSharedRateStateIntegration`, `TestSharedBotFrequencyAcrossReplicas` |
| AI could change live protection without a mandatory test | Exact-candidate MCP simulation with single-use, key/version-bound receipts; feed changes invalidate stale receipts | [Agent safety gate](agent-access.md#required-simulation-before-live-protection-changes); `TestSimulationIntegration`, `TestWorkspaceCatalogueIntegration` |
| No cold-start recovery during a database outage | Optional authenticated-encrypted snapshot cache with a maximum age | [Recovery snapshots](snapshot-cache.md); `TestSealedSnapshotCache`, `TestSnapshotCacheStartupBeforeDatabaseInitialization` |
| Configuration updates could disrupt open traffic | Compiled snapshots published with an atomic pointer swap; active requests retain admitted state | [Reload behavior](architecture.md#atomic-reload-and-active-connections); HTTP/2, WebSocket and streaming regression coverage |
| Request evidence lacked redaction controls | Capture allowlists, built-in sensitive-value controls and custom capture-time redaction patterns | [Evidence privacy](evidence-privacy.md); `TestCustomEvidenceRedactionBeforePersistence` |
| Background panic could terminate the proxy | Supervised loops contain/log panics and restart with backoff | [Worker behavior](logging.md); `TestWorkerPanicIsContainedAndRestarted` |
| No measured forwarding performance | Hot-path benchmarks and published end-to-end mean/p99 reports | [Benchmarks](benchmarks.md), [comparison limits](proxy-comparison.md); `benchmark_test.go` |
| No standard security telemetry | Structured JSON events, authenticated Prometheus counters/histograms, dashboard CPU/RAM metrics | [Logging](logging.md), [observability](observability.md); telemetry/privacy and metric regressions |
| No alerting or agent wake-up integration | Alert inbox, configurable triggers and notification destinations, signed automation webhook | [Alerts](alerts.md); `TestAlertingIntegration`, provider/signature fixtures |
| Shared rules required manual application-specific imports | Per-rule manifests/files, CVE search, pack selection, reusable policy groups and explicitly pinned updates | [Rule catalogues](rule-feeds.md); `TestWorkspaceCatalogueIntegration`, passing catalogue browser flow |
| No investigation of ordinary requests | Request-detail views for all recorded outcomes with retained evidence and matched policy/rule definitions | [Request investigation](request-investigation.md); `TestRequestDetailsAllOutcomesAndRetention` |

Detailed execution evidence and its scope are in [verification](verification.md). The current catalogue browser flow verified that applying a selected rule preserves an existing policy's assignments/groups and enforces on both replicas. Header-match tests demonstrate that behavior; they do not prove complete PHP/Node.js vulnerability mitigation. The shipped baseline now enables all bundled community mitigations; custom policies choose their own selection. Feed sync does not change existing frozen definitions.

## Remaining feature gaps

1. **Automatic access/audit retention.** These tables still grow unless an operator manages them. Evidence expiry and alert-inbox cleanup already exist but are separate. Add independent retention windows, bounded database-coordinated cleanup and progress/error reporting, with an explicit default that preserves existing data.
2. **Administrator MFA and recovery.** Add TOTP or WebAuthn with enrollment, recovery, one-use backup codes, rate limits and security audits. Neither MCP bearer keys nor CAPTCHA provides administrator MFA.
3. **Per-application/resource authority.** Current MCP scopes restrict management domains across the workspace; administrators do not have granular roles. Enforce any future resource scope consistently through direct APIs and generic MCP operations.
4. **Verified-bot identity.** Challenge clearance is available; authenticated crawler identity is not. Provider verification or bounded forward-confirmed reverse DNS would need an explicit trust/failure design.
5. **Online encryption-key rotation.** Ciphertexts have key identifiers, but there is no overlapping keyring and transactional resealing/recovery workflow. Changing one external key while old ciphertext remains is not rotation.

Automatic retention remains the strongest next operational improvement, followed by administrator MFA. Protocol-specific protections for AI/MCP traffic and upstream API-key brokerage are separate proposed capabilities, not implied by the existing API/SSE endpoint profiles.

## Boundaries to retain

These remain true even with the completed features above:

- Bounded inspection cannot inspect arbitrary payload sizes/protocols. Stream detection cannot recall delivered bytes, and unknown facts are not proof of safety.
- CAPTCHA does not establish permanent human identity or stop a saturated network uplink.
- Shared counters require an optional configured backend; local mode is deliberately per replica. Counter resets and backend failures need an operational plan.
- Asynchronous **access** logging is best effort. Transactional administrative audits have different semantics. Retention solves storage growth, not access-log loss.
- Default cold startup, authentication and several challenge operations require PostgreSQL. Optional sealed recovery can serve stale configuration only within its configured age. Database availability, backups and restore drills remain deployment responsibilities.
- Feed checksums bind rule files to a manifest, not to an independently signed publisher identity. Pinned revisions prevent silent policy changes; the current guards remain partial mitigations.
- Alerts can wake a configured external agent; the current stateless MCP connection itself is not an unsolicited notification channel.
- Published small-workload benchmarks quantify that workload. They do not establish universal latency, capacity or security equivalence with another WAF.
