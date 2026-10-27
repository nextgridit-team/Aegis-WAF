# README screenshots

The original front-page images listed in the first table are real browser screenshots from the isolated acceptance deployment, using application source revision `49f23edd0ff47e02486e8733431bd3c088303fd3` and synthetic traffic on 2026-10-25. They use example domains, a test-only administrator and disposable certificates. They contain no production traffic, real credentials or customer configuration. The captured interface supports light and dark modes; a button label describes the theme it switches to.

| README file                | Acceptance artifact            | Shown                                                |
| -------------------------- | ------------------------------ | ---------------------------------------------------- |
| `overview.png`             | `dashboard-1440.png`           | Traffic overview and system metrics, 1440px viewport |
| `certificates-current.png` | `certificates-dark.png`        | Uploaded and ACME-managed certificate inventory      |
| `signature-sets.png`       | `signature-set-loaded.png`     | Bundled CRS catalogue and explicitly loaded set      |
| `policies.png`             | `managed-signature-policy.png` | Custom group, CRS mode and application assignments   |

The overview is a viewport screenshot, so the dashboard's lower sections are below the frame. These images illustrate the interface, not attack coverage, benchmark performance or successful public-CA issuance.

## Regenerate

Build the application, install the browser-test dependencies and run the dedicated fixture from the repository root:

```sh
docker build -t aegis-waf:readme .
npm --prefix tests ci
(cd tests && npx playwright install chromium)
BROWSER_SCREENSHOT_FULL_PAGE=false BROWSER_ARTIFACT_DIR=/tmp/aegis-readme-shots \
  python3 tests/acme-browser.py aegis-waf:readme
```

Set `BROWSER_EXECUTABLE` if using an existing Chromium-compatible browser. The fixture creates temporary credentials, PostgreSQL, two app replicas, a Pebble test authority and an upstream; it removes its containers and data afterwards. Do not run acceptance fixtures against a real installation.

After a successful run, visually review the selected artifacts for relevance and accidental secrets, then copy them without editing the application content:

```sh
cp /tmp/aegis-readme-shots/dashboard-1440.png docs/screenshots/overview.png
cp /tmp/aegis-readme-shots/certificates-dark.png docs/screenshots/certificates-current.png
cp /tmp/aegis-readme-shots/signature-set-loaded.png docs/screenshots/signature-sets.png
cp /tmp/aegis-readme-shots/managed-signature-policy.png docs/screenshots/policies.png
```

Update the source revision/date above when refreshing them. Older screenshots in this directory remain available to the feature documents that link to them.

## Agent access, address objects and regional drill-down — 2026-10-25

`agent-access.png`, `address-objects.png` and `regional-map.png` were captured from the isolated acceptance deployment using local image `aegis-waf:agent-access-test` (`eb7b332cdfc1`), source included in the accompanying scoped-MCP/address-object change. The browser verified a real downloadable skill ZIP, object/group creation and scoped key creation. Only a non-secret synthetic key prefix appears. Regional UI counts use a synthetic US/Washington API fixture; MMDB enrichment and database sync are tested separately against the licensed small MaxMind test database. The images do not establish production City-dataset accuracy or external agent reasoning quality.

## Response provenance and live traffic — 2026-10-25

`response-status.png` and `live-traffic-map.png` come from the isolated final browser fixture (`aegis-waf:status-labels-test`, local image `9b2291f45ad3`, `/tmp/aegis-live-release`). The table includes real fixture upstream/WAF responses; the map animates actual allowed/blocked requests sent through the fixture. Private fixture clients use an explicitly logical unknown-location marker, not invented geographic positions. IP-object names and hostnames are synthetic. The live view also passed application filtering, pause/resume, reduced-motion behavior and four responsive widths.

`local-traffic-flow.png` is the `animated-local-flow.png` component capture from `tests/browser.cjs`, using isolated proxy hosts and observed test requests. It shows the host-only live diagram; no production traffic or credentials are used.

## System, metrics and selective CAPTCHA — 2026-10-25

`system.png` and `bot-challenge.png` come from `/tmp/aegis-platform-browser-final`, the passing isolated browser/Pebble acceptance fixture for source revision `4cc198dccedbb8cefce558ef58dc083750fcf07a`. System shows local/shared counter selection and authenticated metrics discovery. The challenge shows the self-hosted verification page for a suspicious fixture client; ordinary clients were also verified to pass without a challenge. The test database, keys, certificates and cookies were disposable, and the challenge has expired. No production settings or traffic are shown.

## Configurable alerts — 2026-10-26

`alerts.png` is `alerts-1440.png` from `/tmp/aegis-alerts-browser-final`, the passing isolated browser/Pebble fixture for the configurable-alerting change. It shows a real recorded fixture CRS block producing an application-scoped alert and an administrator acknowledgement. The fixture also created a signed automation destination, sent its explicit test and verified 390px/1440px layouts. Receiver URLs, signing secrets and production traffic are not shown. This verifies the Aegis workflow against an isolated HTTP receiver, not delivery to live Slack/Discord/other third-party accounts or execution by an external AI agent.

## Compact local traffic flow — 2026-10-26

`local-traffic-flow.png` was refreshed from `animated-local-flow.png` in `/tmp/aegis-local-flow-browser`, the passing isolated browser/Pebble fixture using `aegis-waf:local-flow-ux`. It shows the compact proxy-host pills and real fixture allowed/blocked pulses, replacing the earlier large-card capture. Search, pagination and 0/1/4/60/500-host extremes are separately tested with explicitly synthetic fixtures in `tests/local-flow-ui.cjs`, including light/dark themes, 320–1440px widths and 200% zoom. The published screenshot uses disposable example hosts and traffic, not production data.

## Policy-owned community mitigations — 2026-10-26

`rule-catalogue.png` is the unedited artifact from the passing `/tmp/aegis-policy-community-browser` acceptance run, captured on the policy-owned control implementation based on `68304f0`. It shows enable/disable, all/individual selection and per-rule coverage/compatibility in the actual policy editor with synthetic test data. The suite verifies selection persistence, existing groups/assignments and independent on/off enforcement on two replicas. It does not demonstrate complete CVE coverage or exploit prevention.

## Policy sensitivity and curated managed sets — 2026-10-26

`curated-set-builder.png`, `policy-sensitivity.png` and `policy-sensitivity-custom.png` are unedited captures from the passing `/tmp/aegis-policy-ux-review` browser/Pebble fixture, using tested local image `aegis-waf:policy-ux` (`123a691a0952`) built on base `307e336` with the accompanying policy UX changes before commit. Names, policies and traffic are synthetic. The suite verifies selection persistence, source provenance, Observe defaults, Custom/preset round-tripping, preservation of policy tuning and enforcement through two replicas. The builder selects SQL detector 942100 for demonstration; it is not a recommended full-protection baseline or proof of complete SQL injection coverage. These screenshots show the actual interface, not a mockup or production traffic.

## Guided policy editor — 2026-10-26

`policy-editor-traffic.png` is the unedited desktop capture from `tests/policy-editor-ui.cjs`, using the policy editor changes on base `7c07c36`. It uses synthetic policies, address objects and assignments; no production traffic or credentials. The fixture checks exact untouched saves (including custom thresholds and fractional KiB), keyboard-operated mode choices/scales, scoped-exception validation and rule selection limits, country/address/method choices, failed-save recovery, 320–1440px layouts, dark mode and 200% zoom. Run `BROWSER_EXECUTABLE=/path/to/chromium npm --prefix tests run test:policies` after building the dashboard. This fixture verifies UI behavior; real API/proxy enforcement is covered separately by the isolated two-replica acceptance suite.

## Contextual help and local glossary — 2026-10-26

`context-help.png` and `help-glossary.png` are unedited captures from the passing `tests/context-help-ui.cjs` fixture, built on base `7c07c36` with the accompanying uncommitted policy-editor and contextual-help changes. The policy, signature-set metadata and account are synthetic. No production settings, keys, certificates or request data appear. The fixture checks help in policy, proxy-host, certificate-upload and agent-key forms, Escape/focus behavior, light dismissal, unchanged values, no management writes, local documentation links, 320–1440px layouts, dark mode and an effective 200% layout using viewport/pixel-density emulation. The separate policy fixture verifies full save round trips. These captures show the real rendered interface, not a mockup.
