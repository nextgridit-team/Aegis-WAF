# README screenshots

The front-page images are real browser screenshots from the isolated acceptance deployment, using application source revision `49f23edd0ff47e02486e8733431bd3c088303fd3` and synthetic traffic on 2026-10-25. They use example domains, a test-only administrator and disposable certificates. They contain no production traffic, real credentials or customer configuration. The captured interface supports light and dark modes; a button label describes the theme it switches to.

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
