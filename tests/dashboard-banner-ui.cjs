/* Dashboard management-plaintext banner fixture: production bundle, stubbed API.
   Run BROWSER_EXECUTABLE=/opt/brave-bin/brave node tests/dashboard-banner-ui.cjs */
const { chromium } = require("playwright");
const assert = require("node:assert/strict"),
  http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
(async () => {
  const server = http.createServer((req, res) => {
    const f = path.join(
      __dirname,
      "../internal/app/assets",
      req.url === "/" ? "index.html" : path.basename(req.url.split("?")[0]),
    );
    if (!fs.existsSync(f)) return res.writeHead(404).end();
    res.setHeader(
      "Content-Type",
      f.endsWith(".js")
        ? "application/javascript"
        : f.endsWith(".css")
          ? "text/css"
          : "text/html",
    );
    res.end(fs.readFileSync(f));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  let browser;
  try {
    browser = await chromium.launch({
      executablePath: process.env.BROWSER_EXECUTABLE,
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    let plaintext = true;
    const report = {
      minutes: 15,
      site_id: 0,
      connections: 0,
      inflight: 0,
      reporting_replicas: 1,
      geo_updated_at: null,
      dropped_logs: 0,
      totals: {
        requests: 0,
        blocked: 0,
        flagged: 0,
        exempt: 0,
        errors: 0,
        rps: 0,
        clients: 0,
        mean_duration_ms: 0,
      },
      series: [],
      countries: [],
      statuses: [],
      response_statuses: [],
      signals: [],
      recent: [],
    };
    await page.route("**/api/**", async (route) => {
      const p = new URL(route.request().url()).pathname;
      let json = [];
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "test", csrf: "fixture" };
      if (p === "/api/status")
        json = {
          database_available: true,
          configuration_version: 1,
          management_plaintext_non_loopback: plaintext,
        };
      if (p === "/api/sites") json = [];
      if (p === "/api/dashboard") json = report;
      await route.fulfill({ json });
    });
    // A plaintext non-loopback management bind renders the warning banner.
    await page.goto(`http://127.0.0.1:${server.address().port}/#dashboard`);
    await page.getByRole("heading", { name: "Dashboard", exact: true }).waitFor();
    const banner = page.getByRole("alert").filter({
      hasText: "Management connection is not encrypted.",
    });
    await banner.waitFor();
    await banner
      .getByText(/non-loopback address/)
      .waitFor();
    // A clean bind renders no banner at all.
    plaintext = false;
    await page.reload();
    await page.getByRole("heading", { name: "Dashboard", exact: true }).waitFor();
    await page.locator("#dashboard-data").waitFor();
    assert.equal(await page.getByRole("alert").count(), 0);
    assert.deepEqual(errors, []);
    console.log("dashboard banner: PASS");
  } finally {
    await browser?.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
