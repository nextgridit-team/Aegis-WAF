/* Dashboard cost-of-protection panel fixture: production bundle, stubbed API.
   Run BROWSER_EXECUTABLE=/opt/brave-bin/brave node tests/endpoint-costs-ui.cjs */
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
    let costsOn = true;
    const report = {
      minutes: 15,
      site_id: 1,
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
    const costs = {
      site_id: 1,
      hours: 1,
      endpoints: [
        {
          path_class: "/api/items/{id}",
          requests: 1234,
          blocked: 12,
          forwarded: 1222,
          total_p50_ms: 12.5,
          total_p95_ms: 30.25,
          added_p50_ms: 0.5,
          added_p95_ms: 2.1,
          top_rules: [
            { rule_id: 4, group: "API guards", count: 9 },
            { rule_id: 7, count: 3 },
          ],
        },
      ],
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
          management_plaintext_non_loopback: false,
        };
      if (p === "/api/sites")
        json = [{ id: 1, name: "Cost fixture", hostnames: ["cost.example.com"] }];
      if (p === "/api/dashboard") json = report;
      if (p === "/api/protection-settings") json = [];
      if (p === "/api/endpoint-costs") json = costsOn ? costs : { site_id: 1, hours: 1, endpoints: [] };
      await route.fulfill({ json });
    });
    // With an application selected, the panel renders the aggregated row.
    await page.goto(
      `http://127.0.0.1:${server.address().port}/#dashboard?site_id=1`,
    );
    const panel = page.locator("section.dashboard-panel", {
      has: page.getByRole("heading", { name: "Cost of protection" }),
    });
    await panel.waitFor();
    await panel.getByText("/api/items/{id}").waitFor();
    await panel.getByText("1,234").waitFor();
    await panel.getByText("12", { exact: true }).waitFor();
    await panel.getByText("12.5 ms / 30.3 ms").waitFor();
    await panel.getByText("0.5 ms / 2.1 ms").waitFor();
    await panel.getByText("API guards ×9").waitFor();
    await panel
      .getByText(/folded into/)
      .waitFor();
    // With no endpoints recorded, the panel explains the empty state.
    costsOn = false;
    await page.reload();
    await page.getByRole("heading", { name: "Cost of protection" }).waitFor();
    await page
      .locator("section.dashboard-panel", {
        has: page.getByRole("heading", { name: "Cost of protection" }),
      })
      .getByText("No requests reached this application in the trailing hour.")
      .waitFor();
    assert.deepEqual(errors, []);
    console.log("endpoint costs panel: PASS");
  } finally {
    await browser?.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
