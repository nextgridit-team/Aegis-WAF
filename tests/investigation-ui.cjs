/* Activity investigation fixture: production bundle, stubbed API.
   Run BROWSER_EXECUTABLE=/opt/brave-bin/brave node tests/investigation-ui.cjs */
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
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const accessPages = [];
    const seenQueries = [];
    const row = (id, over = {}) => ({
      id,
      at: "2026-11-17T12:00:00Z",
      site_id: 2,
      method: "POST",
      status: 403,
      duration_ms: 4,
      peer: "198.51.100.7",
      blocked: true,
      request_id: "fix-" + id,
      rule_results: [],
      ...over,
    });
    await page.route("**/api/**", async (route) => {
      const url = new URL(route.request().url());
      const p = url.pathname;
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
        json = [
          { id: 2, name: "Portal", hostnames: ["portal.example.com"] },
          { id: 3, name: "Admin", hostnames: ["admin.example.com"] },
        ];
      if (p === "/api/certificates" || p === "/api/acme/accounts" || p === "/api/dns/credentials" || p === "/api/address-objects" || p === "/api/address-groups")
        json = [];
      if (p === "/api/jobs") json = [];
      if (p === "/api/audit") {
        seenQueries.push("audit" + url.search);
        json = {
          rows: [
            { id: 5, at: "2026-11-17T12:00:02Z", actor: "admin", action: "policy.saved", resource: "policy:7" },
          ],
          next_cursor: "",
        };
      }
      if (p === "/api/access-logs") {
        seenQueries.push("access" + url.search);
        const cursor = url.searchParams.get("cursor");
        const pageIndex = accessPages.length;
        accessPages.push(url.search);
        json = cursor
          ? {
              rows: [row(41, { peer: "203.0.113.50", status: 451 }), row(42, { peer: "203.0.113.51", status: 452 })],
              next_cursor: "",
            }
          : {
              rows: [row(11), row(12)],
              next_cursor: "Y3Vyc29yLXRva2Vu",
            };
      }
      await route.fulfill({ json });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/#activity`);
    // The investigation filter form renders for both sections.
    await page.locator("#access-filters").waitFor();
    await page.locator("#audit-filters").waitFor();
    await page.getByRole("heading", { name: "Application requests" }).first().waitFor();
    await page.getByText("198.51.100.7").first().waitFor();
    await page.getByText("policy.saved").waitFor();
    // Filters land in the URL and the request after Apply.
    await page.getByLabel("Application", { exact: true }).selectOption("2");
    await page.getByLabel("Decision", { exact: true }).selectOption("true");
    await page.getByLabel("Client IP / CIDR", { exact: true }).fill("198.51.100.0/24");
    await page.locator("#access-filters button[type=submit]").click();
    await page.waitForFunction(() => location.hash.includes("client_ip="));
    assert.match(
      decodeURIComponent(page.url()),
      /site_id=2/,
      "site filter must survive in the URL",
    );
    await page.waitForFunction(() => document.body.textContent.includes("198.51.100.7"));
    assert.ok(
      seenQueries.some((q) => q.includes("site_id=2") && q.includes("blocked=true") && q.includes("client_ip=198.51.100.0%2F24")),
      "filters must reach the API: " + JSON.stringify(seenQueries),
    );
    // Load more follows the cursor and appends without losing rows.
    await page.getByRole("button", { name: "Load more" }).click();
    await page.getByText("203.0.113.51").waitFor();
    assert.ok(page.getByText("198.51.100.7"), "first page rows must remain after load more");
    assert.ok(
      accessPages.some((q) => q.includes("cursor=Y3Vyc29yLXRva2Vu")),
      "load more must send the cursor: " + JSON.stringify(accessPages),
    );
    // URL state survives reload: the same filters are re-applied.
    await page.reload();
    await page.locator("#access-filters").waitFor();
    await page.waitForFunction(() => document.body.textContent.includes("198.51.100.7"));
    assert.equal(
      await page.getByLabel("Application", { exact: true }).inputValue(),
      "2",
      "site filter must be restored from the URL",
    );
    assert.equal(
      await page.getByLabel("Decision", { exact: true }).inputValue(),
      "true",
      "decision filter must be restored from the URL",
    );
    // The bounded export link carries the active filters.
    const exportHref = await page
      .getByRole("link", { name: "CSV" })
      .getAttribute("href");
    assert.match(exportHref, /site_id=2/, "export link carries filters");
    assert.match(exportHref, /access-logs\/export/, "export link targets the export route");
    // Clear resets the view.
    await page.locator('[data-activity-action="clear"]').first().click();
    await page.waitForFunction(() => location.hash === "#activity");
    assert.deepEqual(errors, []);
    console.log("investigation activity filters: PASS");
  } finally {
    await browser?.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
