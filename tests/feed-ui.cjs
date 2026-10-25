const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const assets = path.join(__dirname, "../internal/app/assets");
  const server = http.createServer((req, res) => {
    const file =
      req.url === "/" ? "index.html" : path.basename(req.url.split("?")[0]);
    const target = path.join(assets, file);
    if (!fs.existsSync(target)) {
      res.writeHead(404).end();
      return;
    }
    res.setHeader(
      "Content-Type",
      file.endsWith(".js")
        ? "application/javascript"
        : file.endsWith(".css")
          ? "text/css"
          : "text/html",
    );
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    res.end(fs.readFileSync(target));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    let sources = [];
    let syncFails = true;
    let imported = 0;
    const requests = [];
    const spec = {
      schema_version: 1,
      name: "Configuration <img src=x onerror=alert(1)>",
      scope: { site_id: 1 },
      all: [{ field: "path", op: "equals", value: "/.env" }],
      action: "observe",
      ttl_seconds: 3600,
    };
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        url = new URL(req.url()),
        method = req.method();
      let json = [],
        status = 200;
      if (url.pathname === "/api/setup") json = { setup_required: false };
      if (url.pathname === "/api/me")
        json = { username: "feed-tester", csrf: "test-csrf" };
      if (url.pathname === "/api/status")
        json = {
          configuration_version: 1,
          database_available: true,
          propagation_seconds: 2,
          dropped_access_logs: 0,
        };
      if (url.pathname === "/api/sites")
        json = [
          {
            id: 1,
            name: "Example app",
            hostnames: ["example.test"],
            enabled: true,
          },
        ];
      if (url.pathname === "/api/rule-feeds") {
        if (method === "POST") {
          const body = req.postDataJSON();
          requests.push(body);
          sources = [
            {
              id: 1,
              ...body,
              last_attempt: null,
              last_success: null,
              next_sync: new Date().toISOString(),
              error: "",
              candidates: 0,
              pending: 0,
            },
          ];
          status = 201;
          json = { id: 1 };
        } else json = sources;
      }
      if (url.pathname === "/api/rule-feeds/1/sync") {
        if (syncFails) {
          status = 502;
          sources[0].error = "Feed is temporarily unavailable";
          json = { error: sources[0].error };
        } else {
          sources[0] = {
            ...sources[0],
            error: "",
            last_success: new Date().toISOString(),
            candidates: 1,
            pending: 1,
          };
          json = { synced: true };
        }
      }
      if (url.pathname === "/api/rule-feeds/1/items")
        json = [
          {
            entry_id: "config-probes",
            spec,
            available: true,
            rule_id: null,
            pending: true,
          },
        ];
      if (url.pathname === "/api/rule-feeds/1/import") {
        imported++;
        sources[0].pending = 0;
        json = { rule_ids: [42], enabled: false };
      }
      if (url.pathname === "/api/rule-feeds/1" && method === "DELETE") {
        sources = [];
        json = { deleted: true };
      }
      await route.fulfill({ status, json });
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.goto(base + "/#rule-feeds");
    await page
      .getByRole("heading", { name: "Rules", exact: true })
      .waitFor();
    await page
      .getByRole("button", { name: "Use Aegis starter feed", exact: true })
      .click();
    const dialog = page.getByRole("dialog");
    assert.equal(
      await dialog.getByLabel("Name", { exact: true }).inputValue(),
      "Aegis starter rules",
    );
    assert.ok(
      (
        await dialog.getByLabel("Feed URL", { exact: true }).inputValue()
      ).endsWith("/contents/rules/starter.json"),
    );
    await dialog
      .getByRole("button", { name: "Add source", exact: true })
      .click();
    await dialog.waitFor({ state: "detached" });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].site_id, 1);
    await page.getByRole("button", { name: "Sync now", exact: true }).click();
    await page
      .getByRole("alert")
      .filter({ hasText: "Feed is temporarily unavailable" })
      .waitFor();
    syncFails = false;
    await page.getByRole("button", { name: "Sync now", exact: true }).click();
    await page.getByText("1 pending import", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Review", exact: true }).click();
    await dialog.getByText(spec.name, { exact: true }).waitFor();
    assert.equal(await dialog.locator("img").count(), 0);
    await dialog.getByText("View rule JSON", { exact: true }).click();
    assert.ok(
      (await dialog.locator("pre").textContent()).includes("schema_version"),
    );
    await dialog
      .getByRole("button", { name: "Import pending as drafts", exact: true })
      .click();
    await dialog.waitFor({ state: "detached" });
    assert.equal(imported, 1);
    await page
      .getByRole("status")
      .filter({ hasText: "1 draft rules imported" })
      .waitFor();
    fs.mkdirSync("/tmp/aegis-dashboard-review", { recursive: true });
    await page.screenshot({
      path: "/tmp/aegis-dashboard-review/rule-feeds-desktop.png",
      fullPage: true,
    });
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth > innerWidth,
        ),
        false,
        `feed overflow ${width}`,
      );
    }
    page.once("dialog", (d) => d.accept());
    await page.getByRole("button", { name: "Remove", exact: true }).click();
    await page
      .getByRole("heading", { name: "No rule sources yet", exact: true })
      .waitFor();
    assert.deepEqual(errors, []);
    console.log(
      "PASS: rule source form, starter URL, sync failure/retry, escaped review JSON, draft imports, removal and 4 responsive layouts.",
    );
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
