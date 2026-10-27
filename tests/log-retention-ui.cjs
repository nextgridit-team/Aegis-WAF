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
      }),
      errors = [],
      writes = [];
    page.on("pageerror", (e) => errors.push(e.message));
    let fail = false,
      settings = {
        retention_hours: 6,
        revision: 1,
        last_cleanup_at: null,
        last_export_at: null,
        cleanup_error: "",
        export_error: "",
        access_deleted: 0,
        audit_deleted: 0,
        evidence_deleted: 0,
        pending_access_export: true,
        pending_audit_export: false,
        log_storage_bytes: 1048576,
        dropped_stdout_logs: 0,
        dropped_database_logs: 0,
      };
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        p = new URL(req.url()).pathname;
      let json = [];
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "test", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/rate-state")
        json = {
          settings: {
            backend: "memory",
            address: "",
            username: "",
            tls: false,
            timeout_ms: 100,
          },
          revision: 1,
          has_password: false,
          loaded_revision: 1,
          backend_failures: 0,
        };
      if (p === "/api/log-settings") {
        if (req.method() === "PUT") {
          writes.push(req.postDataJSON());
          if (fail)
            return route.fulfill({
              status: 409,
              json: { error: "log settings changed; reload before saving" },
            });
          assert.equal(req.postDataJSON().revision, settings.revision);
          settings = {
            ...settings,
            retention_hours: req.postDataJSON().retention_hours,
            revision: settings.revision + 1,
          };
        }
        json = settings;
      }
      await route.fulfill({ json });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/#system`);
    const form = () => page.locator("#log-settings-form");
    await form().waitFor();
    assert.equal(
      await form().getByLabel("Retention hours", { exact: true }).inputValue(),
      "6",
    );
    await page
      .getByText("Stored records pending; retained until exported", {
        exact: true,
      })
      .waitFor();
    await form()
      .getByLabel("Database log retention", { exact: true })
      .selectOption("24");
    assert.equal(
      await form().getByLabel("Retention hours", { exact: true }).inputValue(),
      "24",
    );
    await form()
      .getByRole("button", { name: "Save log retention", exact: true })
      .click();
    await page
      .getByText(
        "Log retention saved. Background cleanup removes eligible exported records.",
        { exact: true },
      )
      .waitFor();
    assert.deepEqual(writes[0], { retention_hours: 24, revision: 1 });
    const hours = () => form().getByLabel("Retention hours", { exact: true });
    await hours().fill("49");
    assert.equal(
      await form()
        .getByLabel("Database log retention", { exact: true })
        .inputValue(),
      "custom",
    );
    await hours().fill("0");
    await form()
      .getByRole("button", { name: "Save log retention", exact: true })
      .click();
    assert.equal(writes.length, 1);
    await hours().fill("49");
    fail = true;
    await form()
      .getByRole("button", { name: "Save log retention", exact: true })
      .click();
    await page
      .getByText("log settings changed; reload before saving", { exact: true })
      .waitFor();
    assert.equal(await hours().inputValue(), "49");
    settings = {
      ...settings,
      pending_access_export: false,
      last_export_at: new Date().toISOString(),
      export_error: "<img src=x onerror=alert(1)> sink unavailable",
    };
    await page
      .getByRole("button", { name: "Refresh logging status", exact: true })
      .click();
    await page.getByText("No stored backlog", { exact: true }).waitFor();
    assert.equal(await page.locator("#log-retention-status img").count(), 0);
    assert.equal(await hours().inputValue(), "49");
    for (const width of [390, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.ok(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
      );
      if (process.env.BROWSER_ARTIFACT_DIR) {
        fs.mkdirSync(process.env.BROWSER_ARTIFACT_DIR, { recursive: true });
        await page.screenshot({
          path: path.join(
            process.env.BROWSER_ARTIFACT_DIR,
            `logging-${width}.png`,
          ),
          fullPage: true,
        });
      }
    }
    assert.deepEqual(errors, []);
    console.log(
      "PASS: six-hour default, presets/custom values, revision save, validation, conflict preservation, status refresh, escaped errors and responsive layouts.",
    );
  } finally {
    if (browser) await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
