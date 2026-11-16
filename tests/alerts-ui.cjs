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
      created = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const channel = {
        id: 4,
        name: "Fixture receiver",
        provider: "automation",
        enabled: true,
        revision: 0,
        has_config: true,
      },
      rules = [
        {
          id: 1,
          revision: 1,
          name: "Fixture blocks",
          enabled: true,
          kind: "blocked_volume",
          site_id: 0,
          threshold: 10,
          window_minutes: 5,
          cooldown_minutes: 15,
          channel_ids: [4],
        },
      ],
      inbox = [
        {
          id: 7,
          rule_id: 1,
          at: "2026-11-16T12:00:00Z",
          kind: "inspection_saturation",
          site_id: 0,
          title: "Inspection pool exhausted",
          count: 64,
          window_start: "2026-11-16T11:55:00Z",
          window_end: "2026-11-16T12:00:00Z",
          acknowledged_at: null,
          acknowledged_by: "",
        },
      ];
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        p = new URL(req.url()).pathname;
      let json = [];
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "test", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/notification-channels") json = [channel];
      if (p === "/api/alert-rules") {
        if (req.method() === "POST") {
          const body = req.postDataJSON();
          created.push(body);
          rules.push({
            id: 2,
            revision: 1,
            name: body.name,
            enabled: body.enabled,
            kind: body.kind,
            site_id: body.site_id,
            threshold: body.threshold,
            window_minutes: body.window_minutes,
            cooldown_minutes: body.cooldown_minutes,
            channel_ids: body.channel_ids,
          });
          json = { id: 2 };
        } else json = rules;
      }
      if (p === "/api/alerts") json = inbox;
      if (p === "/api/alert-deliveries") json = [];
      if (p === "/api/sites") json = [];
      await route.fulfill({ json });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/#alerts`);
    await page.getByRole("heading", { name: "Alerts", exact: true }).waitFor();
    // The inbox renders the saturation trigger with its human label.
    await page
      .locator("tbody tr")
      .filter({ hasText: "Inspection pool exhausted" })
      .getByText("Signature inspection saturation")
      .waitFor();
    await page.getByRole("button", { name: "Trigger rules", exact: true }).click();
    await page
      .getByRole("button", { name: "Add alert rule", exact: true })
      .click();
    const dialog = page.getByRole("dialog");
    await dialog.waitFor();
    // The editor offers the saturation trigger and explains its meaning.
    await dialog
      .getByLabel("Trigger", { exact: true })
      .selectOption("inspection_saturation");
    await dialog.getByText(/fail-open/).waitFor();
    await dialog.getByText(/503/).waitFor();
    await dialog.getByLabel("Name", { exact: true }).fill("Pool exhausted");
    await dialog.getByLabel("Fixture receiver", { exact: true }).check();
    await dialog
      .getByRole("button", { name: "Save alert rule", exact: true })
      .click();
    await dialog.waitFor({ state: "detached" });
    assert.equal(created.length, 1);
    assert.equal(created[0].kind, "inspection_saturation");
    assert.equal(created[0].name, "Pool exhausted");
    assert.deepEqual(created[0].channel_ids, [4]);
    assert.ok(created[0].enabled);
    // The rules table labels the new trigger for operators.
    await page
      .locator("tbody tr")
      .filter({ hasText: "Pool exhausted" })
      .getByText("Signature inspection saturation")
      .waitFor();
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
            `alerts-${width}.png`,
          ),
          fullPage: true,
        });
      }
    }
    assert.deepEqual(errors, []);
    console.log(
      "PASS: saturation trigger offered in the rule editor with fail-open/503 copy, saved kind, inbox and rules labels, responsive layouts.",
    );
  } finally {
    if (browser) await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
