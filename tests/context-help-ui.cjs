const { chromium } = require("playwright");
const assert = require("node:assert/strict"),
  http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
const topics = require("../web/src/help-topics.json");
(async () => {
  const dir = process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-context-help";
  fs.mkdirSync(dir, { recursive: true });
  const server = http.createServer((req, res) => {
    const file = path.join(
      __dirname,
      "../internal/app/assets",
      req.url === "/" ? "index.html" : path.basename(req.url.split("?")[0]),
    );
    if (!fs.existsSync(file)) return res.writeHead(404).end();
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
    res.end(fs.readFileSync(file));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage({
        viewport: { width: 1440, height: 1000 },
      }),
      errors = [];
    let writes = 0;
    page.on("pageerror", (e) => errors.push(e.message));
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        p = new URL(req.url()).pathname;
      let json = [];
      if (req.method() !== "GET") writes++;
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "help-test", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/signature-sets")
        json = [
          {
            id: "fixture",
            name: "OWASP CRS",
            version: "4.30.0",
            rule_count: 627,
            digest: "a".repeat(64),
          },
        ];
      await route.fulfill({ json });
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.goto(base + "/#policies");
    await page
      .getByRole("button", { name: "Create policy", exact: true })
      .click();
    const editor = page.locator("#editor"),
      form = page.locator("#policy-form");
    await form.waitFor();
    const initial = await form.evaluate((f) => [...new FormData(f)]);
    const button = form.locator("[data-help-topic=policy]").first();
    await button.focus();
    await button.press("Enter");
    const popup = page.locator("#context-help");
    await popup.waitFor({ state: "visible" });
    assert.equal(await popup.evaluate((e) => e.matches(":popover-open")), true);
    assert.equal(
      await popup.getByRole("heading").innerText(),
      "Protection policy",
    );
    assert.match(await popup.locator("p").innerText(), /saved collection/);
    assert.equal(await button.getAttribute("aria-expanded"), "true");
    await page.screenshot({ path: path.join(dir, "policy-callout.png") });
    // Escape dismisses help, retains unsaved form and returns keyboard focus.
    await page.keyboard.press("Escape");
    assert.equal(await editor.evaluate((e) => e.open), true);
    assert.equal(
      await button.evaluate((e) => e === document.activeElement),
      true,
    );
    assert.equal(await button.getAttribute("aria-expanded"), "false");
    await button.click();
    await button.click();
    assert.equal(
      await popup.evaluate((e) => e.matches(":popover-open")),
      false,
    );
    await button.click();
    const opened = page.waitForEvent("popup");
    await popup
      .getByRole("link", { name: "Read detailed explanation" })
      .click();
    const guide = await opened;
    await guide.waitForLoadState();
    assert.equal(new URL(guide.url()).hash, "#policy");
    assert.equal(await guide.locator("article").count(), topics.length);
    for (const topic of topics) {
      assert.equal(await guide.locator("#" + topic.id).count(), 1);
      assert.ok(topic.summary.length > 20);
    }
    assert.equal(await guide.evaluate(() => window.opener === null), true);
    await guide.screenshot({ path: path.join(dir, "offline-glossary.png") });
    await guide.close();
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    // Help associated with a switch must not activate that switch or submit the form.
    await form.locator("[data-policy-jump=traffic]").click();
    const flood = form.getByRole("switch", {
      name: "Enable HTTP flood protection",
      exact: true,
    });
    const floodHelp = form
      .locator("[name=flood_enabled]")
      .locator("..")
      .locator("..")
      .getByRole("button", {
        name: "Explain HTTP flood protection",
        exact: true,
      });
    await floodHelp.click();
    assert.equal(await flood.isChecked(), false);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    // A closed disclosure stays closed when its help is opened.
    await form.locator("[data-policy-jump=signatures]").click();
    const exceptions = form.locator("[data-policy-exceptions]");
    assert.equal(await exceptions.evaluate((e) => e.open), false);
    await exceptions
      .locator("..")
      .getByRole("button", {
        name: "Explain Signature exceptions",
        exact: true,
      })
      .first()
      .click();
    assert.equal(await exceptions.evaluate((e) => e.open), false);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    assert.deepEqual(await form.evaluate((f) => [...new FormData(f)]), initial);
    assert.equal(await form.locator("label button").count(), 0);
    assert.equal(await form.locator("label[for] label").count(), 0);
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 950 });
      await form.locator("[data-policy-jump=basics]").click();
      await button.click();
      const bounds = await popup.boundingBox();
      assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width + 1);
      assert.equal(
        await popup.evaluate((e) => e.scrollWidth <= e.clientWidth + 1),
        true,
      );
      assert.equal(
        await editor.evaluate((e) => e.scrollWidth <= e.clientWidth + 1),
        true,
      );
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
        true,
      );
      await page.screenshot({ path: path.join(dir, `help-${width}.png`) });
      await popup.getByRole("button", { name: "Close", exact: true }).click();
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.evaluate(() => {
      document.documentElement.dataset.theme = "dark";
    });
    // Browser zoom reduces the effective CSS viewport and increases pixel density.
    // Use those layout metrics rather than CSS zoom, which moves native dialogs differently.
    await page.setViewportSize({width:720,height:500});
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: 720,
      height: 500,
      deviceScaleFactor: 2,
      mobile: false,
    });
    await form.locator("[data-policy-jump=basics]").click();
    await button.click();
    assert.equal(
      await popup.evaluate((e) => e.scrollWidth <= e.clientWidth + 1),
      true,
    );
    const zoomBounds = await popup.boundingBox();
    assert.ok(
      zoomBounds.x >= 0 &&
        zoomBounds.x + zoomBounds.width <= 721 &&
        zoomBounds.y >= 0 &&
        zoomBounds.y + zoomBounds.height <= 501,
      JSON.stringify(zoomBounds),
    );
    await page.screenshot({ path: path.join(dir, "help-dark-zoom.png") });
    await page.keyboard.press("Escape");
    await cdp.send("Emulation.clearDeviceMetricsOverride");
    await page.setViewportSize({ width: 1440, height: 1000 });
    await form.locator("[data-policy-jump=basics]").click();
    await button.click();
    await form.getByLabel("Policy name", { exact: true }).click();
    assert.equal(
      await popup.evaluate((e) => e.matches(":popover-open")),
      false,
    );
    // Async form rebuilds receive exactly one trigger per caption.
    await form.getByRole("button", { name: "Cancel", exact: true }).click();
    await page
      .getByRole("button", { name: "Create policy", exact: true })
      .click();
    await page
      .getByRole("dialog", { name: "Create policy", exact: true })
      .waitFor();
    assert.equal(await form.locator("[data-help-topic=policy]").count(), 1); // one section heading.
    await form.locator("[data-help-topic=policy]").first().click();
    await page.locator('#editor [aria-label="Close dialog"]').click();
    assert.equal(
      await popup.evaluate((e) => e.matches(":popover-open")),
      false,
    );
    // Reused callouts on other forms preserve their values and do not leak typed secrets.
    await page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link", { name: "Applications", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Add application", exact: true })
      .first()
      .click();
    const site = page.locator("#site-form");
    await site.waitFor();
    const siteValues = await site.evaluate((f) => [...new FormData(f)]);
    await site.locator('[data-help-topic="proxy-host"]').first().click();
    assert.match(await popup.locator("p").innerText(), /upstream/i);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    await site.locator('[data-help-topic="endpoint-type"]').first().click();
    assert.match(await popup.locator("p").innerText(), /streaming/i);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    await site.getByText("HTTPS security", { exact: true }).click();
    const hsts = site.locator('[name="hsts_enabled"]');
    await hsts
      .locator("..")
      .locator("..")
      .getByRole("button", {
        name: "Explain HSTS browser protection",
        exact: true,
      })
      .click();
    assert.equal(await hsts.isChecked(), false);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    assert.deepEqual(
      await site.evaluate((f) => [...new FormData(f)]),
      siteValues,
    );
    await site.getByRole("button", { name: "Cancel", exact: true }).click();
    await page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link", { name: "Certificates", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Upload PEM", exact: true })
      .first()
      .click();
    const upload = page.locator("#upload-form");
    await upload.waitFor();
    await upload
      .locator('[name="private_key_pem"]')
      .fill("PRIVATE FIXTURE VALUE MUST STAY IN FORM");
    await upload.locator('[data-help-topic="pem"]').last().click();
    assert.doesNotMatch(await popup.innerText(), /PRIVATE FIXTURE VALUE/);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    assert.equal(
      await upload.locator('[name="private_key_pem"]').inputValue(),
      "PRIVATE FIXTURE VALUE MUST STAY IN FORM",
    );
    await upload.getByRole("button", { name: "Cancel", exact: true }).click();
    await page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link", { name: "Agent access", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Create API key", exact: true })
      .click();
    const key = page.locator("#agent-key-form");
    await key.waitFor();
    const keyValues = await key.evaluate((f) => [...new FormData(f)]);
    await key.locator('[data-help-topic="api-scope"]').first().click();
    assert.match(await popup.locator("p").innerText(), /Scopes limit/);
    await popup.getByRole("button", { name: "Close", exact: true }).click();
    assert.deepEqual(
      await key.evaluate((f) => [...new FormData(f)]),
      keyValues,
    );
    assert.equal(writes, 0);
    assert.deepEqual(errors, []);
    console.log(
      "PASS: contextual help, keyboard/focus/Escape, modal and switch safety, unchanged form values, local glossary links, responsive/dark/zoom, async rebuilds, no API writes.",
    );
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
