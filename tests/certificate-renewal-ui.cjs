const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

(async () => {
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
    res.end(fs.readFileSync(file));
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
    const errors = [],
      writes = [];
    const acme = {
      id: 1,
      name: "Managed certificate",
      origin: "acme",
      domains: ["app.example.test"],
      issuer: "Test CA",
      not_before: "2026-10-01T00:00:00Z",
      not_after: "2026-12-30T00:00:00Z",
      validity: "valid",
      assigned_sites: [],
      challenge_type: "dns-01",
      renew_before_days: null,
      renewal_due_at: "2026-11-30T00:00:00Z",
    };
    const uploaded = {
      ...acme,
      id: 2,
      name: "Uploaded certificate",
      origin: "upload",
      renewal_due_at: null,
    };
    let fail = false;
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        p = new URL(req.url()).pathname;
      let json = [],
        status = 200;
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "admin", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/certificates") json = [acme, uploaded];
      if (p === "/api/acme/jobs")
        json = [
          {
            id: 1,
            certificate_id: 1,
            name: acme.name,
            status: "running",
            attempts: 1,
            orders: [],
            error: "",
          },
        ];
      if (req.method() !== "GET") {
        writes.push({ p, method: req.method(), body: req.postDataJSON() });
        assert.equal(p, "/api/certificates/1/renewal");
        assert.equal(req.method(), "PUT");
        if (fail) {
          status = 503;
          json = { error: "Database temporarily unavailable" };
        } else {
          acme.renew_before_days = req.postDataJSON().renew_before_days;
          acme.renewal_due_at = new Date(
            new Date(acme.not_after).getTime() -
              (acme.renew_before_days ?? 30) * 86400000,
          ).toISOString();
          json = { id: acme.id, renew_before_days: acme.renew_before_days };
        }
      }
      await route.fulfill({ status, json });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/#certificates`);
    const open = () =>
      page
        .getByRole("button", { name: "Managed certificate", exact: true })
        .click();
    const dialog = page.locator("#editor");
    const input = dialog.getByLabel("Automatic renewal window (days)");
    const save = dialog.getByRole("button", {
      name: "Save renewal window",
      exact: true,
    });
    await open();
    assert.equal(await input.inputValue(), "");
    assert.match(await dialog.innerText(), /Saved renewal window starts/);
    assert.equal(
      await dialog
        .getByRole("button", { name: "Renew now", exact: true })
        .isDisabled(),
      true,
    );
    assert.equal(
      await save.isEnabled(),
      true,
      "active jobs must not prevent editing future scheduling",
    );
    for (const value of ["0", "366", "1.5"]) {
      await input.fill(value);
      await save.click();
      assert.equal(await input.evaluate((el) => el.validity.valid), false);
      assert.equal(writes.length, 0);
    }
    await input.fill("14");
    fail = true;
    await save.click();
    await dialog
      .locator("#form-message")
      .filter({ hasText: "Database temporarily unavailable" })
      .waitFor();
    assert.equal(
      await input.inputValue(),
      "14",
      "failed saves must preserve the draft",
    );
    fail = false;
    await save.click();
    await page.waitForFunction(() => !document.querySelector("#editor").open);
    assert.deepEqual(writes.at(-1).body, { renew_before_days: 14 });
    assert.match(
      await page.locator("#certificate-list").innerText(),
      /14 days before expiry/,
    );
    await open();
    assert.equal(await input.inputValue(), "14");
    await input.fill("45");
    await dialog
      .getByRole("button", { name: "Close dialog", exact: true })
      .click();
    assert.equal(writes.length, 2, "closing must not save the draft");
    await open();
    assert.equal(await input.inputValue(), "14");
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.equal(
        await dialog.evaluate((el) => el.scrollWidth <= el.clientWidth + 1),
        true,
        `dialog overflow at ${width}`,
      );
    }
    await page.screenshot({ path: "/tmp/aegis-certificate-renewal.png" });
    await input.fill("");
    await save.click();
    await page.waitForFunction(() => !document.querySelector("#editor").open);
    assert.deepEqual(writes.at(-1).body, { renew_before_days: null });
    await open();
    assert.equal(await input.inputValue(), "");
    await dialog
      .getByRole("button", { name: "Close dialog", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Uploaded certificate", exact: true })
      .click();
    assert.equal(await input.count(), 0);
    assert.equal(await save.count(), 0);
    assert.equal(
      await dialog
        .getByRole("button", { name: "Replace PEM", exact: true })
        .count(),
      1,
    );
    assert.deepEqual(errors, []);
    console.log(
      "PASS: per-certificate renewal editing, defaults, validation, active-job behavior, failed-save preservation, cancellation, uploaded-certificate exclusion and responsive layout.",
    );
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
