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
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage({
        viewport: { width: 1440, height: 1000 },
      }),
      errors = [],
      probes = [],
      writes = [];
    let mode = "trust",
      release;
    page.on("pageerror", (e) => errors.push(e.message));
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        p = new URL(req.url()).pathname;
      let json = [];
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "test", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/upstreams/test") {
        probes.push(req.postDataJSON());
        if (mode === "slow") await new Promise((r) => (release = r));
        json =
          mode === "trust"
            ? {
                reachable: false,
                stage: "tls_trust",
                message: "Untrusted issuer. Add a trusted certificate.",
                duration_ms: 8,
                certificate: {
                  pem: "PUBLIC CERTIFICATE FIXTURE",
                  sha256: "a".repeat(64),
                  subject:
                    "CN=backend.example.test <img src=x onerror=alert(1)>",
                  issuer: "CN=Private CA",
                  not_after: "2030-01-01T00:00:00Z",
                  can_trust: true,
                },
                tls_verified: false,
              }
            : {
                reachable: true,
                stage: "http",
                message: "Connected; upstream returned an HTTP error.",
                status: 401,
                tls_verified: true,
                duration_ms: 9,
              };
      }
      if (p === "/api/sites" && req.method() === "POST") {
        writes.push(req.postDataJSON());
        json = { id: 1 };
      }
      await route.fulfill({ json });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/#proxy-hosts`);
    await page
      .getByRole("button", { name: "Add application", exact: true })
      .first()
      .click();
    const form = page.locator("#site-form"),
      status = form.locator("[data-upstream-test-result]");
    await form.waitFor();
    await form.getByLabel("Name", { exact: true }).fill("Private app");
    await form
      .getByLabel("Domains", { exact: true })
      .fill("private.example.test");
    await form
      .getByLabel("Upstream URL", { exact: true })
      .fill("https://192.0.2.3:8006");
    await form
      .getByRole("button", { name: "Test upstream", exact: true })
      .click();
    await status.filter({ hasText: "Untrusted issuer" }).waitFor();
    assert.equal(writes.length, 0);
    await form
      .getByLabel("Trust a private upstream certificate", { exact: true })
      .check();
    assert.equal(
      await form.locator("[name=upstream_trusted_certificates]").inputValue(),
      "PUBLIC CERTIFICATE FIXTURE",
    );
    assert.equal(
      await form.locator("[data-upstream-certificate] img").count(),
      0,
    );
    assert.match(
      await form.locator("[data-upstream-certificate]").innerText(),
      /SHA-256/,
    );
    assert.equal(probes[0].host_header, "private.example.test");
    await form.getByText("Upstream TLS", { exact: true }).click();
    await form
      .getByLabel("Trusted upstream certificates (PEM)", { exact: true })
      .fill("PUBLIC CERTIFICATE FIXTURE");
    await form
      .getByLabel("Upstream TLS server name", { exact: true })
      .fill("backend.example.test");
    await form
      .getByLabel("Trust a private upstream certificate", { exact: true })
      .check();
    mode = "success";
    await form
      .getByRole("button", { name: "Test upstream", exact: true })
      .click();
    await status.filter({ hasText: "HTTP 401" }).waitFor();
    assert.match(await status.innerText(), /TLS verified/);
    assert.equal(probes[1].upstream_tls.server_name, "backend.example.test");
    assert.equal(
      probes[1].upstream_tls.trusted_certificates_pem,
      "PUBLIC CERTIFICATE FIXTURE",
    );
    mode = "slow";
    await form
      .getByRole("button", { name: "Test upstream", exact: true })
      .click();
    await page.waitForFunction(
      () => document.querySelector("[data-test-upstream]").disabled,
    );
    await form
      .getByLabel("Upstream URL", { exact: true })
      .fill("https://changed.example.test");
    while (!release) await new Promise((r) => setTimeout(r, 5));
    release();
    await form
      .getByRole("button", { name: "Test upstream", exact: true })
      .waitFor({ state: "visible" });
    await page.waitForFunction(
      () => !document.querySelector("[data-test-upstream]").disabled,
    );
    assert.match(await status.innerText(), /Test again/);
    assert.equal(writes.length, 0);
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 950 });
      assert.equal(
        await page
          .locator("#editor")
          .evaluate((e) => e.scrollWidth <= e.clientWidth + 1),
        true,
        `dialog overflow ${width}`,
      );
    }
    await form
      .getByRole("button", { name: "Save application", exact: true })
      .click();
    await page.waitForFunction(() => !document.querySelector("#editor").open);
    assert.equal(writes.length, 1);
    assert.deepEqual(writes[0].upstream_tls, {
      server_name: "backend.example.test",
      trusted_certificates_pem: "PUBLIC CERTIFICATE FIXTURE",
    });
    assert.deepEqual(errors, []);
    console.log(
      "PASS: unsaved upstream diagnostics, TLS guidance, HTTP/TLS status distinction, stale-result rejection, unchanged settings until save, responsive form and saved trust payload.",
    );
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
