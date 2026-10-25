/* API-intercepted UX tests. No external CA registration or DNS changes. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
(async () => {
  const assets = path.join(__dirname, "../internal/app/assets");
  const server = http.createServer((req, res) => {
    const name = req.url === "/" ? "index.html" : req.url.slice(1);
    if (!["index.html", "app.js", "style.css"].includes(name)) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.setHeader(
      "Content-Type",
      name.endsWith(".js")
        ? "text/javascript"
        : name.endsWith(".css")
          ? "text/css"
          : "text/html",
    );
    res.end(fs.readFileSync(path.join(assets, name)));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    for (const scenario of [
      "first request",
      "credential retry",
      "issuance retry",
      "saved setup",
      "registration recovery",
      "close during registration",
    ]) {
      const context = await browser.newContext();
      const page = await context.newPage();
      const errors = [];
      page.on("pageerror", (e) => errors.push(e.message));
      const calls = { account: [], credential: [], certificate: [] };
      let accounts =
        scenario === "saved setup"
          ? [
              {
                id: 1,
                directory: "https://acme-v02.api.letsencrypt.org/directory",
                email: "owner@example.test",
                tos_accepted_at: new Date().toISOString(),
              },
            ]
          : [];
      let credentials =
        scenario === "saved setup"
          ? [{ id: 2, name: "Saved Cloudflare", provider: "cloudflare" }]
          : [];
      let certificates = [];
      let failed = false;
      let releaseRegistration;
      await page.route("**/api/**", async (route) => {
        const request = route.request(),
          url = new URL(request.url());
        let data = [],
          status = 200;
        if (url.pathname === "/api/setup") data = { setup_required: false };
        if (url.pathname === "/api/me")
          data = { username: "test-admin", csrf: "test-csrf" };
        if (url.pathname === "/api/status")
          data = {
            configuration_version: 1,
            database_available: true,
            propagation_seconds: 2,
            dropped_access_logs: 0,
          };
        if (url.pathname === "/api/acme/directory")
          data = { terms_url: "https://example.test/terms" };
        if (url.pathname === "/api/acme/accounts") {
          if (request.method() === "POST") {
            const body = request.postDataJSON();
            calls.account.push(body);
            if (scenario === "close during registration")
              await new Promise((resolve) => {
                releaseRegistration = resolve;
              });
            accounts = [
              {
                id: 1,
                directory: "https://acme-v02.api.letsencrypt.org/directory",
                email: body.email,
                tos_accepted_at: new Date().toISOString(),
              },
            ];
            data = { id: 1 };
            status = 201;
            if (scenario === "registration recovery" && !failed) {
              failed = true;
              status = 503;
              data = { error: "Response lost after registration" };
            }
          } else data = accounts;
        }
        if (url.pathname === "/api/dns/credentials") {
          if (request.method() === "POST") {
            const body = request.postDataJSON();
            calls.credential.push(body);
            if (scenario === "credential retry" && !failed) {
              failed = true;
              status = 503;
              data = { error: "Temporary credential store failure" };
            } else {
              credentials = [
                { id: 2, name: body.name, provider: "cloudflare" },
              ];
              data = { id: 2 };
            }
          } else data = credentials;
        }
        if (
          url.pathname === "/api/acme/certificates" &&
          request.method() === "POST"
        ) {
          const body = request.postDataJSON();
          calls.certificate.push(body);
          if (scenario === "issuance retry" && !failed) {
            failed = true;
            status = 503;
            data = { error: "Temporary queue failure" };
          } else {
            data = { id: 3 };
            status = 202;
            certificates = [
              {
                id: 3,
                name: body.name,
                domains: body.domains,
                origin: "acme",
                validity: "pending",
                not_before: null,
                not_after: null,
                issuer: "",
                assigned_sites: [],
                account_id: 1,
                challenge_type: "dns-01",
              },
            ];
          }
        }
        if (url.pathname === "/api/certificates") data = certificates;
        await route.fulfill({ status, json: data });
      });
      await page.goto(base);
      await page
        .getByRole("heading", { name: "Certificates", exact: true })
        .waitFor();
      await page
        .getByRole("button", { name: "Request certificate", exact: true })
        .click();
      const dialog = page.getByRole("dialog");
      await dialog
        .getByRole("heading", { name: "Request a certificate", exact: true })
        .waitFor({ timeout: 5000 });
      await dialog
        .getByLabel("Domains", { exact: true })
        .fill("example.test, *.example.test");
      assert.equal(
        await dialog.locator("[name=challenge_type]").inputValue(),
        "dns-01",
      );
      assert.equal(
        await dialog
          .getByLabel("Certificate authority", { exact: true })
          .isVisible(),
        false,
      );
      assert.equal(
        await dialog.locator("[name=directory]").inputValue(),
        "production",
      );
      assert.equal(calls.account.length, 0);
      if (scenario !== "saved setup") {
        await dialog
          .getByLabel("Account email", { exact: true })
          .fill("owner@example.test");
        await dialog
          .getByLabel("Cloudflare API token", { exact: true })
          .fill("cloudflare_test_" + "t".repeat(32));
      } else {
        assert.equal(
          await dialog
            .getByLabel("Account email", { exact: true })
            .inputValue(),
          "owner@example.test",
        );
        assert.equal(
          await dialog
            .getByLabel("Account email", { exact: true })
            .getAttribute("readonly"),
          "",
        );
        assert.equal(
          await dialog
            .getByLabel("Cloudflare API token", { exact: true })
            .isVisible(),
          false,
        );
      }
      await page.waitForFunction(
        () => !document.querySelector("[name=accept_terms]").disabled,
      );
      await dialog
        .getByRole("button", { name: "Request certificate", exact: true })
        .click();
      assert.equal(
        calls.account.length +
          calls.credential.length +
          calls.certificate.length,
        0,
        "unchecked terms must prevent all setup side effects",
      );
      await dialog
        .getByLabel("I accept this authority’s terms of service.", {
          exact: true,
        })
        .check();
      if (scenario === "first request") {
        await dialog
          .getByLabel("Cloudflare API token", { exact: true })
          .fill("bad");
        await dialog
          .getByRole("button", { name: "Request certificate", exact: true })
          .click();
        await dialog.getByRole("alert").waitFor();
        assert.equal(
          calls.account.length,
          0,
          "invalid token syntax must not create an account",
        );
        await dialog
          .getByLabel("Cloudflare API token", { exact: true })
          .fill("cloudflare_test_" + "t".repeat(32));
        for (const width of [320, 390, 1440]) {
          await page.setViewportSize({ width, height: 900 });
          assert.equal(
            await page.evaluate(
              () => document.documentElement.scrollWidth > innerWidth,
            ),
            false,
          );
        }
        const artifacts =
          process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-onboarding-review";
        fs.mkdirSync(artifacts, { recursive: true });
        await page.screenshot({
          path: path.join(artifacts, "single-form.png"),
          fullPage: true,
        });
      }
      await dialog
        .getByRole("button", { name: "Request certificate", exact: true })
        .click();
      if (scenario === "close during registration") {
        for (let i = 0; !releaseRegistration && i < 100; i++)
          await page.waitForTimeout(10);
        assert.ok(releaseRegistration);
        await dialog
          .getByRole("button", { name: "Cancel", exact: true })
          .click();
        releaseRegistration();
        await page.waitForTimeout(600);
        assert.equal(calls.account.length, 1);
        assert.equal(calls.credential.length, 0);
        assert.equal(calls.certificate.length, 0);
        assert.deepEqual(errors, []);
        await context.close();
        console.log(
          "PASS: close during registration stops subsequent credential/issuance steps",
        );
        continue;
      }
      if (scenario === "credential retry" || scenario === "issuance retry") {
        await dialog.getByRole("alert").waitFor();
        assert.equal(
          await dialog.getByLabel("Domains", { exact: true }).inputValue(),
          "example.test, *.example.test",
        );
        assert.equal(
          await dialog
            .getByLabel("Account email", { exact: true })
            .inputValue(),
          "owner@example.test",
        );
        if (scenario === "issuance retry")
          assert.equal(
            await dialog
              .getByLabel("Cloudflare API token", { exact: true })
              .isVisible(),
            false,
            "confirmed credentials must be reused after a queue failure",
          );
        await dialog
          .getByRole("button", { name: "Request certificate", exact: true })
          .click();
      }
      await dialog.waitFor({ state: "detached" });
      assert.equal(
        calls.account.length,
        scenario === "saved setup" ? 0 : 1,
        "confirmed accounts must not be recreated on retry",
      );
      assert.equal(
        calls.credential.length,
        scenario === "saved setup"
          ? 0
          : scenario === "credential retry"
            ? 2
            : 1,
        "confirmed credentials must not be recreated on retry",
      );
      const certificate = calls.certificate.at(-1);
      assert.deepEqual(certificate.domains, ["example.test", "*.example.test"]);
      assert.equal(certificate.account_id, 1);
      assert.equal(certificate.dns_credential_id, 2);
      assert.equal(certificate.challenge_type, "dns-01");
      assert.equal(certificate.name, "example.test");
      assert.ok(!JSON.stringify(certificate).includes("cloudflare_test_"));
      assert.deepEqual(errors, []);
      await context.close();
      console.log("PASS: " + scenario);
    }
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
