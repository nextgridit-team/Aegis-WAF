/* Run only against an isolated test deployment. This creates and deletes data.
   NODE_PATH must resolve Playwright; BROWSER_CREDENTIALS_FILE is a private JSON
   file containing {secret,password}. BROWSER_BASE_URL defaults to localhost. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { execFileSync } = require("node:child_process");
(async () => {
  const state = JSON.parse(
    fs.readFileSync(process.env.BROWSER_CREDENTIALS_FILE, "utf8"),
  );
  const base = process.env.BROWSER_BASE_URL || "http://127.0.0.1:19090";
  const out = process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-waf-browser";
  fs.mkdirSync(out, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-waf-browser-cert-"));
  const certificate = (host, name) => {
    const chain = path.join(tmp, name + ".pem"),
      key = path.join(tmp, name + ".key");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        key,
        "-out",
        chain,
        "-days",
        "90",
        "-subj",
        "/CN=" + host,
        "-addext",
        "subjectAltName=DNS:" + host,
        "-addext",
        "basicConstraints=critical,CA:FALSE",
      ],
      { stdio: "pipe" },
    );
    return {
      chain: fs.readFileSync(chain, "utf8"),
      key: fs.readFileSync(key, "utf8"),
    };
  };
  const valid = certificate("app.example.com", "valid"),
    wrong = certificate("wrong.example.com", "wrong");
  const upstream = http.createServer((req, res) => {
    res.end("browser verified upstream");
  });
  await new Promise((resolve) => upstream.listen(18081, "127.0.0.1", resolve));
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
      reducedMotion: "reduce",
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(base);
    await page
      .getByRole("heading", {
        name: /Create your administrator|Sign in to your gateway/,
      })
      .waitFor();
    if (
      await page
        .getByRole("heading", { name: "Create your administrator" })
        .count()
    ) {
      await page.screenshot({
        path: path.join(out, "setup-desktop.png"),
        fullPage: true,
      });
      await page
        .getByLabel("Bootstrap secret", { exact: true })
        .fill(state.secret);
      await page.getByLabel("Username", { exact: true }).fill("browser-admin");
      await page.getByLabel("Password", { exact: true }).fill(state.password);
      await page
        .getByRole("button", { name: "Create administrator", exact: true })
        .click();
    }
    await page
      .getByRole("heading", { name: "Sign in to your gateway" })
      .waitFor();
    await page.getByLabel("Username", { exact: true }).fill("browser-admin");
    await page.getByLabel("Password", { exact: true }).fill(state.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page
      .getByRole("heading", { name: "Your application edge" })
      .waitFor();
    const me = await (await page.request.get(base + "/api/me")).json();
    const headers = { "X-Requested-With": "aegis-waf", "X-CSRF-Token": me.csrf };
    for (const site of await (
      await page.request.get(base + "/api/sites")
    ).json()) {
      if (site.name === "Browser application")
        await page.request.delete(base + "/api/sites/" + site.id, { headers });
    }
    for (const cert of await (
      await page.request.get(base + "/api/certificates")
    ).json()) {
      if (cert.name === "Browser TLS")
        await page.request.delete(base + "/api/certificates/" + cert.id, {
          headers,
        });
    }
    await page.reload();
    await page
      .getByRole("heading", { name: "Your application edge" })
      .waitFor();
    await page.screenshot({
      path: path.join(out, "overview-desktop.png"),
      fullPage: true,
    });
    await page.getByRole("link", { name: "Certificates", exact: true }).click();
    await page
      .getByRole("button", { name: "Upload certificate", exact: true })
      .click();
    await page
      .getByLabel("Certificate name", { exact: true })
      .fill("Browser TLS");
    await page
      .getByLabel("PEM certificate chain", { exact: true })
      .fill(valid.chain);
    await page.getByLabel("PEM private key", { exact: true }).fill(valid.key);
    await page
      .locator("#upload-form")
      .getByRole("button", { name: "Upload certificate", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Certificate saved." })
      .waitFor();
    assert.equal(await page.locator("textarea").count(), 0);
    assert.ok(!(await page.content()).includes("BEGIN PRIVATE KEY"));
    await page
      .getByRole("link", { name: "Protected sites", exact: true })
      .click();
    await page.getByRole("button", { name: "Add site", exact: true }).click();
    await page
      .getByLabel("Application name", { exact: true })
      .fill("Browser application");
    await page.getByLabel("Hostnames", { exact: true }).fill("app.example.com");
    await page
      .getByLabel("Upstream URL", { exact: true })
      .fill("http://127.0.0.1:18081");
    await page
      .getByLabel("TLS certificate", { exact: true })
      .selectOption({ label: "Browser TLS · app.example.com" });
    await page.getByRole("button", { name: "Save site", exact: true }).click();
    await page.getByRole("status").filter({ hasText: "Site saved." }).waitFor();
    await page.reload();
    await page
      .locator("td")
      .filter({ hasText: "Browser application" })
      .first()
      .waitFor();
    await new Promise((resolve) => setTimeout(resolve, 2200));
    const response = await new Promise((resolve, reject) => {
      const r = http.get(
        process.env.BROWSER_PROXY_URL || "http://127.0.0.1:18080/",
        { headers: { Host: "app.example.com" } },
        (res) => {
          let body = "";
          res.on("data", (c) => (body += c));
          res.on("end", () => resolve({ status: res.statusCode, body }));
        },
      );
      r.on("error", reject);
    });
    assert.deepEqual(response, {
      status: 200,
      body: "browser verified upstream",
    });
    await page.screenshot({
      path: path.join(out, "sites-desktop.png"),
      fullPage: true,
    });
    await page.getByRole("link", { name: "Certificates", exact: true }).click();
    await page.getByRole("button", { name: "Replace", exact: true }).click();
    await page
      .getByLabel("PEM certificate chain", { exact: true })
      .fill(wrong.chain);
    await page.getByLabel("PEM private key", { exact: true }).fill(wrong.key);
    await page
      .getByRole("button", { name: "Replace certificate", exact: true })
      .click();
    await page
      .getByRole("alert")
      .filter({ hasText: "does not cover app.example.com" })
      .waitFor();
    assert.equal(
      await page.getByLabel("Certificate name", { exact: true }).inputValue(),
      "Browser TLS",
    );
    assert.equal(
      await page
        .getByLabel("PEM certificate chain", { exact: true })
        .inputValue(),
      wrong.chain,
    );
    await page.screenshot({
      path: path.join(out, "replacement-rejected.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await page
      .getByRole("link", { name: "ACME & renewal", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Request certificate", exact: true })
      .click();
    await page
      .getByRole("alert")
      .filter({ hasText: "Register an ACME account first" })
      .waitFor();
    await page
      .getByRole("button", { name: "Register account", exact: true })
      .click();
    await page
      .getByLabel("Account email", { exact: true })
      .fill("test@example.com");
    await page
      .locator("#account-form")
      .getByRole("button", { name: "Register account", exact: true })
      .click();
    await page
      .getByRole("alert")
      .filter({ hasText: "Explicit acceptance" })
      .waitFor();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    for (const width of [390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      for (const name of [
        "Overview",
        "Protected sites",
        "Certificates",
        "ACME & renewal",
        "Activity",
      ]) {
        await page.getByRole("link", { name, exact: true }).click();
        await page.waitForFunction(
          () => !document.querySelector("#view.loading"),
        );
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth > innerWidth,
          ),
          false,
          `${name} overflows at ${width}`,
        );
      }
      await page
        .getByRole("link", { name: "Protected sites", exact: true })
        .click();
      await page
        .getByRole("heading", { name: "Protected sites", exact: true })
        .waitFor();
      await page.screenshot({
        path: path.join(out, `sites-${width}.png`),
        fullPage: true,
      });
    }
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    await page.getByLabel("Enable routing", { exact: true }).uncheck();
    await page.getByRole("button", { name: "Save site", exact: true }).click();
    await page.getByRole("status").filter({ hasText: "Site saved." }).waitFor();
    await page.reload();
    await page.getByText("disabled", { exact: true }).waitFor();
    page.on("dialog", (d) => d.accept());
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("status").filter({ hasText: "Deleted." }).waitFor();
    await page.getByRole("link", { name: "Certificates", exact: true }).click();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("status").filter({ hasText: "Deleted." }).waitFor();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page
      .getByRole("heading", { name: "Sign in to your gateway" })
      .waitFor();
    assert.deepEqual(errors, []);
    console.log(
      "PASS: real setup/login, certificate upload, site persistence/routing, rejected replacement preserves input, CA acceptance guard, 15 responsive page checks, disable/delete/logout, no browser exceptions.",
    );
  } finally {
    await browser.close();
    await new Promise((resolve) => upstream.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
