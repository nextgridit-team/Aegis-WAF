/* Uses a dedicated test deployment. `python3 tests/acme-browser.py` provisions
   an isolated deployment and a real ACME test authority for the complete flow. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { execFileSync } = require("node:child_process");
(async () => {
  const state = JSON.parse(
    fs.readFileSync(process.env.BROWSER_CREDENTIALS_FILE, "utf8"),
  );
  const base = process.env.BROWSER_BASE_URL || "http://127.0.0.1:19090";
  const out = process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-ui-review";
  fs.mkdirSync(out, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-browser-cert-"));
  const upstream = process.env.BROWSER_UPSTREAM_URL || "http://upstream:8000";
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const exceptions = [];
  page.on("pageerror", (e) => exceptions.push(e.message));
  const screenshot = async (name) =>
    page.screenshot({ path: path.join(out, name + ".png"), fullPage: true });
  const message = (text) => page.getByRole("status").filter({ hasText: text });
  const dialog = () => page.getByRole("dialog");
  const nav = (label) =>
    page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link", { name: label, exact: true });
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
  const httpsRequest = (port, host, ca) =>
    new Promise((resolve, reject) => {
      const req = https.get(
        {
          hostname: "127.0.0.1",
          port,
          servername: host,
          path: "/",
          headers: { Host: host },
          ca,
          rejectUnauthorized: Boolean(ca),
        },
        (res) => {
          let body = "";
          const authorized = res.socket.authorized;
          res.on("data", (c) => (body += c));
          res.on("end", () =>
            resolve({ status: res.statusCode, body, authorized }),
          );
        },
      );
      req.on("error", reject);
    });
  const eventually = async (fn) => {
    let last;
    for (let i = 0; i < 30; i++) {
      try {
        return await fn();
      } catch (e) {
        last = e;
        await page.waitForTimeout(500);
      }
    }
    throw last;
  };
  try {
    await page.goto(base);
    await page.getByRole("heading", { name: "Set up your gateway" }).waitFor();
    await screenshot("setup-desktop");
    await page
      .getByLabel("Bootstrap secret", { exact: true })
      .fill(state.secret);
    await page.getByLabel("Username", { exact: true }).fill("browser-admin");
    await page.getByLabel("Password", { exact: true }).fill(state.password);
    await page
      .getByRole("button", { name: "Create administrator", exact: true })
      .click();
    await page.getByRole("heading", { name: "Welcome back" }).waitFor();
    await page.getByLabel("Username", { exact: true }).fill("browser-admin");
    await page.getByLabel("Password", { exact: true }).fill(state.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page
      .getByRole("heading", { name: "Certificates", exact: true })
      .waitFor();
    await page
      .getByRole("heading", { name: "Your first certificate starts here" })
      .waitFor();
    await screenshot("certificates-empty-desktop");
    // ACME-first onboarding creates the real account and then a real certificate.
    if (process.env.BROWSER_ACME_DIRECTORY) {
      await page
        .getByRole("button", { name: "Request certificate", exact: true })
        .click();
      await dialog()
        .getByRole("heading", { name: "Connect a certificate authority" })
        .waitFor();
      await dialog()
        .getByLabel("Certificate authority", { exact: true })
        .selectOption("custom");
      await dialog()
        .getByLabel("Directory URL", { exact: true })
        .fill(process.env.BROWSER_ACME_DIRECTORY);
      await dialog()
        .getByLabel("Account email", { exact: true })
        .fill("browser@example.test");
      await dialog()
        .getByRole("button", { name: "Reload terms", exact: true })
        .click();
      await dialog()
        .getByLabel("I accept this authority’s terms of service.", {
          exact: true,
        })
        .waitFor();
      await page.waitForFunction(
        () => !document.querySelector("[name=accept_terms]").disabled,
      );
      // Terms are never accepted implicitly.
      await dialog()
        .getByRole("button", { name: "Continue to domains", exact: true })
        .click();
      assert.equal(
        await dialog()
          .getByRole("heading", { name: "Connect a certificate authority" })
          .count(),
        1,
      );
      await dialog()
        .getByLabel("I accept this authority’s terms of service.", {
          exact: true,
        })
        .check();
      await screenshot("acme-authority");
      await dialog()
        .getByRole("button", { name: "Continue to domains", exact: true })
        .click();
      await dialog()
        .getByRole("heading", { name: "Request a certificate", exact: true })
        .waitFor();
      await dialog()
        .getByLabel("Domains", { exact: true })
        .fill("app.example.test");
      await dialog()
        .getByLabel("Certificate name (optional)", { exact: true })
        .fill("Application TLS");
      await dialog()
        .getByLabel("My DNS and port 80 forwarding are ready.", { exact: true })
        .check();
      await screenshot("acme-request");
      await dialog()
        .getByRole("button", { name: "Request certificate", exact: true })
        .click();
      await message("Certificate requested.").waitFor();
      const row = page
        .locator("#certificate-list tbody tr")
        .filter({ hasText: "Application TLS" });
      await row
        .locator(".badge")
        .filter({ hasText: "Valid" })
        .waitFor({ timeout: 120000 });
      await page
        .locator(".job-row")
        .filter({ hasText: "Application TLS" })
        .getByText("Issued", { exact: true })
        .waitFor();
      await screenshot("certificates-issued-desktop");
      await row
        .getByRole("button", { name: "Connect site", exact: true })
        .click();
      await dialog()
        .getByRole("heading", { name: "Connect an application" })
        .waitFor();
      assert.equal(
        await dialog().getByLabel("Domains", { exact: true }).inputValue(),
        "app.example.test",
      );
      await dialog().getByLabel("Upstream URL", { exact: true }).fill(upstream);
      await screenshot("connect-proxy");
      await dialog()
        .getByRole("button", { name: "Save proxy host", exact: true })
        .click();
      await message("Proxy host saved.").waitFor();
      await page.reload();
      await page
        .getByRole("heading", { name: "Proxy hosts", exact: true })
        .waitFor();
      const root = fs.readFileSync(process.env.BROWSER_ISSUER_ROOT, "utf8");
      for (const port of [
        process.env.BROWSER_HTTPS_PORT,
        process.env.BROWSER_ALT_HTTPS_PORT,
      ]) {
        if (!port) continue;
        await eventually(async () => {
          const response = await httpsRequest(port, "app.example.test", root);
          assert.deepEqual(response, {
            status: 200,
            body: "ACME verified application",
            authorized: true,
          });
        });
      }
      await screenshot("proxy-hosts-desktop");
    }
    // Upload and failed replacement preserve the working certificate and inputs.
    const valid = certificate("manual.example.test", "valid"),
      wrong = certificate("wrong.example.test", "wrong");
    await nav("Certificates").click();
    await page.getByRole("button", { name: "Upload PEM", exact: true }).click();
    await dialog()
      .getByLabel("Certificate name", { exact: true })
      .fill("Manual TLS");
    await dialog()
      .getByLabel("PEM certificate chain", { exact: true })
      .fill(valid.chain);
    await dialog()
      .getByLabel("PEM private key", { exact: true })
      .fill(valid.key);
    await dialog()
      .getByRole("button", { name: "Upload certificate", exact: true })
      .click();
    await message("Certificate saved.").waitFor();
    assert.ok(!(await page.content()).includes("BEGIN PRIVATE KEY"));
    let manual = page
      .locator("#certificate-list tbody tr")
      .filter({ hasText: "Manual TLS" });
    await manual
      .getByRole("button", { name: "Connect site", exact: true })
      .click();
    await dialog().getByLabel("Upstream URL", { exact: true }).fill(upstream);
    await dialog()
      .getByRole("button", { name: "Save proxy host", exact: true })
      .click();
    await message("Proxy host saved.").waitFor();
    await nav("Certificates").click();
    manual = page
      .locator("#certificate-list tbody tr")
      .filter({ hasText: "Manual TLS" });
    await manual.getByRole("button", { name: "Details", exact: true }).click();
    await dialog()
      .getByRole("button", { name: "Replace PEM", exact: true })
      .click();
    await dialog()
      .getByLabel("PEM certificate chain", { exact: true })
      .fill(wrong.chain);
    await dialog()
      .getByLabel("PEM private key", { exact: true })
      .fill(wrong.key);
    await dialog()
      .getByRole("button", { name: "Replace certificate", exact: true })
      .click();
    await dialog()
      .getByRole("alert")
      .filter({ hasText: "does not cover manual.example.test" })
      .waitFor();
    assert.equal(
      await dialog()
        .getByLabel("PEM certificate chain", { exact: true })
        .inputValue(),
      wrong.chain,
    );
    await page.keyboard.press("Escape");
    assert.equal(await dialog().count(), 0);
    // Keyboard focus and modal input must survive background status polling.
    const upload = page.getByRole("button", {
      name: "Upload PEM",
      exact: true,
    });
    await upload.focus();
    await upload.click();
    await dialog()
      .getByLabel("Certificate name", { exact: true })
      .fill("Keep my input");
    await page.waitForTimeout(4500);
    assert.equal(
      await dialog()
        .getByLabel("Certificate name", { exact: true })
        .inputValue(),
      "Keep my input",
    );
    await page.keyboard.press("Escape");
    assert.equal(
      await upload.evaluate((el) => el === document.activeElement),
      true,
    );
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      for (const label of [
        "Certificates",
        "Proxy hosts",
        "Activity",
        "Certificate authorities",
      ]) {
        await nav(label).click();
        await page.getByRole("heading", { name: label, exact: true }).waitFor();
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth > innerWidth,
          ),
          false,
          `${label} overflows at ${width}`,
        );
      }
      await nav("Certificates").click();
      await page
        .getByRole("heading", { name: "Certificates", exact: true })
        .waitFor();
      await screenshot(`certificates-${width}`);
      await nav("Proxy hosts").click();
      await page
        .getByRole("heading", { name: "Proxy hosts", exact: true })
        .waitFor();
      await screenshot(`proxy-hosts-${width}`);
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await nav("Certificates").click();
    await page
      .getByRole("heading", { name: "Certificates", exact: true })
      .waitFor();
    await screenshot("certificates-desktop");
    // A mutation failure keeps the form editable and does not claim success.
    await nav("Proxy hosts").click();
    const manualSite = page
      .locator("#site-list tbody tr")
      .filter({ hasText: "Manual TLS" });
    await manualSite.getByRole("button", { name: "Edit", exact: true }).click();
    await dialog()
      .getByLabel("Domains", { exact: true })
      .fill("uncovered.example.test");
    await dialog()
      .getByRole("button", { name: "Save proxy host", exact: true })
      .click();
    await dialog()
      .getByRole("alert")
      .filter({ hasText: "does not cover" })
      .waitFor();
    assert.equal(
      await dialog().getByLabel("Domains", { exact: true }).inputValue(),
      "uncovered.example.test",
    );
    await dialog().getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByRole("heading", { name: "Welcome back" }).waitFor();
    assert.deepEqual(exceptions, []);
    console.log(
      (process.env.BROWSER_ACME_DIRECTORY
        ? "PASS: guided ACME account/issuance, automatic updates, certificate-to-proxy handoff and trusted HTTPS through both replicas; "
        : "PASS (ACME integration skipped: no BROWSER_ACME_DIRECTORY): ") +
        "setup/login, PEM errors, form preservation, keyboard focus, 16 responsive checks and logout.",
    );
  } catch (error) {
    await screenshot("failure");
    throw error;
  } finally {
    await browser.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
