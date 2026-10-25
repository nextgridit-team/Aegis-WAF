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
  const nav = (label) => label === "Rule feeds" ? { click: async () => { await nav("Rules").click(); await page.getByRole("navigation", {name: "Rule workspace"}).getByRole("link", {name: "Rule feeds", exact:true}).click(); } } :
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
  const httpsRequest = (port, host, ca, requestPath = "/", extraHeaders = {}) =>
    new Promise((resolve, reject) => {
      const req = https.get(
        {
          hostname: "127.0.0.1",
          port,
          servername: host,
          path: requestPath,
          headers: { Host: host, ...extraHeaders },
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
    await page.emulateMedia({ colorScheme: "dark" });
    await page.waitForFunction(
      () => document.documentElement.dataset.theme === "dark",
    );
    await screenshot("setup-dark");
    await page
      .getByRole("button", { name: "Switch color theme", exact: true })
      .click();
    assert.equal(
      await page.evaluate(() => document.documentElement.dataset.theme),
      "light",
    );
    await page.reload();
    await page
      .getByRole("heading", { name: "Set up your gateway", exact: true })
      .waitFor();
    assert.equal(
      await page.evaluate(() => document.documentElement.dataset.theme),
      "light",
    );

    await page
      .getByLabel("Bootstrap secret", { exact: true })
      .fill("  " + state.secret + "  ");
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
      .getByRole("heading", { name: "Dashboard", exact: true })
      .waitFor();
    await page
      .getByText("No traffic in this time range.", { exact: false })
      .waitFor();
    await screenshot("dashboard-empty");
    await nav("Certificates").click();
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
        .getByRole("heading", { name: "Request a certificate", exact: true })
        .waitFor();
      await dialog()
        .getByLabel("Domains", { exact: true })
        .fill("app.example.test");
      await dialog()
        .getByLabel("Account email", { exact: true })
        .fill("browser@example.test");
      await dialog().getByText("Advanced options", { exact: true }).click();
      await dialog()
        .getByLabel("Certificate authority", { exact: true })
        .selectOption("custom");
      await dialog()
        .getByLabel("Directory URL", { exact: true })
        .fill(process.env.BROWSER_ACME_DIRECTORY);
      await dialog()
        .getByLabel("Domain verification", { exact: true })
        .selectOption("http-01");
      await dialog()
        .getByRole("button", { name: "Reload terms", exact: true })
        .click();
      await page.waitForFunction(
        () => !document.querySelector("[name=accept_terms]").disabled,
      );
      await dialog()
        .getByLabel("Certificate name (optional)", { exact: true })
        .fill("Application TLS");
      await dialog()
        .getByLabel("My DNS and port 80 forwarding are ready.", { exact: true })
        .check();
      // The only submit provisions the account and queues issuance; terms stay explicit.
      await dialog()
        .getByRole("button", { name: "Request certificate", exact: true })
        .click();
      assert.equal(
        await dialog()
          .getByRole("heading", { name: "Request a certificate", exact: true })
          .count(),
        1,
      );
      await dialog()
        .getByLabel("I accept this authority’s terms of service.", {
          exact: true,
        })
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
      await dialog()
        .getByLabel("HTTP flood protection", { exact: true })
        .selectOption("observe");
      await dialog()
        .getByLabel("Requests / second per client", { exact: true })
        .fill("35");
      await dialog()
        .getByLabel("Client burst allowance", { exact: true })
        .fill("70");
      await dialog()
        .getByLabel("Anti-bot protection", { exact: true })
        .selectOption("observe");
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
    // Configure opt-in evidence, draft a rule, replay it, then enforce on both replicas.
    // Cloudflare credentials are managed in the browser; never returned by reads.
    await nav("Certificate authorities").click();
    await page
      .getByRole("heading", { name: "Certificate authorities", exact: true })
      .waitFor();
    await page
      .getByRole("button", { name: "Connect Cloudflare", exact: true })
      .click();
    await dialog()
      .getByLabel("Credential name", { exact: true })
      .fill("Cloudflare browser test");
    await dialog()
      .getByLabel("Cloudflare API token", { exact: true })
      .fill("invalid");
    await dialog()
      .getByRole("button", { name: "Save Cloudflare credential", exact: true })
      .click();
    await dialog().getByRole("alert").waitFor();
    const mockToken = "browser_test_" + "c".repeat(32);
    await dialog()
      .getByLabel("Cloudflare API token", { exact: true })
      .fill(mockToken);
    await dialog()
      .getByRole("button", { name: "Save Cloudflare credential", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    const dnsMetadata = await (
      await page.request.get(base + "/api/dns/credentials")
    ).text();
    assert.ok(!dnsMetadata.includes(mockToken));
    await nav("Certificates").click();
    await page
      .getByRole("button", { name: "Request certificate", exact: true })
      .click();
    assert.equal(
      await dialog().locator("[name=challenge_type]").inputValue(),
      "dns-01",
    );
    await dialog()
      .getByLabel("Cloudflare credential", { exact: true })
      .selectOption({ label: "Cloudflare browser test" });
    assert.equal(await dialog().locator("[name=dns_ready]").isEnabled(), false);
    await dialog()
      .getByLabel("Domains", { exact: true })
      .fill("*.example.test");
    await screenshot("cloudflare-dns-form");
    await dialog()
      .getByLabel("Cloudflare credential", { exact: true })
      .selectOption("new");
    await dialog()
      .getByLabel("Cloudflare API token", { exact: true })
      .fill(mockToken);
    assert.equal(
      await dialog().getByLabel("Domains", { exact: true }).inputValue(),
      "*.example.test",
    );
    await screenshot("cloudflare-single-form");
    await page.keyboard.press("Escape");
    await page
      .getByRole("button", { name: "Switch color theme", exact: true })
      .click();
    assert.notEqual(
      await page
        .locator(".inventory")
        .evaluate((el) => getComputedStyle(el).backgroundColor),
      "rgb(255, 255, 255)",
    );
    await screenshot("certificates-dark");
    await page.reload();
    await page
      .getByRole("heading", { name: "Certificates", exact: true })
      .waitFor();
    assert.equal(
      await page.evaluate(() => document.documentElement.dataset.theme),
      "dark",
    );
    await nav("Traffic").click();
    await page
      .getByRole("heading", { name: "Traffic evidence", exact: true })
      .waitFor();
    const captureRow = page
      .getByRole("region", { name: "Traffic capture settings", exact: true })
      .locator("tbody tr")
      .filter({ hasText: "Manual TLS" });
    await captureRow
      .getByRole("button", { name: "Configure", exact: true })
      .click();
    await dialog()
      .getByLabel("Enable bounded traffic sampling", { exact: true })
      .check();
    await dialog()
      .getByLabel("Capture paths with common token/identifier redaction", {
        exact: true,
      })
      .check();
    await dialog()
      .getByLabel("Query keys (up to four)", { exact: true })
      .fill("q");
    await dialog()
      .getByRole("button", { name: "Save capture settings", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page.waitForTimeout(2500);
    const ports = [
      process.env.BROWSER_HTTPS_PORT,
      process.env.BROWSER_ALT_HTTPS_PORT,
    ].filter(Boolean);
    for (const port of ports) {
      assert.equal(
        (
          await httpsRequest(
            port,
            "manual.example.test",
            null,
            "/.env?q=Bearer+private-sample&password=never-persist",
          )
        ).status,
        200,
      );
    }
    await page.waitForTimeout(1500);
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await page
      .getByRole("button", { name: "Inspect", exact: true })
      .first()
      .waitFor();
    await page
      .getByRole("button", { name: "Inspect", exact: true })
      .first()
      .click();
    const evidenceText = await dialog().textContent();
    assert.ok(evidenceText.includes("redacted"));
    assert.ok(
      !evidenceText.includes("private-sample") &&
        !evidenceText.includes("never-persist"),
    );
    await page.keyboard.press("Escape");
    await nav("Rules").click();
    await page.getByRole("heading", { name: "Rules", exact: true }).waitFor();
    await page
      .getByRole("button", { name: "Create rule", exact: true })
      .click();
    await dialog()
      .getByLabel("Rule name", { exact: true })
      .fill("Environment file probes");
    await dialog()
      .getByLabel("Proxy host", { exact: true })
      .selectOption({ label: "Manual TLS · manual.example.test" });
    await dialog().getByLabel("Value", { exact: true }).fill("/.env");
    await dialog()
      .getByLabel("Active lifetime (seconds)", { exact: true })
      .fill("60");
    await dialog()
      .getByRole("button", { name: "Save draft", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    const ruleRow = () =>
      page
        .getByRole("region", { name: "Rules", exact: true })
        .locator("tbody tr")
        .filter({ hasText: "Environment file probes" });
    await ruleRow().getByText("draft", { exact: true }).waitFor();
    assert.equal(
      (await httpsRequest(ports[0], "manual.example.test", null, "/.env"))
        .status,
      200,
    );
    await ruleRow()
      .getByRole("button", { name: "Observe", exact: true })
      .click();
    await ruleRow().getByText("observe", { exact: true }).waitFor();
    await page.waitForTimeout(2500);
    for (const port of ports)
      assert.equal(
        (await httpsRequest(port, "manual.example.test", null, "/.env")).status,
        200,
      );
    await ruleRow().getByRole("button", { name: "Test", exact: true }).click();
    await dialog()
      .getByRole("button", { name: "Evaluate locally", exact: true })
      .click();
    await dialog()
      .getByRole("status")
      .filter({ hasText: "No live requests sent" })
      .waitFor();
    assert.ok(
      (await dialog().getByRole("status").textContent()).includes("0 unknown"),
    );
    await page.keyboard.press("Escape");
    await ruleRow()
      .getByRole("button", { name: "Details", exact: true })
      .click();
    page.once("dialog", (d) => d.accept());
    await dialog()
      .getByRole("button", { name: "Enforce blocking", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    for (const port of ports)
      await eventually(async () =>
        assert.equal(
          (await httpsRequest(port, "manual.example.test", null, "/.env"))
            .status,
          403,
        ),
      );
    for (const port of ports)
      assert.equal(
        (await httpsRequest(port, "manual.example.test", null, "/safe")).status,
        200,
      );
    await screenshot("rules-desktop");
    await ruleRow()
      .getByRole("button", { name: "Disable", exact: true })
      .click();
    for (const port of ports)
      await eventually(async () =>
        assert.equal(
          (await httpsRequest(port, "manual.example.test", null, "/.env"))
            .status,
          200,
        ),
      );
    await ruleRow()
      .getByRole("button", { name: "Details", exact: true })
      .click();
    await dialog()
      .getByRole("button", { name: "Rollback previous", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    for (const port of ports)
      await eventually(async () =>
        assert.equal(
          (await httpsRequest(port, "manual.example.test", null, "/.env"))
            .status,
          403,
        ),
      );
    await ruleRow()
      .getByRole("button", { name: "Details", exact: true })
      .click();
    await dialog()
      .getByRole("button", { name: "Edit draft", exact: true })
      .click();
    await dialog()
      .getByRole("button", { name: "Save draft", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await ruleRow().getByText("draft", { exact: true }).waitFor();
    for (const port of ports)
      await eventually(async () =>
        assert.equal(
          (await httpsRequest(port, "manual.example.test", null, "/.env"))
            .status,
          200,
        ),
      );
    // JSON proposals remain drafts; invalid input stays editable, exports round-trip.
    await ruleRow()
      .getByRole("button", { name: "Details", exact: true })
      .click();
    const downloaded = page.waitForEvent("download");
    await dialog()
      .getByRole("button", { name: "Export JSON", exact: true })
      .click();
    const download = await downloaded;
    const exported = JSON.parse(fs.readFileSync(await download.path(), "utf8"));
    assert.equal(exported.all[0].value, "/.env");
    await page.keyboard.press("Escape");
    await page
      .getByRole("button", { name: "Import JSON", exact: true })
      .click();
    await dialog().getByLabel("Rule JSON", { exact: true }).fill("{bad");
    await dialog()
      .getByRole("button", { name: "Import draft", exact: true })
      .click();
    await dialog()
      .getByRole("alert")
      .filter({ hasText: "not valid JSON" })
      .waitFor();
    assert.equal(
      await dialog().getByLabel("Rule JSON", { exact: true }).inputValue(),
      "{bad",
    );
    exported.name = "Imported <img src=x> probe draft";
    await dialog()
      .getByLabel("Rule JSON", { exact: true })
      .fill(JSON.stringify(exported));
    await dialog()
      .getByRole("button", { name: "Import draft", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page
      .getByRole("region", { name: "Rules", exact: true })
      .locator("tbody tr")
      .filter({ hasText: "Imported <img src=x> probe draft" })
      .getByText("draft", { exact: true })
      .waitFor();
    const importedRow = page
      .getByRole("region", { name: "Rules", exact: true })
      .locator("tbody tr")
      .filter({ hasText: exported.name });
    await importedRow
      .getByRole("button", { name: "Details", exact: true })
      .click();
    await dialog()
      .getByRole("heading", { name: exported.name, exact: true })
      .waitFor();
    assert.equal(await dialog().locator("img").count(), 0);
    await page.keyboard.press("Escape");
    await nav("Activity").click();
    await page
      .getByRole("region", { name: "Application requests", exact: true })
      .getByText(/#\d+ · observe · matched/)
      .first()
      .waitFor();
    // Dashboard and browser-managed protection operate on the real test proxy.
    await nav("Dashboard").click();
    await page
      .getByRole("heading", { name: "Incoming traffic", exact: true })
      .waitFor();
    await page
      .getByLabel("Application", { exact: true })
      .selectOption({ label: "Manual TLS" });
    await page.getByLabel("Time range", { exact: true }).selectOption("5");
    await page
      .getByRole("button", { name: "Protection settings", exact: true })
      .click();
    await dialog()
      .getByLabel("Application", { exact: true })
      .selectOption({ label: "Manual TLS" });
    await dialog()
      .getByLabel("Flood mode", { exact: true })
      .selectOption("observe");
    await dialog()
      .getByLabel("Bot mode", { exact: true })
      .selectOption("observe");
    await dialog()
      .getByRole("button", { name: "Save protection", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page
      .getByRole("status")
      .filter({ hasText: "Protection saved" })
      .waitFor();
    await page.waitForTimeout(2500);
    const botRequest = () =>
      new Promise((resolve, reject) => {
        const req = https.get(
          {
            hostname: "127.0.0.1",
            port: ports[0],
            servername: "manual.example.test",
            rejectUnauthorized: false,
            headers: {
              Host: "manual.example.test",
              "User-Agent": "sqlmap/test",
            },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode));
          },
        );
        req.on("error", reject);
      });
    assert.equal(await botRequest(), 200);
    await page
      .getByRole("button", { name: "Protection settings", exact: true })
      .click();
    await dialog()
      .getByLabel("Bot mode", { exact: true })
      .selectOption("block");
    await dialog()
      .getByRole("button", { name: "Save protection", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await eventually(async () => assert.equal(await botRequest(), 403));
    await page.locator("#dashboard-site").selectOption("");
    await page.waitForTimeout(4500);
    await page
      .getByRole("heading", { name: "Bot & flood signals", exact: true })
      .waitFor();
    await screenshot("dashboard-desktop");
    await page
      .getByRole("button", { name: "Switch color theme", exact: true })
      .click();
    await screenshot("dashboard-dark");
    await page
      .getByRole("button", { name: "Switch color theme", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Enable map locations", exact: true })
      .click();
    await dialog()
      .getByRole("heading", { name: "Enable country locations", exact: true })
      .waitFor();
    await dialog().getByRole("checkbox").check();
    await dialog()
      .getByRole("button", { name: "Download country database", exact: true })
      .click();
    await dialog().waitFor({ state: "detached", timeout: 90000 });
    await page
      .getByRole("button", { name: "Update database", exact: true })
      .waitFor();
    const dashboardReport = await (
      await page.request.get(base + "/api/dashboard")
    ).json();
    const peer = dashboardReport.recent[0].peer;
    await page
      .getByRole("button", { name: "Protection settings", exact: true })
      .click();
    await dialog()
      .getByLabel("Application", { exact: true })
      .selectOption({ label: "Manual TLS" });
    await dialog()
      .getByLabel("Trusted proxy CIDRs", { exact: true })
      .fill(peer + (peer.includes(":") ? "/128" : "/32"));
    await dialog()
      .getByRole("button", { name: "Save protection", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page.waitForTimeout(2500);
    assert.equal(
      (
        await httpsRequest(ports[0], "manual.example.test", null, "/", {
          "X-Forwarded-For": "8.8.8.8",
          "User-Agent": "ordinary-browser",
        })
      ).status,
      200,
    );
    await eventually(async () => {
      const report = await (
        await page.request.get(base + "/api/dashboard")
      ).json();
      assert.ok(
        report.countries.some((c) => c.country === "US" && c.requests > 0),
      );
    });
    await page.waitForTimeout(4500);
    await screenshot("dashboard-desktop");
    // App-scoped client-IP sources, component exemptions and custom headers.
    await page
      .getByRole("button", { name: "Protection settings", exact: true })
      .click();
    await dialog()
      .getByLabel("Application", { exact: true })
      .selectOption({ label: "Manual TLS" });
    await dialog()
      .getByLabel("Flood mode", { exact: true })
      .selectOption("block");
    await dialog()
      .getByLabel("Requests / second per client", { exact: true })
      .fill("1");
    await dialog()
      .getByLabel("Client burst allowance", { exact: true })
      .fill("1");
    await dialog()
      .getByLabel("Client IP header", { exact: true })
      .selectOption("x-real-ip");
    await dialog()
      .getByLabel("HTTP flood exempt IPs / CIDRs", { exact: true })
      .fill("8.8.8.8/32");
    await dialog()
      .getByLabel("Anti-bot exempt IPs / CIDRs", { exact: true })
      .fill("8.8.8.8/32");
    await dialog()
      .getByRole("button", { name: "Save protection", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await nav("Proxy hosts").click();
    const headerSite = () =>
      page.locator("#site-list tbody tr").filter({ hasText: "Manual TLS" });
    await headerSite()
      .getByRole("button", { name: "Edit", exact: true })
      .click();
    await dialog().getByText("Protection options", { exact: true }).click();
    assert.equal(
      await dialog()
        .getByLabel("Client IP header", { exact: true })
        .inputValue(),
      "x-real-ip",
    );
    assert.equal(
      await dialog()
        .getByLabel("HTTP flood exempt IPs / CIDRs", { exact: true })
        .inputValue(),
      "8.8.8.8/32",
    );
    await dialog().getByText("Proxy headers", { exact: true }).click();
    const addHeader = async (side, name, value, op = "set") => {
      await dialog()
        .getByRole("button", { name: `Add ${side} header`, exact: true })
        .click();
      const row = dialog()
        .locator(`[data-header-side="${side}"] [data-header-row]`)
        .last();
      await row
        .getByLabel(
          `${side === "request" ? "Request" : "Response"} header name`,
          { exact: true },
        )
        .fill(name);
      await row.getByRole("combobox").selectOption(op);
      if (op === "set") await row.getByRole("textbox").last().fill(value);
    };
    await addHeader("request", "X-Aegis-Test", "configured");
    await addHeader("request", "X-Strip-Me", "", "remove");
    await addHeader("response", "X-Aegis-Response", "protected");
    await addHeader("response", "Server", "", "remove");
    await addHeader("request", "x-aegis-test", "duplicate");
    await dialog()
      .getByRole("button", { name: "Save proxy host", exact: true })
      .click();
    await dialog()
      .getByRole("alert")
      .filter({ hasText: "unique name" })
      .waitFor();
    await dialog()
      .locator('[data-header-side="request"] [data-header-row]')
      .last()
      .getByRole("button")
      .click();
    await screenshot("proxy-header-settings");
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.equal(
        await dialog().evaluate((el) => el.scrollWidth > el.clientWidth),
        false,
        `header editor overflow ${width}`,
      );
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await dialog()
      .getByRole("button", { name: "Save proxy host", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page.waitForTimeout(2500);
    const headerProbe = (ip = "8.8.8.8", ua = "sqlmap/test") =>
      new Promise((resolve, reject) => {
        const req = https.get(
          {
            hostname: "127.0.0.1",
            port: ports[0],
            servername: "manual.example.test",
            rejectUnauthorized: false,
            headers: {
              Host: "manual.example.test",
              "X-Real-IP": ip,
              "X-Forwarded-For": "192.168.1.9",
              "X-Strip-Me": "remove-me",
              "User-Agent": ua,
            },
          },
          (res) => {
            res.resume();
            res.on("end", () =>
              resolve({ status: res.statusCode, headers: res.headers }),
            );
          },
        );
        req.on("error", reject);
      });
    for (let i = 0; i < 5; i++) {
      const result = await headerProbe();
      assert.equal(result.status, 200);
      assert.equal(result.headers["x-seen-client-ip"], "8.8.8.8");
      assert.equal(result.headers["x-seen-test-header"], "configured");
      assert.equal(result.headers["x-seen-stripped-header"], "");
      assert.equal(result.headers["x-aegis-response"], "protected");
      assert.equal(result.headers.server, undefined);
    }
    assert.equal(
      (await headerProbe("1.1.1.1", "ordinary-browser")).status,
      200,
    );
    const limited = await headerProbe("1.1.1.1", "ordinary-browser");
    assert.equal(limited.status, 429);
    assert.equal(limited.headers["x-aegis-response"], "protected");
    await headerSite()
      .getByRole("button", { name: "Edit", exact: true })
      .click();
    await dialog().getByText("Proxy headers", { exact: true }).click();
    await dialog()
      .getByLabel("Forward validated client headers to the upstream", {
        exact: true,
      })
      .uncheck();
    await dialog()
      .getByRole("button", { name: "Save proxy host", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page.waitForTimeout(2500);
    const noForward = await headerProbe();
    assert.equal(noForward.status, 200);
    assert.equal(noForward.headers["x-seen-client-ip"], "");
    assert.equal(noForward.headers["x-seen-test-header"], "configured");
    await nav("Dashboard").click();
    await page.waitForTimeout(4500);
    await page
      .getByText(/HTTP flood exempt/)
      .first()
      .waitFor();
    // First-party public feed: real download, candidate review and draft import.
    await nav("Rule feeds").click();
    await page
      .getByRole("button", { name: "Use Aegis starter feed", exact: true })
      .click();
    await dialog()
      .getByLabel("Application", { exact: true })
      .selectOption({ label: "Manual TLS" });
    await dialog()
      .getByRole("button", { name: "Add source", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page.getByRole("button", { name: "Sync now", exact: true }).click();
    await page
      .getByText("3 pending import", { exact: true })
      .waitFor({ timeout: 45000 });
    await page.getByRole("button", { name: "Review", exact: true }).click();
    await dialog()
      .getByText("Exposed configuration probes", { exact: true })
      .waitFor();
    await dialog()
      .getByRole("button", { name: "Import pending as drafts", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page
      .getByRole("status")
      .filter({ hasText: "3 draft rules imported" })
      .waitFor();
    await screenshot("rule-feeds-live");
    // Discover a real local keyless provider without invoking inference.
    await nav("AI backend").click();
    await page.getByLabel("API base URL", {exact:true}).fill(upstream + "/v1");
    await page.getByLabel("No API key · clear any saved key", {exact:true}).check();
    await page.getByRole("button", {name:"Check connection & load models",exact:true}).click();
    await page.getByText("Connected · 1 models available. Select a model and save.", {exact:true}).waitFor();
    await page.getByLabel("Model", {exact:true}).selectOption("test-chat-model");
    await page.getByRole("button", {name:"Save provider",exact:true}).click();
    await message("AI provider saved").waitFor();
    await page.reload();
    await page.getByLabel("Model", {exact:true}).waitFor();
    assert.equal(await page.getByLabel("Model",{exact:true}).inputValue(),"test-chat-model");
    assert.equal(await page.getByLabel("API key",{exact:true}).inputValue(),"");
    await screenshot("ai-provider-configured");
    await nav("Policies").click();
    await page.getByRole("button",{name:"Create policy",exact:true}).click();
    await dialog().getByLabel("Policy name",{exact:true}).fill("External test policy");
    await dialog().getByLabel("Policy mode",{exact:true}).selectOption("block");
    await dialog().getByLabel("Enable anti-bot signals",{exact:true}).check();
    await dialog().getByRole("button",{name:"Add rule group",exact:true}).click();
    await dialog().getByLabel("Group name",{exact:true}).fill("Imported signatures");
    await dialog().getByRole("group",{name:"Group signatures",exact:true}).getByRole("checkbox").first().check();
    await dialog().getByRole("button",{name:"Add application",exact:true}).click();
    await dialog().getByLabel("Assignment application",{exact:true}).selectOption({label:"Manual TLS"});
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await page.getByRole("heading",{name:"Policies",exact:true}).waitFor();
    await screenshot("policies-assigned");
    await eventually(async()=>assert.equal((await httpsRequest(Number(process.env.BROWSER_HTTPS_PORT),"manual.example.test",null,"/",{"User-Agent":"sqlmap"})).status,403));
    await nav("Dashboard").click();
    const resources=page.locator("section").filter({has:page.getByRole("heading",{name:"System performance",exact:true})});
    await resources.waitFor();
    await resources.getByText("Per-replica resources",{exact:true}).click();
    await page.waitForTimeout(4500);
    assert.equal(await resources.locator("details").evaluate(el=>el.open),true,"resource details closed during refresh");
    assert.equal(await resources.locator("tbody tr").count(),2,"missing replica resource rows");
    assert.match(await resources.innerText(), /MiB|GiB/);
    await screenshot("system-performance");
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      for (const label of [
        "Dashboard",
        "Certificates",
        "Proxy hosts",
        "Activity",
        "Certificate authorities",
        "Rules",
        "Rule feeds",
        "Traffic",
        "Policies",
        "AI backend",
      ]) {
        await nav(label).click();
        await page
          .getByRole("heading", {
            name: label === "Traffic" ? "Traffic evidence" : label === "Rule feeds" ? "Rules" : label,
            exact: true,
          })
          .waitFor();
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth > innerWidth,
          ),
          false,
          `${label} overflows at ${width}`,
        );
      }
      await nav("Dashboard").click();
      await page
        .getByRole("heading", { name: "Incoming traffic", exact: true })
        .waitFor();
      await screenshot(`dashboard-${width}`);
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
      for (const label of ["Rules", "Traffic"]) {
        await nav(label).click();
        await page
          .getByRole("heading", {
            name: label === "Traffic" ? "Traffic evidence" : label === "Rule feeds" ? "Rules" : label,
            exact: true,
          })
          .waitFor();
        await screenshot(`${label.toLowerCase()}-${width}`);
      }
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
        "setup/login, PEM errors, form preservation, keyboard focus, rules draft/observe/block/disable/rollback, bounded redacted evidence, offline replay, 40 responsive checks, CPU/RAM replica telemetry, provider setup and policy assignment, traffic dashboard/app filters, real country download/lookup, and bot observe/block and logout.",
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
