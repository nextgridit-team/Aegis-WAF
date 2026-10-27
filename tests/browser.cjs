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
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--host-resolver-rules=MAP manual.example.test 127.0.0.1"],
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const exceptions = [];
  page.on("pageerror", (e) => exceptions.push(e.message));
  const screenshot = async (name) =>
    page.screenshot({
      path: path.join(out, name + ".png"),
      fullPage: process.env.BROWSER_SCREENSHOT_FULL_PAGE !== "false",
    });
  const message = (text) => page.getByRole("status").filter({ hasText: text });
  const dialog = () => page.getByRole("dialog");
  const nav = (label) => (label === "Rule feeds" || label === "Signature sets") ? { click: async () => { await nav("Rules").click(); await page.getByRole("navigation", {name: "Rule workspace"}).getByRole("link", {name: label, exact:true}).click(); } } :
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
  const httpsRequest = (port, host, ca, requestPath = "/", extraHeaders = {}, includeHeaders = false) =>
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
            resolve({ status: res.statusCode, body, authorized, ...(includeHeaders ? {headers: res.headers} : {}) }),
          );
        },
      );
      req.on("error", reject);
    });
  const tlsFingerprint=(port,host,ca)=>new Promise((resolve,reject)=>{
    const socket=require('node:tls').connect({host:'127.0.0.1',port:Number(port),servername:host,ca,rejectUnauthorized:true},()=>{const fingerprint=socket.getPeerCertificate().fingerprint256;socket.end();resolve(fingerprint);});socket.on('error',reject);
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
      const rotationPorts=[process.env.BROWSER_HTTPS_PORT,process.env.BROWSER_ALT_HTTPS_PORT].filter(Boolean);
      const fingerprints=await Promise.all(rotationPorts.map(port=>tlsFingerprint(port,'app.example.test',root)));
      await nav('Certificates').click();
      const managedRow=page.locator('#certificate-list tbody tr').filter({hasText:'Application TLS'});
      await managedRow.getByRole('button',{name:'Details',exact:true}).click();
      await dialog().getByRole('button',{name:'Renew now',exact:true}).click();
      await message('Renewal queued.').waitFor();
      for(let index=0;index<rotationPorts.length;index++){
        // The existing certificate remains usable throughout queued reissuance.
        assert.equal((await httpsRequest(rotationPorts[index],'app.example.test',root)).status,200);
        await eventually(async()=>assert.notEqual(await tlsFingerprint(rotationPorts[index],'app.example.test',root),fingerprints[index]));
      }
      await nav('Proxy hosts').click();
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
    assert.equal(await dialog().getByRole('button',{name:'Renew now',exact:true}).count(),0,'uploaded certificates must not offer ACME renewal');
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
    await dialog().getByLabel("Additional redaction patterns (one regex per line)",{exact:true}).fill("private-sample");
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
    await dialog().getByText("Client identity, trusted proxies and exemptions", { exact: true }).click();
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

    await dialog().getByText("HTTPS security", { exact: true }).click();
    await dialog().getByLabel("Enforce HSTS", { exact: true }).check();
    await dialog().getByLabel("HSTS max age (seconds)", { exact: true }).fill("86400");
    await dialog().getByLabel("Include subdomains in HSTS", { exact: true }).check();
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
    assert.equal(await dialog().getByLabel("Enforce HSTS", { exact: true }).isChecked(), true);
    assert.equal(await dialog().getByLabel("HSTS max age (seconds)", { exact: true }).inputValue(), "86400");
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
    // Legacy custom-source compatibility: real download and draft import.
    await nav("Rule feeds").click();
    await page
      .getByRole("button", { name: "Add source", exact: true })
      .click();
    await dialog().getByLabel("Name", {exact:true}).fill("Aegis starter rules");
    await dialog().getByLabel("Feed URL", {exact:true}).fill("https://api.github.com/repos/nextgridit-team/Aegis-WAF/contents/rules/starter.json");
    await dialog()
      .getByLabel("Application", { exact: true })
      .selectOption({ label: "Manual TLS · legacy v1" });
    await dialog()
      .getByRole("button", { name: "Add source", exact: true })
      .click();
    await dialog().waitFor({ state: "detached" });
    await page.locator("tbody tr").filter({hasText:"Aegis starter rules"}).getByRole("button", { name: "Sync now", exact: true }).click();
    await page
      .getByText("3 pending import", { exact: true })
      .waitFor({ timeout: 45000 });
    await page.locator("tbody tr").filter({hasText:"Aegis starter rules"}).getByRole("button", { name: "Review", exact: true }).click();
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
    await nav("Signature sets").click();
    await page.getByRole("region",{name:"Available signature sets",exact:true}).getByRole("button",{name:"View signatures",exact:true}).click();
    await dialog().getByLabel("Search signatures",{exact:true}).fill("942100");
    await dialog().getByRole("region",{name:"Signature inventory",exact:true}).getByText(/SQL Injection Attack Detected/i).waitFor();
    await dialog().getByLabel("Search signatures",{exact:true}).fill("");
    await dialog().getByRole("button",{name:"Next",exact:true}).click();
    await dialog().getByText(/Page 2 of/).waitFor();
    await dialog().getByRole("button",{name:"Previous",exact:true}).click();
    await dialog().getByLabel("Entry type",{exact:true}).selectOption("response");
    assert.ok(await dialog().getByRole("region",{name:"Signature inventory",exact:true}).getByText("Response · optional",{exact:true}).count());
    await dialog().getByLabel("Entry type",{exact:true}).selectOption("request");
    for(const width of [320,390,768,1440]){
      await page.setViewportSize({width,height:1000});
      assert.ok(await dialog().evaluate(el=>el.scrollWidth<=el.clientWidth+1),"signature browser overflows dialog");
      await dialog().evaluate(el=>{el.scrollTop=0});
      await screenshot("signature-browser-"+width);
    }
    await dialog().getByRole("button",{name:"Close",exact:true}).click();

    await page.getByRole("region",{name:"Loaded signature sets",exact:true}).getByText("OWASP Core Rule Set",{exact:true}).waitFor();
    assert.equal(await page.getByRole("navigation",{name:"Rule workspace",exact:true}).evaluate(el=>getComputedStyle(el).flexDirection),"row","rule workspace tabs should stay horizontal");
    await screenshot("signature-set-loaded");
    // Address objects and MCP access are managed entirely in the dashboard.
    await nav("Address objects").click();
    await page.getByRole("button",{name:"New object",exact:true}).click();
    await dialog().getByLabel("Name",{exact:true}).fill("Agent localhost");
    await dialog().getByLabel("IP address or subnet",{exact:true}).fill("127.0.0.1");
    await dialog().getByRole("button",{name:"Save object",exact:true}).click();
    await message("Address entry saved").waitFor();
    await page.getByRole("button",{name:"New group",exact:true}).click();
    await dialog().getByLabel("Name",{exact:true}).fill("Automation sources");
    await dialog().getByLabel("Agent localhost · 127.0.0.1",{exact:true}).check();
    await dialog().getByRole("button",{name:"Save group",exact:true}).click();
    await message("Address entry saved").waitFor();
    await screenshot("address-objects");
    await nav("Agent access").click();
    assert.equal(await page.getByRole("switch").isChecked(),false);
    const skillDownload=page.waitForEvent("download");
    await page.getByRole("link",{name:"Download agent skill",exact:true}).click();
    const downloadedSkill=await skillDownload;
    assert.equal(downloadedSkill.suggestedFilename(),"aegis-waf.zip");
    await downloadedSkill.saveAs(path.join(out,"aegis-waf.zip"));
    await page.getByRole("button",{name:"Create API key",exact:true}).click();
    await dialog().getByLabel("Key name",{exact:true}).fill("Browser review agent");
    await dialog().getByLabel("Allowed source objects / groups",{exact:true}).selectOption({label:"Automation sources · 1 objects"});
    await dialog().getByRole("button",{name:"Generate key",exact:true}).click();
    await dialog().getByRole("heading",{name:"Save your API key",exact:true}).waitFor();
    assert.ok((await dialog().getByLabel("API key",{exact:true}).inputValue()).startsWith("aegis_mcp_"));
    await dialog().getByRole("button",{name:"Done",exact:true}).click();
    await screenshot("agent-access");
    await nav("Signature sets").click();
    await page.getByRole("region",{name:"Loaded signature sets",exact:true}).getByRole("button",{name:"Apply to policy",exact:true}).click();
    await dialog().getByLabel("Policy",{exact:true}).selectOption("");
    await dialog().getByRole("button",{name:"Configure policy",exact:true}).click();
    assert.equal(await dialog().locator('select[name="signature_mode"]').inputValue(),"observe");
    assert.ok(await dialog().getByLabel("Signature set",{exact:true}).inputValue());
    await dialog().getByLabel("Policy name",{exact:true}).fill("External test policy");
    await dialog().locator('select[name="mode"]').selectOption("block",{force:true});
    await dialog().getByLabel("Enable anti-bot signals",{exact:true}).check();
    await dialog().locator('select[name="signature_mode"]').selectOption("observe",{force:true});
    await dialog().getByLabel("Signature set",{exact:true}).selectOption({index:1});
    for (const title of ["Advanced signature tuning", "Body and response inspection", "Signature exceptions"]) {
      const summary = dialog().getByText(title,{exact:true});
      if (!(await summary.locator("..").evaluate(el => el.open))) await summary.click();
    }
    await dialog().getByLabel("Oversized request action",{exact:true}).selectOption("process_partial");
    await dialog().locator('select[name="signature_response_mode"]').selectOption("observe",{force:true});
    await dialog().getByLabel("Response inspection limit (KiB)",{exact:true}).fill("128");
    await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).fill("6");
    await dialog().getByLabel("Oversized response action",{exact:true}).selectOption("process_partial");
    await dialog().getByRole("button",{name:"Add rule group",exact:true}).click();
    await dialog().getByLabel("Group name",{exact:true}).fill("Imported signatures");
    await dialog().getByRole("group",{name:"Group signatures",exact:true}).getByRole("checkbox").first().check();
    await dialog().getByRole("button",{name:"Add application",exact:true}).click();
    await dialog().getByLabel("Assignment application",{exact:true}).selectOption({label:"Manual TLS"});
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await nav("Policies").click();
    await page.getByRole("heading",{name:"Policies",exact:true}).waitFor();
    await screenshot("policies-assigned");
    await eventually(async()=>assert.equal((await httpsRequest(Number(process.env.BROWSER_HTTPS_PORT),"manual.example.test",null,"/",{"User-Agent":"sqlmap"})).status,403));
    const managedAttack="/search?q="+encodeURIComponent("1' UNION SELECT password FROM users --");
    const managedHeaders={"User-Agent":"browser","Accept":"text/html"};
    await eventually(async()=>assert.equal((await httpsRequest(Number(process.env.BROWSER_HTTPS_PORT),"manual.example.test",null,managedAttack,managedHeaders)).status,200));
    const policyRow=page.locator("tbody tr").filter({hasText:"External test policy"}).filter({has:page.getByRole("button",{name:"Edit",exact:true})});
    await nav("Signature sets").click();
    await page.getByRole("region",{name:"Loaded signature sets",exact:true}).getByRole("button",{name:"Apply to policy",exact:true}).click();
    await dialog().getByLabel("Policy",{exact:true}).selectOption({label:"External test policy"});
    await dialog().getByRole("button",{name:"Configure policy",exact:true}).click();
    assert.equal(await dialog().getByLabel("Policy name",{exact:true}).inputValue(),"External test policy");
    assert.equal(await dialog().getByLabel("Group name",{exact:true}).inputValue(),"Imported signatures");
    assert.equal(await dialog().getByLabel("Oversized request action",{exact:true}).inputValue(),"process_partial");
    assert.equal(await dialog().locator('select[name="signature_response_mode"]').inputValue(),"observe");
    assert.equal(await dialog().getByLabel("Response inspection limit (KiB)",{exact:true}).inputValue(),"128");
    assert.equal(await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).inputValue(),"6");
    assert.equal(await dialog().getByLabel("Oversized response action",{exact:true}).inputValue(),"process_partial");
    for (const title of ["Advanced signature tuning", "Body and response inspection", "Signature exceptions"]) {
      const summary = dialog().getByText(title,{exact:true});
      if (!(await summary.locator("..").evaluate(el => el.open))) await summary.click();
    }
    await screenshot("response-inspection-policy");
    assert.equal(await dialog().getByLabel("Assignment application",{exact:true}).locator("option:checked").textContent(),"Manual TLS");
    await dialog().getByRole("button",{name:"Browse signatures and exclusions",exact:true}).click();
    await dialog().getByLabel("Search signatures",{exact:true}).fill("942100");
    await dialog().getByLabel("Exclude rule 942100",{exact:true}).check();
    assert.equal(await dialog().getByLabel("Excluded CRS rule IDs",{exact:true}).inputValue(),"942100");
    await screenshot("policy-signature-exclusions");
    await dialog().getByLabel("Exclude rule 942100",{exact:true}).uncheck();
    assert.equal(await dialog().getByLabel("Excluded CRS rule IDs",{exact:true}).inputValue(),"");
    await dialog().locator('select[name="signature_mode"]').selectOption("block",{force:true});
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    for(const port of [process.env.BROWSER_HTTPS_PORT,process.env.BROWSER_ALT_HTTPS_PORT]){
      await eventually(async()=>assert.equal((await httpsRequest(Number(port),"manual.example.test",null,managedAttack,managedHeaders)).status,403));
    }
    const hstsProbe = await httpsRequest(Number(process.env.BROWSER_HTTPS_PORT), "manual.example.test", null, "/", managedHeaders, true);
    assert.equal(hstsProbe.headers["strict-transport-security"], "max-age=86400; includeSubDomains");
    await nav("Policies").click();
    await screenshot("managed-signature-policy");
    await nav("Policies").click();
    await policyRow.getByRole("button",{name:"Edit",exact:true}).click();
    await dialog().getByLabel("Enable community mitigations",{exact:true}).check();
    await dialog().locator('select[name="signature_mode"]').selectOption("off",{force:true});
    await dialog().getByLabel("All available mitigations",{exact:true}).check();
    assert.ok(await dialog().locator("[data-community-rule]:checked").count()>=2);
    await dialog().getByLabel("All available mitigations",{exact:true}).uncheck();
    await dialog().getByRole("checkbox",{name:/Node.js Brotli request guard/}).check();
    assert.equal(await dialog().getByLabel("All available mitigations",{exact:true}).isChecked(),false);
    await dialog().getByLabel("Find community mitigations",{exact:true}).fill("CVE-2026-111497");
    assert.equal(await dialog().locator("[data-community-item]:visible").count(),1);
    await dialog().getByLabel("Find community mitigations",{exact:true}).fill("");
    await dialog().locator("[data-community]").scrollIntoViewIfNeeded();
    await screenshot("rule-catalogue");
    assert.equal(await dialog().getByLabel("Assignment application",{exact:true}).locator("option:checked").textContent(),"Manual TLS");
    assert.equal(await dialog().getByLabel("Group name",{exact:true}).inputValue(),"Imported signatures");
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    for(const port of [process.env.BROWSER_HTTPS_PORT,process.env.BROWSER_ALT_HTTPS_PORT]){
      await eventually(async()=>assert.equal((await httpsRequest(Number(port),"manual.example.test",null,"/",{...managedHeaders,"Content-Encoding":"br"})).status,403));
      assert.equal((await httpsRequest(Number(port),"manual.example.test",null,"/",{...managedHeaders,"Accept-Encoding":"br"})).status,200);
    }
    await policyRow.getByRole("button",{name:"Edit",exact:true}).click();
    await dialog().getByLabel("Enable community mitigations",{exact:true}).uncheck();
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    for(const port of [process.env.BROWSER_HTTPS_PORT,process.env.BROWSER_ALT_HTTPS_PORT]){
      await eventually(async()=>assert.equal((await httpsRequest(Number(port),"manual.example.test",null,"/",{...managedHeaders,"Content-Encoding":"br"})).status,200));
    }
    await policyRow.getByRole("button",{name:"Edit",exact:true}).click();
    await dialog().getByLabel("Enable community mitigations",{exact:true}).check();
    assert.equal(await dialog().locator("[data-community-rule]:checked").count(),1);
    await dialog().locator('select[name="signature_mode"]').selectOption("block",{force:true});
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await nav("Rule feeds").click();
    await page.getByRole("button", {name:"Use Aegis community feed",exact:true}).click();
    assert.equal(await dialog().getByRole("button",{name:"Apply selected to policy",exact:true}).count(),0);
    await dialog().getByRole("button",{name:"Close",exact:true}).click();
    await nav("Dashboard").click();
    const resources=page.locator("section").filter({has:page.getByRole("heading",{name:"System performance",exact:true})});
    await resources.waitFor();
    await resources.getByText("Per-replica resources",{exact:true}).click();
    await page.waitForTimeout(4500);
    assert.equal(await resources.locator("details").evaluate(el=>el.open),true,"resource details closed during refresh");
    assert.equal(await resources.locator("tbody tr").count(),2,"missing replica resource rows");
    assert.match(await resources.innerText(), /MiB|GiB/);
    await screenshot("system-performance");
    await page.getByRole("region",{name:"Recent requests",exact:true}).getByRole("button",{name:"View details",exact:true}).first().click();
    await dialog().getByRole("heading",{name:/Request #/}).waitFor();
    await dialog().getByRole("heading",{name:"Retained request evidence",exact:true}).waitFor();
    for(const width of [320,390,768,1440]){
      await page.setViewportSize({width,height:1000});
      assert.ok(await dialog().evaluate(el=>el.scrollWidth<=el.clientWidth+1),"request details overflow dialog");
      await dialog().evaluate(el=>{el.scrollTop=0});
      await screenshot("request-details-"+width);
    }
    await dialog().getByRole("button",{name:"Close",exact:true}).click();
    await nav("Activity").click();
    const logged=await (await page.request.get(base+"/api/access-logs")).json();
    for(const outcome of ["allowed","flagged","blocked"]){
      const entry=logged.find(event=>outcome==="blocked"?event.blocked:outcome==="flagged"?!event.blocked&&(event.signals.length>0||event.rule_results.some(r=>r.result==="matched"&&r.action==="observe")):!event.blocked&&!event.signals.length&&!event.rule_results.some(r=>r.result==="matched"&&r.action==="observe"));
      assert.ok(entry,"missing "+outcome+" fixture request");
      await page.locator(`button[data-action="request-details"][data-id="${entry.id}"]`).click();
      await dialog().getByRole("heading",{name:"Request #"+entry.id,exact:true}).waitFor();
      await dialog().getByRole("heading",{name:outcome==="blocked"?"Blocked":outcome==="flagged"?"Flagged · allowed":"Allowed",exact:true}).waitFor();
      await dialog().getByRole("button",{name:"Close",exact:true}).click();
    }

    await nav("Address objects").click();
    await page.getByRole("button",{name:"Set local network location",exact:true}).click();
    const originalReference=(await (await page.request.get(base+"/api/geolocation/local")).json()).public_ip;
    let detectionCalls=0;
    await page.route("**/api/geolocation/local/detect",async route=>{
      detectionCalls++;
      await route.fulfill(detectionCalls===1?{json:{public_ip:"8.8.8.8",source:"replica_egress",provider:"ipify"}}:{status:503,json:{error:"Public IP detection unavailable. Enter the address manually or try again."}});
    });
    await dialog().getByRole("button",{name:"Detect public IP",exact:true}).click();
    await dialog().getByText("Detected outbound IP. Review the address, then save to apply.",{exact:true}).waitFor();
    assert.equal(await dialog().getByLabel("Gateway public IP",{exact:true}).inputValue(),"8.8.8.8");
    assert.equal((await (await page.request.get(base+"/api/geolocation/local")).json()).public_ip,originalReference,"detection must not save settings");
    await dialog().getByLabel("Gateway public IP",{exact:true}).fill("216.160.83.56");
    await dialog().getByRole("button",{name:"Detect public IP",exact:true}).click();
    await dialog().getByText(/Public IP detection unavailable/).waitFor();
    assert.equal(await dialog().getByLabel("Gateway public IP",{exact:true}).inputValue(),"216.160.83.56");
    assert.equal(await dialog().getByRole("button",{name:"Save local location",exact:true}).isEnabled(),true);
    await page.unroute("**/api/geolocation/local/detect");
    await screenshot("detect-gateway-public-ip");
    await dialog().getByRole("button",{name:"Save local location",exact:true}).click();
    await message("Local location saved").waitFor();
    assert.equal((await (await page.request.get(base+"/api/geolocation/local")).json()).public_ip,"216.160.83.56");
    const loggedPeer=await page.evaluate(async()=>{const response=await fetch('/api/access-logs');return (await response.json())[0].peer;});
    await nav("Address objects").click();
    await page.getByRole("button",{name:"New object",exact:true}).click();
    await dialog().getByLabel("Name",{exact:true}).fill("Recorded client");
    await dialog().getByRole("checkbox",{name:/Local network/}).check();
    await dialog().getByLabel("IP address or subnet",{exact:true}).fill(loggedPeer);
    await dialog().getByRole("button",{name:"Save object",exact:true}).click();
    await message("Address entry saved").waitFor();
    await page.waitForTimeout(2200); // Configuration refresh applies local flags to future logs.
    await nav("Dashboard").click();
    await page.getByLabel("Application",{exact:true}).selectOption("");
    const namedRow=page.getByRole("region",{name:"Recent requests",exact:true}).getByRole("row").filter({hasText:"Recorded client"}).first();
    await namedRow.waitFor();
    await namedRow.getByRole("button",{name:"View details",exact:true}).click();
    await dialog().getByText("Current IP objects",{exact:true}).waitFor();
    await dialog().getByText(loggedPeer,{exact:true}).first().waitFor();
    await dialog().getByRole("button",{name:"Close",exact:true}).click();
    const responseBreakdown=page.getByRole("region",{name:"Response status breakdown",exact:true});
    await responseBreakdown.waitFor();
    for(const column of ["Proxy host","Response source","HTTP status","Requests","Share of selected traffic"]){await responseBreakdown.getByRole("columnheader",{name:column,exact:true}).waitFor();}
    await responseBreakdown.getByText("Upstream application",{exact:true}).first().waitFor();
    assert.ok(await responseBreakdown.evaluate(el=>el.scrollWidth<=el.clientWidth+1),"desktop response status columns should all fit");
    await responseBreakdown.locator("..").screenshot({path:path.join(out,"response-status-breakdown.png")});
    await page.route("**/api/live-traffic**",async route=>{
      const response=await route.fetch();const data=await response.json();
      if(data.gateway_location?.country==='US')data.gateway_location.map_point={latitude:47,longitude:-122};
      for(const event of data.events||[])if(event.country==='US'&&event.location_source==='local_reference')event.map_point={latitude:47,longitude:-122};
      await route.fulfill({response,json:data});
    });
    await page.getByRole("button",{name:"Live traffic map",exact:true}).click();
    await page.getByRole("heading",{name:"Live traffic map",exact:true}).waitFor();
    await page.waitForFunction(()=>document.querySelector('[data-gateway-marker]')?.getAttribute('data-country')==='US');
    assert.notEqual(await page.locator('[data-gateway-marker]').getAttribute('transform'),'translate(185 155)');
    await page.waitForFunction(()=>document.querySelector('[data-gateway-marker]')?.getAttribute('data-precision')==='regional');
    assert.equal(await page.locator('[data-gateway-marker]').getAttribute('transform'),'translate(58 43)');
    const flow=page.locator('[data-local-flow]');
    await flow.getByText('Aegis WAF',{exact:true}).waitFor();
    await flow.getByRole('button',{name:'Manual TLS',exact:true}).focus();
    await page.keyboard.press('Enter');
    await page.waitForFunction(()=>document.querySelector('[aria-label="Live map application"]').selectedOptions[0].textContent==='Manual TLS');
    assert.ok((await flow.getByRole('link',{name:'Open Manual TLS',exact:true}).getAttribute('href')).startsWith('https://'));
    await flow.getByRole('button',{name:'All applications',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('[aria-label="Live map application"]').value==='');
    await screenshot('gateway-country-and-local-flow');
    assert.equal(await nav("Live traffic map").count(),0,"live page should not add a sidebar item");
    await page.emulateMedia({reducedMotion:"no-preference"});
    await flow.scrollIntoViewIfNeeded();
    assert.equal((await httpsRequest(ports[0],"manual.example.test",null,"/safe",{"User-Agent":"curl/8"})).status,200);
    assert.equal(await botRequest(),403);
    await page.locator('.live-flow').first().waitFor({timeout:10000});
    const liveLog=page.getByRole("region",{name:"Live request log",exact:true});
    await liveLog.locator('.live-row-allowed').first().waitFor();
    await liveLog.locator('.live-row-blocked').first().waitFor();
    assert.equal(await flow.locator('.local-flow-upstream').count(),0,'upstream endpoints should not be displayed');
    await flow.locator('.local-flow-packet[data-outcome="allowed"]').first().waitFor();
    await flow.locator('.local-flow-packet[data-outcome="blocked"]').first().waitFor();
    const packet=flow.locator('.local-flow-packet[data-outcome="allowed"]').first();
    const position=await packet.evaluate(node=>{const m=node.getCTM();return {x:m.e,y:m.f};});
    await page.waitForTimeout(150);
    const moved=await packet.evaluate(node=>{const m=node.getCTM();return {x:m.e,y:m.f};});
    assert.ok(Math.hypot(position.x-moved.x,position.y-moved.y)>0.1,'flow pulse should actually move');
    await flow.screenshot({path:path.join(out,'animated-local-flow.png')});
    await page.waitForTimeout(1900);
    assert.equal(await flow.locator('.local-flow-packet').count(),0,'idle feed must not generate synthetic pulses');
    await eventually(async()=>{
      const events=await (await page.request.get(base+"/api/access-logs")).json();
      const local=events.find(event=>event.peer===loggedPeer&&event.location_source?.startsWith("local_"));
      assert.ok(local,"new requests should carry local display-location provenance");
      assert.equal(local.location_reference_ip,"216.160.83.56");
      assert.ok(local.client_objects.includes("Recorded client"));
    });
    await liveLog.getByText(/Local network ·/).first().waitFor();
    await screenshot("live-traffic-map");
    await page.getByRole("button",{name:"Pause feed",exact:true}).click();
    await page.getByText("Paused · WAF protection continues",{exact:true}).waitFor();
    await page.getByLabel("Live map application",{exact:true}).selectOption({label:"Manual TLS"});
    await page.getByRole("button",{name:"Resume feed",exact:true}).click();
    await liveLog.getByText("Manual TLS",{exact:true}).first().waitFor();
    await page.emulateMedia({reducedMotion:"reduce"});
    assert.equal(await page.locator('.live-flow').count(),0,"reduced motion should clear animations");
    assert.equal(await flow.locator('.local-flow-packet').count(),0,'reduced motion must clear local flow pulses');
    for(const width of [320,390,768,1440]){await page.setViewportSize({width,height:900});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'live map overflows at '+width);await screenshot('live-map-'+width);}
    await page.getByRole('checkbox',{name:'Hide local traffic',exact:true}).check();
    await eventually(async()=>assert.equal(await liveLog.getByText(/Local network ·/).count(),0));
    const externalFeed=await (await page.request.get(base+'/api/live-traffic?exclude_local=true')).json();
    assert.ok(externalFeed.events.every(event=>!event.location_source?.startsWith('local_')));
    const retainedLocal=await (await page.request.get(base+'/api/access-logs')).json();
    assert.ok(retainedLocal.some(event=>event.location_source?.startsWith('local_')),'hiding local traffic must retain logs');
    await page.getByRole("link",{name:"Back to dashboard",exact:true}).click();
    await page.getByRole('checkbox',{name:'Hide local traffic on maps',exact:true}).waitFor();
    assert.equal(await page.getByRole('checkbox',{name:'Hide local traffic on maps',exact:true}).isChecked(),true);
    await page.getByRole('checkbox',{name:'Hide local traffic on maps',exact:true}).uncheck();
    await page.unroute("**/api/live-traffic**");
    // Map interaction uses synthetic regional aggregates; database enrichment is
    // independently verified with a real MMDB fixture in Go integration tests.
    await page.route("**/api/dashboard/regions?**",async route=>{
      const target=new URL(route.request().url());
      await route.fulfill({json:{country:"US",region:target.searchParams.get("region")||"",minutes:15,site_id:0,regions:[{region_code:"WA",region_name:"Washington",requests:7,blocked:2}],recent:[]}});
    });
    await nav("Dashboard").click();
    await page.locator('[data-map-country="US"]').click();
    await page.getByRole("heading",{name:"United States · regions",exact:true}).waitFor();
    await page.getByRole("button",{name:"View Washington requests",exact:true}).click();
    await page.getByRole("heading",{name:"Washington · recent requests",exact:true}).waitFor();
    await screenshot("regional-map");
    await page.getByRole("button",{name:"Back to world",exact:true}).click();
    await page.locator('[data-map-country="US"]').waitFor();
    await page.unroute("**/api/dashboard/regions?**");
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
        "Signature sets",
        "Traffic",
        "Policies",
        "Address objects",
        "Agent access",
      ]) {
        await nav(label).click();
        await page
          .getByRole("heading", {
            name: label === "Traffic" ? "Traffic evidence" : (label === "Rule feeds" || label === "Signature sets") ? "Rules" : label,
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
      for (const label of ["Rules", "Traffic", "System"]) {
        await nav(label).click();
        await page
          .getByRole("heading", {
            name: label === "Traffic" ? "Traffic evidence" : (label === "Rule feeds" || label === "Signature sets") ? "Rules" : label,
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
    // Shared state is configured in the browser; failed checks do not activate a backend.
    await nav("System").click();
    await page.getByRole("heading",{name:"System",exact:true}).waitFor();
    const rateForm=page.locator("#rate-state-form");
    await rateForm.getByLabel("Counter backend",{exact:true}).selectOption("redis");
    await rateForm.getByLabel("Server address",{exact:true}).fill("127.0.0.1:1");
    await rateForm.getByRole("button",{name:"Test connection",exact:true}).click();
    await page.getByRole("alert").filter({hasText:"could not connect/authenticate"}).waitFor();
    await rateForm.getByLabel("Counter backend",{exact:true}).selectOption("memory");
    await rateForm.getByRole("button",{name:"Save rate state",exact:true}).click();
    await page.getByText("Rate-state settings saved. Replicas normally refresh within two seconds.",{exact:true}).waitFor();
    const scrape=await page.evaluate(async()=>{const r=await fetch("/metrics");return {status:r.status,body:await r.text()};});
    assert.equal(scrape.status,200);assert.ok(scrape.body.includes("aegis_requests_total"));assert.ok(scrape.body.includes("aegis_inspection_duration_seconds_bucket"));
    // The shipped baseline can be selected atomically while creating a host.
    await nav("Proxy hosts").click();
    await page.getByRole("button",{name:"Add proxy host",exact:true}).click();
    await dialog().getByLabel("Name",{exact:true}).fill("Baseline-protected app");
    await dialog().getByLabel("Domains",{exact:true}).fill("baseline.example.test");
    await dialog().getByLabel("Upstream URL",{exact:true}).fill(upstream);
    await dialog().getByLabel("Initial protection policy",{exact:true}).selectOption({label:"Baseline protection · block"});
    await dialog().getByLabel("Endpoint type",{exact:true}).selectOption("streaming");
    await dialog().getByLabel("Streaming inspection window (bytes)",{exact:true}).fill("4096");
    await screenshot("baseline-application-policy");
    await dialog().getByRole("button",{name:"Save proxy host",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await eventually(async()=>{
      const response=await page.request.get(process.env.BROWSER_PROXY_URL+"/search?q="+encodeURIComponent("1' UNION SELECT password FROM users --"),{headers:{Host:"baseline.example.test","User-Agent":"browser",Accept:"text/html"}});
      assert.equal(response.status(),403);
    });
    // A streaming host can be changed to API, persisted, and still enforce CRS.
    await page.locator("tbody tr").filter({hasText:"Baseline-protected app"}).getByRole("button",{name:"Edit",exact:true}).click();
    await dialog().getByLabel("Endpoint type",{exact:true}).selectOption("api");
    await dialog().getByRole("button",{name:"Save proxy host",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await page.locator("tbody tr").filter({hasText:"Baseline-protected app"}).getByText(/API ·/).waitFor();
    await eventually(async()=>{
      const response=await page.request.get(process.env.BROWSER_PROXY_URL+"/search?q="+encodeURIComponent("1' UNION SELECT password FROM users --"),{headers:{Host:"baseline.example.test","User-Agent":"browser",Accept:"text/html"}});
      assert.equal(response.status(),403);
      assert.equal((await response.json()).error,"managed_signature_rejected");
    });
    // Notification destinations, threshold rules and acknowledgement are browser-managed.
    await nav("Alerts").click();
    await page.getByRole("heading",{name:"Alerts",exact:true}).waitFor();
    await page.getByRole("button",{name:"Destinations",exact:true}).click();
    await page.getByRole("button",{name:"Add destination",exact:true}).click();
    await dialog().getByLabel("Name",{exact:true}).fill("Fixture agent receiver");
    await dialog().getByLabel("Provider",{exact:true}).selectOption("automation");
    await dialog().getByLabel("Destination URL (write only)",{exact:true}).fill(upstream+"/alerts");
    await dialog().getByLabel("Signing secret / token (write only)",{exact:true}).fill("isolated-browser-fixture-signing-secret-123456");
    await dialog().getByLabel("Allow private-network destination (HTTP allowed only to private/loopback addresses)",{exact:true}).check();
    await dialog().getByRole("button",{name:"Save destination",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await page.locator("tbody tr").filter({hasText:"Fixture agent receiver"}).getByRole("button",{name:"Send test",exact:true}).click();
    await page.getByText("Test notification delivered.",{exact:true}).waitFor();
    await page.getByRole("button",{name:"Trigger rules",exact:true}).click();
    await page.getByRole("button",{name:"Add alert rule",exact:true}).click();
    await dialog().getByLabel("Name",{exact:true}).fill("Investigate fixture blocks");
    await dialog().getByLabel("Application",{exact:true}).selectOption({label:"Baseline-protected app"});
    await dialog().getByLabel("Threshold (count; days for certificate expiration)",{exact:true}).fill("1");
    await dialog().getByLabel("Fixture agent receiver",{exact:true}).check();
    await dialog().getByRole("button",{name:"Save alert rule",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await page.request.get(process.env.BROWSER_PROXY_URL+"/search?q="+encodeURIComponent("1' UNION SELECT password FROM users --"),{headers:{Host:"baseline.example.test","User-Agent":"browser",Accept:"application/json"}});
    await page.getByRole("button",{name:/^Inbox/}).click();
    await eventually(async()=>{await page.getByRole("button",{name:"Refresh",exact:true}).click();assert.equal(await page.locator("tbody tr").filter({hasText:"Investigate fixture blocks"}).count(),1)});
    await page.locator("tbody tr").filter({hasText:"Investigate fixture blocks"}).getByRole("button",{name:"Acknowledge",exact:true}).click();
    await page.locator("tbody tr").filter({hasText:"Investigate fixture blocks"}).getByRole("cell",{name:/^Acknowledged/}).waitFor();
    for(const width of [390,1440]){await page.setViewportSize({width,height:1000});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.screenshot({path:path.join(out,`alerts-${width}.png`)});}
    await nav("Proxy hosts").click();
    // Fully self-hosted selective CAPTCHA: no provider keys or test bypass route.
    if (process.env.BROWSER_CAPTCHA_DATABASE_CONTAINER) {
      await nav("Policies").click();
      await page.locator("tbody tr").filter({hasText:"External test policy"}).getByRole("button",{name:"Edit",exact:true}).click();
      await dialog().locator('select[name="signature_mode"]').selectOption("off",{force:true});
      await dialog().getByText("Selective bot verification",{exact:true}).click();
      await dialog().getByLabel("Challenge suspected bots with self-hosted CAPTCHA",{exact:true}).check();
      await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
      await dialog().waitFor({state:"detached"});
      await page.waitForTimeout(2500);
      const captchaURL=`https://manual.example.test:${process.env.BROWSER_HTTPS_PORT}/captcha-browser`;
      const ordinary=await browser.newContext({ignoreHTTPSErrors:true,userAgent:"Mozilla/5.0 Chrome/144.0 ordinary",extraHTTPHeaders:{"X-Real-IP":"198.51.100.58"}});
      const normalPage=await ordinary.newPage();
      assert.equal((await normalPage.goto(captchaURL)).status(),200);
      assert.equal((await ordinary.cookies()).filter(c=>c.name.startsWith("__Host-aegis_")).length,0);
      await ordinary.close();
      const suspect=await browser.newContext({ignoreHTTPSErrors:true,userAgent:"Mozilla/5.0 HeadlessChrome/144.0 suspicious",extraHTTPHeaders:{"X-Real-IP":"198.51.100.58"}});
      const challenge=await suspect.newPage();
      assert.equal((await challenge.goto(captchaURL)).status(),403);
      await challenge.getByRole("heading",{name:"Verify your request",exact:true}).waitFor();
      const image=challenge.locator("img");await image.waitFor();await challenge.waitForFunction(el=>el.complete&&el.naturalWidth===240,await image.elementHandle());
      for(const width of [390,1440]) {await challenge.setViewportSize({width,height:1000});assert.ok(await challenge.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await challenge.screenshot({path:path.join(out,`captcha-${width}.png`)});}
      const pending=(await suspect.cookies()).find(c=>c.name==="__Host-aegis_challenge");assert.ok(pending.secure&&pending.httpOnly);
      const key=Buffer.from(fs.readFileSync(process.env.BROWSER_TEST_ENCRYPTION_KEY_FILE,"utf8").trim(),"base64");
      const decrypt=(encoded,aad)=>{const raw=Buffer.from(encoded,"base64url");const d=require("node:crypto").createDecipheriv("aes-256-gcm",key,raw.subarray(0,12));d.setAAD(Buffer.from(aad));d.setAuthTag(raw.subarray(-16));return Buffer.concat([d.update(raw.subarray(12,-16)),d.final()]);};
      const claims=JSON.parse(decrypt(pending.value,"primary:bot-cookie-v1"));assert.match(claims.i,/^[A-Za-z0-9_-]{43}$/);
      // Fixture-only DB access reads the encrypted solution; production has no
      // answer-reading endpoint and no hard-coded passing CAPTCHA answer.
      const row=execFileSync("docker",["exec",process.env.BROWSER_CAPTCHA_DATABASE_CONTAINER,"psql","-XAt","-U","aegis_waf","-d","aegis_waf","-c",`SELECT key_id,encode(answer_cipher,'base64') FROM bot_challenges WHERE id='${claims.i}'`],{encoding:"utf8"}).trim();
      const split=row.indexOf("|");const answer=decrypt(row.slice(split+1).replace(/\s/g,""),row.slice(0,split)+":bot-answer:"+claims.i+":"+claims.s).map(d=>d+48).toString();
      await challenge.getByLabel("Enter the six digits",{exact:true}).fill(answer);
      await Promise.all([challenge.waitForURL(captchaURL),challenge.getByRole("button",{name:"Verify and continue",exact:true}).click()]);
      assert.equal(await challenge.locator("body").innerText(),"ACME verified application");
      assert.ok((await suspect.cookies()).some(c=>c.name==="__Host-aegis_clearance"&&c.httpOnly&&c.secure));
      assert.equal((await challenge.goto(`https://manual.example.test:${process.env.BROWSER_ALT_HTTPS_PORT}/captcha-browser`)).status(),200);
      await suspect.close();
    }
    // Curated artifacts and sensitivity round-trip through the real management UI.
    await nav("Policies").click();
    await page.getByRole("button",{name:"Create policy",exact:true}).click();
    assert.equal(await dialog().locator('select[name="mode"]').inputValue(),"observe");
    assert.equal(await dialog().locator('select[name="signature_mode"]').inputValue(),"observe");
    assert.ok(await dialog().getByLabel("Signature set",{exact:true}).inputValue());
    assert.equal(await dialog().locator("[data-sensitivity-label]").textContent(),"2 · Standard");
    await dialog().getByRole("button",{name:"Cancel",exact:true}).click();
    await nav("Signature sets").click();
    await page.getByRole("button",{name:"Create curated set",exact:true}).click();
    await dialog().getByLabel("Set name",{exact:true}).fill("SQL request guard");
    const sourceSet=await dialog().getByLabel("Source signature set",{exact:true}).inputValue();
    await dialog().getByLabel("Search signatures",{exact:true}).fill("942100");
    await dialog().getByLabel("Include rule 942100",{exact:true}).check();
    await dialog().getByLabel("Search signatures",{exact:true}).fill("941100");
    assert.equal(await dialog().getByLabel("Include rule 941100",{exact:true}).isChecked(),false);
    await dialog().getByLabel("Search signatures",{exact:true}).fill("942100");
    assert.equal(await dialog().getByLabel("Include rule 942100",{exact:true}).isChecked(),true);
    for(const width of [390,1440]){await page.setViewportSize({width,height:1000});assert.ok(await dialog().evaluate(el=>el.scrollWidth<=el.clientWidth+1));await screenshot("curated-set-builder-"+width);}
    await dialog().getByRole("button",{name:"Save curated set",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    const setList=await (await page.request.get(base+"/api/signature-sets")).json();
    const curatedSet=setList.find(s=>s.name==="SQL request guard");
    assert.deepEqual(curatedSet.curation.selected_rule_ids,[942100]);assert.equal(curatedSet.curation.source_set_id,sourceSet);
    const curatedRow=page.getByRole("region",{name:"Loaded signature sets",exact:true}).locator("tbody tr").filter({hasText:"SQL request guard"});
    await curatedRow.getByRole("button",{name:"Review upstream",exact:true}).click();
    await message("No newer source is available").waitFor();
    await curatedRow.getByRole("button",{name:"Apply to policy",exact:true}).click();
    await dialog().getByLabel("Policy",{exact:true}).selectOption({label:"External test policy"});
    await dialog().getByRole("button",{name:"Configure policy",exact:true}).click();
    assert.equal(await dialog().getByLabel("Signature set",{exact:true}).inputValue(),curatedSet.id);
    assert.equal(await dialog().locator('select[name="signature_mode"]').inputValue(),"observe");
    for (const title of ["Advanced signature tuning", "Body and response inspection", "Signature exceptions"]) {
      const summary = dialog().getByText(title,{exact:true});
      if (!(await summary.locator("..").evaluate(el => el.open))) await summary.click();
    }
    assert.equal(await dialog().getByLabel("Oversized request action",{exact:true}).inputValue(),"process_partial");
    assert.equal(await dialog().locator('select[name="signature_response_mode"]').inputValue(),"observe");
    assert.equal(await dialog().getByLabel("Response inspection limit (KiB)",{exact:true}).inputValue(),"128");
    assert.equal(await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).inputValue(),"6");
    const bodyBefore=await dialog().getByLabel("Inspected body limit (KiB)",{exact:true}).inputValue();
    const sensitivity=dialog().getByLabel("Signature sensitivity",{exact:true});
    await sensitivity.focus();await sensitivity.press("End");
    assert.equal(await dialog().getByLabel("CRS paranoia level",{exact:true}).inputValue(),"4");
    assert.equal(await dialog().getByLabel("CRS inbound anomaly threshold",{exact:true}).inputValue(),"2");
    assert.equal(await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).inputValue(),"2");
    await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).fill("6");
    assert.equal(await dialog().locator("[data-sensitivity-label]").textContent(),"Custom");
    const customSliderValue=await sensitivity.inputValue();
    const sensitivityBox=await sensitivity.boundingBox();
    await page.mouse.move(sensitivityBox.x+sensitivityBox.width-8,sensitivityBox.y+sensitivityBox.height/2);
    await page.mouse.down();await page.mouse.up();
    assert.equal(await sensitivity.inputValue(),customSliderValue);
    assert.equal(await dialog().locator("[data-sensitivity-label]").textContent(),"Custom");
    assert.equal(await dialog().getByLabel("CRS paranoia level",{exact:true}).inputValue(),"4");
    assert.equal(await dialog().getByLabel("CRS inbound anomaly threshold",{exact:true}).inputValue(),"2");
    assert.equal(await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).inputValue(),"6");
    await sensitivity.focus();await sensitivity.press("Home");await sensitivity.press("ArrowRight");
    assert.equal(await dialog().locator("[data-sensitivity-label]").textContent(),"2 · Standard");
    assert.equal(await dialog().getByLabel("CRS outbound anomaly threshold",{exact:true}).inputValue(),"4");
    assert.equal(await dialog().getByLabel("Inspected body limit (KiB)",{exact:true}).inputValue(),bodyBefore);
    assert.equal(await dialog().locator('select[name="signature_mode"]').inputValue(),"observe");
    await dialog().getByLabel("CRS inbound anomaly threshold",{exact:true}).fill("7");
    assert.equal(await dialog().locator("[data-sensitivity-label]").textContent(),"Custom");
    await screenshot("policy-sensitivity-custom");
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    await nav("Policies").click();
    await policyRow.getByRole("button",{name:"Edit",exact:true}).click();
    assert.equal(await dialog().locator("[data-sensitivity-label]").textContent(),"Custom");
    for (const title of ["Advanced signature tuning", "Body and response inspection", "Signature exceptions"]) {
      const summary = dialog().getByText(title,{exact:true});
      if (!(await summary.locator("..").evaluate(el => el.open))) await summary.click();
    }
    assert.equal(await dialog().getByLabel("CRS inbound anomaly threshold",{exact:true}).inputValue(),"7");
    await sensitivity.focus();await sensitivity.press("Home");await sensitivity.press("ArrowRight");
    await screenshot("policy-sensitivity-standard");
    await dialog().locator('select[name="signature_mode"]').selectOption("block",{force:true});
    await dialog().getByRole("button",{name:"Save policy",exact:true}).click();
    await dialog().waitFor({state:"detached"});
    for(const port of [process.env.BROWSER_HTTPS_PORT,process.env.BROWSER_ALT_HTTPS_PORT]){
      await eventually(async()=>assert.equal((await httpsRequest(Number(port),"manual.example.test",null,managedAttack,managedHeaders)).status,403));
      assert.equal((await httpsRequest(Number(port),"manual.example.test",null,"/search?q="+encodeURIComponent("<script>alert(1)</script>"),managedHeaders)).status,200);
    }
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
        "setup/login, PEM errors, form preservation, keyboard focus, rules draft/observe/block/disable/rollback, bounded redacted evidence, offline replay, responsive layouts, shared rate-state controls, streaming profiles, authenticated management metrics, CPU/RAM replica telemetry, scoped agent keys, address objects, regional drill-down and policy assignment, traffic dashboard/app filters, real country download/lookup, and bot observe/block and logout.",
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
