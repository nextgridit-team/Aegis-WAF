const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const artifacts =
    process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-exceptions-strict";
  fs.mkdirSync(artifacts, { recursive: true });
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
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'",
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
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const original = {
      name: "Exceptions policy",
      description: "",
      mode: "observe",
      flood_enabled: false,
      bot_enabled: false,
      block_empty_user_agent: false,
      requests_per_second: 100,
      burst: 200,
      site_requests_per_second: 100,
      site_burst: 200,
      managed_signatures: {
        set_id: "crs-fixture",
        mode: "observe",
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 5,
        body_limit_bytes: 65600,
        body_limit_action: "process_partial",
        response_mode: "off",
        response_body_limit_bytes: 50000,
        response_body_limit_action: "process_partial",
        excluded_rule_ids: [],
        scoped_exclusions: [
          { rule_ids: [942100], path_prefix: "/search" },
        ],
      },
      groups: [],
    };
    const applications = [{ site_id: 1, source_cidrs: [], priority: 10000 }];
    const policies = [
      { id: 1, revision: 3, spec: structuredClone(original), applications },
    ];
    await page.route("**/api/**", async (route) => {
      const p = new URL(route.request().url()).pathname;
      let json = [],
        status = 200;
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "exceptions-test", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/sites") json = [{ id: 1, name: "Public app", policies: [] }];
      if (p === "/api/address-objects") json = [];
      if (p === "/api/address-groups") json = [];
      if (p === "/api/signature-sets")
        json = [
          {
            id: "crs-fixture",
            name: "OWASP CRS",
            version: "4.30.0",
            rule_count: 627,
            digest: "a".repeat(64),
          },
        ];
      if (p === "/api/rule-catalog") json = [];
      if (p === "/api/policies") json = policies;
      await route.fulfill({ status, json });
    });
    const form = () => page.locator("#policy-form");
    await page.goto(`http://127.0.0.1:${server.address().port}/#policies`);
    await page.locator('[data-action="edit-policy"]').first().click();
    await form().waitFor();
    const section = async (text) => {
      await page
        .getByRole("navigation", { name: "Policy sections" })
        .getByRole("button", { name: text })
        .click();
    };
    const expand = async (text) => {
      const d = form()
        .locator("details")
        .filter({ has: page.locator(":scope > summary", { hasText: text }) });
      if (!(await d.getAttribute("open")))
        await d.locator(":scope > summary").click();
    };
    await section("Signature protection");
    await expand("Signature exceptions");
    await expand("Edit scoped exclusions as JSON");
    const raw = form().locator("[name=signature_scoped_exclusions]");
    const status = form().locator("[data-exception-status]");
    // A misspelled scope key must fail editor validation naming the key.
    await raw.fill(
      JSON.stringify([
        {
          rule_ids: [942100],
          path_prefix: "/search",
          client_cidr: ["10.0.0.0/8"],
        },
      ]),
    );
    assert.equal(
      await raw.evaluate((e) => e.validity.valid),
      false,
      "unknown key accepted by editor validation",
    );
    assert.match(
      await status.innerText(),
      /client_cidr/,
      "editor error does not name the unknown key",
    );
    // Known keys still validate.
    await raw.fill(
      JSON.stringify([
        {
          rule_ids: [942100],
          path_prefix: "/search",
          parameters: ["q"],
          client_cidrs: ["10.0.0.0/8"],
        },
      ]),
    );
    assert.equal(await raw.evaluate((e) => e.validity.valid), true);
    assert.equal(await form().locator(".policy-exception-row:disabled").count(), 0);
    await page.screenshot({ path: path.join(artifacts, "exceptions.png") });
    assert.deepEqual(errors, []);
    console.log(
      "PASS: unknown scoped-exclusion keys rejected with the key named; known keys still validate",
    );
  } finally {
    await browser.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
