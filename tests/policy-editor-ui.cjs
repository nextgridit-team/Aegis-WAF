const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const artifacts =
    process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-policy-editor-ui";
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
      name: "Custom exact policy",
      description: "Preserve every configured value",
      mode: "observe",
      flood_enabled: false,
      bot_enabled: true,
      block_empty_user_agent: true,
      requests_per_second: 37,
      burst: 111,
      site_requests_per_second: 12345,
      site_burst: 54321,
      bot_challenge: {
        enabled: false,
        score_threshold: 73,
        clearance_minutes: 47,
        risk_requests_per_second: 61,
        risk_burst: 211,
      },
      managed_signatures: {
        set_id: "crs-fixture",
        mode: "block",
        paranoia_level: 2,
        inbound_threshold: 7,
        outbound_threshold: 6,
        body_limit_bytes: 65600,
        body_limit_action: "process_partial",
        response_mode: "observe",
        response_body_limit_bytes: 50000,
        response_body_limit_action: "process_partial",
        excluded_rule_ids: [941100],
        scoped_exclusions: [
          { rule_ids: [942100], path_prefix: "//search" },
          {
            rule_ids: [941100],
            parameters: ["q"],
            client_cidrs: ["192.0.2.0/24"],
          },
        ],
      },
      network_access: {
        block_addresses: { object_ids: [1], group_ids: [] },
        allow_addresses: { object_ids: [], group_ids: [1] },
        block_cidrs: ["198.51.100.0/24"],
        allow_cidrs: ["192.0.2.0/24"],
        allow_scope: "geo",
        geo_mode: "observe",
        geo_strategy: "block_selected",
        countries: ["US", "CA", "AX"],
        unknown_country: "allow",
      },
      community_mitigations: { enabled: false, rules: [] },
      groups: [
        {
          name: "WebDAV",
          path_prefix: "/dav",
          methods: ["PROPFIND", "GET"],
          rules: [],
        },
      ],
    };
    const applications = [
      { site_id: 1, source_cidrs: [], priority: 10000 },
      { site_id: 2, source_cidrs: ["10.0.0.0/8"], priority: 101 },
    ];
    let policies = [
        { id: 1, revision: 3, spec: structuredClone(original), applications },
      ],
      saved,
      failSave = false;
    await page.route("**/api/**", async (route) => {
      const request = route.request(),
        p = new URL(request.url()).pathname;
      let json = [],
        status = 200;
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "policy-test", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/sites")
        json = [
          { id: 1, name: "Public app", policies: [] },
          { id: 2, name: "Internal app", policies: [] },
        ];
      if (p === "/api/address-objects")
        json = [
          { id: 1, name: "Office", value: "192.0.2.0/24" },
          { id: 2, name: "Remote team", value: "203.0.113.0/24" },
        ];
      if (p === "/api/address-groups")
        json = [{ id: 1, name: "Trusted team", object_ids: [1, 2] }];
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
      if (p === "/api/signature-sets/crs-fixture/rules")
        json = {
          rules: Array.from({ length: 30 }, (_, i) => ({
            id: 942100 + i,
            name: `Fixture detector ${i}`,
            category: i < 20 ? "First twenty" : "Remaining",
            scope: "request",
            selectable: true,
            tags: [],
            severity: "CRITICAL",
            phase: 2,
            paranoia_level: 1,
            source: "fixture.conf",
          })),
        };
      if (p === "/api/policies") json = policies;
      if (
        /\/api\/policies(?:\/1)?$/.test(p) &&
        ["POST", "PUT"].includes(request.method())
      ) {
        saved = request.postDataJSON();
        if (failSave) {
          status = 503;
          json = { error: "Database unavailable" };
        } else {
          policies = [
            {
              id: 1,
              revision: 4,
              spec: {
                ...saved.spec,
                groups: saved.spec.groups.map((g) => ({ ...g, rules: [] })),
                community_mitigations: {
                  enabled: saved.spec.community_mitigations.enabled,
                  rules: [],
                },
              },
              applications: saved.applications,
            },
          ];
          json = { id: 1 };
        }
      }
      await route.fulfill({ status, json });
    });
    const form = () => page.locator("#policy-form");
    const open = async () => {
      await page.locator('[data-action="edit-policy"]').first().click();
      await form().waitFor();
    };
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
    await page.goto(`http://127.0.0.1:${server.address().port}/#policies`);
    await open();
    assert.equal(await form().locator(".policy-editor-nav button").count(), 6);
    assert.match(
      await form().locator(".policy-live-summary").innerText(),
      /capped to Observe/,
    );
    // Untouched edit must preserve exact values, including fractional KiB and dormant settings.
    await page
      .getByRole("button", { name: "Save policy", exact: true })
      .click();
    await form().waitFor({ state: "detached" });
    const expected = structuredClone(original);
    expected.community_mitigations = { enabled: false, rule_ids: [] };
    expected.groups = original.groups.map(({ rules, ...g }) => ({
      ...g,
      rule_ids: [],
    }));
    assert.deepEqual(saved.spec, expected);
    assert.deepEqual(saved.applications, applications);
    assert.equal(saved.refresh_rules, false);
    assert.deepEqual(saved.refresh_rule_ids, []);
    await open();
    await section("Policy basics");
    const modes = form().getByRole("radiogroup", {
      name: "Policy mode",
      exact: true,
    });
    await modes.getByRole("radio", { checked: true }).press("End");
    assert.equal(await form().locator("[name=mode]").inputValue(), "block");
    await modes.getByRole("radio", { checked: true }).press("Home");
    assert.equal(await form().locator("[name=mode]").inputValue(), "off");
    await section("Bot & flood protection");
    await form()
      .getByRole("switch", {
        name: "Enable HTTP flood protection",
        exact: true,
      })
      .check();
    const rate = form().locator("[data-scale-for=requests_per_second]");
    await rate.press("ArrowRight");
    assert.equal(
      await form().locator("[name=requests_per_second]").inputValue(),
      "39",
    );
    await form().locator("[name=burst]").fill("1");
    assert.equal(
      await form()
        .locator("[name=burst]")
        .evaluate((e) => e.validity.valid),
      false,
    );
    await form().locator("[name=burst]").fill("120");
    assert.equal(
      await form()
        .locator("[name=burst]")
        .evaluate((e) => e.validity.valid),
      true,
    );
    await page.screenshot({ path: path.join(artifacts, "traffic.png") });
    await section("Signature protection");
    assert.match(
      await form().locator("[data-sensitivity-label]").innerText(),
      /Custom/,
    );
    await expand("Body and response inspection");
    assert.equal(
      await form().locator("[name=signature_body_kib]").inputValue(),
      "64.0625",
    );
    await form().locator("[data-scale-for=signature_body_kib]").press("End");
    assert.equal(
      await form().locator("[name=signature_body_kib]").inputValue(),
      "1024",
    );
    await expand("Signature exceptions");
    assert.equal(await form().locator(".policy-exception-row").count(), 2);
    await form()
      .getByRole("button", { name: "Add scoped exception", exact: true })
      .click();
    const row = form().locator(".policy-exception-row").last();
    await row.getByLabel("Signature rule IDs", { exact: true }).fill("942100");
    assert.equal(
      await row
        .getByLabel("Request path prefix", { exact: true })
        .evaluate((e) => e.validity.valid),
      false,
    );
    await row.getByLabel("Request path prefix", { exact: true }).fill("/api");
    const raw = form().locator("[name=signature_scoped_exclusions]");
    assert.deepEqual(JSON.parse(await raw.inputValue()).at(-1), {
      rule_ids: [942100],
      path_prefix: "/api",
    });
    const firstRow = form().locator(".policy-exception-row").first();
    await firstRow
      .getByRole("button", { name: "Choose rules", exact: true })
      .click();
    const picker = firstRow.locator("[data-exception-browser]");
    await picker
      .getByLabel("Category", { exact: true })
      .selectOption("First twenty");
    await picker
      .getByRole("button", { name: "Select matching", exact: true })
      .click();
    assert.equal(JSON.parse(await raw.inputValue())[0].rule_ids.length, 20);
    await picker
      .getByLabel("Category", { exact: true })
      .selectOption("Remaining");
    await picker
      .getByRole("button", { name: "Select matching", exact: true })
      .click();
    assert.match(
      await picker.locator("[data-signature-count]").innerText(),
      /at most 20/,
    );
    await picker.getByLabel("Include rule 942120", { exact: true }).click();
    assert.equal(
      await picker
        .getByLabel("Include rule 942120", { exact: true })
        .isChecked(),
      false,
    );
    assert.equal(JSON.parse(await raw.inputValue())[0].rule_ids.length, 20);
    // Changing even to an empty set clears stale inventory and preserves typed exceptions.
    const beforeSetChange = await raw.inputValue();
    await form().locator("[name=signature_set]").selectOption("");
    assert.equal(await picker.innerHTML(), "");
    assert.equal(await raw.inputValue(), beforeSetChange);
    await form().locator("[name=signature_set]").selectOption("crs-fixture");
    await expand("Edit scoped exclusions as JSON");
    await raw.fill("{broken");
    assert.equal(await raw.evaluate((e) => e.validity.valid), false);
    await raw.fill(
      JSON.stringify(original.managed_signatures.scoped_exclusions),
    );
    assert.equal(await raw.evaluate((e) => e.validity.valid), true);
    assert.equal(
      await form().locator(".policy-exception-row:disabled").count(),
      0,
    );
    await page.screenshot({ path: path.join(artifacts, "signatures.png") });
    await section("Access & location");
    const blockObjects = form().locator(".policy-checkbox-picker").first();
    await blockObjects
      .getByPlaceholder("Find an object or group")
      .fill("Remote");
    await blockObjects.getByRole("checkbox", { name: /Remote team/ }).check();
    assert.equal(
      await form()
        .locator('[name="network_block_addresses"] option:checked')
        .count(),
      2,
    );
    const countrySearch = form().getByPlaceholder(
      "Find a country by name or code",
    );
    await countrySearch.fill("France");
    await form()
      .getByLabel(/France.*FR/)
      .check();
    assert.deepEqual(
      (await form().locator("[name=network_countries]").inputValue()).split(
        ", ",
      ),
      ["AX", "CA", "FR", "US"],
    );
    await page.screenshot({ path: path.join(artifacts, "access.png") });
    await section("Targeted rules");
    assert.equal(
      await form().locator("[data-group-methods]").inputValue(),
      "PROPFIND, GET",
    );
    await form().getByRole("button", { name: "POST", exact: true }).click();
    assert.match(
      await form().locator("[data-group-methods]").inputValue(),
      /PROPFIND/,
    );
    await section("Application assignments");
    await form()
      .locator("[data-scale-for=assignment_priority]")
      .last()
      .press("ArrowRight");
    assert.equal(
      await form().locator("[data-assignment-priority]").last().inputValue(),
      "102",
    );
    failSave = true;
    await page
      .getByRole("button", { name: "Save policy", exact: true })
      .click();
    await page.getByText("Database unavailable", { exact: true }).waitFor();
    assert.equal(await form().count(), 1);
    assert.equal(
      await form().locator("[name=requests_per_second]").inputValue(),
      "39",
    );
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 950 });
      await section("Bot & flood protection");
      assert.equal(
        await page
          .locator("dialog")
          .evaluate((e) => e.scrollWidth <= e.clientWidth + 1),
        true,
        `dialog overflow at ${width}`,
      );
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
        true,
        `page overflow at ${width}`,
      );
      await page.screenshot({
        path: path.join(artifacts, `width-${width}.png`),
      });
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.evaluate(() => {
      document.documentElement.dataset.theme = "dark";
      document.documentElement.style.zoom = "2";
    });
    await section("Policy basics");
    assert.equal(
      await page
        .locator("dialog")
        .evaluate((e) => e.scrollWidth <= e.clientWidth + 1),
      true,
      "zoomed dialog overflow",
    );
    await page.screenshot({ path: path.join(artifacts, "dark-zoom-200.png") });
    await page.evaluate(() => {
      document.documentElement.dataset.theme = "light";
      document.documentElement.style.zoom = "1";
    });
    await form().getByRole("button", { name: "Cancel", exact: true }).click();
    await page
      .getByRole("button", { name: "Create policy", exact: true })
      .click();
    await page
      .getByRole("dialog")
      .getByRole("heading", { name: "Create policy", exact: true })
      .waitFor();
    assert.equal(await form().locator("[name=mode]").inputValue(), "observe");
    assert.equal(
      await form().locator("[name=signature_threshold]").inputValue(),
      "5",
    );
    assert.equal(
      await form().locator("[name=signature_outbound_threshold]").inputValue(),
      "4",
    );
    await page.screenshot({ path: path.join(artifacts, "create.png") });
    assert.deepEqual(errors, []);
    console.log(
      "PASS: exact edit round trip; mode keyboard; scales; validation; scoped exceptions; country/method selection; failed save; responsive layouts; creation defaults",
    );
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
