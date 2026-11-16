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
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'",
    );
    res.end(fs.readFileSync(file));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  let browser;
  try {
    browser = await chromium.launch({
      executablePath: process.env.BROWSER_EXECUTABLE,
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const original = {
      name: "Shared posture",
      description: "",
      mode: "observe",
      flood_enabled: false,
      bot_enabled: false,
      block_empty_user_agent: false,
      requests_per_second: 20,
      burst: 60,
      site_requests_per_second: 1000,
      site_burst: 2000,
      bot_challenge: {},
      managed_signatures: {
        set_id: "crs-fixture",
        mode: "observe",
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        body_limit_bytes: 65536,
        body_limit_action: "reject",
        response_mode: "off",
        response_body_limit_bytes: 262144,
        response_body_limit_action: "reject",
        excluded_rule_ids: [],
        scoped_exclusions: [],
      },
      network_access: {},
      community_mitigations: { enabled: false, mode: "observe", rules: [] },
      groups: [],
    };
    let policies = [
      {
        id: 1,
        revision: 2,
        spec: structuredClone(original),
        applications: [{ site_id: 1, source_cidrs: [], priority: 10000 }],
      },
    ];
    let saved,
      checkCalls = [],
      checkResult = {
        limit: 8,
        distinct: 3,
        distinct_after: 3,
        would_create_new: false,
        blocked: false,
        nearest_policy_id: 0,
        nearest_policy: "",
        differing_fields: [],
      };
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
        json = [{ id: 1, name: "Capacity app", policies: [] }];
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
      if (p === "/api/rules") json = [];
      if (p === "/api/policy-capacity")
        json = {
          limit: 8,
          distinct: 3,
          remaining: 5,
          configurations: [
            {
              id: "abcd1234",
              options: original.managed_signatures,
              policies: [{ id: 1, name: "Shared posture", mode: "observe" }],
            },
          ],
        };
      if (p === "/api/policy-capacity/check") {
        checkCalls.push(request.postDataJSON());
        json = checkResult;
      }
      if (p === "/api/policies") json = policies;
      if (/\/api\/policies(?:\/1)?$/.test(p) && ["POST", "PUT"].includes(request.method())) {
        saved = request.postDataJSON();
        policies = [
          {
            id: 1,
            revision: 3,
            spec: {
              ...saved.spec,
              groups: [],
              community_mitigations: {
                enabled: saved.spec.community_mitigations.enabled,
                mode: saved.spec.community_mitigations.mode,
                update_mode: saved.spec.community_mitigations.update_mode,
                rules: [],
              },
            },
            applications: saved.applications,
          },
        ];
        json = { id: 1 };
      }
      await route.fulfill({ status, json });
    });
    const form = () => page.locator("#policy-form");
    const open = async () => {
      await page.locator('[data-action="edit-policy"]').first().click();
      await form().waitFor();
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
    // The editor surfaces current engine usage next to signature settings.
    const chip = form().locator("[data-policy-capacity]");
    await chip.waitFor();
    assert.match(await chip.innerText(), /3 of 8/);
    assert.match(await chip.innerText(), /share one engine/);
    // Saving an unchanged posture reuses the engine: the preflight runs but
    // needs no confirmation.
    await page
      .getByRole("button", { name: "Save policy", exact: true })
      .click();
    await form().waitFor({ state: "detached" });
    assert.equal(checkCalls.length, 1);
    assert.equal(checkCalls[0].policy_id, 1);
    assert.ok(saved.spec.managed_signatures.inbound_threshold === 5);
    // A new-shape posture triggers the pre-save warning naming usage and the
    // nearest reusable configuration; accepting it saves.
    checkResult = {
      ...checkResult,
      distinct: 7,
      distinct_after: 8,
      would_create_new: true,
      blocked: false,
      nearest_policy: "Jellyfin posture",
      differing_fields: ["stream_window_bytes"],
    };
    await open();
    await expand("Advanced signature tuning");
    await form().locator("[name=signature_threshold]").fill("9");
    const dialogs = [];
    page.on("dialog", (dialog) => {
      dialogs.push(dialog.message());
      dialog.accept();
    });
    await page
      .getByRole("button", { name: "Save policy", exact: true })
      .click();
    await form().waitFor({ state: "detached" });
    assert.equal(checkCalls.length, 2);
    assert.equal(checkCalls[1].policy_id, 1);
    assert.equal(checkCalls[1].mode, "observe");
    assert.equal(checkCalls[1].options.inbound_threshold > 5, true);
    assert.equal(dialogs.length, 1);
    assert.match(dialogs[0], /configuration 8 of 8/);
    assert.match(dialogs[0], /Jellyfin posture/);
    assert.match(dialogs[0], /stream_window_bytes/);
    assert.ok(saved.spec.managed_signatures.inbound_threshold > 5);
    // A blocked preflight stops the save with a visible error instead.
    checkResult = {
      ...checkResult,
      distinct: 8,
      distinct_after: 9,
      blocked: true,
    };
    await open();
    await expand("Advanced signature tuning");
    await form().locator("[name=signature_threshold]").fill("9");
    await page
      .getByRole("button", { name: "Save policy", exact: true })
      .click();
    await page
      .getByText(/over the per-replica engine limit/)
      .waitFor();
    assert.equal(checkCalls.length, 3);
    assert.match(
      await form().locator("[data-policy-capacity]").innerText(),
      /3 of 8/,
    );
    assert.equal(await form().count(), 1);
    for (const width of [390, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.ok(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
      );
    }
    if (process.env.BROWSER_ARTIFACT_DIR) {
      fs.mkdirSync(process.env.BROWSER_ARTIFACT_DIR, { recursive: true });
      await page.screenshot({
        path: path.join(
          process.env.BROWSER_ARTIFACT_DIR,
          "policy-capacity-blocked.png",
        ),
        fullPage: true,
      });
    }
    assert.deepEqual(errors, []);
    console.log(
      "PASS: capacity chip (N of 8), reuse skips preflight, new shape warns with nearest posture and field diff, blocked save surfaces an inline error, responsive layouts.",
    );
  } finally {
    if (browser) await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
