const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const artifacts =
    process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-applications-ui";
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
      viewport: { width: 1440, height: 1050 },
    });
    const errors = [],
      writes = [],
      trafficScopes = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const managed = {
      set_id: "crs-fixture",
      mode: "block",
      paranoia_level: 1,
      inbound_threshold: 5,
      body_limit_bytes: 1048576,
      body_limit_action: "reject",
      response_mode: "block",
      response_body_limit_bytes: 262144,
      response_body_limit_action: "reject",
      outbound_threshold: 4,
      excluded_rule_ids: [],
      scoped_exclusions: [],
    };
    const base = {
      name: "Public baseline",
      description: "",
      mode: "observe",
      flood_enabled: true,
      bot_enabled: false,
      block_empty_user_agent: false,
      requests_per_second: 20,
      burst: 60,
      site_requests_per_second: 1000,
      site_burst: 2000,
      groups: [],
      managed_signatures: managed,
      network_access: {
        block_cidrs: ["198.51.100.0/24"],
        allow_cidrs: ["192.0.2.0/24"],
        allow_scope: "all",
        geo_mode: "block",
        geo_strategy: "block_selected",
        countries: ["US"],
        unknown_country: "allow",
      },
      community_mitigations: { enabled: false, rules: [] },
    };
    let policies = [
      {
        id: 1,
        revision: 3,
        spec: structuredClone(base),
        applications: [
          { site_id: 1, source_cidrs: [], priority: 10000 },
          { site_id: 2, source_cidrs: [], priority: 10000 },
        ],
      },
      {
        id: 2,
        revision: 1,
        spec: {
          ...structuredClone(base),
          name: "Office policy",
          mode: "block",
        },
        applications: [
          { site_id: 1, source_cidrs: ["10.0.0.0/8"], priority: 100 },
        ],
      },
    ];
    const local = {
      mode: "off",
      bot_mode: "off",
      requests_per_second: 20,
      burst: 60,
      site_requests_per_second: 1000,
      site_burst: 2000,
      trusted_proxies: [],
      flood_exempt_cidrs: [],
      bot_exempt_cidrs: [],
    };
    const app = (id, name) => ({
      id,
      name,
      hostnames: [`app${id}.example.test`],
      upstream: `http://upstream${id}:8000`,
      enabled: true,
      certificate_id: 1,
      preserve_host: true,
      redirect_https: true,
      protection: local,
      traffic_profile: "web",
      policies: [],
    });
    let sites = [
      app(1, "Customer portal"),
      { ...app(2, "Billing API"), traffic_profile: "api" },
      {
        ...app(3, "New application"),
        certificate_id: null,
        redirect_https: false,
      },
      { ...app(4, "Paused workspace"), enabled: false },
      { ...app(5, "Legacy console"), certificate_id: 2 },
    ];
    const certs = [
      {
        id: 1,
        name: "Applications TLS",
        validity: "valid",
        not_before: "2020-01-01T00:00:00Z",
        not_after: "2099-01-01T00:00:00Z",
        domains: ["*.example.test"],
        origin: "pem",
        assigned_sites: [],
      },
      {
        id: 2,
        name: "Expired TLS",
        validity: "expired",
        not_before: "2020-01-01T00:00:00Z",
        not_after: "2021-01-01T00:00:00Z",
        domains: ["*.example.test"],
        origin: "pem",
        assigned_sites: [],
      },
    ];
    const event = {
      id: 51,
      at: new Date().toISOString(),
      site_id: 1,
      peer: "203.0.113.7",
      method: "POST",
      status: 403,
      duration_ms: 2,
      blocked: true,
      signals: ["managed_signature"],
      rule_results: [],
      policy_id: 1,
      policy_name: "Public baseline",
      policy_revision: 2,
      managed_signatures: {
        set_id: "crs-fixture",
        mode: "block",
        rule_ids: [942100],
      },
    };
    const report = {
      at: new Date().toISOString(),
      minutes: 15,
      dropped_logs: 0,
      reporting_replicas: 1,
      connections: 1,
      inflight: 0,
      systems: [],
      totals: {
        requests: 40,
        blocked: 1,
        flagged: 2,
        exempt: 0,
        errors: 0,
        rps: 0.5,
        clients: 3,
        mean_duration_ms: 2,
      },
      series: [],
      countries: [],
      statuses: [],
      response_statuses: [],
      signals: [],
      recent: [event],
    };
    const rules = [
      {
        id: 942100,
        name: "SQL injection detection",
        category: "SQLI",
        tags: ["attack-sqli"],
        severity: "CRITICAL",
        phase: 2,
        paranoia_level: 1,
        selectable: true,
      },
      {
        id: 949110,
        name: "Anomaly scoring",
        category: "Scoring",
        tags: [],
        severity: "CRITICAL",
        phase: 2,
        paranoia_level: 1,
      },
    ];
    let failPolicies = false,
      failTraffic = false,
      delayTraffic,
      staleRelease;
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        url = new URL(req.url()),
        p = url.pathname;
      let json = [],
        status = 200;
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me")
        json = { username: "application-review", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 42 };
      if (p === "/api/sites")
        json = sites.map((s) => ({
          ...s,
          policies: policies.flatMap((p) =>
            p.applications
              .filter((a) => a.site_id === s.id)
              .map((a) => ({
                id: p.id,
                name: p.spec.name,
                mode: p.spec.mode,
                revision: p.revision,
                source_cidrs: a.source_cidrs,
                priority: a.priority,
              })),
          ),
        }));
      if (p === "/api/certificates") json = certs;
      if (p === "/api/policies") {
        json = policies;
        if (failPolicies) {
          status = 503;
          json = { error: "Unavailable" };
        }
      }
      if (p === "/api/signature-sets")
        json = [
          {
            id: "crs-fixture",
            name: "OWASP CRS",
            version: "4.30.0",
            rule_count: 2,
            digest: "a".repeat(64),
          },
        ];
      if (p === "/api/signature-sets/crs-fixture/rules") json = { rules };
      if (p === "/api/dashboard") {
        trafficScopes.push(url.searchParams.get("site_id"));
        if (delayTraffic) {
          delayTraffic = false;
          await new Promise((r) => (staleRelease = r));
        }
        json = {
          ...report,
          site_id: Number(url.searchParams.get("site_id")),
          ...(url.searchParams.get("site_id") === "2"
            ? {
                recent: [],
                totals: {
                  ...report.totals,
                  requests: 0,
                  blocked: 0,
                  flagged: 0,
                },
              }
            : {}),
        };
        if (failTraffic) {
          status = 503;
          json = { error: "Unavailable" };
        }
      }
      if (p === "/api/protection-settings")
        json = sites.map((s) => ({ site_id: s.id, settings: local }));
      if (p === "/api/access-logs/51")
        json = {
          event,
          application: {
            name: "Customer portal",
            current_hostnames: ["app1.example.test"],
          },
          managed_rules: rules,
          custom_rules: [],
          evidence_state: "not_captured",
          evidence: null,
          policy_snapshot: { ...base, mode: "block" },
        };
      if (req.method() !== "GET") {
        writes.push({ p, body: req.postDataJSON() });
        if (p === "/api/policies/1") {
          const b = req.postDataJSON();
          policies[0] = {
            id: 1,
            revision: 4,
            spec: b.spec,
            applications: b.applications,
          };
          json = { id: 1 };
        }
      }
      await route.fulfill({ status, json });
    });
    const url = `http://127.0.0.1:${server.address().port}/`;
    const go = async (hash) => {
      if (page.url() === url + "#" + hash) await page.reload();
      else await page.goto(url + "#" + hash);
      await page.locator("#view h1").waitFor();
    };
    await go("proxy-hosts"); // Existing bookmarks continue to work.
    await page
      .getByRole("heading", { name: "Applications", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("link", { name: "Applications", exact: true })
        .getAttribute("aria-current"),
      "page",
    );
    const row = page
      .locator("#application-list tr")
      .filter({ hasText: "Customer portal" });
    assert.match(await row.innerText(), /Observe/);
    assert.match(await row.innerText(), /Signatures Observe/);
    assert.match(await row.innerText(), /1 CIDR overrides/);
    await page.screenshot({
      path: path.join(artifacts, "applications-overview.png"),
      fullPage: true,
      animations: "disabled",
    });
    await page.getByLabel("Find an application").fill("app2.example");
    assert.equal(await page.locator("#application-list tbody tr").count(), 1);
    await page.getByLabel("Find an application").fill("no match");
    await page
      .getByRole("heading", { name: "No applications match" })
      .waitFor();
    await page.getByLabel("Find an application").fill("");
    await page
      .getByLabel("Filter applications", { exact: true })
      .selectOption("paused");
    assert.match(
      await page.locator("#application-list").innerText(),
      /Paused workspace/,
    );
    await page
      .getByLabel("Filter applications", { exact: true })
      .selectOption("attention");
    assert.equal(await page.locator("#application-list tbody tr").count(), 3);
    await page
      .getByLabel("Filter applications", { exact: true })
      .selectOption("all");
    await row.getByRole("link", { name: "Open", exact: true }).click();
    await page
      .getByRole("heading", { name: "Recent traffic", exact: true })
      .waitFor();
    assert.equal(trafficScopes.at(-1), "1");
    const baseline = page
      .locator(".application-policy")
      .filter({ hasText: "Default · all other clients" });
    for (const label of [
      "Request signatures",
      "Response inspection",
      "HTTP flood",
      "CIDR blocking",
      "Geo blocking",
    ]) {
      const component = baseline
        .locator(".application-components > div")
        .filter({ hasText: label });
      assert.equal(
        await component.locator(".badge").innerText(),
        "Observe",
        label,
      );
    }
    assert.match(await baseline.innerText(), /bypass all WAF protection/);
    assert.match(await baseline.innerText(), /Shared by 2 applications/);
    await page.screenshot({
      path: path.join(artifacts, "application-detail.png"),
      fullPage: true,
      animations: "disabled",
    });
    await page
      .getByRole("button", { name: "View details", exact: true })
      .click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Draft exception", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Draft exception", exact: true })
        .count(),
      1,
      "scoring rules cannot be excluded",
    );
    await page
      .getByRole("button", { name: "Draft exception", exact: true })
      .click();
    await page.locator("#policy-form").waitFor();
    assert.match(
      await page.locator("#policy-form").innerText(),
      /Unsaved exception.*request #51/,
    );
    assert.match(
      await page.locator("#policy-form").innerText(),
      /current policy \(v3\), shared by 2/,
    );
    const exception = page.locator(".policy-exception-row").last();
    assert.equal(
      await exception.getByLabel("Signature rule IDs").inputValue(),
      "942100",
    );
    assert.equal(
      await page.locator("#policy-form").evaluate((f) => f.checkValidity()),
      false,
      "unscoped drafts must not be saveable",
    );
    assert.equal(writes.length, 0);
    await exception.getByLabel("Request path prefix").fill("/search");
    await page.screenshot({
      path: path.join(artifacts, "request-exception-draft.png"),
      fullPage: true,
      animations: "disabled",
    });
    await page
      .getByRole("button", { name: "Save policy", exact: true })
      .click();
    await page.locator("#policy-form").waitFor({ state: "detached" });
    assert.equal(writes.length, 1);
    assert.deepEqual(writes[0].body.spec.managed_signatures.scoped_exclusions, [
      { rule_ids: [942100], path_prefix: "/search" },
    ]);
    assert.equal(
      writes[0].body.spec.mode,
      "observe",
      "current policy mode preserved",
    );
    assert.equal(writes[0].body.revision, 3);
    assert.equal(writes[0].body.applications.length, 2);
    await page
      .getByRole("heading", { name: "Recent traffic", exact: true })
      .waitFor();
    await page.getByRole("link", { name: "Open traffic dashboard" }).click();
    await page.locator("#dashboard-data .metric-grid").waitFor();
    assert.equal(
      await page.getByLabel("Application", { exact: true }).inputValue(),
      "1",
    );
    await page.goBack();
    await page
      .getByRole("heading", { name: "Customer portal", exact: true })
      .waitFor();
    // Historical matches must never draft against a different current set or create a replacement policy.
    await page
      .getByRole("heading", { name: "Recent traffic", exact: true })
      .waitFor();
    policies[0].spec.managed_signatures.set_id = "replacement-set";
    await page
      .getByRole("button", { name: "View details", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Draft exception", exact: true })
      .click();
    await page
      .locator("#form-message")
      .filter({ hasText: "different signature set" })
      .waitFor();
    assert.equal(await page.locator("#policy-form").count(), 0);
    policies[0].spec.managed_signatures.set_id = "crs-fixture";
    const removed = policies.shift();
    await page
      .getByRole("button", { name: "Review current policy", exact: true })
      .click();
    await page
      .locator("#form-message")
      .filter({ hasText: "no longer available" })
      .waitFor();
    assert.equal(await page.locator("#policy-form").count(), 0);
    assert.equal(writes.length, 1);
    policies.unshift(removed);
    await page
      .getByRole("button", { name: "Close dialog", exact: true })
      .click();
    await go("applications/2");
    await page
      .getByRole("heading", { name: "No requests recorded in this window" })
      .waitFor();
    await go("applications/4");
    assert.match(await page.locator("#view").innerText(), /Routing is paused/);
    await go("applications/5");
    assert.match(
      await page.locator("#view").innerText(),
      /Certificate expired/,
    );
    await go("applications/999");
    await page
      .getByRole("heading", { name: "Application unavailable" })
      .waitFor();
    failPolicies = true;
    await go("applications");
    assert.match(
      await page.locator("#application-list").innerText(),
      /Unavailable/,
    );
    assert.doesNotMatch(
      await page.locator("#application-list").innerText(),
      /Signatures Observe/,
    );
    failPolicies = false;
    failTraffic = true;
    await go("applications/1");
    await page.getByRole("heading", { name: "Traffic unavailable" }).waitFor();
    assert.match(
      await page.locator("#view").innerText(),
      /Protection by client scope/,
    );
    failTraffic = false;
    delayTraffic = true;
    await go("applications/1");
    for (let i = 0; !staleRelease && i < 100; i++)
      await page.waitForTimeout(10);
    assert.equal(typeof staleRelease, "function");
    await page
      .getByRole("link", { name: "All applications", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Applications", exact: true })
      .waitFor();
    staleRelease();
    await page.waitForTimeout(100);
    assert.equal(
      await page.locator("#application-traffic").count(),
      0,
      "late traffic must not overwrite navigation",
    );
    sites.push({
      ...app(6, "Untrusted <img src=x onerror=alert(1)> " + "x".repeat(100)),
      hostnames: ["a".repeat(63) + ".example.test"],
    });
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 950 });
      await go("applications");
      assert.equal(await page.locator("#view img").count(), 0);
      assert(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
        `overview overflow ${width}`,
      );
      await go("applications/1");
      await page
        .getByRole("heading", { name: "Recent traffic", exact: true })
        .waitFor();
      assert(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
        `detail overflow ${width}`,
      );
      if (width === 390)
        await page.screenshot({
          path: path.join(artifacts, "application-mobile.png"),
          fullPage: true,
          animations: "disabled",
        });
    }
    await page.setViewportSize({ width: 320, height: 950 });
    await go("applications/6");
    assert.equal(await page.locator("#view img").count(), 0);
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
      "long detail name overflow",
    );
    await page.setViewportSize({ width: 1440, height: 1050 });
    await go("applications/1");
    await page
      .getByRole("heading", { name: "Recent traffic", exact: true })
      .waitFor();
    assert.equal(
      await page
        .locator(".application-sections")
        .evaluate((el) => getComputedStyle(el).flexDirection),
      "row",
    );
    await page.getByRole("button", { name: "Switch color theme" }).click();
    await page.waitForTimeout(200);
    await page.screenshot({
      path: path.join(artifacts, "application-dark.png"),
      fullPage: true,
      animations: "disabled",
    });
    await page.setViewportSize({ width: 720, height: 500 });
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
      "200% layout equivalent",
    );
    sites = [];
    await go("applications");
    await page
      .getByRole("heading", {
        name: "Connect it. Choose protection. Verify traffic.",
      })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Request certificate", exact: true })
        .count(),
      1,
    );
    assert.deepEqual(errors, []);
    console.log(
      "PASS: application overview/detail, search, routing/TLS attention, effective modes, CIDR scopes, shared-policy exception draft/save, scoped traffic, legacy links, browser history, missing data, stale replies, escaping and responsive themes.",
    );
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
