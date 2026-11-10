const { chromium } = require("playwright");
const assert = require("node:assert/strict"),
  http = require("node:http"),
  fs = require("node:fs"),
  path = require("node:path");
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
    res.end(fs.readFileSync(file));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({
    executablePath: process.env.BROWSER_EXECUTABLE,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage({
        viewport: { width: 1440, height: 1050 },
      }),
      errors = [],
      writes = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("dialog", (d) => d.accept());
    const oidc = {
      name: "Microsoft Entra ID",
      type: "oidc",
      enabled: true,
      oidc: {
        issuer: "https://login.microsoftonline.com/TENANT-ID/v2.0",
        client_id: "",
        groups_claim: "roles",
        scopes: ["openid", "profile", "email"],
      },
    };
    const ldap = {
      name: "Active Directory",
      type: "ldap",
      enabled: true,
      ldap: {
        url: "ldaps://directory.example.test:636",
        bind_dn: "",
        user_base_dn: "",
        group_base_dn: "",
        user_filter: "(sAMAccountName={username})",
        username_attribute: "sAMAccountName",
        email_attribute: "mail",
        groups_attribute: "memberOf",
        group_filter: "(member={dn})",
        group_name_attribute: "cn",
      },
    };
    const providers = [],
      applications = [
        {
          site_id: 1,
          name: "Finance",
          hostnames: ["finance.example.test"],
          revision: 0,
          settings: {
            enabled: false,
            provider_id: 0,
            public_origin: "https://finance.example.test",
            allowed_groups: [],
            allow_any_authenticated: false,
            session_minutes: 30,
          },
        },
      ];
    let sessions = [
      {
        id: "session-opaque-value",
        site_id: 1,
        provider_id: 1,
        identity: { username: "alice" },
        expires_at: "2030-01-01T00:00:00Z",
      },
    ];
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        url = new URL(req.url()),
        p = url.pathname,
        m = req.method();
      let json = [];
      if (p === "/api/setup") json = { setup_required: false };
      if (p === "/api/me") json = { username: "admin", csrf: "fixture" };
      if (p === "/api/status")
        json = { database_available: true, configuration_version: 1 };
      if (p === "/api/identity-providers/presets") json = [oidc, ldap];
      if (p === "/api/identity-providers" && m === "GET") json = providers;
      if (p === "/api/identity-providers" && m === "POST") {
        const body = req.postDataJSON();
        writes.push({ p, body });
        const { secret, revision, clear_secret, ...settings } = body;
        const id = providers.length + 1;
        providers.push({
          id,
          revision: 1,
          settings,
          has_secret: !!secret,
          applications: [],
        });
        json = { id };
      }
      if (/^\/api\/identity-providers\/\d+$/.test(p) && m === "PUT") {
        const body = req.postDataJSON();
        writes.push({ p, body });
        const item = providers.find(
          (v) => v.id === Number(p.split("/").at(-1)),
        );
        assert.equal(body.revision, item.revision);
        const { secret, revision, clear_secret, ...settings } = body;
        item.settings = settings;
        item.revision++;
        json = { id: item.id };
      }
      if (p.endsWith("/test"))
        json = { ok: true, message: "TLS and provider connection verified." };
      if (p.endsWith("/groups"))
        json = {
          supported: true,
          truncated: false,
          groups: [
            {
              id: "CN=Finance,OU=Groups,DC=example,DC=test",
              name: "Finance <img src=x>",
            },
          ],
        };
      if (p === "/api/application-access") json = applications;
      if (p === "/api/application-access/1" && m === "PUT") {
        const body = req.postDataJSON();
        writes.push({ p, body });
        assert.equal(body.revision, applications[0].revision);
        const { revision, ...settings } = body;
        applications[0].settings = settings;
        applications[0].revision++;
        json = { saved: true };
      }
      if (p === "/api/application-sessions") json = sessions;
      if (p.startsWith("/api/application-sessions/") && m === "DELETE") {
        writes.push({ p });
        sessions = [];
        json = { revoked: true };
      }
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify(json),
      });
    });
    await page.goto(
      `http://127.0.0.1:${server.address().port}/#application-access`,
    );
    await page
      .getByRole("heading", { name: "Application access", exact: true })
      .waitFor();
    await page
      .getByRole("button", { name: "Add identity provider", exact: true })
      .click();
    await page.getByLabel("Client ID", { exact: true }).fill("aegis-client");
    await page
      .getByLabel("Client secret", { exact: true })
      .fill("secret-never-returned");
    await page.getByRole("button", { name: "Save provider and test" }).click();
    await page
      .getByRole("cell", { name: "Microsoft Entra ID", exact: true })
      .first()
      .waitFor();
    assert.equal(providers[0].settings.oidc.groups_claim, "roles");
    await page.getByRole("button", { name: "Configure access" }).click();
    await page
      .locator('#application-access-form [name="provider_id"]')
      .selectOption("1");
    await page
      .getByLabel("Public HTTPS origin")
      .fill("https://finance.example.test:443");
    assert.equal(
      await page.getByLabel("OIDC redirect URI").inputValue(),
      "https://finance.example.test/__aegis/auth/callback",
    );
    await page.getByLabel("Require sign-in for this application").check();
    await page
      .getByLabel("Allowed groups / roles (one per line)")
      .fill("Finance.Reader\nFinance.Admin");
    await page.getByRole("button", { name: "Save access settings" }).click();
    await page.getByText("Sign-in required", { exact: true }).waitFor();
    assert.deepEqual(applications[0].settings.allowed_groups, [
      "Finance.Reader",
      "Finance.Admin",
    ]);
    await page.locator('[data-access-action="provider"][data-id="1"]').click();
    assert.equal(
      await page.getByLabel("Client secret", { exact: true }).inputValue(),
      "",
    );
    await page.getByLabel("Display name").fill("Company identity");
    await page
      .getByRole("button", { name: "Save provider", exact: true })
      .click();
    await page
      .getByRole("cell", { name: "Company identity", exact: true })
      .first()
      .waitFor();
    assert.equal(
      writes.find((v) => v.p === "/api/identity-providers/1").body.secret,
      "",
    );
    await page
      .getByRole("button", { name: "Add identity provider", exact: true })
      .click();
    await page.getByLabel("Provider template").selectOption("1");
    await page
      .getByLabel("Service bind DN")
      .fill("CN=Reader,DC=example,DC=test");
    await page.getByLabel("Service bind password").fill("directory-secret");
    await page
      .getByLabel("User search base DN")
      .fill("OU=People,DC=example,DC=test");
    await page
      .getByLabel("Group search base DN")
      .fill("OU=Groups,DC=example,DC=test");
    await page.getByRole("button", { name: "Save provider and test" }).click();
    await page
      .getByRole("cell", { name: "Active Directory", exact: true })
      .waitFor();
    await page.getByRole("button", { name: "Configure access" }).click();
    await page
      .locator('#application-access-form [name="provider_id"]')
      .selectOption("2");
    await page.getByLabel("Allowed groups / roles (one per line)").fill("");
    await page
      .getByRole("button", { name: "Search groups", exact: true })
      .click();
    await page.getByRole("button", { name: "Add Finance <img src=x>" }).click();
    assert.equal(await page.locator("#access-group-results img").count(), 0);
    await page.getByRole("button", { name: "Save access settings" }).click();
    await page.locator("#editor[open]").waitFor({ state: "hidden" });
    assert.deepEqual(applications[0].settings.allowed_groups, [
      "CN=Finance,OU=Groups,DC=example,DC=test",
    ]);
    await page.getByRole("button", { name: "Revoke", exact: true }).click();
    await page.getByText("No active application sessions.").waitFor();
    await page.getByRole("button", { name: "Configure access" }).click();
    await page.getByLabel("Who can sign in?").selectOption("any");
    assert.equal(await page.locator("#access-any-help").isVisible(), true);
    assert.equal(await page.locator("#access-groups").isVisible(), false);
    await page.getByRole("button", { name: "Save access settings" }).click();
    await page.locator("#editor[open]").waitFor({ state: "hidden" });
    assert.equal(applications[0].settings.allow_any_authenticated, true);
    assert.deepEqual(applications[0].settings.allowed_groups, []);
    const dir =
      process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-application-access-ui";
    fs.mkdirSync(dir, { recursive: true });
    await page.screenshot({
      path: path.join(dir, "access-desktop.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: path.join(dir, "access-mobile.png"),
      fullPage: true,
    });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > window.innerWidth + 1,
      ),
      false,
      "page overflows mobile viewport",
    );
    assert.deepEqual(errors, []);
    console.log(
      "Application access UI: provider templates, secret preservation, groups, sessions, and mobile layout passed",
    );
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
