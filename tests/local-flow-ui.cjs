/* Isolated local-flow UX fixture: synthetic hosts/events, production component/CSS.
   Run BROWSER_EXECUTABLE=/opt/brave-bin/brave node tests/local-flow-ui.cjs. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const { execFileSync } = require("node:child_process");
(async () => {
  const root = path.resolve(__dirname, ".."),
    temp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-local-flow-"));
  const out = process.env.BROWSER_ARTIFACT_DIR || "/tmp/aegis-local-flow-ux";
  fs.mkdirSync(out, { recursive: true });
  execFileSync(
    path.join(root, "web/node_modules/.bin/esbuild"),
    [
      path.join(root, "web/src/local-flow.ts"),
      "--bundle",
      "--format=esm",
      "--outfile=" + path.join(temp, "flow.js"),
    ],
    { stdio: "pipe" },
  );
  const html =
    '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local flow fixture</title><link rel="stylesheet" href="/style.css"><body><main class="flow-fixture"><section class="dashboard-panel" id="flow"></section></main><script type="module" src="/fixture.js"></script></body></html>';
  const fixture = `import {mountLocalFlow} from '/flow.js';
 let update;window.flowFilter='';window.events=[];
 window.mountFlow=(count=4)=>{
  update?.dispose();window.flowFilter='';window.events=[];
  const names=['Jellyfin','Home Assistant','Sparks Manor Requests','TPOT'];
  const sites=Array.from({length:count},(_,n)=>({id:n+1,name:count===4?names[n]:'Proxy host '+String(n+1).padStart(3,'0'),hostnames:['app-'+(n+1)+'.example.test'],certificate_id:1,enabled:n!==3,upstream:'http://not-displayed:8000'}));
  if(count>12){sites[7].name='International customer portal with a very long descriptive application name';sites[7].hostnames=['a-very-long-customer-subdomain.department.example.test','other.example.test'];sites[8].hostnames=['*.example.test'];sites[9].name='<img src=x onerror=alert(1)> Untrusted name';}
  window.sites=sites;
  update=mountLocalFlow(document.querySelector('#flow'),sites,id=>{window.flowFilter=id;update(window.events.filter(e=>!id||String(e.site_id)===id),id)});
  window.updateFlow=(events,selected='',fresh=[])=>{window.events=events;window.flowFilter=selected;update(events,selected,fresh)};
  window.disposeFlow=()=>update.dispose();
 };window.mountFlow();`;
  const server = http.createServer((req, res) => {
    if (req.url === "/") {
      res.setHeader("Content-Type", "text/html");
      res.end(html);
    } else if (req.url === "/style.css") {
      res.setHeader("Content-Type", "text/css");
      res.end(
        fs.readFileSync(path.join(root, "web/src/style.css")) +
          "\n.flow-fixture{max-width:1200px;margin:40px auto;padding:0 20px}.flow-fixture .dashboard-panel{margin:0}",
      );
    } else if (req.url === "/flow.js") {
      res.setHeader("Content-Type", "application/javascript");
      res.end(fs.readFileSync(path.join(temp, "flow.js")));
    } else if (req.url === "/fixture.js") {
      res.setHeader("Content-Type", "application/javascript");
      res.end(fixture);
    } else res.writeHead(404).end();
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
        reducedMotion: "reduce",
      }),
      errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("http://127.0.0.1:" + server.address().port);
    await page.waitForFunction(() => !!window.mountFlow);
    const flow = page.locator("#flow");
    const load = async (count) => {
      await page.evaluate((n) => window.mountFlow(n), count);
      await page.waitForTimeout(70);
    };
    await load(4);
    await page.evaluate(() =>
      window.updateFlow([
        { site_id: 1, blocked: false },
        { site_id: 1, blocked: true },
        { site_id: 2, blocked: false },
        { site_id: 3, blocked: false },
      ]),
    );
    for (const theme of ["dark", "light"]) {
      await page.evaluate(
        (t) => (document.documentElement.dataset.theme = t),
        theme,
      );
      await flow.screenshot({
        path: path.join(out, "four-hosts-" + theme + ".png"),
      });
    }
    const pill = flow.locator('[data-flow-site="1"]');
    assert.ok(
      (await pill.boundingBox()).height <= 60,
      "hosts must be compact pills",
    );
    assert.equal(await pill.locator("[data-flow-blocked] b").innerText(), "1");
    await flow.getByRole("button", { name: "Jellyfin", exact: true }).focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => window.flowFilter), "1");
    assert.equal(
      await pill.locator("button").getAttribute("aria-pressed"),
      "true",
    );
    assert.equal(
      await flow
        .locator('[data-flow-site="2"] [data-flow-allowed] b')
        .innerText(),
      "—",
      "out-of-scope counts must not imply zero",
    );
    assert.equal(
      await page.evaluate(() => document.activeElement.dataset.flowFilter),
      "1",
      "selection must preserve keyboard focus",
    );
    assert.equal(
      await flow
        .getByRole("link", { name: "Open Jellyfin", exact: true })
        .getAttribute("href"),
      "https://app-1.example.test",
    );
    await flow
      .getByRole("button", { name: "All applications", exact: true })
      .click();
    assert.equal(await page.evaluate(() => window.flowFilter), "");
    await load(60);
    assert.equal(
      await flow.locator("[data-flow-site]").count(),
      12,
      "limit rendering to a page of hosts",
    );
    assert.ok(
      (await flow.boundingBox()).height < 650,
      "large inventories must not create a tall diagram",
    );
    await flow.getByRole("button", { name: "Next hosts", exact: true }).click();
    await flow.getByText("13–24 of 60 hosts", { exact: true }).waitFor();
    await flow
      .getByRole("button", { name: "Previous hosts", exact: true })
      .click();
    await flow.getByText("1–12 of 60 hosts", { exact: true }).waitFor();
    assert.equal(
      await flow.locator("img").count(),
      0,
      "host names must remain escaped text",
    );
    const search = flow.getByRole("searchbox", {
      name: "Find a proxy host",
      exact: true,
    });
    await search.fill("customer-subdomain");
    assert.equal(
      await flow.locator("[data-flow-site]").count(),
      1,
      "search must include hostnames",
    );
    await search.fill("nonexistent-host");
    await flow
      .getByText("No hosts match your search.", { exact: true })
      .waitFor();
    await flow
      .getByRole("button", { name: "Clear search", exact: true })
      .click();
    assert.equal(await search.inputValue(), "");
    await search.fill("Proxy host 055");
    await flow
      .getByRole("button", { name: "Proxy host 055", exact: true })
      .click();
    assert.equal(await page.evaluate(() => window.flowFilter), "55");
    assert.equal(await search.inputValue(), "");
    assert.equal(
      await page.evaluate(() => document.activeElement.dataset.flowFilter),
      "55",
      "search selection must retain focus",
    );
    await flow.getByText("49–60 of 60 hosts", { exact: true }).waitFor();
    await page.evaluate(() => window.updateFlow([], "2"));
    assert.equal(
      await flow.locator('[data-flow-filter="2"]').getAttribute("aria-pressed"),
      "true",
      "external filter must reveal its host page",
    );
    await flow
      .getByRole("button", { name: "All applications", exact: true })
      .click();
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.waitForTimeout(80);
      assert.ok(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
        "page overflow at " + width,
      );
      assert.ok(
        await flow.evaluate((el) => el.scrollWidth <= el.clientWidth + 1),
        "flow overflow at " + width,
      );
      await flow.screenshot({
        path: path.join(out, "sixty-hosts-" + width + ".png"),
      });
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.evaluate(() => (document.documentElement.style.zoom = "2"));
    await page.waitForTimeout(100);
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
      "overflow at 200% zoom",
    );
    await flow.screenshot({ path: path.join(out, "sixty-hosts-zoom.png") });
    await page.evaluate(() => (document.documentElement.style.zoom = ""));
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.waitForTimeout(120); // Let zoom reflow and media-change cleanup settle.
    const event = { site_id: 1, blocked: false };
    await page.evaluate((e) => window.updateFlow([e], "", [e]), event);
    const packet = flow.locator(".local-flow-packet");
    await packet.waitFor();
    const before = await packet.evaluate((n) => {
      const m = n.getCTM();
      return { x: m.e, y: m.f };
    });
    await page.waitForTimeout(150);
    const after = await packet.evaluate((n) => {
      const m = n.getCTM();
      return { x: m.e, y: m.f };
    });
    assert.ok(
      Math.hypot(before.x - after.x, before.y - after.y) > 0.1,
      "packets must actually move",
    );
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.waitForFunction(
      () => document.querySelectorAll(".local-flow-packet").length === 0,
    );
    assert.equal(await flow.locator(".local-flow-packet").count(), 0);
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.evaluate((e) => window.updateFlow([e], "", [e]), event);
    await page.evaluate(() => window.disposeFlow());
    assert.equal(
      await flow.locator(".local-flow-packet").count(),
      0,
      "cleanup must remove timers/effects",
    );
    await load(500);
    assert.equal(await flow.locator("[data-flow-site]").count(), 12);
    await search.fill("Proxy host 500");
    assert.equal(await flow.locator("[data-flow-site]").count(), 1);
    await load(0);
    await flow
      .getByText("Add a proxy host to see its traffic here.", { exact: true })
      .waitFor();
    assert.equal(await flow.locator(".local-flow-route").count(), 0);
    await load(1);
    assert.ok(
      (await flow.locator("[data-flow-site]").boundingBox()).width < 400,
      "a single host must not stretch into a large card",
    );
    await page.setViewportSize({ width: 320, height: 1000 });
    await flow
      .getByRole("button", { name: "Proxy host 001", exact: true })
      .click();
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
    );
    assert.deepEqual(errors, []);
    console.log(
      "PASS: compact local-flow pills, 0/4/60/500 hosts, search/pagination, filter/focus/link/count semantics, responsive themes/zoom, animation and cleanup.",
    );
  } finally {
    if (browser) await browser.close();
    await new Promise((r) => server.close(r));
    fs.rmSync(temp, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
