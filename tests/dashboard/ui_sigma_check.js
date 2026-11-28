// Playwright: alert Sigma trên dashboard. In JSON kết quả. Fixture SYNTHETIC.
const { chromium } = require("playwright");
const [base, tok, shotDir] = process.argv.slice(2);
const out = {};
(async () => {
  const browser = await chromium.launch();
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  const external = [];
  page.on("request", (r) => { if (!r.url().startsWith(base)) external.push(r.url()); });
  await page.goto(base + "/ui/"); await page.fill("#token", tok); await page.click("form.login button[type=submit]");
  await page.waitForSelector("nav:not([hidden])");
  const rows = async () => { await page.waitForSelector("table tbody tr, .state:not(:has-text('Đang tải'))"); return page.locator("table tbody tr"); };

  await page.goto(base + "/ui/#/alerts"); let r = await rows();
  const all = await page.textContent("table");
  out.source_column_has_sigma_and_dacn = all.includes("Sigma") && all.includes("DACN");
  await page.goto(base + "/ui/#/alerts?source=SIGMA"); await page.waitForTimeout(300); r = await rows();
  const sig = await r.allTextContents();
  out.filter_sigma_only = sig.length >= 1 && sig.every((t) => t.includes("Sigma") && t.includes("DACN-SIG-"));
  out.filter_select_kept = (await page.inputValue("select[name=source]")) === "SIGMA";
  await page.goto(base + "/ui/#/alerts?source=DACN"); await page.waitForTimeout(300); r = await rows();
  out.filter_dacn_excludes_sigma = (await r.allTextContents()).every((t) => !t.includes("DACN-SIG-"));
  await page.screenshot({ path: shotDir + "/alerts_sigma.png" });

  await page.goto(base + "/ui/#/alerts?source=SIGMA"); r = await rows();
  await r.filter({ hasText: "DACN-SIG-92626ddd" }).first().click();
  await page.waitForSelector("#sigma-panel");
  const p = await page.textContent("#sigma-panel");
  out.panel_explains = p.includes("selection") && p.includes("synthetic_only") && p.includes("CommandLine");
  out.panel_author = (await page.textContent("#sigma-author")).trim().length > 0;
  const href = await page.getAttribute("#sigma-source a", "href");
  out.panel_source_link = !!href && href.startsWith("https://github.com/SigmaHQ/sigma/blob/ddf1d4f87fd2") &&
    (await page.getAttribute("#sigma-source a", "rel")) === "noopener noreferrer";
  out.xss_rendered_as_text = p.includes("<img") && (await page.evaluate(() => window.__xss)) === undefined;
  await page.screenshot({ path: shotDir + "/sigma_alert.png", fullPage: true });

  await page.goto(base + "/ui/#/rules");
  await page.waitForSelector("#sigma-rules table");
  const sr = await page.textContent("#sigma-rules");
  out.rules_section = sr.includes("Đã nạp (28)") && sr.includes("Bị loại (0)") && sr.includes("ddf1d4f87fd2");
  await page.locator("#sigma-rules table tbody tr").filter({ hasText: "DACN-SIG-92626ddd" }).first().click();
  await page.waitForSelector("#sigma-source-text");
  out.rule_source_text = (await page.textContent("#sigma-source-text")).includes("detection:");
  await page.screenshot({ path: shotDir + "/sigma_rules.png", fullPage: true });
  out.no_external_requests = external.length === 0;
  await browser.close();
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
