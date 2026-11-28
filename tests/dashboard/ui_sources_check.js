// Playwright: nguồn phát hiện DACN/Defender và khung script PowerShell (hạng mục 9, docs/architecture/w8). In JSON kết quả.
// Fixture SYNTHETIC; không phải kiểm thử tích hợp thật.
const { chromium } = require("playwright");
const [base, tokApprover, tokViewer, secret, shotDir] = process.argv.slice(2);
const out = {};
(async () => {
  const browser = await chromium.launch();
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  const external = [];
  page.on("request", (r) => { if (!r.url().startsWith(base)) external.push(r.url()); });
  const login = async (tok) => { await page.goto(base + "/ui/"); await page.evaluate(() => sessionStorage.clear());
    await page.goto(base + "/ui/"); await page.fill("#token", tok); await page.click("form.login button[type=submit]"); await page.waitForSelector("nav:not([hidden])"); };
  const rows = async () => { await page.waitForSelector("table tbody tr, .state:not(:has-text('Đang tải'))"); return page.locator("table tbody tr"); };
  const openAlert = async (text) => { await page.goto(base + "/ui/#/alerts"); const r = await rows();
    await r.filter({ hasText: text }).first().click(); await page.waitForSelector("h1"); };

  await login(tokApprover);
  await page.goto(base + "/ui/#/alerts");
  let r = await rows();
  const allText = await page.textContent("table");
  out.source_column_has_both = allText.includes("Defender") && allText.includes("DACN");
  await page.goto(base + "/ui/#/alerts?source=DEFENDER"); await page.waitForTimeout(300); r = await rows();
  const defRows = await r.allTextContents();
  out.filter_defender_only = defRows.length >= 1 && defRows.every((t) => t.includes("Defender"));
  out.filter_select_kept = (await page.inputValue("select[name=source]")) === "DEFENDER";
  await page.goto(base + "/ui/#/alerts?source=DACN"); await page.waitForTimeout(300); r = await rows();
  const dacnRows = await r.allTextContents();
  out.filter_dacn_excludes_defender = dacnRows.length >= 1 && dacnRows.every((t) => !t.includes("Defender"));
  await page.screenshot({ path: shotDir + "/alerts_sources.png" });

  await openAlert("Microsoft Defender phát hiện");
  await page.waitForSelector("#defender-panel");
  const dp = await page.textContent("#defender-panel");
  out.defender_panel_context = dp.includes("Virus:DOS/EICAR_Test_File") && dp.includes("không xác minh lại");
  await page.screenshot({ path: shotDir + "/defender_alert.png" });

  await openAlert("Script block PowerShell");
  await page.waitForSelector("#script-text");
  const masked = await page.textContent("#script-text");
  out.script_masked = masked.includes("«ĐÃ CHE»") && !masked.includes(secret);
  out.script_xss_rendered_as_text = masked.includes("<img") && (await page.evaluate(() => window.__xss)) === undefined;
  out.reveal_enabled_for_approver = await page.isEnabled("#script-reveal");
  await page.click("#script-reveal");
  await page.click("dialog#modal button.primary");
  await page.waitForSelector("#script-raw");
  out.reveal_shows_original = (await page.textContent("#script-raw")).includes(secret);
  await page.screenshot({ path: shotDir + "/script_reveal.png" });

  await login(tokViewer);
  await openAlert("Script block PowerShell");
  await page.waitForSelector("#script-text");
  out.reveal_disabled_for_viewer = !(await page.isEnabled("#script-reveal"));
  out.viewer_sees_no_secret = !(await page.textContent("body")).includes(secret);
  out.no_object_text = !(await page.textContent("body")).includes("[object");
  out.no_external_requests = external.length === 0 ? true : external;
  await browser.close();
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
