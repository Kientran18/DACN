// Kiểm thử giao diện bằng Playwright (Node). In JSON {check: true/false/chi tiết}. KHÔNG phải kiểm thử tích hợp thật:
// chạy với API + DuckDB fixture synthetic (data_label=SAMPLE).
const { chromium } = require("playwright");
const [base, tokApprover, tokViewer, shotDir] = process.argv.slice(2);
const out = {};
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  const external = [];
  page.on("request", (r) => { if (!r.url().startsWith(base)) external.push(r.url()); });
  const dialogs = [];
  page.on("dialog", (d) => { dialogs.push(d.message()); d.dismiss(); });
  const login = async (tok) => { await page.goto(base + "/ui/"); await page.evaluate(() => sessionStorage.clear());
    await page.goto(base + "/ui/"); await page.fill("#token", tok); await page.click("form.login button[type=submit]"); await page.waitForSelector("nav:not([hidden])"); };

  await page.goto(base + "/ui/"); await page.evaluate(() => sessionStorage.clear()); await page.goto(base + "/ui/");
  out.login_form_when_no_token = await page.isVisible("form.login");
  await page.fill("#token", "sai-token"); await page.click("form.login button[type=submit]");
  await page.waitForSelector(".state.error[role=alert]");
  out.bad_token_shows_error = (await page.textContent(".state.error")).includes("Token không hợp lệ");

  await login(tokApprover);
  await page.waitForSelector(".grid .card");
  out.sample_banner_visible = await page.isVisible("#sample-banner");
  out.sample_banner_text = (await page.textContent("#sample-banner")).includes("DỮ LIỆU MẪU");
  out.mode_badge_dry_run = (await page.textContent("#mode-badge")).includes("DRY-RUN");
  out.overview_no_object_text = !(await page.textContent("body")).includes("[object");
  out.overview_has_alert_row = (await page.locator("table tbody tr").count()) >= 1;
  out.timezone_labelled_utc = (await page.textContent("body")).includes("UTC");
  await page.screenshot({ path: shotDir + "/overview.png" });

  // loading: làm chậm API để thấy trạng thái "Đang tải…"
  await page.route("**/events*", async (r) => { await new Promise((s) => setTimeout(s, 1200)); await r.continue(); });
  await page.goto(base + "/ui/#/events?kind=process");
  await page.waitForSelector(".state");
  out.loading_state_shown = (await page.textContent(".state")).includes("Đang tải");
  await page.waitForSelector("table tbody tr");
  await page.unroute("**/events*");

  // events: rỗng + có dữ liệu
  await page.goto(base + "/ui/#/events?kind=process&hostname=KHONG-TON-TAI");
  await page.waitForFunction(() => { const s = document.querySelector(".state"); return s && !s.textContent.includes("Đang tải"); });
  out.events_empty_state = (await page.textContent(".state")).includes("Không có sự kiện");
  await page.goto(base + "/ui/#/events?kind=process");
  await page.waitForSelector("table tbody tr");
  out.events_rows = await page.locator("table tbody tr").count();
  await page.locator("table tbody tr").first().click();
  await page.waitForSelector("dialog[open] pre");
  out.event_modal_has_no_raw_data = !(await page.textContent("dialog[open] pre")).includes('"raw_data"');
  await page.keyboard.press("Escape");

  // alerts + XSS
  await page.goto(base + "/ui/#/alerts");
  await page.waitForSelector("table tbody tr");
  out.alerts_rows = await page.locator("table tbody tr").count();
  await page.locator("table tbody tr").first().click();
  await page.waitForSelector("h2 .tag.obs");
  out.three_labels = (await page.locator(".tag.obs").count()) >= 1 && (await page.locator(".tag.inf").count()) >= 1 && (await page.locator(".tag.gap").count()) >= 1;
  out.xss_not_executed = (await page.evaluate(() => window.__xss === undefined)) && dialogs.length === 0;
  out.xss_payload_shown_as_text = (await page.textContent("body")).includes("<img src=x onerror");
  out.no_injected_img = (await page.locator("img[src='x']").count()) === 0;
  out.no_object_object_text = !(await page.textContent("body")).includes("[object");
  out.evidence_status_shown = (await page.textContent("body")).includes("Trạng thái:");
  await page.waitForSelector("#alert-response table tbody tr");
  out.alert_detail_shows_response_action = (await page.textContent("#alert-response")).includes("QUARANTINE_FILE");
  await page.screenshot({ path: shotDir + "/alert_detail.png", fullPage: true });

  // raw xml: cần xác nhận
  await page.click("text=Xem raw XML (ghi audit)");
  await page.waitForSelector("dialog[open]");
  out.raw_requires_confirmation = (await page.textContent("dialog[open]")).includes("ghi vào audit");
  await page.click("dialog[open] >> text=Đóng");

  // response
  await page.goto(base + "/ui/#/response");
  await page.waitForSelector(".mode-big");
  out.response_mode_prominent = (await page.textContent(".card .mode-big")).includes("DRY-RUN");
  out.approver_can_request = !(await page.locator("button:has-text('Gửi yêu cầu')").isDisabled());
  await page.screenshot({ path: shotDir + "/response.png" });

  // rules
  await page.goto(base + "/ui/#/rules");
  await page.waitForSelector("table tbody tr");
  out.rules_rows = await page.locator("table tbody tr").count();

  // viewer: không được ghi
  await login(tokViewer);
  await page.goto(base + "/ui/#/response");
  await page.waitForSelector("button:has-text('Gửi yêu cầu')");
  out.viewer_cannot_request = await page.locator("button:has-text('Gửi yêu cầu')").isDisabled();

  // mobile
  await page.setViewportSize({ width: 390, height: 800 });
  await page.goto(base + "/ui/#/overview"); await page.waitForSelector(".grid .card");
  out.mobile_no_horizontal_scroll = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
  await page.screenshot({ path: shotDir + "/overview_mobile.png" });

  out.no_external_requests = external.length === 0 ? true : external;
  console.log(JSON.stringify(out));
  await browser.close();
})().catch((e) => { console.log(JSON.stringify({ fatal: String(e) })); process.exit(1); });
