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

  // rủi ro tổng hợp trên chi tiết alert: có giải thích, ghi rõ heuristic và không kích hoạt response
  await page.waitForSelector("#risk-panel table tbody tr");
  const riskText = await page.textContent("#risk-panel");
  out.risk_panel_says_uncalibrated = riskText.includes("heuristic chưa hiệu chỉnh");
  out.risk_panel_says_no_response = riskText.includes("không kích hoạt response");
  out.risk_panel_lists_ml_not_evaluated = riskText.includes("ML_STATIC") && riskText.includes("DISABLED");
  out.risk_panel_has_component_reason = riskText.includes("severity=");

  // raw xml: cần xác nhận
  await page.click("text=Xem raw XML (ghi audit)");
  await page.waitForSelector("dialog[open]");
  out.raw_requires_confirmation = (await page.textContent("dialog[open]")).includes("ghi vào audit");
  await page.click("dialog[open] >> text=Đóng");

  // D1: alert thiếu Event 1 của chính nó nhưng có tiến trình con -> cây vẫn hiện tiến trình con
  const orphanId = await page.evaluate(async (tok) => {
    const r = await fetch("/alerts?limit=50", { headers: { Authorization: "Bearer " + tok } });
    return ((await r.json()).items.find((a) => a.rule_name === "ui-orphan-parent") || {}).alert_id || null;
  }, tokApprover);
  out.d1_orphan_alert_found = !!orphanId;
  await page.goto(base + "/ui/#/alerts/" + orphanId);
  await page.waitForSelector(".tree");
  out.d1_tree_shows_descendant_when_root_missing = (await page.textContent(".tree")).includes("orphan_child.exe");
  out.d1_tree_says_root_missing = (await page.textContent(".tree")).includes("thiếu");

  // D2: /evidence lỗi thì trang chi tiết alert vẫn hiện các phần còn lại
  await page.route("**/alerts/*/evidence*", (r) => r.fulfill({ status: 500, contentType: "application/json",
    body: JSON.stringify({ error: { code: "E-INTERNAL", message: "lỗi nội bộ" } }) }));
  await page.goto(base + "/ui/#/overview"); await page.waitForSelector(".grid .card");      // rời trang để dựng lại, tránh dương tính giả
  await page.goto(base + "/ui/#/alerts/" + orphanId);
  out.d2_detail_renders_when_evidence_fails = await page.waitForSelector("h2 .tag.obs", { timeout: 4000 }).then(() => true, () => false);
  await page.unroute("**/alerts/*/evidence*");

  // D3: ô SHA-256 chỉ có ở loại sự kiện hỗ trợ lọc theo hash (process, file)
  const shaCount = async (kind) => { await page.goto(base + "/ui/#/events?kind=" + kind); await page.waitForSelector("form.filters");
    return await page.locator("input[name=sha256]").count(); };
  out.d3_sha256_filter_on_process_and_file = (await shaCount("process")) === 1 && (await shaCount("file")) === 1;
  out.d3_no_sha256_filter_on_registry_and_network = (await shaCount("registry")) === 0 && (await shaCount("network")) === 0;

  // trang rủi ro + cột rủi ro ở danh sách alert
  await page.goto(base + "/ui/#/alerts");
  await page.waitForSelector("table tbody tr .risk-badge");
  out.alerts_table_has_risk_column = (await page.locator("table thead th:has-text('Rủi ro')").count()) === 1;
  await page.goto(base + "/ui/#/risk");
  await page.waitForSelector("#risk-process table tbody tr");
  out.risk_rows = await page.locator("#risk-process table tbody tr").count();
  out.risk_page_labels_heuristic = (await page.textContent("main")).includes("heuristic chưa hiệu chỉnh");
  await page.locator("#risk-process table tbody tr").first().click();
  await page.waitForSelector("dialog[open] #risk-panel");
  out.risk_modal_has_components = (await page.textContent("dialog[open]")).includes("Thành phần");
  await page.keyboard.press("Escape");
  await page.screenshot({ path: shotDir + "/risk.png", fullPage: true });
  // /alerts/{id}/risk lỗi thì trang chi tiết vẫn hiện
  await page.route("**/alerts/*/risk", (r) => r.fulfill({ status: 500, contentType: "application/json",
    body: JSON.stringify({ error: { code: "E-INTERNAL", message: "lỗi nội bộ" } }) }));
  await page.goto(base + "/ui/#/overview"); await page.waitForSelector(".grid .card");
  await page.goto(base + "/ui/#/alerts/" + orphanId);
  out.detail_renders_when_risk_fails = await page.waitForSelector("h2 .tag.obs", { timeout: 4000 }).then(() => true, () => false);
  await page.unroute("**/alerts/*/risk");

  // ---- màn hình cây tiến trình (fixture SYNTHETIC) ----
  const G = (i) => "abababab-0000-0000-0000-" + String(i).padStart(12, "0");
  const treeUrl = (q) => base + "/ui/#/tree?" + new URLSearchParams(q).toString();
  const settled = (sel) => page.waitForFunction((s) => { const b = document.querySelector(s); return b && !b.querySelector(".state:not(.error)")?.textContent.includes("Đang tải") && b.children.length > 0; }, sel);
  out.tree_nav_link = (await page.locator("nav a[href='#/tree']").count()) === 1;
  await page.goto(base + "/ui/#/tree"); await page.waitForSelector("#tree-box .state");
  out.tree_empty_prompt = (await page.textContent("#tree-box")).includes("Nhập Host");
  // tìm theo image -> chọn -> cây
  await page.goto(treeUrl({ image: "tree_sim" })); await page.waitForSelector("#tree-box table tbody tr");
  out.tree_search_rows = await page.locator("#tree-box table tbody tr").count();
  await page.locator("#tree-box table tbody tr").first().click();
  await page.waitForSelector("#ptree .pnode.focus");
  const treeText = await page.textContent("#ptree");
  out.tree_focus_is_searched_process = (await page.textContent("#ptree .pnode.focus")).includes("tree_sim.exe");
  out.tree_no_data_parent_shown = treeText.includes("không có dữ liệu") && (await page.locator("#ptree .pnode.nodata").count()) === 1;
  out.tree_no_data_uses_child_parent_image = (await page.textContent("#ptree .pnode.nodata")).includes("userinit.exe");
  out.tree_has_ancestors = treeText.includes("explorer.exe") && treeText.includes("cmd.exe");
  out.tree_node_alert_badge = (await page.textContent("#ptree .pnode.focus")).includes("DACN-DET-001 · high");
  out.tree_node_risk_badge = (await page.locator("#ptree .pnode.focus .risk-badge").count()) === 1;
  out.tree_node_event_counts = (await page.textContent("#ptree .pnode.focus")).includes("file 27") && (await page.textContent("#ptree .pnode.focus")).includes("dns 1");
  out.tree_xss_text_only = (await page.evaluate(() => window.__xss === undefined)) && (await page.locator("img[src='x']").count()) === 0 && treeText.includes("<img src=x onerror") === false;
  // nút chi tiết của trọng tâm
  await page.waitForSelector("#node-events table tbody tr");
  const panel = await page.textContent("#node-panel");
  out.tree_panel_fields = panel.includes("tree_sim.exe --synthetic") && panel.includes("High") && panel.includes("ef".repeat(32)) && panel.includes("LAB\\user01");
  out.tree_panel_evidence_link = (await page.locator("#node-panel a.evidence-link[href^='#/alerts/']").count()) === 1;
  out.tree_panel_no_raw = !panel.includes("raw_data\"") && panel.includes("raw_xml chỉ xem qua Evidence");
  out.tree_events_first_page = await page.locator("#node-events table tbody tr").count();
  await page.click("#node-events button:has-text('Xem thêm sự kiện')");
  await page.waitForFunction(() => document.querySelectorAll("#node-events table tbody tr").length > 25);
  out.tree_events_more = await page.locator("#node-events table tbody tr").count();
  await page.screenshot({ path: shotDir + "/process_tree.png", fullPage: true });
  // chọn nút NO_DATA: giải thích trung thực, không bịa trường
  await page.click("#ptree .pnode.nodata");
  await page.waitForSelector("#node-panel h2 .badge.warn");
  const np = await page.textContent("#node-panel");
  out.tree_no_data_panel_honest = np.includes("Silver không có Event 1") && np.includes("userinit.exe") && !np.includes("image_path");
  // chọn tổ tiên cmd.exe (command line chứa payload XSS) -> chỉ là chữ
  await page.locator("#ptree .pnode", { hasText: "cmd.exe" }).click();
  await page.waitForSelector("#node-panel");
  out.tree_xss_in_panel_is_text = (await page.textContent("#node-panel")).includes("<img src=x onerror") && (await page.evaluate(() => window.__xss === undefined));
  // giới hạn số nút -> "xem thêm nhánh con"
  await page.goto(treeUrl({ hostname: "LAB-HOST-01", process_guid: G(2), max_nodes: "4" }));
  await page.waitForSelector("#ptree .pnode.focus");
  out.tree_limit_badge = (await page.textContent("#tree-box")).includes("đã chạm giới hạn 4 nút");
  out.tree_more_children_button = (await page.locator("#ptree button:has-text('Xem thêm nhánh con')").count()) >= 1;
  // không tìm thấy
  await page.goto(treeUrl({ hostname: "LAB-HOST-01", process_guid: G(77) }));
  await page.waitForSelector("#tree-box .state"); await settled("#tree-box");
  out.tree_not_found_state = (await page.textContent("#tree-box")).includes("Không tìm thấy tiến trình");
  // loading + lỗi
  await page.route("**/investigation/process-tree*", async (r) => { await new Promise((s) => setTimeout(s, 1200)); await r.continue(); });
  await page.goto(treeUrl({ hostname: "LAB-HOST-01", process_guid: G(3) }));
  await page.waitForSelector("#tree-box .state");
  out.tree_loading_state = (await page.textContent("#tree-box .state")).includes("Đang tải");
  await page.waitForSelector("#ptree");
  await page.unroute("**/investigation/process-tree*");
  await page.route("**/investigation/process-tree*", (r) => r.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: { code: "E-INTERNAL", message: "lỗi nội bộ" } }) }));
  await page.goto(base + "/ui/#/overview"); await page.waitForSelector(".grid .card");
  await page.goto(treeUrl({ hostname: "LAB-HOST-01", process_guid: G(3) }));
  await page.waitForSelector("#tree-box .state.error");
  out.tree_error_state = (await page.textContent("#tree-box .state.error")).includes("E-INTERNAL");
  await page.unroute("**/investigation/process-tree*");
  // từ chi tiết alert -> màn hình cây
  const treeAlertId = await page.evaluate(async (tok) => {
    const r = await fetch("/alerts?limit=50", { headers: { Authorization: "Bearer " + tok } });
    return ((await r.json()).items.find((a) => a.rule_name === "ui-tree-node") || {}).alert_id || null;
  }, tokApprover);
  await page.goto(base + "/ui/#/alerts/" + treeAlertId);
  await page.waitForSelector("#open-tree");
  await page.click("#open-tree");
  await page.waitForSelector("#ptree .pnode.focus");
  out.tree_opened_from_alert = (await page.textContent("#ptree .pnode.focus")).includes("tree_sim.exe") && (await page.locator("#tree-box a:has-text('Quay lại alert')").count()) === 1;
  out.tree_no_response_buttons = (await page.locator("main button:has-text('Duyệt'), main button:has-text('Gửi yêu cầu'), main button:has-text('TERMINATE')").count()) === 0;

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
  await page.goto(treeUrl({ hostname: "LAB-HOST-01", process_guid: G(3) })); await page.waitForSelector("#node-events table tbody tr");
  out.tree_mobile_no_horizontal_scroll = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
  await page.screenshot({ path: shotDir + "/process_tree_mobile.png", fullPage: true });

  out.no_external_requests = external.length === 0 ? true : external;
  console.log(JSON.stringify(out));
  await browser.close();
})().catch((e) => { console.log(JSON.stringify({ fatal: String(e) })); process.exit(1); });
