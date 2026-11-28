"use strict";
/* DACN EDR Dashboard (PH9). JS thuần, không thư viện, không CDN.
   AN TOÀN: mọi dữ liệu từ API (có thể do kẻ tấn công kiểm soát: command line, tên tệp) chỉ được đưa vào DOM bằng
   textContent. KHÔNG dùng innerHTML/insertAdjacentHTML/outerHTML/document.write trong tệp này. */

const TOKEN_KEY = "dacn_token";          // sessionStorage: mất khi đóng tab
const state = { me: null, health: null };
const $ = (id) => document.getElementById(id);
const view = $("view");

// ---------- DOM helper (an toàn) ----------
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
const fmt = (v) => (v === null || v === undefined || v === "" ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v));
function utc(v) {                         // luôn hiển thị UTC rõ ràng
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d) ? String(v) : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "") + " UTC";
}
const badge = (text, kind) => h("span", { class: "badge " + (kind || ""), text });
const sevKind = (s) => ({ critical: "bad", high: "bad", medium: "warn", low: "ok" }[s] || "");
const riskBadge = (r) => r ? h("span", { class: "badge risk-badge " + sevKind(r.level), text: r.level + " · " + r.score }) : h("span", { class: "muted", text: "—" });
const riskKey = (host, guid) => host + "|" + guid;
// Nguồn phát hiện: "Defender" = DACN chỉ phản ánh phát hiện của Microsoft Defender (không xác minh lại); "DACN" = rule của DACN.
// Suy luận nối sự kiện Defender/PowerShell với tiến trình Sysmon (GET /alerts/{id}/process-links). Không phải bằng chứng.
const linkKind = (c) => ({ UNIQUE: "ok", AMBIGUOUS: "warn", NONE: "", NOT_APPLICABLE: "" }[c] || "");
function linksPanel(id, a) {
  const box = h("div", { id: "links-panel" });
  load(box, () => api("/alerts/" + id + "/process-links"), (r) => {
    if (!r.events.length) { box.append(empty("Không có sự kiện Defender/PowerShell để nối.")); return; }
    for (const ev of r.events) for (const l of ev.links) {
      box.append(h("div", { class: "card" },
        h("p", {}, badge(l.confidence, linkKind(l.confidence)), " " + l.method + " — " + l.basis),
        h("p", { class: "muted", text: l.note || "" }),
        l.candidates.length ? table([
          { label: "Tiến trình", render: (c) => fmt(c.image_path), wrap: true }, { key: "pid", label: "PID" },
          { label: "Bắt đầu / tạo tệp", render: (c) => utc(c.start_utc || c.file_event_utc) },
          { label: "Cây tiến trình", render: (c) => h("a", { class: "link-tree", href: treeHash({ hostname: ev.hostname, process_guid: c.process_guid, alert: id }), text: "mở →" }) }],
          l.candidates) : empty(l.confidence === "NOT_APPLICABLE" ? "Không đủ dữ liệu để nối." : "Không tìm thấy tiến trình ứng viên trong Silver.")));
    }
    box.append(h("p", { class: "muted", text: "Cửa sổ nhìn lại " + r.lookback_hours + " giờ (heuristic). " + r.note }));
  });
  return box;
}
// "Sigma" = rule cộng đồng Sigma dịch sang DACN (synthetic_only, chưa kiểm chứng trên dữ liệu thật của DACN).
const sourceBadge = (a) => badge(a.source_label || "DACN", a.source_label === "Defender" ? "ext" : a.source_label === "Sigma" ? "sigma" : "");
// Link ra ngoài chỉ khi là https (dữ liệu từ API, không tin cậy); mở tab mới, không gửi referrer.
const extLink = (url, text) => (typeof url === "string" && url.startsWith("https://"))
  ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: text || url }) : h("span", { class: "muted", text: fmt(url) });
async function riskMap() {            // điểm theo (host, process_guid); lỗi thì bảng alert vẫn hiện, cột rủi ro để "—"
  try { const d = await api("/risk/subjects?kind=process&limit=500"); const m = {}; for (const i of d.items) m[riskKey(i.subject.hostname, i.subject.process_guid)] = i; return m; }
  catch (e) { if (e.status === 401) throw e; return {}; }
}
function riskPanel(r) {               // giải thích đầy đủ: thành phần, nguồn, trọng số, lý do, phần chưa đánh giá, khoảng trống dữ liệu
  const subj = r.subject.kind === "process" ? "tiến trình " + r.subject.process_guid + " @ " + r.subject.hostname
    : "host " + r.subject.hostname + " (cửa sổ " + r.subject.window_seconds + " giây đến " + utc(r.subject.window_end) + ")";
  return h("div", { id: "risk-panel", class: "card" },
    h("p", {}, riskBadge(r), " ", h("span", { text: "Chủ thể: " + subj })),
    h("p", { class: "muted", text: "Cấu hình v" + r.config.version + " (" + r.config.status + ") — heuristic chưa hiệu chỉnh trên dữ liệu có nhãn; điểm chỉ để ưu tiên điều tra, không kích hoạt response. Độ đầy đủ: " + r.completeness }),
    h("p", { class: "muted", text: "Công thức: " + r.formula + " · thưởng đa dạng: " + r.diversity_bonus }),
    h("h3", { text: "Thành phần" }),
    r.components.length ? table([{ key: "category", label: "Cơ chế" }, { key: "label", label: "Nguồn", wrap: true },
      { label: "Điểm gốc", render: (c) => fmt(c.base_points) }, { label: "Trọng số", render: (c) => fmt(c.weight) },
      { label: "Điểm", render: (c) => c.included ? fmt(c.points) : badge("không tính", "warn") }, { key: "reason", label: "Lý do", wrap: true }], r.components)
      : empty("Không có tín hiệu nào được tính cho chủ thể này."),
    h("h3", { text: "Chưa đánh giá" }),
    r.not_evaluated.length ? h("ul", {}, r.not_evaluated.map((x) => h("li", { text: x.source + ": " + x.reason }))) : h("p", { class: "muted", text: "không có" }),
    h("h3", { text: "Khoảng trống dữ liệu (không cộng điểm)" }),
    r.data_gaps.length ? h("ul", {}, r.data_gaps.map((g) => h("li", { text: g.rule_id + " thiếu " + (g.missing_fields || []).join(", ") + " (" + g.coverage_status + ")" }))) : h("p", { class: "muted", text: "không có" }));
}

// ---------- API ----------
class ApiErr extends Error { constructor(status, code, msg) { super(msg); this.status = status; this.code = code; } }
async function api(path, opts = {}) {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: { "Authorization": "Bearer " + token, ...(opts.body ? { "Content-Type": "application/json" } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* không phải JSON */ }
  if (res.status === 401) { sessionStorage.removeItem(TOKEN_KEY); showLogin("Token không hợp lệ hoặc đã hết hiệu lực."); throw new ApiErr(401, "E-UNAUTHENTICATED", "unauthenticated"); }
  if (!res.ok) throw new ApiErr(res.status, data?.error?.code || "E-HTTP", data?.error?.message || ("Lỗi " + res.status));
  return data;
}
const qs = (o) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== "" && v != null) p.set(k, v); const s = p.toString(); return s ? "?" + s : ""; };
const can = (perm) => !!state.me && state.me.permissions.includes(perm);

// ---------- trạng thái loading / rỗng / lỗi ----------
async function load(container, fn, render) {
  clear(container).append(h("div", { class: "state", text: "Đang tải…" }));
  try {
    const data = await fn();
    clear(container);
    render(data);
  } catch (e) {
    if (e.status === 401) return;
    clear(container).append(h("div", { class: "state error", role: "alert", text: "Lỗi: " + (e.code ? e.code + " — " : "") + e.message }));
  }
}
const empty = (why) => h("div", { class: "state", text: why });

function table(cols, rows, onClick) {
  const t = h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", { text: c.label })))));
  const tb = h("tbody");
  for (const r of rows) {
    const tr = h("tr", { class: onClick ? "click" : "", tabIndex: onClick ? 0 : undefined });
    for (const c of cols) {
      const v = c.render ? c.render(r) : fmt(r[c.key]);
      tr.append(h("td", { class: c.wrap ? "wrap" : "" }, v));
    }
    if (onClick) { tr.addEventListener("click", () => onClick(r)); tr.addEventListener("keydown", (e) => { if (e.key === "Enter") onClick(r); }); }
    tb.append(tr);
  }
  t.append(tb);
  return h("div", { class: "table-wrap" }, t);
}

// ---------- modal ----------
function modal(title, body, buttons) {
  const m = $("modal"), b = clear($("modal-body"));
  b.append(h("h2", { text: title }), body, h("div", { class: "actions" }, buttons.map((x) =>
    h("button", { type: "button", class: x.kind || "", text: x.label, onclick: () => { if (x.close !== false) m.close(); x.fn && x.fn(); } }))));
  if (!m.open) m.showModal();
}
const closeBtn = { label: "Đóng" };

// ---------- đăng nhập ----------
function showLogin(msg) {
  $("nav").hidden = true; $("logout").hidden = true; $("whoami").textContent = ""; $("mode-badge").hidden = true;
  const inp = h("input", { type: "password", id: "token", autocomplete: "off", required: true, "aria-label": "API token" });
  const form = h("form", { class: "card login", onsubmit: async (e) => {
    e.preventDefault(); sessionStorage.setItem(TOKEN_KEY, inp.value); inp.value = ""; await boot();
  } }, h("h1", { text: "Đăng nhập" }), msg ? h("p", { class: "state error", role: "alert", text: msg }) : null,
    h("label", {}, "API token (tạo bằng python -m api.auth)", inp), h("div", { class: "actions" }, h("button", { class: "primary", type: "submit", text: "Vào" })));
  clear(view).append(form);
}

// ---------- header ----------
function paintHeader() {
  const h0 = state.health;
  $("sample-banner").hidden = !(h0 && h0.data_label === "SAMPLE");
  const mb = $("mode-badge");
  if (h0) {
    const dry = h0.response.mode !== "execute" || !h0.response.execute_unlocked;
    mb.textContent = dry ? "RESPONSE: DRY-RUN (không thay đổi hệ thống)" : "RESPONSE: EXECUTE (đang mở khóa)";
    mb.className = "badge mode-big " + (dry ? "ok" : "bad"); mb.hidden = false;
  }
  $("whoami").textContent = state.me ? state.me.actor + " · " + state.me.role : "";
  $("nav").hidden = false; $("logout").hidden = false;
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", location.hash.startsWith(a.getAttribute("href"))));
}

// ---------- trang: tổng quan ----------
async function pageOverview() {
  view.append(h("h1", { text: "Tổng quan" }));
  const box = h("div"); view.append(box);
  await load(box, async () => {
    const [health, stats, latest, risks] = await Promise.all([api("/health"), api("/stats"), api("/alerts?limit=5"), riskMap()]);
    state.health = health; paintHeader();
    return { health, stats, latest, risks, at: new Date() };
  }, ({ health, stats, latest, risks, at }) => {
    const ag = health.agent, pl = health.pipeline, en = health.engine;
    box.append(h("p", { class: "muted", text: "Cập nhật lúc " + utc(at) + " · nguồn dữ liệu: " + (health.data_label === "SAMPLE" ? "MẪU (synthetic)" : "chưa xác nhận") }));
    box.append(h("div", { class: "grid" },
      h("div", { class: "card" }, h("h3", { text: "Agent" }), h("dl", { class: "kv" },
        h("dt", { text: "Trạng thái" }), h("dd", {}, badge(ag.status, { UNKNOWN: "warn", STALE: "bad", ERROR: "bad" }[ag.status] || "ok")),
        ag.heartbeat ? [h("dt", { text: "Heartbeat" }), h("dd", { text: utc(ag.heartbeat) + (ag.heartbeat_age_s != null ? " (" + Math.round(ag.heartbeat_age_s) + " giây trước)" : "") }), h("dt", { text: "Sự kiện ghi" }), h("dd", { text: fmt(ag.events_written) })] : [h("dt", { text: "Ghi chú" }), h("dd", { text: ag.note || "—" })])),
      h("div", { class: "card" }, h("h3", { text: "Pipeline" }), h("dl", { class: "kv" },
        h("dt", { text: "Segment đã nạp" }), h("dd", { text: fmt(pl.segments_ingested) }),
        h("dt", { text: "Bản ghi đọc" }), h("dd", { text: fmt(pl.records_read) }),
        h("dt", { text: "Quarantine" }), h("dd", { text: fmt(pl.records_quarantined) + " (DLQ: " + fmt(pl.dlq_rows) + ")" }),
        h("dt", { text: "Lần nạp cuối" }), h("dd", { text: utc(pl.last_ingest_utc) }),
        health.core && health.core.last_error ? [h("dt", { text: "Lỗi core gần nhất" }), h("dd", {}, badge(health.core.last_error.type + " · " + utc(health.core.last_error.at_utc), "bad"))] : null)),
      h("div", { class: "card" }, h("h3", { text: "Detection engine" }), h("dl", { class: "kv" },
        h("dt", { text: "Rule" }), h("dd", { text: en.rules_enabled + " bật / " + en.rules_loaded + " nạp" }),
        h("dt", { text: "Audit chain" }), h("dd", {}, badge(health.audit_chain_ok ? "nguyên vẹn" : "PHÁT HIỆN BẤT THƯỜNG", health.audit_chain_ok ? "ok" : "bad")))),
      h("div", { class: "card" }, h("h3", { text: "Khoảng trống telemetry" }), h("p", { text: fmt(stats.coverage_gaps) + " mục (INSUFFICIENT_TELEMETRY — không phải cảnh báo đe dọa)" }))));
    box.append(h("h2", { text: "Alert theo mức độ" }));
    const sev = stats.alerts_by_severity, total = Object.values(sev).reduce((a, b) => a + b, 0);
    box.append(total === 0 ? empty("Chưa có alert nào. (Chưa có dữ liệu phù hợp rule, hoặc chưa chạy engine.)")
      : h("div", { class: "bars" }, ["critical", "high", "medium", "low"].filter((s) => sev[s]).map((s) =>
        h("div", { class: "row" }, h("span", { text: s }), h("div", { class: "bar", style: "width:" + Math.round((sev[s] / total) * 100) + "%" }), h("span", { text: sev[s] })))));
    box.append(h("h2", { text: "Alert mới nhất" }), latest.items.length === 0 ? empty("Không có alert.") : alertTable(latest.items, risks));
  });
}

// ---------- trang: telemetry ----------
const EV_COLS = {
  process: [["timestamp", "Thời gian"], ["sysmon_event_id", "Event"], ["hostname", "Host"], ["image_path", "Image"], ["command_line", "Command line"]],
  file: [["timestamp", "Thời gian"], ["sysmon_event_id", "Event"], ["hostname", "Host"], ["file_path", "Đường dẫn"], ["image_path", "Process"]],
  registry: [["timestamp", "Thời gian"], ["sysmon_event_id", "Event"], ["hostname", "Host"], ["target_object", "Khóa"], ["details", "Giá trị"]],
  network: [["timestamp", "Thời gian"], ["sysmon_event_id", "Event"], ["hostname", "Host"], ["dest_ip", "Đích"], ["dns_query_name", "DNS"]],
};
async function pageEvents() {
  const f = Object.fromEntries(new URLSearchParams(location.hash.split("?")[1] || ""));
  f.kind = f.kind || "process"; const offset = parseInt(f.offset || "0", 10), limit = 25;
  view.append(h("h1", { text: "Telemetry Explorer" }));
  const field = (name, label, type) => h("label", {}, label, h("input", { name, type: type || "text", value: f[name] || "" }));
  const form = h("form", { class: "filters", onsubmit: (e) => {
    e.preventDefault(); const d = new FormData(form), p = {};
    for (const [k, v] of d.entries()) if (v) p[k] = k.startsWith("since") || k.startsWith("until") ? new Date(v + "Z").toISOString() : v;
    location.hash = "#/events" + qs(p);
  } },
    h("label", {}, "Loại", h("select", { name: "kind" }, Object.keys(EV_COLS).map((k) => h("option", { value: k, text: k, selected: k === f.kind })))),
    field("hostname", "Host"), field("process_guid", "process_guid"), field("sysmon_event_id", "Event ID", "number"),
    ["process", "file"].includes(f.kind) ? field("sha256", "SHA-256") : null,          // API chỉ lọc hash cho process/file
    f.kind === "file" ? field("file_path", "Đường dẫn tệp") : field("image_path", "Image path"),
    h("label", {}, "Từ (UTC)", h("input", { name: "since", type: "datetime-local" })), h("label", {}, "Đến (UTC)", h("input", { name: "until", type: "datetime-local" })),
    h("button", { class: "primary", type: "submit", text: "Lọc" }));
  const box = h("div"); view.append(form, box);
  const params = { ...f, limit, offset }; delete params.offset; params.offset = offset;
  await load(box, () => api("/events" + qs(params)), (d) => {
    if (!d.items.length) { box.append(empty(offset > 0 ? "Hết dữ liệu ở trang này." : "Không có sự kiện khớp bộ lọc (hoặc chưa có dữ liệu được nạp).")); }
    else {
      const cols = EV_COLS[f.kind].map(([key, label]) => ({ key, label, wrap: key !== "timestamp", render: key === "timestamp" ? (r) => utc(r[key]) : undefined }));
      box.append(table(cols, d.items, (r) => modal("Chi tiết sự kiện (Silver)", h("pre", { text: JSON.stringify(r, null, 2) }), [closeBtn])));
      box.append(h("p", { class: "muted", text: "raw_data/raw_xml không hiển thị ở đây: chỉ xem qua Evidence của alert (có kiểm soát quyền và ghi audit)." }));
    }
    const go = (o) => { const p = { ...f, offset: o }; location.hash = "#/events" + qs(p); };
    box.append(h("div", { class: "pager" }, h("button", { type: "button", text: "← Trước", disabled: offset === 0, onclick: () => go(Math.max(0, offset - limit)) }),
      h("span", { class: "muted", text: "Dòng " + (offset + 1) + "–" + (offset + d.items.length) }),
      h("button", { type: "button", text: "Sau →", disabled: d.items.length < limit, onclick: () => go(offset + limit) })));
  });
}

// ---------- trang: alerts ----------
function alertTable(items, risks) {
  return table([
    { label: "Mức", render: (a) => badge(a.severity, sevKind(a.severity)) },
    { label: "Nguồn", render: sourceBadge },
    { label: "Rủi ro", render: (a) => riskBadge(risks && a.process_guid ? risks[riskKey(a.hostname, a.process_guid)] : null) },
    { label: "Rule", render: (a) => a.rule_id + " v" + a.rule_version }, { key: "rule_name", label: "Tên", wrap: true },
    { label: "Trạng thái", render: (a) => badge(a.status) }, { key: "hostname", label: "Host" },
    { label: "Lần đầu", render: (a) => utc(a.first_seen_utc) }, { key: "occurrence_count", label: "Số lần" }, { key: "coverage_status", label: "Độ phủ" },
  ], items, (a) => { location.hash = "#/alerts/" + a.alert_id; });
}
async function pageAlerts() {
  const f = Object.fromEntries(new URLSearchParams(location.hash.split("?")[1] || ""));
  view.append(h("h1", { text: "Alerts" }));
  const sel = h("select", { name: "status" }, [""].concat(["NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"]).map((s) => h("option", { value: s, text: s || "(tất cả)", selected: s === (f.status || "") })));
  const src = h("select", { name: "source" }, [["", "(tất cả)"], ["DACN", "DACN (rule của DACN)"], ["SIGMA", "Sigma (rule cộng đồng)"], ["DEFENDER", "Defender (phản ánh Microsoft Defender)"]]
    .map(([v, t]) => h("option", { value: v, text: t, selected: v === (f.source || "") })));
  const form = h("form", { class: "filters", onsubmit: (e) => { e.preventDefault(); location.hash = "#/alerts" + qs({ status: sel.value, source: src.value }); } },
    h("label", {}, "Trạng thái", sel), h("label", {}, "Nguồn phát hiện", src), h("button", { class: "primary", type: "submit", text: "Lọc" }));
  const box = h("div"); view.append(form, box);
  await load(box, async () => { const [d, risks] = await Promise.all([api("/alerts" + qs({ status: f.status, source: f.source, limit: 50 })), riskMap()]); return { d, risks }; }, ({ d, risks }) =>
    box.append(d.items.length ? alertTable(d.items, risks) : empty(f.status || f.source ? "Không có alert khớp bộ lọc." : "Chưa có alert nào.")));
}

// ---------- trang: chi tiết alert / điều tra ----------
const labelled = (kind, text) => h("span", { class: "tag " + kind, text });
function treeNode(n, cur) {
  return h("li", {}, h("span", { class: cur ? "cur" : "", text: (cur ? "▶ " : "") + fmt(n.image_path) }), n.command_line ? h("div", { class: "muted", text: n.command_line }) : null);
}
async function pageAlertDetail(id) {
  view.append(h("a", { href: "#/alerts", text: "← Danh sách alert" }));
  const box = h("div"); view.append(box);
  await load(box, async () => {
    const [a, hist, tl, tree, ev] = await Promise.all([api("/alerts/" + id), api("/alerts/" + id + "/history"),
      api("/alerts/" + id + "/timeline").catch((e) => ({ error: e.message })), api("/alerts/" + id + "/process-tree").catch((e) => ({ error: e.message })),
      api("/alerts/" + id + "/evidence").catch((e) => ({ error: e.message }))]);
    return { a, hist, tl, tree, ev };
  }, ({ a, hist, tl, tree, ev }) => {
    box.append(h("h1", {}, badge(a.severity, sevKind(a.severity)), " ", sourceBadge(a), " " + a.rule_name));
    box.append(h("h2", {}, labelled("obs", "QUAN SÁT"), "Dữ liệu từ telemetry"), h("dl", { class: "kv card" },
      ["rule_id", "rule_version", "status", "hostname", "process_guid", "image_path", "command_line", "occurrence_count"].map((k) => [h("dt", { text: k }), h("dd", { text: fmt(a[k]) })]),
      h("dt", { text: "first_seen" }), h("dd", { text: utc(a.first_seen_utc) }), h("dt", { text: "last_seen" }), h("dd", { text: utc(a.last_seen_utc) }),
      h("dt", { text: "nguồn phát hiện" }), h("dd", {}, sourceBadge(a), " " + fmt(a.detection_source)),
      h("dt", { text: "trường khớp" }), h("dd", { text: fmt(a.matched_fields) })));
    if (a.source_label === "Defender") {
      const ctx = (a.matched_fields && a.matched_fields.context) || {};
      box.append(h("h2", {}, labelled("obs", "QUAN SÁT"), "Phát hiện của Microsoft Defender"), h("div", { class: "card", id: "defender-panel" },
        h("p", { class: "muted", text: "Alert này phản ánh sự kiện của Microsoft Defender (Event 1116/1117/5001/5007/5013). DACN không xác minh lại; " +
          "severity Defender gốc nằm trong severity_name, severity alert do rule DACN gán. Defender không ghi PID: tiến trình liên quan bên dưới là suy luận." }),
        Object.keys(ctx).length ? h("dl", { class: "kv" }, Object.entries(ctx).map(([k, v]) => [h("dt", { text: k }), h("dd", { text: fmt(v) })])) : empty("Không có trường ngữ cảnh.")));
    }
    if (a.source_label === "Sigma" && a.matched_fields && a.matched_fields.sigma) box.append(...sigmaPanel(a));
    if (!a.process_guid && (a.source_label === "Defender" || (a.matched_fields && a.matched_fields.script_block_id))) {
      box.append(h("h2", {}, labelled("inf", "SUY LUẬN"), "Tiến trình liên quan (nối với Sysmon)"), linksPanel(id, a));
    }
    if (a.matched_fields && a.matched_fields.script_block_id) {
      box.append(h("h2", {}, labelled("obs", "QUAN SÁT"), "Script PowerShell (Event 4104)"));
      const sbBox = h("div", { id: "script-panel" }); box.append(sbBox);
      load(sbBox, () => api("/alerts/" + id + "/script"), (sb) => {
        sbBox.append(h("p", { class: "muted", text: "Đã che chuỗi giống bí mật bằng heuristic (không bảo đảm che hết). Luật đã áp dụng: " +
            (sb.redaction_rules.length ? sb.redaction_rules.join(", ") : "không có") + ". Phần: " + sb.parts_seen + "/" + sb.message_total +
            (sb.missing_message_numbers.length ? " (thiếu " + sb.missing_message_numbers.join(", ") + ")" : "") + "." }),
          h("pre", { id: "script-text", text: sb.text }),
          h("div", { class: "actions" }, h("button", { type: "button", id: "script-reveal", text: "Hiện bản gốc (ghi audit)", disabled: !can("raw"),
            title: can("raw") ? "" : "vai trò không đủ quyền", onclick: () =>
              modal("Xem script gốc", h("p", { text: "Thao tác này được ghi vào audit log (SCRIPT_RAW_VIEW). Script có thể chứa mật khẩu, token hoặc dữ liệu nhạy cảm." }), [closeBtn,
                { label: "Đồng ý xem", kind: "primary", fn: async () => {
                  try { const r = await api("/alerts/" + id + "/script?reveal=true");
                    modal("Script gốc (không che)", h("pre", { id: "script-raw", text: r.text }), [closeBtn]);
                  } catch (e) { modal("Lỗi", h("p", { text: e.message }), [closeBtn]); } } }]) })));
      });
    }
    box.append(h("h2", {}, labelled("inf", "SUY LUẬN"), "Do rule đưa ra (không phải bằng chứng)"), h("dl", { class: "kv card" },
      h("dt", { text: "Lý do mức độ" }), h("dd", { text: a.severity_reason }),
      h("dt", { text: "MITRE" }), h("dd", { text: a.mitre_technique_ids ? a.mitre_technique_ids.join(", ") + " (gán theo rule; chưa kiểm chứng trên endpoint thật)" : "không gán (rule không có căn cứ)" })));
    box.append(h("h2", {}, labelled("gap", "THIẾU DỮ LIỆU"), "Giới hạn của kết luận"), h("div", { class: "card" },
      h("p", { text: "coverage_status: " + a.coverage_status }), h("p", { text: "missing_fields: " + (a.missing_fields.length ? a.missing_fields.join(", ") : "không có") })));
    // rủi ro tổng hợp (tải riêng: lỗi không làm hỏng trang)
    box.append(h("h2", {}, labelled("inf", "SUY LUẬN"), "Rủi ro tổng hợp từ nhiều cơ chế"));
    const riskBox = h("div"); box.append(riskBox);
    load(riskBox, () => api("/alerts/" + id + "/risk"), (r) => riskBox.append(riskPanel(r)));
    // bằng chứng nguồn
    box.append(h("h2", { text: "Bằng chứng nguồn (Silver → Bronze)" }));
    if (ev.error) box.append(empty("Không tải được bằng chứng: " + ev.error));
    else box.append(h("p", {}, "Trạng thái: ", badge(ev.status, ev.status === "FULL" ? "ok" : "warn")),
      table([{ key: "event_id", label: "event_id", wrap: true }, { label: "Bronze", render: (e) => e.bronze ? e.bronze.segment + "#" + e.bronze.line_no : "—", wrap: true },
        { key: "status", label: "Trạng thái" }, { label: "Event", render: (e) => fmt(e.silver && (e.silver.sysmon_event_id ?? e.silver.windows_event_id)) },
        { label: "Kênh", render: (e) => fmt(e.silver && e.silver.channel), wrap: true }], ev.events));
    box.append(h("div", { class: "actions" }, h("button", { type: "button", text: "Xem raw XML (ghi audit)", disabled: !can("raw"), title: can("raw") ? "" : "vai trò không đủ quyền", onclick: () =>
      modal("Xem raw XML", h("p", { text: "Thao tác này được ghi vào audit log. Nội dung có thể chứa dữ liệu nhạy cảm." }), [closeBtn,
        { label: "Đồng ý xem", kind: "primary", fn: async () => {
          try { const r = await api("/alerts/" + id + "/evidence?include_raw=true");
            modal("raw XML", h("div", {}, r.events.map((e) => h("pre", { text: e.raw_xml || "(không có raw: " + e.status + ")" }))), [closeBtn]);
          } catch (e) { modal("Lỗi", h("p", { text: e.message }), [closeBtn]); } } }]) })));
    // timeline
    box.append(h("h2", { text: "Timeline (theo process_guid, UTC)" }));
    if (tl.error) box.append(empty(tl.error)); else box.append(tl.events.length ? table([
      { label: "Thời gian", render: (e) => utc(e.timestamp) }, { key: "record_id", label: "record_id" }, { key: "sysmon_event_id", label: "Event" },
      { key: "event_type", label: "Loại" }, { label: "Lệch giờ (s)", render: (e) => fmt(e.skew_seconds) }], tl.events) : empty("Không có sự kiện cùng process_guid."));
    // process tree
    box.append(h("h2", { text: "Cây tiến trình" }));
    if (a.process_guid && a.hostname) box.append(h("p", {}, h("a", { id: "open-tree", href: treeHash({ hostname: a.hostname, process_guid: a.process_guid, alert: id }),
      text: "Mở màn hình cây tiến trình (alert, rủi ro, sự kiện theo từng nút) →" })));
    if (tree.error) box.append(empty(tree.error)); else {
      box.append(h("p", {}, "Độ phủ tổ tiên: ", badge(tree.coverage_status, tree.coverage_status === "FULL" ? "ok" : "warn")));
      const all = [...tree.ancestors].reverse().map((n) => [n, false]); if (tree.process) all.push([tree.process, true]);
      let root = h("ul"), cur = root;
      for (const [n, isCur] of all) { const li = treeNode(n, isCur), ul = h("ul"); li.append(ul); cur.append(li); cur = ul; }
      if (!tree.process) cur.append(h("li", {}, h("span", { class: "cur", text: "▶ (thiếu Event 1 của tiến trình này trong Silver)" })));   // không bịa nút, chỉ báo phần thiếu
      for (const d of tree.descendants) cur.append(treeNode(d, false));
      const hasAny = all.length > 0 || tree.descendants.length > 0;
      box.append(h("div", { class: "card tree" }, hasAny ? root : empty("Không có dữ liệu tiến trình trong Silver.")));
    }
    // trạng thái
    box.append(h("h2", { text: "Trạng thái và ghi chú" }), table([{ key: "from_status", label: "Từ" }, { key: "to_status", label: "Đến" }, { key: "actor", label: "Người" },
      { label: "Thời gian", render: (r) => utc(r.at_utc) }, { key: "note", label: "Ghi chú", wrap: true }], hist.items));
    const note = h("input", { required: true, maxLength: 1000, placeholder: "Ghi chú bắt buộc", "aria-label": "Ghi chú chuyển trạng thái" });
    box.append(h("div", { class: "actions" }, note, a.allowed_transitions.map((s) => h("button", { type: "button", text: "→ " + s, disabled: !can("alert_write"), onclick: async () => {
      if (!note.value.trim()) { note.focus(); return; }
      try { await api("/alerts/" + id + "/transition", { method: "POST", body: { to_status: s, note: note.value } }); route(); }
      catch (e) { modal("Không đổi được trạng thái", h("p", { text: e.message }), [closeBtn]); } } })),
      a.allowed_transitions.length ? null : h("span", { class: "muted", text: "Trạng thái cuối, không chuyển tiếp." })));
    // incident
    const title = h("input", { placeholder: "Tiêu đề incident", maxLength: 200, "aria-label": "Tiêu đề incident" });
    const out = h("p", { class: "muted" });
    box.append(h("h2", { text: "Incident" }), h("div", { class: "actions" }, title, h("button", { type: "button", text: "Tạo incident và gán alert này", disabled: !can("alert_write"), onclick: async () => {
      try { const r = await api("/incidents", { method: "POST", body: { title: title.value } }); await api("/incidents/" + r.incident_id + "/alerts", { method: "POST", body: { alert_id: id } });
        out.textContent = "Đã tạo incident " + r.incident_id; } catch (e) { out.textContent = "Lỗi: " + e.message; } } })), out);
    // hành động response đã yêu cầu cho alert này
    box.append(h("h2", { text: "Hành động response của alert này" }));
    const respBox = h("div", { id: "alert-response" }); box.append(respBox);
    load(respBox, () => api("/response/actions?alert_id=" + encodeURIComponent(id) + "&limit=50"), (r) => {
      respBox.append(r.items.length ? table([{ key: "action_type", label: "Loại" }, { key: "status", label: "Trạng thái" }, { key: "requested_mode", label: "Chế độ yêu cầu" },
        { label: "Kết quả", render: (x) => x.result ? (x.result.mode || "") + (x.result.code ? " — " + x.result.code : "") : "—" }], r.items) : empty("Chưa có hành động response nào cho alert này."));
    });
    box.append(h("div", { class: "actions" }, h("a", { href: "#/response?alert=" + id, text: "Yêu cầu hành động response cho alert này →" })));
  });
}

// ---------- trang: cây tiến trình (điều tra, CHỈ ĐỌC) ----------
const baseName = (p) => (p ? String(p).split(/[\\/]/).pop() : null);
const treeHash = (o) => "#/tree" + qs(o);
const CAT_LABEL = { file: "file", registry: "registry", network: "net", dns: "dns" };
function nodeButton(n, risk, selected, onSelect) {
  const nodata = n.status === "NO_DATA";
  const title = nodata ? "không có dữ liệu (thiếu Event 1 trong Silver)" : fmt(baseName(n.image_path));
  const counts = Object.entries(n.event_counts || {}).filter(([, v]) => v > 0).map(([k, v]) => CAT_LABEL[k] + " " + v).join(" · ");
  const meta = nodata ? (n.parent_image ? "ParentImage theo Event 1 của tiến trình con: " + n.parent_image : "không có ParentImage")
    : "pid " + fmt(n.pid) + " · " + utc(n.start_utc) + (n.end_utc ? " → " + utc(n.end_utc) : "");
  return h("button", { type: "button", class: "pnode" + (n.role === "focus" ? " focus" : "") + (nodata ? " nodata" : "") + (selected ? " selected" : ""),
    "data-guid": n.process_guid, "aria-pressed": selected ? "true" : "false", onclick: () => onSelect(n) },
    h("div", { class: "img" }, n.role === "focus" ? "▶ " : "", title),
    h("div", { class: "meta", text: meta }),
    h("div", {}, nodata ? badge("NO_DATA", "warn") : null,
      n.alerts.slice(0, 3).map((a) => h("span", { class: "badge node-alert " + sevKind(a.severity), text: a.rule_id + " · " + a.severity })),
      n.alerts.length > 3 ? badge("+" + (n.alerts.length - 3) + " alert") : null,
      risk ? riskBadge(risk) : null, counts ? h("span", { class: "meta", text: counts }) : null));
}
function nodePanel(n, tree, risk) {
  const panel = h("div", { id: "node-panel", class: "card" });
  const nodata = n.status === "NO_DATA";
  panel.append(h("h2", {}, badge(n.role === "focus" ? "trọng tâm" : n.role === "ancestor" ? "tổ tiên" : "con cháu"), " ",
    nodata ? badge("NO_DATA", "warn") : badge("OBSERVED", "ok"), " ", nodata ? "Không có dữ liệu" : fmt(baseName(n.image_path))));
  if (nodata) panel.append(h("p", { class: "muted", text: "Silver không có Event 1 của tiến trình này. Chỉ hiện các trường Parent* có thật trong Event 1 của tiến trình con (nguồn: event_id " + fmt(n.evidence_source) + "); các trường khác để trống, không suy đoán." }));
  const rows = nodata ? [["process_guid", n.process_guid], ["hostname", n.hostname], ["ParentImage (từ con)", n.parent_image], ["ParentCommandLine (từ con)", n.parent_command_line], ["ParentProcessId (từ con)", n.pid_from_child]]
    : [["process_guid", n.process_guid], ["hostname", n.hostname], ["image_path", n.image_path], ["command_line", n.command_line], ["user_name", n.user_name],
      ["integrity_level", n.integrity_level], ["pid / ppid", fmt(n.pid) + " / " + fmt(n.ppid)], ["file_sha256", n.file_sha256], ["hashes", n.hashes], ["imphash", n.imphash],
      ["bắt đầu (Event 1)", utc(n.start_utc)], ["kết thúc (Event 5)", n.end_utc ? utc(n.end_utc) : "không có Event 5 trong Silver"], ["cwd", n.current_working_directory],
      ["parent_guid", n.parent_guid], ["parent_image", n.parent_image], ["parent_command_line", n.parent_command_line], ["event_id (Event 1)", n.event_id]];
  panel.append(h("dl", { class: "kv" }, rows.map(([k, v]) => [h("dt", { text: k }), h("dd", { text: fmt(v) })])));
  panel.append(h("div", { class: "actions" },
    n.role !== "focus" ? h("button", { type: "button", text: "Đặt làm trọng tâm", onclick: () => { location.hash = treeHash({ hostname: tree.hostname, process_guid: n.process_guid }); } }) : null,
    h("button", { type: "button", text: "Chi tiết rủi ro", onclick: async () => {
      try { modal("Chi tiết rủi ro", riskPanel(await api("/risk/process" + qs({ hostname: n.hostname, process_guid: n.process_guid }))), [closeBtn]); }
      catch (e) { modal("Lỗi", h("p", { text: e.message }), [closeBtn]); } } }),
    risk ? riskBadge(risk) : h("span", { class: "muted", text: "chưa có điểm rủi ro" })));
  panel.append(h("h3", { text: "Alert của tiến trình" }));
  panel.append(n.alerts.length ? table([{ label: "Mức", render: (a) => badge(a.severity, sevKind(a.severity)) }, { label: "Rule", render: (a) => a.rule_id + " v" + a.rule_version },
    { label: "Trạng thái", render: (a) => badge(a.status) }, { label: "Bằng chứng", render: (a) => h("a", { href: "#/alerts/" + encodeURIComponent(a.alert_id), class: "evidence-link", text: "chi tiết & raw_xml →" }) }], n.alerts)
    : h("p", { class: "muted", text: "Không có alert gắn với tiến trình này." }));
  panel.append(h("h3", { text: "Sự kiện của tiến trình (UTC)" }), h("p", { class: "muted", text: "Không hiện raw_data/raw_xml; raw_xml chỉ xem qua Evidence của alert (kiểm soát quyền, ghi audit)." }));
  const evBox = h("div", { id: "node-events" }); panel.append(evBox);
  const w = tree.window || {}, limit = 25;
  const cols = [{ label: "Thời gian", render: (e) => utc(e.timestamp) }, { label: "Loại", render: (e) => badge(e.category) }, { key: "sysmon_event_id", label: "Event" }, { key: "summary", label: "Chi tiết", wrap: true }];
  const more = async (offset, wrap) => {
    const d = await api("/investigation/process-events" + qs({ hostname: n.hostname, process_guid: n.process_guid, since: w.since, until: w.until, limit, offset }));
    if (!d.items.length && offset === 0) { wrap.append(empty("Không có sự kiện của tiến trình này trong Silver" + (w.since || w.until ? " (trong cửa sổ đã chọn)." : "."))); return; }
    wrap.append(table(cols, d.items, (e) => modal("Sự kiện (Silver)", h("pre", { text: JSON.stringify(e, null, 2) }), [closeBtn])));
    if (d.has_more) { const b = h("button", { type: "button", class: "more", text: "Xem thêm sự kiện", onclick: async () => { b.remove(); try { await more(offset + limit, wrap); } catch (e) { wrap.append(h("div", { class: "state error", text: "Lỗi: " + e.message })); } } }); wrap.append(b); }
  };
  const loading = h("div", { class: "state", text: "Đang tải…" }); evBox.append(loading);
  more(0, evBox).then(() => loading.remove(), (e) => { loading.remove(); if (e.status !== 401) evBox.append(h("div", { class: "state error", role: "alert", text: "Lỗi: " + (e.code ? e.code + " — " : "") + e.message })); });
  return panel;
}
function renderTree(box, tree, risks) {
  const covKind = tree.coverage_status === "FULL" ? "ok" : "warn";
  box.append(h("p", {}, "Độ phủ tổ tiên: ", badge(tree.coverage_status, covKind), " · " + tree.nodes.length + " nút · host " + tree.hostname,
    tree.node_limit_reached ? [" ", badge("đã chạm giới hạn " + tree.limits.max_nodes + " nút", "warn")] : null,
    tree.ancestors_truncated ? [" ", badge("tổ tiên bị cắt ở độ sâu " + tree.limits.max_depth, "warn")] : null,
    tree.descendants_truncated ? [" ", badge("con cháu bị cắt ở độ sâu " + tree.limits.max_depth, "warn")] : null,
    tree.window && (tree.window.since || tree.window.until) ? h("span", { class: "muted", text: " · cửa sổ con cháu: " + (tree.window.since ? utc(tree.window.since) : "…") + " → " + (tree.window.until ? utc(tree.window.until) : "…") }) : null));
  const inSet = new Set(tree.nodes.map((n) => n.process_guid)), kids = {};
  for (const n of tree.nodes) if (n.parent_guid && inSet.has(n.parent_guid) && n.process_guid !== n.parent_guid) (kids[n.parent_guid] = kids[n.parent_guid] || []).push(n);
  const roots = tree.nodes.filter((n) => !(n.parent_guid && inSet.has(n.parent_guid)));
  const layout = h("div", { class: "tree-layout" }), left = h("div", { class: "ptree", id: "ptree" }), right = h("div");
  let selected = tree.nodes.find((n) => n.role === "focus") || tree.nodes[0];
  const riskOf = (n) => risks[riskKey(n.hostname, n.process_guid)];
  const paint = () => {
    const build = (n, seen) => {
      if (seen.has(n.process_guid)) return null; seen.add(n.process_guid);
      const li = h("li", {}, nodeButton(n, riskOf(n), n === selected, (x) => { selected = x; paint(); }));
      if (n.children_truncated) li.append(h("button", { type: "button", class: "more", text: "Xem thêm nhánh con (mở từ nút này) →", onclick: () => { location.hash = treeHash({ hostname: tree.hostname, process_guid: n.process_guid }); } }));
      const ch = (kids[n.process_guid] || []).map((c) => build(c, seen)).filter(Boolean);
      if (ch.length) li.append(h("ul", {}, ch));
      return li;
    };
    const seen = new Set();
    clear(left).append(h("ul", {}, roots.map((r) => build(r, seen)).filter(Boolean)));
    clear(right).append(nodePanel(selected, tree, riskOf(selected)));
  };
  layout.append(left, right); box.append(layout); paint();
}
async function pageTree() {
  const f = Object.fromEntries(new URLSearchParams(location.hash.split("?")[1] || ""));
  view.append(h("h1", { text: "Cây tiến trình" }));
  view.append(h("p", { class: "muted", text: "Nối cha–con bằng ProcessGuid trên cùng một host (không dùng PID). Tiến trình không có Event 1 trong Silver hiện là nút “không có dữ liệu”, không suy đoán. Màn hình chỉ đọc." }));
  const field = (name, label, attrs) => h("label", {}, label, h("input", { name, value: f[name] || "", ...(attrs || {}) }));
  const dt = (v) => (v ? new Date(v).toISOString().slice(0, 16) : "");
  const form = h("form", { class: "filters", id: "tree-search", onsubmit: (e) => {
    e.preventDefault(); const d = new FormData(form), p = {};
    for (const [k, v] of d.entries()) if (v) p[k] = k === "since" || k === "until" ? new Date(v + "Z").toISOString() : v.trim();
    location.hash = treeHash(p);
  } },
    field("hostname", "Host", { maxLength: 255 }), field("process_guid", "process_guid", { maxLength: 64 }),
    field("image", "Image chứa", { maxLength: 260 }), field("sha256", "SHA-256", { maxLength: 64 }),
    h("label", {}, "Con cháu từ (UTC)", h("input", { name: "since", type: "datetime-local", value: dt(f.since) })),
    h("label", {}, "đến (UTC)", h("input", { name: "until", type: "datetime-local", value: dt(f.until) })),
    h("label", {}, "Tối đa nút", h("select", { name: "max_nodes" }, ["50", "200", "500"].map((v) => h("option", { value: v, text: v, selected: v === (f.max_nodes || "200") })))),
    h("button", { class: "primary", type: "submit", text: "Xem" }));
  const box = h("div", { id: "tree-box" }); view.append(form, box);
  if (f.hostname && f.process_guid) {
    await load(box, async () => {
      const [tree, risks] = await Promise.all([api("/investigation/process-tree" + qs({ hostname: f.hostname, process_guid: f.process_guid, max_nodes: f.max_nodes, since: f.since, until: f.until })), riskMap()]);
      return { tree, risks };
    }, ({ tree, risks }) => {
      if (f.alert) box.append(h("p", {}, h("a", { href: "#/alerts/" + encodeURIComponent(f.alert), text: "← Quay lại alert" })));
      if (!tree.nodes.length) { box.append(empty("Không tìm thấy tiến trình " + f.process_guid + " trên host " + f.hostname + " trong Silver (không có Event 1, sự kiện hay alert).")); return; }
      renderTree(box, tree, risks);
    });
  } else if (f.image || f.sha256) {
    await load(box, () => api("/investigation/process-search" + qs({ hostname: f.hostname, image: f.image, sha256: f.sha256, limit: 50 })), (d) => {
      box.append(...(d.items.length ? [h("p", { class: "muted", text: d.items.length + " tiến trình (Event 1) khớp — chọn một dòng để xem cây." + (d.items.length >= d.limit ? " Có thể còn kết quả khác: thu hẹp bộ lọc." : "") }),
        table([{ label: "Bắt đầu", render: (r) => utc(r.start_utc) }, { key: "hostname", label: "Host" }, { key: "image_path", label: "Image", wrap: true },
          { key: "command_line", label: "Command line", wrap: true }, { key: "process_guid", label: "process_guid", wrap: true }], d.items,
          (r) => { location.hash = treeHash({ hostname: r.hostname, process_guid: r.process_guid }); })]
        : [empty("Không có tiến trình nào khớp image/SHA-256 đã nhập.")]));
    });
  } else {
    box.append(empty("Nhập Host + process_guid để xem cây, hoặc Image/SHA-256 để tìm tiến trình. Cũng có thể mở từ trang chi tiết alert."));
  }
}

// ---------- trang: response ----------
async function pageResponse() {
  const f = Object.fromEntries(new URLSearchParams(location.hash.split("?")[1] || ""));
  view.append(h("h1", { text: "Response" }));
  const box = h("div"); view.append(box);
  await load(box, async () => ({ h: await api("/health"), acts: await api("/response/actions?limit=50") }), ({ h: hh, acts }) => {
    state.health = hh; paintHeader();
    const dry = hh.response.mode !== "execute" || !hh.response.execute_unlocked;
    box.append(h("div", { class: "card" }, h("span", { class: "badge mode-big " + (dry ? "ok" : "bad"), text: dry ? "DRY-RUN — hành động chỉ được mô phỏng, không thay đổi hệ thống" : "EXECUTE — hành động có thể thay đổi VM lab" }),
      h("p", { class: "muted", text: "Chế độ do policy trên máy quyết định, không đổi được từ giao diện. Mục tiêu bị từ chối nếu nằm ngoài thư mục lab hoặc thuộc danh sách bảo vệ." })));
    // yêu cầu
    const type = h("select", {}, ["QUARANTINE_FILE", "TERMINATE_PROCESS", "RESTORE_FILE", "ADD_WHITELIST", "REMOVE_WHITELIST"].map((t) => h("option", { value: t, text: t })));
    const target = h("textarea", { "aria-label": "Mục tiêu (JSON)", placeholder: '{"path": "C:\\\\Users\\\\...\\\\AppData\\\\Local\\\\Temp\\\\dacn_lab\\\\DACN_LAB_x.exe"}' });
    const mode = h("select", {}, ["dry_run", "execute"].map((t) => h("option", { value: t, text: t })));
    const alertId = h("input", { value: f.alert || "", placeholder: "alert_id (tùy chọn)", maxLength: 64 });
    const msg = h("p", { class: "muted" });
    box.append(h("h2", { text: "Yêu cầu hành động" }), h("div", { class: "card" }, h("div", { class: "filters" }, h("label", {}, "Loại", type), h("label", {}, "Chế độ yêu cầu", mode), h("label", {}, "Alert", alertId)),
      h("label", {}, "Mục tiêu (JSON, định danh đầy đủ)", target), h("div", { class: "actions" }, h("button", { class: "primary", type: "button", text: "Gửi yêu cầu", disabled: !can("request_action"), onclick: async () => {
        let t; try { t = JSON.parse(target.value); } catch (_) { msg.textContent = "Mục tiêu không phải JSON hợp lệ."; return; }
        try { await api("/response/actions", { method: "POST", body: { action_type: type.value, target: t, requested_mode: mode.value, alert_id: alertId.value || null } }); route(); }
        catch (e) { msg.textContent = "Lỗi: " + e.message; } } })), msg));
    // hàng đợi
    box.append(h("h2", { text: "Hàng đợi và kết quả" }));
    const decide = (a, kind) => {
      const reason = h("input", { placeholder: "Lý do (bắt buộc)", maxLength: 1000, "aria-label": "Lý do" });
      modal((kind === "approve" ? "Duyệt" : "Từ chối") + " hành động " + a.action_type,
        h("div", {}, h("p", { text: "Chế độ yêu cầu: " + a.requested_mode + " — chế độ hiệu lực: " + (dry ? "DRY-RUN" : "theo policy") }), h("p", { text: "Mục tiêu đầy đủ:" }),
          h("pre", { text: JSON.stringify(a.target, null, 2) }), h("p", { text: "Hệ quả: tiến trình đã kết thúc không khôi phục được; tệp cách ly có thể restore; ADD_WHITELIST làm hash đó không còn bị phát hiện (REMOVE_WHITELIST hoàn tác)." }), h("label", {}, "Lý do", reason)),
        [closeBtn, { label: kind === "approve" ? "Duyệt" : "Từ chối", kind: kind === "approve" ? "primary" : "danger", close: false, fn: async () => {
          if (!reason.value.trim()) { reason.focus(); return; }
          try { await api("/response/actions/" + a.action_id + "/" + kind, { method: "POST", body: { reason: reason.value } }); $("modal").close(); route(); }
          catch (e) { reason.value = ""; reason.placeholder = e.message; } } }]);
    };
    box.append(acts.items.length ? table([{ label: "Thời gian", render: (a) => utc(a.requested_at_utc) }, { key: "action_type", label: "Loại" }, { label: "Trạng thái", render: (a) => badge(a.status) },
      { key: "requested_mode", label: "Chế độ" }, { key: "requested_by", label: "Yêu cầu bởi" }, { key: "approved_by", label: "Duyệt bởi" },
      { label: "Mục tiêu", wrap: true, render: (a) => JSON.stringify(a.target) }, { label: "Kết quả", wrap: true, render: (a) => a.result ? (a.result.code || a.result.mode || "") + " " + (a.result.message || "") : "—" },
      { label: "", render: (a) => a.status === "REQUESTED" ? h("span", {}, h("button", { type: "button", text: "Duyệt", disabled: !can("approve"), onclick: () => decide(a, "approve") }), " ",
        h("button", { type: "button", class: "danger", text: "Từ chối", disabled: !can("approve"), onclick: () => decide(a, "reject") })) : "" }], acts.items) : empty("Chưa có yêu cầu hành động nào."));
  });
}

// ---------- trang: rủi ro ----------
async function pageRisk() {
  view.append(h("h1", { text: "Rủi ro tổng hợp" }));
  view.append(h("p", { class: "muted", text: "Gộp rule/correlation, IOC, static analysis và tín hiệu ML (nếu bật) thành một mức rủi ro theo chủ thể. Trọng số là heuristic chưa hiệu chỉnh; điểm chỉ để sắp xếp ưu tiên điều tra, không kích hoạt response." }));
  const cfgBox = h("div"), procBox = h("div", { id: "risk-process" }), hostBox = h("div", { id: "risk-host" });
  view.append(cfgBox, h("h2", { text: "Theo tiến trình (process_guid)" }), procBox, h("h2", { text: "Theo host (cửa sổ thời gian dữ liệu)" }), hostBox);
  load(cfgBox, () => api("/risk/config"), (c) => cfgBox.append(h("p", { class: "muted", text: "Cấu hình v" + c.version + " · " + c.status + " · sha256 " + c.sha256.slice(0, 12) + "… · ML: " +
    Object.entries(c.ml_enabled).map(([k, v]) => k + "=" + (v ? "bật" : "tắt")).join(", ") })));
  const show = (r) => modal("Chi tiết rủi ro", riskPanel(r), [closeBtn]);
  const cols = (kind) => [{ label: "Rủi ro", render: riskBadge }, { label: "Host", render: (r) => r.subject.hostname },
    kind === "process" ? { label: "process_guid", wrap: true, render: (r) => r.subject.process_guid } : { label: "Cửa sổ đến", render: (r) => utc(r.subject.window_end) },
    { label: "Cơ chế", render: (r) => Object.keys(r.categories).join(", ") || "—" }, { label: "Thành phần", render: (r) => String(r.components.length) },
    { key: "completeness", label: "Độ đầy đủ" }];
  await Promise.all([
    load(procBox, () => api("/risk/subjects?kind=process&limit=100"), (d) => procBox.append(d.items.length ? table(cols("process"), d.items, show) : empty("Chưa có chủ thể nào có tín hiệu."))),
    load(hostBox, () => api("/risk/subjects?kind=host&limit=50"), (d) => hostBox.append(d.items.length ? table(cols("host"), d.items, show) : empty("Chưa có host nào có tín hiệu."))),
  ]);
}

// Khung giải thích alert Sigma: selection nào đúng, field đã khớp, ghi công tác giả + giấy phép (DRL 1.1 yêu cầu giữ tác giả).
function sigmaPanel(a) {
  const sg = a.matched_fields.sigma, at = a.matched_fields.attribution || {};
  const fields = Object.entries(sg.fields || {}).map(([k, v]) => [h("dt", { text: k }),
    h("dd", { text: v && typeof v === "object" && v.redacted ? "(không hiển thị văn bản script; sha256 " + v.sha256 + ", " + v.length + " ký tự)" : fmt(v) })]);
  return [h("h2", {}, labelled("obs", "QUAN SÁT"), "Rule Sigma"), h("div", { class: "card", id: "sigma-panel" },
    h("p", { class: "muted", text: "Rule cộng đồng Sigma, dịch bằng bộ biên dịch tập con của DACN. Trạng thái synthetic_only: chưa kiểm chứng trên dữ liệu thật " +
      "của DACN; level do tác giả Sigma đặt. Alert Sigma không bao giờ kích hoạt response." }),
    h("dl", { class: "kv" },
      h("dt", { text: "tiêu đề Sigma" }), h("dd", { text: fmt(sg.title) }), h("dt", { text: "id Sigma" }), h("dd", { text: fmt(sg.id) }),
      h("dt", { text: "level / status" }), h("dd", { text: fmt(sg.level) + " / " + fmt(sg.status) }),
      h("dt", { text: "condition" }), h("dd", {}, h("code", { text: fmt(sg.condition) })),
      h("dt", { text: "selection đúng" }), h("dd", { text: (sg.selections_true || []).join(", ") || "—" }),
      h("dt", { text: "tác giả" }), h("dd", { id: "sigma-author", text: fmt(at.author) }),
      h("dt", { text: "giấy phép" }), h("dd", {}, extLink(at.license_url, fmt(at.license))),
      h("dt", { text: "rule gốc" }), h("dd", { id: "sigma-source" }, at.source_url ? extLink(at.source_url) : h("span", { text: fmt(at.source_path) }))),
    h("h3", { text: "Field đã khớp" }), fields.length ? h("dl", { class: "kv" }, fields) : empty("Không có field."))];
}

// ---------- trang: rules ----------
async function pageRules() {
  view.append(h("h1", { text: "Rules (chỉ đọc)" }));
  const box = h("div"); view.append(box);
  await load(box, () => api("/rules"), (d) => box.append(d.items.length ? table([{ key: "rule_id", label: "Rule" }, { key: "legacy_id", label: "Legacy" }, { key: "rule_version", label: "Ver" },
    { key: "name", label: "Tên", wrap: true }, { label: "Trạng thái", render: (r) => badge(r.status, r.status === "enabled" ? "ok" : "warn") }, { label: "Mức", render: (r) => badge(r.severity, sevKind(r.severity)) },
    { key: "validation_status", label: "Kiểm chứng" }, { label: "MITRE", render: (r) => fmt(r.mitre_technique_ids) }, { key: "response_policy", label: "Response" }], d.items,
    (r) => api("/rules/" + r.rule_id).then((full) => modal(r.rule_id, h("pre", { text: JSON.stringify(full, null, 2) }), [closeBtn]))) : empty("Không có rule nào được nạp.")));
  view.append(h("h2", { text: "Rule Sigma" }));
  const sbox = h("div", { id: "sigma-rules" }); view.append(sbox);
  await load(sbox, () => api("/sigma/rules"), (d) => {
    sbox.append(h("p", { class: "muted", text: (d.enabled ? "Sigma ĐANG BẬT. " : "Sigma đang TẮT (config/sigma-rules.yaml enabled: false); danh sách dưới đây chỉ để xem trước. ") +
      "Rule Sigma là synthetic_only, không phải tỷ lệ phát hiện, không kích hoạt response." +
      (d.source && d.source.commit ? " Nguồn SigmaHQ @" + d.source.commit.slice(0, 12) + ", giấy phép " + fmt(d.source.license) + "." : "") }));
    sbox.append(h("h3", { text: "Đã nạp (" + d.loaded.length + ")" }), d.loaded.length ? table([{ key: "rule_id", label: "Rule" }, { key: "title", label: "Tiêu đề Sigma", wrap: true },
      { label: "Mức", render: (r) => badge(r.severity, sevKind(r.severity)) }, { label: "Hoạt động", render: (r) => badge(r.active ? "bật" : "tắt", r.active ? "ok" : "warn") },
      { key: "dacn_table", label: "Bảng Silver" }, { label: "MITRE", render: (r) => fmt(r.mitre_technique_ids) }, { key: "author", label: "Tác giả", wrap: true },
      { label: "Ghi chú độ phủ", render: (r) => fmt((r.coverage_notes || []).join("; ")), wrap: true }], d.loaded,
      (r) => api("/sigma/rules/" + r.rule_id).then((full) => modal(r.rule_id, h("div", {}, h("p", {}, "Rule gốc: ", extLink(full.summary.source_url, full.summary.source_path)),
        h("pre", { id: "sigma-source-text", text: full.source_text || "(không đọc được tệp)" })), [closeBtn]))) : empty("Không có rule Sigma nào."));
    sbox.append(h("h3", { text: "Bị loại (" + d.rejected.length + ")" }), d.rejected.length ? table([{ key: "code", label: "Mã" }, { key: "path", label: "Tệp", wrap: true },
      { key: "title", label: "Tiêu đề", wrap: true }, { key: "reason", label: "Lý do", wrap: true }], d.rejected) : empty("Không có rule nào bị loại."));
  });
}

// ---------- router ----------
async function route() {
  clear(view);
  if (!sessionStorage.getItem(TOKEN_KEY)) return showLogin();
  paintHeader();
  const hash = location.hash || "#/overview", path = hash.split("?")[0];
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", path.startsWith(a.getAttribute("href"))));
  if (path === "#/overview") return pageOverview();
  if (path === "#/events") return pageEvents();
  if (path === "#/alerts") return pageAlerts();
  if (path.startsWith("#/alerts/")) return pageAlertDetail(decodeURIComponent(path.slice(9)));
  if (path === "#/response") return pageResponse();
  if (path === "#/rules") return pageRules();
  if (path === "#/risk") return pageRisk();
  if (path === "#/tree") return pageTree();
  view.append(empty("Không tìm thấy trang."));
}
async function boot() {
  try { state.me = await api("/me"); state.health = await api("/health").catch(() => null); }
  catch (e) { return; }
  await route();
}
window.addEventListener("hashchange", route);
$("logout").addEventListener("click", () => { sessionStorage.removeItem(TOKEN_KEY); state.me = null; showLogin(); });
if (sessionStorage.getItem(TOKEN_KEY)) boot(); else showLogin();
