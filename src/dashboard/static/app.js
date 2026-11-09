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
    const [health, stats, latest] = await Promise.all([api("/health"), api("/stats"), api("/alerts?limit=5")]);
    state.health = health; paintHeader();
    return { health, stats, latest, at: new Date() };
  }, ({ health, stats, latest, at }) => {
    const ag = health.agent, pl = health.pipeline, en = health.engine;
    box.append(h("p", { class: "muted", text: "Cập nhật lúc " + utc(at) + " · nguồn dữ liệu: " + (health.data_label === "SAMPLE" ? "MẪU (synthetic)" : "chưa xác nhận") }));
    box.append(h("div", { class: "grid" },
      h("div", { class: "card" }, h("h3", { text: "Agent" }), h("dl", { class: "kv" },
        h("dt", { text: "Trạng thái" }), h("dd", {}, badge(ag.status, { UNKNOWN: "warn", STALE: "bad" }[ag.status] || "ok")),
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
    box.append(h("h2", { text: "Alert mới nhất" }), latest.items.length === 0 ? empty("Không có alert.") : alertTable(latest.items));
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
    field("hostname", "Host"), field("process_guid", "process_guid"), field("sysmon_event_id", "Event ID", "number"), field("sha256", "SHA-256"),
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
function alertTable(items) {
  return table([
    { label: "Mức", render: (a) => badge(a.severity, sevKind(a.severity)) },
    { label: "Rule", render: (a) => a.rule_id + " v" + a.rule_version }, { key: "rule_name", label: "Tên", wrap: true },
    { label: "Trạng thái", render: (a) => badge(a.status) }, { key: "hostname", label: "Host" },
    { label: "Lần đầu", render: (a) => utc(a.first_seen_utc) }, { key: "occurrence_count", label: "Số lần" }, { key: "coverage_status", label: "Độ phủ" },
  ], items, (a) => { location.hash = "#/alerts/" + a.alert_id; });
}
async function pageAlerts() {
  const f = Object.fromEntries(new URLSearchParams(location.hash.split("?")[1] || ""));
  view.append(h("h1", { text: "Alerts" }));
  const sel = h("select", { name: "status" }, [""].concat(["NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"]).map((s) => h("option", { value: s, text: s || "(tất cả)", selected: s === (f.status || "") })));
  const form = h("form", { class: "filters", onsubmit: (e) => { e.preventDefault(); location.hash = "#/alerts" + qs({ status: sel.value }); } },
    h("label", {}, "Trạng thái", sel), h("button", { class: "primary", type: "submit", text: "Lọc" }));
  const box = h("div"); view.append(form, box);
  await load(box, () => api("/alerts" + qs({ status: f.status, limit: 50 })), (d) =>
    box.append(d.items.length ? alertTable(d.items) : empty(f.status ? "Không có alert ở trạng thái " + f.status + "." : "Chưa có alert nào.")));
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
      api("/alerts/" + id + "/evidence")]);
    return { a, hist, tl, tree, ev };
  }, ({ a, hist, tl, tree, ev }) => {
    box.append(h("h1", {}, badge(a.severity, sevKind(a.severity)), " " + a.rule_name));
    box.append(h("h2", {}, labelled("obs", "QUAN SÁT"), "Dữ liệu từ telemetry"), h("dl", { class: "kv card" },
      ["rule_id", "rule_version", "status", "hostname", "process_guid", "image_path", "command_line", "occurrence_count"].map((k) => [h("dt", { text: k }), h("dd", { text: fmt(a[k]) })]),
      h("dt", { text: "first_seen" }), h("dd", { text: utc(a.first_seen_utc) }), h("dt", { text: "last_seen" }), h("dd", { text: utc(a.last_seen_utc) }),
      h("dt", { text: "trường khớp" }), h("dd", { text: fmt(a.matched_fields) })));
    box.append(h("h2", {}, labelled("inf", "SUY LUẬN"), "Do rule đưa ra (không phải bằng chứng)"), h("dl", { class: "kv card" },
      h("dt", { text: "Lý do mức độ" }), h("dd", { text: a.severity_reason }),
      h("dt", { text: "MITRE" }), h("dd", { text: a.mitre_technique_ids ? a.mitre_technique_ids.join(", ") + " (gán theo rule; chưa kiểm chứng trên endpoint thật)" : "không gán (rule không có căn cứ)" })));
    box.append(h("h2", {}, labelled("gap", "THIẾU DỮ LIỆU"), "Giới hạn của kết luận"), h("div", { class: "card" },
      h("p", { text: "coverage_status: " + a.coverage_status }), h("p", { text: "missing_fields: " + (a.missing_fields.length ? a.missing_fields.join(", ") : "không có") })));
    // bằng chứng nguồn
    box.append(h("h2", { text: "Bằng chứng nguồn (Silver → Bronze)" }), h("p", {}, "Trạng thái: ", badge(ev.status, ev.status === "FULL" ? "ok" : "warn")));
    box.append(table([{ key: "event_id", label: "event_id", wrap: true }, { label: "Bronze", render: (e) => e.bronze ? e.bronze.segment + "#" + e.bronze.line_no : "—", wrap: true },
      { key: "status", label: "Trạng thái" }, { label: "Event", render: (e) => fmt(e.silver && e.silver.sysmon_event_id) }], ev.events));
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
    if (tree.error) box.append(empty(tree.error)); else {
      box.append(h("p", {}, "Độ phủ tổ tiên: ", badge(tree.coverage_status, tree.coverage_status === "FULL" ? "ok" : "warn")));
      const all = [...tree.ancestors].reverse().map((n) => [n, false]); if (tree.process) all.push([tree.process, true]);
      let root = h("ul"), cur = root;
      for (const [n, isCur] of all) { const li = treeNode(n, isCur), ul = h("ul"); li.append(ul); cur.append(li); cur = ul; }
      for (const d of tree.descendants) cur.append(treeNode(d, false));
      box.append(h("div", { class: "card tree" }, all.length ? root : empty("Không có dữ liệu tiến trình trong Silver.")));
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
    box.append(h("div", { class: "actions" }, h("a", { href: "#/response?alert=" + id, text: "Yêu cầu hành động response cho alert này →" })));
  });
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
    const type = h("select", {}, ["QUARANTINE_FILE", "TERMINATE_PROCESS", "RESTORE_FILE"].map((t) => h("option", { value: t, text: t })));
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
          h("pre", { text: JSON.stringify(a.target, null, 2) }), h("p", { text: "Hệ quả: tiến trình đã kết thúc không khôi phục được; tệp cách ly có thể restore." }), h("label", {}, "Lý do", reason)),
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

// ---------- trang: rules ----------
async function pageRules() {
  view.append(h("h1", { text: "Rules (chỉ đọc)" }));
  const box = h("div"); view.append(box);
  await load(box, () => api("/rules"), (d) => box.append(d.items.length ? table([{ key: "rule_id", label: "Rule" }, { key: "legacy_id", label: "Legacy" }, { key: "rule_version", label: "Ver" },
    { key: "name", label: "Tên", wrap: true }, { label: "Trạng thái", render: (r) => badge(r.status, r.status === "enabled" ? "ok" : "warn") }, { label: "Mức", render: (r) => badge(r.severity, sevKind(r.severity)) },
    { key: "validation_status", label: "Kiểm chứng" }, { label: "MITRE", render: (r) => fmt(r.mitre_technique_ids) }, { key: "response_policy", label: "Response" }], d.items,
    (r) => api("/rules/" + r.rule_id).then((full) => modal(r.rule_id, h("pre", { text: JSON.stringify(full, null, 2) }), [closeBtn]))) : empty("Không có rule nào được nạp.")));
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
