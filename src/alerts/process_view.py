"""Màn hình cây tiến trình phục vụ điều tra: truy vấn CHỈ ĐỌC theo (hostname, process_guid).

Khác `alerts.timeline.process_tree` (giữ nguyên cho `/alerts/{id}/process-tree`): lọc theo hostname, mỗi nút có đủ
trường Event 1 (image, command line, user, integrity, hash, thời điểm), thời điểm Event 5, số sự kiện
file/registry/network/DNS và alert gắn với nút; có giới hạn số nút/độ sâu và cửa sổ thời gian cho con cháu.

Nguyên tắc:
- Nối cha-con bằng ProcessGuid (ADR 0002), không bằng PID.
- Không bịa dữ liệu: tiến trình không có Event 1 trong Silver là nút `NO_DATA`; nó chỉ mang ParentImage,
  ParentCommandLine, ParentProcessId lấy từ Event 1 của tiến trình con (ghi rõ `evidence_source`), mọi trường khác để None.
- Không trả `raw_data`; raw_xml chỉ qua endpoint evidence của alert (có kiểm soát quyền và audit).
- Không tính/lưu điểm rủi ro ở đây và không gọi response."""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
MAX_DEPTH, MAX_NODES, MAX_EVENTS = 20, 500, 200
CATEGORIES = ("process", "file", "registry", "network", "dns")

_PROC_COLS = ("event_id", "timestamp", "record_id", "hostname", "process_guid", "parent_guid", "pid", "ppid", "image_path",
              "command_line", "current_working_directory", "user_name", "integrity_level", "session_id", "parent_image",
              "parent_command_line", "file_sha256", "imphash", "hashes")
_EVENT_COLS = {
    "silver_process_events": ("image_path", "command_line", "user_name", "integrity_level", "file_sha256"),
    "silver_file_events": ("operation", "file_path", "file_extension", "image_path", "creation_utc_time", "user_name", "file_sha256"),
    "silver_registry_events": ("operation", "target_object", "value_name", "details", "new_name", "image_path", "user_name"),
    "silver_network_events": ("image_path", "user_name", "protocol", "direction", "src_ip", "src_port", "dest_ip", "dest_port",
                              "dest_hostname", "dns_query_name", "dns_query_status", "dns_query_results"),
}
_EMPTY_FIELDS = ("event_id", "pid", "image_path", "command_line", "current_working_directory", "user_name", "integrity_level",
                 "session_id", "file_sha256", "imphash", "hashes", "start_utc", "end_utc")


def _rows(con, sql: str, params: list) -> List[Dict]:
    cur = con.execute(sql, params)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _window_sql(since, until, col: str = "timestamp"):
    sql, p = "", []
    if since is not None:
        sql += f" and {col} >= ?"; p.append(since)
    if until is not None:
        sql += f" and {col} < ?"; p.append(until)
    return sql, p


def _event1(con, hostname: str, guid: str) -> Optional[Dict]:
    r = _rows(con, f"select {', '.join(_PROC_COLS)} from silver_process_events where hostname=? and process_guid=? "
                   "and sysmon_event_id=1 order by timestamp, record_id limit 1", [hostname, guid])
    return r[0] if r else None


def _observed(e1: Dict, role: str, depth: int) -> Dict:
    n = {k: e1[k] for k in _PROC_COLS if k not in ("timestamp", "record_id", "ppid")}
    n.update(status="OBSERVED", role=role, depth=depth, start_utc=e1["timestamp"], end_utc=None, ppid=e1["ppid"],
             pid_from_child=None, evidence_source=e1["event_id"], children_truncated=False)
    return n


def _no_data(hostname: str, guid: str, role: str, depth: int, child_e1: Optional[Dict]) -> Dict:
    """Nút cho tiến trình không có Event 1 trong Silver. Chỉ dùng trường Parent* có thật trong Event 1 của con."""
    n = {k: None for k in _EMPTY_FIELDS}
    n.update(hostname=hostname, process_guid=guid, parent_guid=None, status="NO_DATA", role=role, depth=depth, ppid=None,
             parent_image=child_e1["parent_image"] if child_e1 else None,
             parent_command_line=child_e1["parent_command_line"] if child_e1 else None,
             pid_from_child=child_e1["ppid"] if child_e1 else None,
             evidence_source=child_e1["event_id"] if child_e1 else None, children_truncated=False)
    return n


def _children(con, hostname: str, parents: List[str], since, until) -> List[Dict]:
    if not parents:
        return []
    w, wp = _window_sql(since, until)
    rows = _rows(con, f"select {', '.join(_PROC_COLS)} from silver_process_events where hostname=? and sysmon_event_id=1 "
                      f"and list_contains(?, parent_guid){w} order by timestamp, record_id", [hostname, parents] + wp)
    seen, out = set(), []
    for r in rows:                     # một nút cho mỗi GUID (Event 1 đầu tiên)
        if r["process_guid"] not in seen:
            seen.add(r["process_guid"]); out.append(r)
    return out


def _validate_limits(max_depth: int, max_nodes: int) -> None:
    if not (1 <= int(max_depth) <= MAX_DEPTH):
        raise ValueError(f"max_depth phải trong [1, {MAX_DEPTH}]")
    if not (1 <= int(max_nodes) <= MAX_NODES):
        raise ValueError(f"max_nodes phải trong [1, {MAX_NODES}]")


def process_tree_view(con, hostname: str, process_guid: str, *, max_depth: int = 8, max_nodes: int = 200,
                      since=None, until=None) -> Dict:
    """Cây quanh một tiến trình trên một host.

    nodes: phẳng, theo thứ tự hiển thị (tổ tiên xa → gần, trọng tâm, con cháu theo BFS và thời điểm bắt đầu); cha-con qua
    `parent_guid`. `depth` âm cho tổ tiên, 0 cho trọng tâm, dương cho con cháu. Cửa sổ `since`/`until` (theo `timestamp`
    Silver) chỉ lọc con cháu và số sự kiện; tổ tiên và trọng tâm luôn hiện vì chúng là ngữ cảnh.
    coverage_status: FULL | PARTIAL_ANCESTRY (có nút NO_DATA, vòng lặp hoặc bị cắt ở max_depth) | NOT_FOUND."""
    _validate_limits(max_depth, max_nodes)
    focus_e1 = _event1(con, hostname, process_guid)
    status = "FULL"
    if focus_e1 is not None:
        focus = _observed(focus_e1, "focus", 0)
    else:
        kids = _children(con, hostname, [process_guid], None, None)
        has_events = any(con.execute(f"select 1 from {t} where hostname=? and process_guid=? limit 1",
                                     [hostname, process_guid]).fetchone() for t in _EVENT_COLS)
        has_alert = con.execute("select 1 from alerts where hostname=? and process_guid=? limit 1",
                                [hostname, process_guid]).fetchone()
        if not (kids or has_events or has_alert):
            return {"hostname": hostname, "focus": process_guid, "nodes": [], "coverage_status": "NOT_FOUND",
                    "ancestors_truncated": False, "descendants_truncated": False, "node_limit_reached": False,
                    "window": {"since": since, "until": until}, "limits": {"max_depth": max_depth, "max_nodes": max_nodes}}
        focus = _no_data(hostname, process_guid, "focus", 0, kids[0] if kids else None)
        status = "PARTIAL_ANCESTRY"

    # -- tổ tiên --------------------------------------------------------------------------------------
    ancestors: List[Dict] = []
    seen = {process_guid}
    child_e1, cur = focus_e1, (focus_e1 or {}).get("parent_guid")
    ancestors_truncated = False
    while cur and cur != _ZERO_GUID:
        if len(ancestors) >= max_depth:
            ancestors_truncated, status = True, "PARTIAL_ANCESTRY"; break
        if cur in seen:
            status = "PARTIAL_ANCESTRY"; break          # vòng lặp GUID (dữ liệu bất thường): dừng, không lặp vô hạn
        seen.add(cur)
        e1 = _event1(con, hostname, cur)
        if e1 is None:
            ancestors.append(_no_data(hostname, cur, "ancestor", -(len(ancestors) + 1), child_e1))
            status = "PARTIAL_ANCESTRY"; break
        ancestors.append(_observed(e1, "ancestor", -(len(ancestors) + 1)))
        child_e1, cur = e1, e1["parent_guid"]
    for a in ancestors:
        a["children_truncated"] = None                  # tổ tiên chỉ hiện nhánh dẫn tới trọng tâm, không liệt kê anh em
    nodes = list(reversed(ancestors)) + [focus]
    node_limit_reached = len(nodes) > max_nodes
    nodes = nodes[-max_nodes:] if node_limit_reached else nodes   # giữ trọng tâm khi giới hạn rất nhỏ

    # -- con cháu (BFS theo tầng) ------------------------------------------------------------------------
    by_guid = {n["process_guid"]: n for n in nodes}
    frontier, descendants_truncated = [process_guid], False
    for depth in range(1, max_depth + 1):
        nxt = []
        for c in _children(con, hostname, frontier, since, until):
            if c["process_guid"] in seen:
                continue
            if len(nodes) >= max_nodes:
                node_limit_reached = True
                by_guid[c["parent_guid"]]["children_truncated"] = True
                continue
            seen.add(c["process_guid"])
            n = _observed(c, "descendant", depth)
            nodes.append(n); by_guid[n["process_guid"]] = n; nxt.append(n["process_guid"])
        frontier = nxt
        if not frontier:
            break
    else:
        for c in _children(con, hostname, frontier, since, until):     # còn con cháu sâu hơn max_depth
            if c["process_guid"] not in seen:
                by_guid[c["parent_guid"]]["children_truncated"] = True
                descendants_truncated = True

    _attach_end_times(con, hostname, nodes)
    _attach_event_counts(con, hostname, nodes, since, until)
    _attach_alerts(con, hostname, nodes)
    return {"hostname": hostname, "focus": process_guid, "nodes": nodes, "coverage_status": status,
            "ancestors_truncated": ancestors_truncated, "descendants_truncated": descendants_truncated,
            "node_limit_reached": node_limit_reached, "window": {"since": since, "until": until},
            "limits": {"max_depth": max_depth, "max_nodes": max_nodes}}


def _guids(nodes: Iterable[Dict], observed_only: bool = False) -> List[str]:
    return [n["process_guid"] for n in nodes if not observed_only or n["status"] == "OBSERVED"]


def _attach_end_times(con, hostname: str, nodes: List[Dict]) -> None:
    g = _guids(nodes, observed_only=True)
    if not g:
        return
    ends = dict(con.execute("select process_guid, min(timestamp) from silver_process_events where hostname=? and "
                            "sysmon_event_id=5 and list_contains(?, process_guid) group by 1", [hostname, g]).fetchall())
    for n in nodes:
        if n["status"] == "OBSERVED":
            n["end_utc"] = ends.get(n["process_guid"])


def _attach_event_counts(con, hostname: str, nodes: List[Dict], since, until) -> None:
    g = _guids(nodes)
    counts = {x: {"file": 0, "registry": 0, "network": 0, "dns": 0} for x in g}
    w, wp = _window_sql(since, until)
    for table, cat in (("silver_file_events", "file"), ("silver_registry_events", "registry")):
        for guid, c in con.execute(f"select process_guid, count(*) from {table} where hostname=? and "
                                   f"list_contains(?, process_guid){w} group by 1", [hostname, g] + wp).fetchall():
            counts[guid][cat] = c
    for guid, net, dns in con.execute("select process_guid, count(*) filter (where sysmon_event_id<>22), "
                                      "count(*) filter (where sysmon_event_id=22) from silver_network_events where "
                                      f"hostname=? and list_contains(?, process_guid){w} group by 1", [hostname, g] + wp).fetchall():
        counts[guid]["network"], counts[guid]["dns"] = net, dns
    for n in nodes:
        n["event_counts"] = counts[n["process_guid"]]


def _attach_alerts(con, hostname: str, nodes: List[Dict]) -> None:
    by: Dict[str, List[Dict]] = {x: [] for x in _guids(nodes)}
    for a in _rows(con, "select alert_id, process_guid, rule_id, rule_version, rule_name, severity, status, first_seen_utc "
                        "from alerts where hostname=? and list_contains(?, process_guid) order by first_seen_utc, alert_id",
                   [hostname, list(by)]):
        by[a.pop("process_guid")].append(a)
    for n in nodes:
        n["alerts"] = by[n["process_guid"]]


# -- timeline của một nút ----------------------------------------------------------------------------------
def _category(table: str, sysmon_event_id: int) -> str:
    if table == "silver_network_events":
        return "dns" if sysmon_event_id == 22 else "network"
    return table[len("silver_"):-len("_events")]


def _summary(cat: str, e: Dict) -> Optional[str]:
    d = e["detail"]
    if cat == "process":
        return (d.get("command_line") or d.get("image_path")) if e["sysmon_event_id"] == 1 else e["event_type"]
    if cat == "file":
        return d.get("file_path")
    if cat == "registry":
        t = d.get("target_object")
        return f"{t} = {d['details']}" if t and d.get("details") else t
    if cat == "dns":
        return d.get("dns_query_name")
    ip = d.get("dest_ip") or d.get("dest_hostname")
    return f"{ip}:{d['dest_port']}" if ip and d.get("dest_port") is not None else ip


def process_events(con, hostname: str, process_guid: str, *, kinds: Optional[List[str]] = None, since=None, until=None,
                   limit: int = 50, offset: int = 0) -> Dict:
    """Sự kiện Silver của một tiến trình trên một host, gộp các bảng, theo (timestamp, record_id). Không có raw_data."""
    kinds = list(kinds) if kinds else list(CATEGORIES)
    bad = set(kinds) - set(CATEGORIES)
    if bad:
        raise ValueError(f"kinds không hợp lệ: {sorted(bad)}")
    limit, offset = min(max(int(limit), 1), MAX_EVENTS), max(int(offset), 0)
    want = offset + limit + 1
    w, wp = _window_sql(since, until)
    items: List[Dict] = []
    for table, cols in _EVENT_COLS.items():
        cats = set(kinds) & ({"network", "dns"} if table == "silver_network_events" else {_category(table, 1)})
        if not cats:
            continue
        extra = ""
        if table == "silver_network_events" and cats != {"network", "dns"}:
            extra = " and sysmon_event_id=22" if cats == {"dns"} else " and sysmon_event_id<>22"
        sql = (f"select event_id, timestamp, record_id, sysmon_event_id, event_type, {', '.join(cols)} from {table} "
               f"where hostname=? and process_guid=?{extra}{w} order by timestamp, record_id, event_id limit ?")
        for r in _rows(con, sql, [hostname, process_guid] + wp + [want]):
            e = {k: r[k] for k in ("event_id", "timestamp", "record_id", "sysmon_event_id", "event_type")}
            e["category"] = _category(table, r["sysmon_event_id"])
            e["detail"] = {k: r[k] for k in cols if r[k] is not None}
            e["summary"] = _summary(e["category"], e)
            items.append(e)
    items.sort(key=lambda e: (e["timestamp"], e["record_id"], e["event_id"]))
    page = items[offset:offset + limit]
    return {"hostname": hostname, "process_guid": process_guid, "items": page, "limit": limit, "offset": offset,
            "has_more": len(items) > offset + limit}


# -- tìm tiến trình ----------------------------------------------------------------------------------------
def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_processes(con, *, hostname: Optional[str] = None, image: Optional[str] = None, sha256: Optional[str] = None,
                     limit: int = 50) -> List[Dict]:
    """Tìm Event 1 theo image (chứa chuỗi, không phân biệt hoa thường) và/hoặc sha256 (khớp đúng). Cần image hoặc sha256."""
    if not image and not sha256:
        raise ValueError("cần image hoặc sha256")
    cond, p = ["sysmon_event_id=1"], []
    if hostname:
        cond.append("hostname=?"); p.append(hostname)
    if image:
        cond.append("lower(image_path) like ? escape '\\'"); p.append("%" + _like_escape(image.lower()) + "%")
    if sha256:
        cond.append("lower(file_sha256)=?"); p.append(sha256.lower())
    return _rows(con, "select hostname, process_guid, parent_guid, pid, image_path, command_line, user_name, file_sha256, "
                      "timestamp as start_utc, event_id from silver_process_events where " + " and ".join(cond) +
                 " order by timestamp, record_id limit ?", p + [min(max(int(limit), 1), MAX_EVENTS)])
