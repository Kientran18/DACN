"""Lớp truy vấn tham số hóa (PH3-T06). Không ghép giá trị vào SQL; tên bảng/cột qua danh sách trắng.
Không JOIN theo PID (ADR 0002): cây tiến trình dùng process_guid."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

_FILTERS = {
    "silver_process_events": {"hostname", "process_guid", "parent_guid", "image_path", "file_sha256", "command_line", "sysmon_event_id"},
    "silver_file_events": {"hostname", "process_guid", "image_path", "file_path", "file_sha256", "sysmon_event_id"},
    "silver_registry_events": {"hostname", "process_guid", "image_path", "sysmon_event_id"},
    "silver_network_events": {"hostname", "process_guid", "image_path", "sysmon_event_id"},
}
MAX_LIMIT = 1000


class Query:
    def __init__(self, con):
        self.con = con

    def _rows(self, sql: str, params: list) -> List[Dict[str, Any]]:
        cur = self.con.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def events(self, table: str, *, since=None, until=None, limit: int = 100, offset: int = 0,
               **filters) -> List[Dict[str, Any]]:
        if table not in _FILTERS:
            raise ValueError(f"bảng không được hỗ trợ: {table}")
        bad = set(filters) - _FILTERS[table]
        if bad:
            raise ValueError(f"bộ lọc không hỗ trợ: {sorted(bad)}")
        where, params = [], []
        for k, v in filters.items():
            where.append(f"{k} = ?"); params.append(v)
        if since is not None:
            where.append("timestamp >= ?"); params.append(since)
        if until is not None:
            where.append("timestamp < ?"); params.append(until)
        sql = f"select * from {table}" + (" where " + " and ".join(where) if where else "")
        sql += " order by timestamp, event_id limit ? offset ?"
        return self._rows(sql, params + [min(max(int(limit), 1), MAX_LIMIT), max(int(offset), 0)])

    def process_tree(self, root_process_guid: str, hostname: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "select * from v_process_tree_lineage where root_process_guid = ?"
        params: list = [root_process_guid]
        if hostname:
            sql += " and hostname = ?"; params.append(hostname)
        return self._rows(sql + " order by tree_depth, timestamp", params)

    def correlated(self, process_guid: str, start, end, limit: int = 500) -> Dict[str, List[Dict[str, Any]]]:
        """Mọi sự kiện của một process_guid trong cửa sổ thời gian [start, end)."""
        return {t: self.events(t, process_guid=process_guid, since=start, until=end, limit=limit)
                for t in _FILTERS}
