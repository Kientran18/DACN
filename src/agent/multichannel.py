"""Agent đa kênh (live): một EventLogSource + Checkpoint + BronzeWriter + health cho MỖI kênh, chạy luân phiên.

Thiết kế: docs/architecture/w8/telemetry-defender-powershell-proposal.md mục 2.2 (phương án A, người dùng duyệt 2026-11-26).
- Lỗi một kênh (thiếu quyền C-006, kênh không tồn tại A-002) không chặn kênh khác.
- Checkpoint riêng `agent/checkpoint_live_<slug>.json`. Kênh Sysmon kế thừa `agent/checkpoint_live.json` cũ (sao chép,
  không xóa tệp cũ) để nâng cấp không đọc lại từ đầu.
- Segment riêng theo kênh: Sysmon giữ tên `seg-<thời gian>-<n>` như cũ; kênh khác `seg-<slug>-<thời gian>-<n>`, nên
  manifest first/last_record_id chỉ thuộc một kênh.
- Mỗi lượt đọc tối đa `max_events_per_run` sự kiện mỗi kênh (kênh ồn không bỏ đói Sysmon).
- `agent/health.json` giữ các khóa cấp cao cũ (state, heartbeat, last_event_at, last_seal_at, events_written,
  errors_by_code) và thêm `channels`. state: `error` khi mọi kênh lỗi, `degraded` khi chỉ một phần lỗi.
TRẠNG THÁI: test với nguồn giả trên Linux; CHƯA chạy trên Windows.
"""
from __future__ import annotations

import json
import os
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

import windows_channels as wc

from .bronze_writer import BronzeWriter
from .checkpoint import Checkpoint
from .runner import AgentRunner


class ChannelConfigError(ValueError):
    """CFG-006: kênh cấu hình không được hỗ trợ."""


def resolve_channels(channel_configs) -> List[dict]:
    """Kiểm tra tên kênh với windows_channels; trả [{name (chuẩn), xpath}] cho các kênh enabled."""
    out = []
    for c in channel_configs:
        name = wc.canonical_channel(c.name)
        if name is None:
            raise ChannelConfigError(f"CFG-006 kênh không được hỗ trợ: {c.name!r}; hỗ trợ: {sorted(wc.CHANNEL_SOURCES)}")
        if c.enabled:
            out.append({"name": name, "xpath": c.xpath or wc.DEFAULT_XPATH[name]})
    if not out:
        raise ChannelConfigError("CFG-006 không có kênh nào enabled")
    return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MultiChannelAgent:
    def __init__(self, channels: List[dict], home: Path, bronze_dir: Path,
                 source_factory: Callable[[str, str], object], *, stop_file: Optional[Path] = None,
                 max_events_per_run: int = 500, batch_size: int = 100):
        self.home = Path(home)
        self.health_path = self.home / "agent" / "health.json"
        self.runners: List[tuple] = []
        for ch in channels:
            name, slug = ch["name"], wc.channel_slug(ch["name"])
            cp_path = self.home / "agent" / f"checkpoint_live_{slug}.json"
            self._migrate_checkpoint(name, cp_path)
            prefix = "" if wc.is_sysmon(name) else f"{slug}-"
            runner = AgentRunner(source_factory(name, ch["xpath"]), BronzeWriter(bronze_dir, name_prefix=prefix),
                                 Checkpoint(cp_path), self.home / "agent" / "channels" / f"{slug}.json",
                                 batch_size=batch_size, mode="live", stop_file=stop_file,
                                 max_events_per_run=max_events_per_run)
            self.runners.append((name, runner))

    def _migrate_checkpoint(self, name: str, new_path: Path) -> None:
        old = self.home / "agent" / "checkpoint_live.json"
        if wc.is_sysmon(name) and not new_path.exists() and old.exists():
            new_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(old, new_path)

    # -- điều khiển -----------------------------------------------------------
    def request_stop(self) -> None:
        for _, r in self.runners:
            r.request_stop()

    def should_stop(self) -> bool:
        return any(r._should_stop() for _, r in self.runners)

    @property
    def failed(self) -> bool:
        return any(r.failed for _, r in self.runners)

    @property
    def source_failed(self) -> bool:
        return any(r.source_failed for _, r in self.runners)

    @property
    def has_backlog(self) -> bool:
        """Có kênh vừa dừng vì giới hạn mỗi lượt: vòng --follow chạy lượt tiếp ngay, không ngủ."""
        return any(r.hit_limit for _, r in self.runners)

    def run_round(self, final: bool = False) -> None:
        """Một lượt: mỗi kênh đọc tối đa max_events_per_run sự kiện, rồi ghi health tổng hợp."""
        for _, r in self.runners:
            if r._should_stop():
                break
            r.run(final=final)
        self.write_health()

    def mark_stopped(self) -> None:
        for _, r in self.runners:
            r.mark_stopped()
        self.write_health()

    # -- health -----------------------------------------------------------------
    def write_health(self) -> None:
        per = {}
        errors, written, last_event, last_seal = Counter(), 0, None, None
        for name, r in self.runners:
            state = r.state or "idle"
            per[name] = {"state": state, "last_event_at": r.last_event_at, "last_seal_at": r.writer.last_sealed_at,
                         "events_written": r.written, "errors_by_code": dict(r.errors)}
            errors.update(r.errors)
            written += r.written
            last_event = max(filter(None, [last_event, r.last_event_at]), default=None)
            last_seal = max(filter(None, [last_seal, r.writer.last_sealed_at]), default=None)
        states = [p["state"] for p in per.values()]
        if all(s == "error" for s in states):
            state = "error"
        elif "error" in states:
            state = "degraded"
        elif "running" in states:
            state = "running"
        elif all(s == "stopped" for s in states):
            state = "stopped"
        else:
            state = "idle"
        h = {"state": state, "heartbeat": _now(), "last_event_at": last_event, "last_seal_at": last_seal,
             "events_written": written, "errors_by_code": dict(errors), "channels": per}
        tmp = self.health_path.with_suffix(".tmp")
        try:
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(h), encoding="utf-8")
            os.replace(tmp, self.health_path)
        except OSError:
            pass     # như AgentRunner: không để lỗi ghi health làm chết agent
