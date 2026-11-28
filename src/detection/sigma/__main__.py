"""CLI rule Sigma (chỉ đọc, không cần mạng, không đụng DB):

  PYTHONPATH=src:poc/sysmon-collector python -m detection.sigma check <tệp.yml> [--origin local|sigmahq]
      Biên dịch thử một tệp: in kết luận HỖ TRỢ / BỊ LOẠI (mã SIG-E*, lý do), bảng Silver, Event ID, và dòng manifest gợi ý.
  PYTHONPATH=src:poc/sysmon-collector python -m detection.sigma list [--config config/sigma-rules.yaml]
      Liệt kê rule trong manifest: đã nạp / bị loại kèm lý do.
Mã thoát: 0 = hỗ trợ (check) / không có rule bị loại (list); 1 = có rule bị loại.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .compiler import compile_rule
from .errors import SigmaRuleError
from .loader import DEFAULT_MANIFEST, LEVEL_TO_SEVERITY, content_sha256, load_sigma


def check(path: Path, origin: str = "local") -> dict:
    raw = path.read_bytes()
    out = {"file": path.name, "sha256": content_sha256(raw)}
    try:
        docs = [d for d in yaml.safe_load_all(raw.decode("utf-8")) if d is not None]
        if len(docs) != 1 or not isinstance(docs[0], dict):
            raise SigmaRuleError("SIG-E001", "tệp phải có đúng một document Sigma")
        doc = docs[0]
        for k in ("title", "id", "status", "level", "logsource", "detection"):
            if k not in doc:
                raise SigmaRuleError("SIG-E001", f"thiếu khóa '{k}'")
        if doc["level"] not in LEVEL_TO_SEVERITY:
            raise SigmaRuleError("SIG-E007", f"level '{doc['level']}' không tạo alert")
        c = compile_rule(doc)
    except (yaml.YAMLError, UnicodeDecodeError):
        return {**out, "supported": False, "code": "SIG-E001", "reason": "YAML lỗi"}
    except SigmaRuleError as exc:
        return {**out, "supported": False, "code": exc.code, "reason": exc.message}
    rel = path.resolve()
    base = DEFAULT_MANIFEST.parent / "rules"
    try:
        rel_path = rel.relative_to(base.resolve()).as_posix()
    except ValueError:
        rel_path = f"local/{path.name}"
    entry = {"path": rel_path, "origin": origin, "sigma_id": str(doc["id"]), "sha256": out["sha256"], "version": 1,
             "enabled": True}
    if origin == "local":
        entry["license"] = "<giấy phép của rule, ví dụ DRL-1.1>"
    return {**out, "supported": True, "rule_id": f"DACN-SIG-{str(doc['id'])[:8].lower()}", "title": doc["title"],
            "status": doc["status"], "level": doc["level"], "dacn_table": c.logsource["table"],
            "event_ids": c.logsource["event_ids"], "coverage_notes": c.coverage_notes,
            "manifest_entry": entry,
            "note": "status experimental cần allow_experimental: true; rule là synthetic_only, không kích hoạt response"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="detection.sigma")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("file", type=Path)
    c.add_argument("--origin", choices=("local", "sigmahq"), default="local")
    li = sub.add_parser("list")
    li.add_argument("--config", type=Path, default=None)
    a = ap.parse_args(argv)
    if a.cmd == "check":
        res = check(a.file, a.origin)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        if res["supported"]:
            print("\n# Dòng manifest gợi ý (src/detection/sigma/manifest.yaml):")
            print(yaml.safe_dump([res["manifest_entry"]], allow_unicode=True, sort_keys=False).rstrip())
        return 0 if res["supported"] else 1
    rep = load_sigma(a.config).report
    out = {"enabled": rep["enabled"], "loaded": [{k: v for k, v in x.items() if not k.startswith("_")} for x in rep["loaded"]],
           "rejected": rep["rejected"]}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 1 if rep["rejected"] else 0


if __name__ == "__main__":
    from common.console import force_utf8_stdio
    force_utf8_stdio()
    sys.exit(main())
