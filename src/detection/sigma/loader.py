"""Nạp rule Sigma theo manifest (ghim sha256) + config/sigma-rules.yaml, dịch sang rule DACN `type: sigma`.

Không nạp một phần âm thầm: mỗi tệp hoặc được nạp, hoặc nằm trong report["rejected"] với mã SIG-E* và lý do.
Rule dict trả về là JSON được (engine lưu vào outbox và băm vào chữ ký rule); bộ đánh giá biên dịch lại từ `sigma.detection`.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

import yaml

from .compiler import compile_rule
from .errors import CODES, SigmaConfigError, SigmaRuleError

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = ROOT / "config" / "sigma-rules.yaml"
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "manifest.yaml"
LEVEL_TO_SEVERITY = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
ALLOWED_STATUS = ("test", "stable")
_CFG_KEYS = {"version", "enabled", "allow_experimental", "max_rules", "regex_max_length", "manifest"}
DEFAULTS = {"enabled": False, "allow_experimental": False, "max_rules": 50, "regex_max_length": 1000, "manifest": None}


def content_sha256(data: bytes) -> str:
    """sha256 trên nội dung đã chuẩn hóa xuống dòng về LF (Git trên Windows có thể đổi sang CRLF khi checkout)."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


@dataclass
class SigmaLoad:
    rules: Dict[str, dict]
    report: dict


def load_sigma_config(path: Optional[Path] = None) -> dict:
    """path=None: tệp mặc định; nếu tệp mặc định không có (bản cài thiếu config) thì Sigma TẮT, không chặn core khởi động.
    Đường dẫn chỉ định rõ mà không đọc được -> lỗi (người dùng muốn dùng cấu hình đó)."""
    if path is None and not DEFAULT_CONFIG.exists():
        return dict(DEFAULTS)
    p = Path(path) if path else DEFAULT_CONFIG
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SigmaConfigError(f"SIGMA-CFG: không đọc được {p.name}") from exc
    return validate_config(data)


def validate_config(data) -> dict:
    if not isinstance(data, dict):
        raise SigmaConfigError("SIGMA-CFG: cấu hình phải là mapping")
    extra = set(data) - _CFG_KEYS
    if extra:
        raise SigmaConfigError(f"SIGMA-CFG: khóa lạ {sorted(extra)}")
    cfg = {**DEFAULTS, **{k: v for k, v in data.items() if k != "version"}}
    for k in ("enabled", "allow_experimental"):
        if not isinstance(cfg[k], bool):
            raise SigmaConfigError(f"SIGMA-CFG: {k} phải là true/false")
    for k, hi in (("max_rules", 1000), ("regex_max_length", 100000)):
        if isinstance(cfg[k], bool) or not isinstance(cfg[k], int) or not 1 <= cfg[k] <= hi:
            raise SigmaConfigError(f"SIGMA-CFG: {k} phải là số nguyên trong [1, {hi}]")
    if cfg["manifest"] is not None and not isinstance(cfg["manifest"], str):
        raise SigmaConfigError("SIGMA-CFG: manifest phải là đường dẫn hoặc null")
    return cfg


def _jsonable(x):
    if isinstance(x, dict):
        return {str(k): _jsonable(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_jsonable(v) for v in x]
    if isinstance(x, (_dt.date, _dt.datetime)):
        return x.isoformat()
    return x


def _techniques(tags) -> List[str]:
    out = []
    for t in tags or []:
        t = str(t).lower()
        if t.startswith("attack.t") and t[8:].replace(".", "").isdigit():
            tid = "T" + t[8:].upper()
            if tid not in out:
                out.append(tid)
    return out


def _translate(doc: dict, entry: dict, source: dict, compiled, sha: str) -> dict:
    sid, level = str(doc["id"]), doc["level"]
    origin = entry.get("origin", "local")
    commit = source.get("commit") if origin == "sigmahq" else None
    src_path = entry["path"][len("sigmahq/"):] if origin == "sigmahq" and entry["path"].startswith("sigmahq/") else entry["path"]
    url = f"{source['repository'].rstrip('/')}/blob/{commit}/{src_path}" if origin == "sigmahq" and commit else None
    techniques = _techniques(doc.get("tags"))
    spec = compiled.logsource
    rule = {
        "rule_id": f"DACN-SIG-{sid[:8].lower()}",
        "rule_version": int(entry.get("version", 1)),
        "name": f"[Sigma] {doc['title']}",
        "description": str(doc.get("description") or doc["title"]).strip(),
        "type": "sigma",
        "status": "enabled" if entry.get("enabled", True) else "disabled",
        "severity": LEVEL_TO_SEVERITY[level],
        "severity_reason": f"level '{level}' của rule Sigma gốc (tác giả Sigma đặt, chưa hiệu chỉnh cho DACN)",
        "detection_source": "SIGMA",
        "false_positives": [str(x) for x in (doc.get("falsepositives") or [])],
        "limitations": ["Rule cộng đồng (Sigma), dịch bằng bộ biên dịch tập con của DACN; chưa kiểm chứng trên dữ liệu thật của DACN",
                        "level/severity do tác giả Sigma đặt, chưa được Cyber hiệu chỉnh"] + list(compiled.coverage_notes),
        "validation_status": "synthetic_only",
        "response_policy": "alert_only",
        "sigma": {
            "id": sid, "title": str(doc["title"]), "status": doc["status"], "level": level,
            "author": str(doc.get("author") or ""), "date": _jsonable(doc.get("date")), "modified": _jsonable(doc.get("modified")),
            "references": [str(x) for x in (doc.get("references") or [])],
            "license": entry.get("license") or source.get("license"), "license_url": source.get("license_url"),
            "origin": origin, "source_path": src_path, "source_commit": commit, "source_url": url, "source_sha256": sha,
            "logsource": _jsonable(doc["logsource"]), "dacn_logsource": spec, "detection": _jsonable(doc["detection"]),
            "coverage_notes": list(compiled.coverage_notes),
        },
    }
    if techniques:
        rule["mitre_technique_ids"] = techniques
        rule["mitre_basis"] = (f"tag attack.* của rule SigmaHQ {sid}" + (f" @commit {commit[:12]}" if commit else "")
                               + "; chưa được Cyber xác minh")
    if spec["kind"] == "scriptblock":
        rule["group_by_field"] = "script_block_id"
    elif spec["kind"] == "defender":
        rule["group_by_field"] = "detection_id"
    return rule


def _summary(rule: dict, active: bool) -> dict:
    """Tóm tắt cho API. Khóa bắt đầu bằng '_' là nội bộ (đường dẫn tệp), API không trả ra."""
    s = rule["sigma"]
    return {"rule_id": rule["rule_id"], "rule_version": rule["rule_version"], "sigma_id": s["id"], "title": s["title"],
            "level": s["level"], "severity": rule["severity"], "sigma_status": s["status"], "enabled": rule["status"] == "enabled",
            "active": active, "logsource": s["logsource"], "dacn_table": s["dacn_logsource"]["table"],
            "event_ids": s["dacn_logsource"]["event_ids"], "author": s["author"], "license": s["license"],
            "license_url": s["license_url"], "origin": s["origin"], "source_path": s["source_path"],
            "source_url": s["source_url"], "mitre_technique_ids": rule.get("mitre_technique_ids", []),
            "coverage_notes": s["coverage_notes"]}


def load_sigma(config: Union[None, dict, Path, str] = None, manifest_path: Optional[Path] = None) -> SigmaLoad:
    cfg = validate_config(config) if isinstance(config, dict) else load_sigma_config(config)
    if manifest_path is None:
        manifest_path = (ROOT / cfg["manifest"]) if cfg["manifest"] else DEFAULT_MANIFEST
    manifest_path = Path(manifest_path)
    try:
        man = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SigmaConfigError(f"SIGMA-CFG: không đọc được manifest {manifest_path.name}") from exc
    if not isinstance(man, dict) or not isinstance(man.get("rules"), list):
        raise SigmaConfigError("SIGMA-CFG: manifest cần khóa 'rules' (danh sách)")
    source = man.get("source") or {}
    base = manifest_path.parent / man.get("base_dir", "rules")
    rejected: List[dict] = []
    candidates: List[dict] = []
    files: Dict[str, str] = {}
    for entry in man["rules"]:
        rec = {"path": entry.get("path"), "sigma_id": entry.get("sigma_id"), "title": None}
        try:
            if not isinstance(entry, dict) or not entry.get("path") or not entry.get("sigma_id"):
                raise SigmaRuleError("SIG-E001", "mục manifest cần path và sigma_id")
            f = (base / entry["path"]).resolve()
            if base.resolve() not in f.parents:
                raise SigmaRuleError("SIG-E001", "path nằm ngoài base_dir của manifest")
            try:
                raw = f.read_bytes()
            except OSError:
                raise SigmaRuleError("SIG-E001", "không đọc được tệp rule") from None
            sha = content_sha256(raw)
            if sha != entry.get("sha256"):
                raise SigmaRuleError("SIG-E009", "sha256 tệp khác manifest (tệp đã bị sửa hoặc manifest chưa cập nhật)")
            try:
                docs = [d for d in yaml.safe_load_all(raw.decode("utf-8")) if d is not None]
            except (yaml.YAMLError, UnicodeDecodeError):
                raise SigmaRuleError("SIG-E001", "YAML lỗi") from None
            if len(docs) != 1 or not isinstance(docs[0], dict):
                raise SigmaRuleError("SIG-E001", "tệp phải có đúng một document Sigma (rule collection chưa hỗ trợ)")
            doc = docs[0]
            rec["title"] = doc.get("title")
            for k in ("title", "id", "status", "level", "logsource", "detection"):
                if k not in doc:
                    raise SigmaRuleError("SIG-E001", f"thiếu khóa '{k}'")
            if str(doc["id"]).lower() != str(entry["sigma_id"]).lower():
                raise SigmaRuleError("SIG-E001", f"id trong tệp ({doc['id']}) khác manifest")
            if doc["status"] not in ALLOWED_STATUS + (("experimental",) if cfg["allow_experimental"] else ()):
                raise SigmaRuleError("SIG-E007", f"status '{doc['status']}' không được phép theo cấu hình")
            if doc["level"] not in LEVEL_TO_SEVERITY:
                raise SigmaRuleError("SIG-E007", f"level '{doc['level']}' không tạo alert (chỉ low/medium/high/critical)")
            if not (entry.get("license") or source.get("license")):
                raise SigmaRuleError("SIG-E001", "thiếu license của rule")
            compiled = compile_rule(doc, regex_max_length=cfg["regex_max_length"])
            cand = _translate(doc, entry, source, compiled, sha)
            files[cand["rule_id"]] = str(f)
            candidates.append(cand)
        except SigmaRuleError as exc:
            rejected.append({**rec, "code": exc.code, "reason": exc.message})
    # trùng id hoặc trùng rule_id (8 hex đầu): loại tất cả bên tham gia, không chọn ngẫu nhiên một bên
    by_id: Dict[str, List[dict]] = {}
    for r in candidates:
        by_id.setdefault(r["rule_id"], []).append(r)
    loaded: List[dict] = []
    for rid, group in by_id.items():
        if len(group) > 1:
            for r in group:
                rejected.append({"path": r["sigma"]["source_path"], "sigma_id": r["sigma"]["id"], "title": r["sigma"]["title"],
                                 "code": "SIG-E008", "reason": f"trùng rule_id {rid} với {len(group) - 1} rule khác"})
        else:
            loaded.append(group[0])
    active_count, rules = 0, {}
    final = []
    for r in loaded:
        if r["status"] == "enabled":
            if active_count >= cfg["max_rules"]:
                rejected.append({"path": r["sigma"]["source_path"], "sigma_id": r["sigma"]["id"], "title": r["sigma"]["title"],
                                 "code": "SIG-E011", "reason": f"vượt max_rules={cfg['max_rules']}"})
                continue
            active_count += 1
        final.append(r)
        if cfg["enabled"]:
            rules[r["rule_id"]] = r
    report = {"enabled": cfg["enabled"], "config": cfg, "manifest": manifest_path.name, "source": source,
              "loaded": [{**_summary(r, cfg["enabled"] and r["status"] == "enabled"), "_file": files.get(r["rule_id"])}
                         for r in final],
              "rejected": rejected, "error_codes": CODES,
              "note": "rule Sigma là synthetic_only; không phải tỷ lệ phát hiện; không kích hoạt response"}
    return SigmaLoad(rules, report)
