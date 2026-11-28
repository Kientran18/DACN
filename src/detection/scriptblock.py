"""Đánh giá rule 'scriptblock' trên PowerShell 4104 (DACN-DET-203/204; docs/architecture/w8 mục 5.2, hạng mục 6).

- Script block ghép theo (hostname, script_block_id, message_total), thứ tự message_number. Thiếu phần -> đánh giá trên phần có,
  chèn ký tự ngăn cách ở chỗ hở (không nối hai phần không liền nhau thành chuỗi giả), coverage_status = PARTIAL_SCRIPT_BLOCK,
  missing_fields liệt kê phần thiếu. Không bịa phần thiếu.
- KHÔNG chép văn bản script vào DetectionResult (có thể chứa bí mật, w8 mục 2.7): matched_fields chỉ có tên mẫu đã khớp,
  sha256 và độ dài của văn bản đã ghép, số phần.
- Giải mã base64 (DET-204) có giới hạn: số ứng viên, kích thước giải mã; không giải nén; chỉ nhận kết quả là văn bản in được
  (UTF-16LE như -EncodedCommand của PowerShell, hoặc UTF-8).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Dict, List, Optional, Tuple

from .result import DetectionResult, make_dedup_key

GAP = "\x00"     # ngăn cách giữa hai phần không liền nhau
DEFAULT_MAX_CANDIDATES = 50
DEFAULT_MAX_DECODED_BYTES = 1 << 20


def assemble(parts: List[dict]) -> Tuple[str, List[int], List[str]]:
    """parts đã lọc một dòng mỗi message_number, sắp theo message_number. Trả (văn bản, số thứ tự có, event_ids)."""
    out, nums, ids, prev = [], [], [], None
    for p in parts:
        n = p["message_number"]
        if prev is not None and n != prev + 1:
            out.append(GAP)
        out.append(p["script_block_text"] or "")
        nums.append(n)
        ids.append(p["event_id"])
        prev = n
    return "".join(out), nums, ids


def find_patterns(text: str, patterns: List[str]) -> List[str]:
    low = text.lower()
    return sorted({p for p in patterns if p.lower() in low})


def _printable(s: str) -> bool:
    return bool(s) and sum(ch.isprintable() or ch in "\r\n\t" for ch in s) >= 0.9 * len(s)


def decode_candidates(text: str, min_length: int, max_candidates: int = DEFAULT_MAX_CANDIDATES,
                      max_decoded_bytes: int = DEFAULT_MAX_DECODED_BYTES) -> Tuple[List[Tuple[str, str]], int]:
    """Trả ([(encoding, văn bản giải mã)], số ứng viên đã xét). Bỏ qua ứng viên sai độ dài/không hợp lệ/quá lớn."""
    out, seen = [], 0
    for m in re.finditer(r"[A-Za-z0-9+/]{%d,}={0,2}" % min_length, text):
        if seen >= max_candidates:
            break
        cand = m.group(0)
        seen += 1
        if len(cand) % 4 or len(cand) // 4 * 3 > max_decoded_bytes:
            continue
        try:
            raw = base64.b64decode(cand, validate=True)
        except (binascii.Error, ValueError):
            continue
        for enc in ("utf-16-le", "utf-8"):
            try:
                s = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            if _printable(s):
                out.append((enc, s))
                break
    return out, seen


def evaluate_scriptblock(rule: dict, hostname: str, script_block_id: str, total: int,
                         parts: List[dict]) -> Optional[DetectionResult]:
    """MATCH hoặc None (không khớp thì không lưu kết quả, như NO_MATCH của rule single)."""
    text, nums, ids = assemble(parts)
    missing = [f"MessageNumber:{n}" for n in range(1, total + 1) if n not in set(nums)]
    patterns = rule["patterns"]
    matched: Dict[str, object] = {}
    b64 = rule.get("base64")
    if b64:
        decoded, n_cand = decode_candidates(text, b64["min_length"], b64.get("max_candidates", DEFAULT_MAX_CANDIDATES),
                                            b64.get("max_decoded_bytes", DEFAULT_MAX_DECODED_BYTES))
        hits = sorted({p for _, s in decoded for p in find_patterns(s, patterns)})
        if not hits:
            return None
        matched.update(decoded_patterns=hits, base64_candidates=n_cand,
                       decoded_encodings=sorted({e for e, s in decoded if find_patterns(s, patterns)}))
    else:
        hits = find_patterns(text, patterns)
        if not hits:
            return None
        matched["patterns"] = hits
    clean = text.replace(GAP, "")
    matched.update(script_block_id=script_block_id, message_total=total, parts_seen=len(nums),
                   script_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest(), script_length=len(clean))
    rid, ver = rule["rule_id"], rule["rule_version"]
    subject = f"{hostname}|{script_block_id}|{total}"
    reason = rule.get("severity_reason", "")
    if missing:
        reason = f"{reason} [script block thiếu {len(missing)}/{total} phần; kết luận trên phần đã có]".strip()
    return DetectionResult(rule_id=rid, rule_version=ver, outcome="MATCH", subject=subject, contributing_event_ids=ids,
                           matched_fields=matched, missing_fields=missing,
                           coverage_status="PARTIAL_SCRIPT_BLOCK" if missing else "FULL",
                           severity=rule["severity"], severity_reason=reason,
                           dedup_key=make_dedup_key(rid, ver, subject))
