"""Khử định danh mẫu Sysmon XML (PH1-T12). KHÔNG ghi đè mẫu gốc; KHÔNG in giá trị gốc.
Thay: tên máy (<Computer>), tên người dùng (DOMAIN\\user, C:\\Users\\user), SID miền (S-1-5-21-a-b-c-rid) bằng giá trị giả nhất quán.
Giữ nguyên cấu trúc, ProcessGuid, quan hệ cha-con. event_id (UUIDv5 theo Computer) sẽ khác khi chạy lại collector - đúng kỳ vọng.
Dùng:  python scripts/sanitize_samples.py --src references/samples/raw --out tests/fixtures/sanitized"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List

SYSTEM_USERS = {"system", "local service", "network service", "nt authority", "nt service", "window manager", "font driver host"}
SYSTEM_SIDS = re.compile(r"^S-1-5-(18|19|20|32-\d+|80-.+)$")


def discover(texts: List[str]) -> Dict[str, str]:
    """Trả ánh xạ gốc -> giả (không bao giờ in ra)."""
    hosts, users, doms, sids = [], [], [], []
    for t in texts:
        hosts += re.findall(r"<Computer>([^<]+)</Computer>", t)
        for dom, usr in re.findall(r'<Data Name="(?:User|LogonUser)">([^\\<]+)\\([^<]+)</Data>', t):
            if dom.lower() not in SYSTEM_USERS and usr.lower() not in SYSTEM_USERS:
                doms.append(dom); users.append(usr)
        users += [u for u in re.findall(r"(?i)[A-Z]:\\Users\\([^\\<\"]+)\\", t) if u.lower() not in ("public", "default", "all users", "default user")]
        sids += re.findall(r"S-1-5-21-\d+-\d+-\d+", t)
    m: Dict[str, str] = {}
    for i, h in enumerate(dict.fromkeys(hosts), 1):
        m[h] = f"LAB-HOST-{i:02d}"
    for i, u in enumerate(dict.fromkeys(users), 1):
        m.setdefault(u, f"LABUSER{i:02d}")
    for i, d in enumerate(dict.fromkeys(doms), 1):
        m.setdefault(d, m.get(d, None) or next(iter(m.values())))   # miền thường trùng tên máy
    for i, s in enumerate(dict.fromkeys(sids), 1):
        m[s] = f"S-1-5-21-1000-1000-{1000 + i}"
    return {k: v for k, v in m.items() if k and not k.startswith("S-1-5-18")}


def apply(text: str, mapping: Dict[str, str]) -> str:
    for k in sorted(mapping, key=len, reverse=True):
        text = re.sub(re.escape(k), mapping[k], text, flags=re.IGNORECASE)
    return text


def leaks(text: str, mapping: Dict[str, str]) -> int:
    return sum(len(re.findall(re.escape(k), text, flags=re.IGNORECASE)) for k in mapping if len(k) >= 4)


def sanitize_dir(src: Path, out: Path) -> dict:
    files = sorted(Path(src).glob("*.xml"))
    texts = [f.read_text(encoding="utf-8") for f in files]
    mapping = discover(texts)
    out.mkdir(parents=True, exist_ok=True)
    total_leaks = 0
    for f, t in zip(files, texts):
        s = apply(t, mapping)
        total_leaks += leaks(s, mapping)
        (out / f.name).write_text(s, encoding="utf-8")
    (out / "README.md").write_text("# Mẫu đã khử định danh\n\nSinh bởi `scripts/sanitize_samples.py` từ `references/samples/raw`. "
                                   "Tên máy/người dùng/SID miền đã thay bằng giá trị giả nhất quán. Dữ liệu vẫn là mẫu lab, không công bố ngoài nhóm khi chưa rà soát.\n", encoding="utf-8")
    return {"files": len(files), "identifiers_replaced": len(mapping), "leaks_remaining": total_leaks}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.out.resolve() == a.src.resolve():
        raise SystemExit("--out phải khác --src (không ghi đè mẫu gốc)")
    rep = sanitize_dir(a.src, a.out)
    print(rep)
    return 1 if rep["leaks_remaining"] else 0


if __name__ == "__main__":
    sys.exit(main())
