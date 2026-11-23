"""Ép stdout/stderr dùng UTF-8. Windows: khi đầu ra đi qua ống dẫn hoặc chuyển hướng (`| Tee-Object`, `> tệp`) Python dùng
codepage ANSI (cp1252) và sập với UnicodeEncodeError khi in tiếng Việt (đo trên VM Windows). Gọi ở đầu `main()` của mọi CLI."""
import sys


def force_utf8_stdio() -> None:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
