"""Sinh XML Sysmon SYNTHETIC (không phải bắt thật) cho test tích hợp trên Linux. Mọi tên máy/người dùng là giả."""
from __future__ import annotations

import itertools
import uuid

HOST = "LAB-HOST"
_rec = itertools.count(5000)
NS = uuid.UUID("22222222-3333-4444-5555-666666666666")


def guid(name: str) -> str:
    return "{" + str(uuid.uuid5(NS, name)).upper() + "}"


def _wrap(eid: int, ts: str, data: dict, rec: int = None) -> str:
    rec = rec or next(_rec)
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/><EventID>{eid}</EventID>"
            f"<Version>5</Version><Level>4</Level><Task>{eid}</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
            f"<TimeCreated SystemTime='{ts}'/><EventRecordID>{rec}</EventRecordID><Correlation/><Execution ProcessID='1' ThreadID='1'/>"
            f"<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>{HOST}</Computer><Security UserID='S-1-5-18'/></System>"
            f"<EventData>{fields}</EventData></Event>")


def _utc(ts: str) -> str:
    return ts.replace("T", " ").rstrip("Z")[:23]


def proc(ts, name, image, cmd, parent="p0", sha="A" * 64, with_cmd=True):
    d = {"RuleName": "-", "UtcTime": _utc(ts), "ProcessGuid": guid(name), "ProcessId": "4000", "Image": image}
    if with_cmd:
        d["CommandLine"] = cmd
    d.update({"CurrentDirectory": "C:\\", "User": "LAB-HOST\\LABUSER", "IntegrityLevel": "Medium",
              "Hashes": f"SHA256={sha},IMPHASH={'0' * 32}", "ParentProcessGuid": guid(parent), "ParentProcessId": "1",
              "ParentImage": "C:\\Windows\\explorer.exe", "ParentCommandLine": "explorer.exe"})
    return _wrap(1, ts, d)


def filecreate(ts, name, path, actor="p0"):
    return _wrap(11, ts, {"RuleName": "file", "UtcTime": _utc(ts), "ProcessGuid": guid(actor), "ProcessId": "1",
                          "Image": "C:\\Windows\\System32\\cmd.exe", "TargetFilename": path, "CreationUtcTime": _utc(ts), "User": "LAB-HOST\\LABUSER"})


def filedelete(ts, path, actor="p0"):
    return _wrap(26, ts, {"RuleName": "file", "UtcTime": _utc(ts), "ProcessGuid": guid(actor), "ProcessId": "1", "User": "LAB-HOST\\LABUSER",
                          "Image": "C:\\Windows\\System32\\cmd.exe", "TargetFilename": path, "Hashes": f"SHA256={'B' * 64},IMPHASH={'0' * 32}", "IsExecutable": "true"})


def regset(ts, target, details, actor="p0"):
    return _wrap(13, ts, {"RuleName": "registry", "EventType": "SetValue", "UtcTime": _utc(ts), "ProcessGuid": guid(actor), "ProcessId": "1",
                          "Image": "C:\\Windows\\System32\\reg.exe", "TargetObject": target, "Details": details, "User": "LAB-HOST\\LABUSER"})


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
DROP = "C:\\Users\\LABUSER\\AppData\\Local\\Temp\\dacn_lab\\DACN_LAB_x_whoami.exe"
IOC_SHA = "C" * 64


def full_scenario():
    """SC01 + SC02 + SC03 + SC06 (lành tính) + một event 1 thiếu CommandLine + một process có hash IOC."""
    return [
        proc("2026-01-01T10:00:00.1000000Z", "sc01", PS, "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand AAAAAAAAAAAAAAAA"),
        regset("2026-01-01T10:01:00.1000000Z", "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DACN_LAB_x_SC02", "cmd.exe /c echo x"),
        filecreate("2026-01-01T10:02:00.1000000Z", "sc03", DROP),
        proc("2026-01-01T10:02:05.1000000Z", "sc03exe", DROP, DROP),
        filedelete("2026-01-01T10:02:10.1000000Z", DROP),
        proc("2026-01-01T10:03:00.1000000Z", "sc06", PS, "powershell.exe -NoProfile -Command Get-Date"),
        proc("2026-01-01T10:04:00.1000000Z", "nocmd", PS, "", with_cmd=False),
        proc("2026-01-01T10:05:00.1000000Z", "ioc", "C:\\Users\\LABUSER\\AppData\\Local\\Temp\\dacn_lab\\DACN_LAB_x_tool.exe", "tool.exe", sha=IOC_SHA),
    ]
