# Required Security Telemetry v1

## Objective

Identify the high-level Windows endpoint telemetry required to support the selected MITRE ATT&CK techniques and initial detection rules.

## Required Telemetry

| Telemetry | Minimum Fields | Priority |
|---|---|---|
| Process Creation | timestamp, PID, PPID, process name, path, command line, user | Critical |
| Process Termination | timestamp, PID, process name, exit/termination context | High |
| File Events | timestamp, operation, file path, process ID, extension | Critical |
| Registry Events | timestamp, operation, key, value, process ID | High |
| Network Connection | timestamp, PID, destination IP, destination port, protocol | High |
| DNS Query | timestamp, process ID, queried domain | Medium |
| Image / DLL Load | timestamp, PID, module path | Medium |
| Scheduled Task Events | timestamp, task name, action, user, target executable | Medium |
| Service Events | timestamp, service name, state/action, process/user | High |
| File Hash | SHA-256, file path, timestamp | High |

## Suggested Event Types

```text
PROCESS_CREATE
PROCESS_TERMINATE
FILE_CREATE
FILE_WRITE
FILE_RENAME
FILE_DELETE
REGISTRY_SET
REGISTRY_DELETE
NETWORK_CONNECT
DNS_QUERY
IMAGE_LOAD
TASK_CREATE
TASK_UPDATE
SERVICE_START
SERVICE_STOP
SERVICE_CHANGE
```

## Normalized Event Schema

A common normalized format should be used so the detection engine is not tightly coupled to a single Windows telemetry source.

Example:

```json
{
  "timestamp": "2026-10-05T10:00:00+07:00",
  "event_type": "PROCESS_CREATE",
  "host": {
    "hostname": "HOST-01"
  },
  "process": {
    "pid": 1234,
    "ppid": 1000,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe ...",
    "hash": "..."
  },
  "user": {
    "name": "user"
  },
  "metadata": {}
}
```

## Telemetry Mapping

| Detection | Required Telemetry |
|---|---|
| DET-001 Suspicious PowerShell | Process, parent process, command line |
| DET-002 Suspicious CMD | Process, parent process, command line |
| DET-003 Run Key Persistence | Registry, process, target path |
| DET-004 Scheduled Task Persistence | Scheduled task, process, command line |
| DET-005 Suspicious Tool Download | Process, network, file creation |
| DET-006 Possible C2 | Process, network, DNS |
| DET-007 Agent Tampering | Process termination, service events, heartbeat |
| DET-008 Ransomware-like Behavior | Process, file write/rename/delete |
| DET-009 Discovery Chain | Process, parent process, command line |
| DET-010 Drop-Execute-Delete | File create, process execution, file delete |

## Windows Telemetry Sources to Evaluate

The implementation team should evaluate:
- Windows Security Event Log.
- Sysmon.
- Event Tracing for Windows (ETW).
- Windows APIs.

For the first prototype, Sysmon can be used as a useful reference/source because it provides rich process, network, file, registry and DNS events.

## References

- Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Event 4688: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
