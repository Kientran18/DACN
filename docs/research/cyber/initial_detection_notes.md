# Initial Detection Notes

> **Cập nhật 2026-10-19:** Danh sách yêu cầu/ý tưởng tuần 2, không phải tất cả đều thu được qua Sysmon hiện tại. Độ phủ có bằng chứng và giới hạn xem [MITRE Matrix v2](mitre-detection-matrix-v2.md); không coi file write/rename hoặc service/heartbeat đã được kiểm chứng.


## Objective

Define initial detection ideas for the selected Windows endpoint threat behaviors.

## Detection Pipeline

```text
Raw Event
    ↓
Normalization
    ↓
Single Event Rules
    ↓
Event Correlation
    ↓
Behavior
    ↓
Risk / Severity
    ↓
Alert
```

## DET-001 - Suspicious PowerShell Execution

### Condition

```text
PowerShell
+
Suspicious Parent
```

Examples of suspicious parents:
- WINWORD.EXE
- EXCEL.EXE
- OUTLOOK.EXE
- Unknown executable from Temp/AppData

### Required Telemetry
- Process creation
- Parent process
- Command line
- User
- Timestamp

### Severity
High

---

## DET-002 - Suspicious Command Shell

### Condition

```text
Unknown/Office Process
        ↓
cmd.exe
```

### Required Telemetry
- Process creation
- Parent process
- Command line

### Severity
Medium to High

---

## DET-003 - Run Key Persistence

### Condition

```text
Registry Run Key modified
+
Target executable is unknown or stored in user-controlled directory
```

Interesting locations:
- Temp
- AppData
- Downloads

### Required Telemetry
- Registry modification
- Responsible process
- Registry key/value
- Target executable path

### Severity
High

---

## DET-004 - Scheduled Task Persistence

### Condition

```text
New Scheduled Task
+
Target executable in suspicious location
```

### Required Telemetry
- Scheduled task event
- Process
- Command line
- User
- Executable path

### Severity
High

---

## DET-005 - Suspicious Tool Download

### Condition

```text
PowerShell / system binary
+
External network connection
+
Executable or script created
```

### Required Telemetry
- Process
- Network connection
- Destination IP/domain
- File creation
- File hash

### Severity
High

---

## DET-006 - Possible Command and Control

### Condition

```text
Unknown process
+
Repeated external connections
```

### Notes

Phase 1 does not require HTTPS content inspection.

The initial implementation may use metadata such as:
- Process name/path
- Destination IP/domain
- Port
- Connection frequency

### Severity
Medium

---

## DET-007 - Security Agent Tampering

### Condition

```text
Agent terminated
OR
Agent service disabled
OR
Security configuration modified
```

### Required Telemetry
- Process termination
- Service state changes
- Agent heartbeat
- Registry/configuration changes

### Severity
Critical

---

## DET-008 - Ransomware-like File Activity

### Condition

```text
Same process
+
Many file modifications
+
Multiple file types
+
Short time window
```

Initial rule concept:

```text
More than N files modified by the same process within T seconds
```

N and T must be tuned during testing.

### Required Telemetry
- Process ID
- File write
- File rename
- File delete
- File extension
- Timestamp

### Severity
Critical

---

## DET-009 - Suspicious Discovery Chain

### Condition

```text
Unknown process
+
System Discovery
+
File/Directory Discovery
```

### Example

```text
unknown.exe
    ↓
cmd.exe
    ↓
systeminfo.exe
    ↓
directory enumeration
```

### Required Telemetry
- Process
- Parent process
- Command line

### Severity
Medium

---

## DET-010 - Drop -> Execute -> Delete

### Condition

```text
File created
    ↓
Executed
    ↓
Deleted shortly afterward
```

### Required Telemetry
- File create
- Process execution
- File delete
- Hash
- Timestamp

### Severity
Medium to High

## Initial Response Mapping

| Detection | Initial Response |
|---|---|
| Suspicious PowerShell | Alert / investigate |
| Run Key persistence | Alert / optionally remove persistence |
| Scheduled Task persistence | Alert / optionally disable task |
| Security agent tampering | Critical alert |
| Ransomware-like behavior | Alert + terminate process candidate |
| Known malicious hash | Block / quarantine candidate |
| Suspicious C2 | Alert / optional network response later |

Automated response should remain conservative during Phase 1 to reduce the risk of damaging legitimate user activity.
