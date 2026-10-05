# Threat Model v1

## 1. Scope

Threat Model v1 covers one Windows 10/11 endpoint protected by the Phase 1 endpoint security prototype.

The system focuses on:
- Endpoint event collection.
- Local event normalization/storage.
- Detection.
- Alert generation.
- Investigation context.
- Basic response.

The system does not include a central management server in Phase 1.

## 2. System Model

```text
┌──────────────── WINDOWS ENDPOINT ────────────────┐
│                                                  │
│ User                                             │
│   │                                              │
│   ▼                                              │
│ Applications / Processes                         │
│   │                                              │
│   ├── Process Events                             │
│   ├── File Events                                │
│   ├── Registry Events                            │
│   └── Network Events                             │
│                  │                               │
│                  ▼                               │
│          Security Collector                      │
│                  │                               │
│                  ▼                               │
│          Normalized Events                       │
│                  │                               │
│          ┌───────┴────────┐                      │
│          ▼                ▼                      │
│     Event Storage    Detection Engine            │
│                           │                      │
│                  ┌────────┼────────┐             │
│                  ▼        ▼        ▼             │
│              Signature   Rule   Behavior         │
│                           │                      │
│                           ▼                      │
│                         Alert                    │
│                           │                      │
│                ┌──────────┴──────────┐           │
│                ▼                     ▼           │
│          Investigation           Response        │
│                                                  │
└──────────────────────────────────────────────────┘
```

## 3. Assets

The following assets should be protected:

- User files.
- User credentials.
- Windows operating system.
- Security agent.
- Security event logs.
- Detection rules.
- Signature database.
- Application processes.
- Registry/system configuration.

## 4. Threat Sources

Threat Model v1 considers:

- Malicious executable.
- Malicious script.
- Downloaded payload.
- Potentially unwanted application.
- Ransomware-like process.
- Compromised legitimate application.
- Local malicious process.

## 5. Out of Scope

The following are not primary Phase 1 targets:

- Kernel rootkits.
- Bootkits and firmware malware.
- Full memory forensics.
- Enterprise Active Directory attacks.
- Cross-endpoint lateral movement.
- Cloud workload security.
- Mobile endpoint security.
- Full SOC/SIEM.
- Advanced automated malware reverse engineering.
- Full enterprise EDR orchestration.

## 6. Trust Boundaries

### Boundary 1 - Internet to Endpoint

```text
Internet
   │
   ▼
Windows Endpoint
```

Main threats:
- Downloaded payloads.
- External C2 communication.
- Malicious content.

### Boundary 2 - Application to Security Monitoring

```text
Applications / Processes
          │
          ▼
   Security Monitoring
```

Main threats:
- Malicious execution.
- LOLBin abuse.
- Masquerading.
- Evasion.

### Boundary 3 - Security Agent to Local Security Data

```text
Security Agent
      │
      ▼
Rules / Logs / Signature Database
```

Main threats:
- Agent termination.
- Rule modification.
- Log deletion.
- Configuration tampering.

## 7. Initial Attack Scenarios

### Scenario 1 - Malicious Download and Execution

```text
User downloads file
        ↓
T1204.002 Malicious File
        ↓
File executed
        ↓
T1059.001 PowerShell
        ↓
T1105 Ingress Tool Transfer
        ↓
Payload executed
```

Detection points:
- File creation in Downloads/Temp.
- Downloaded file execution.
- Suspicious process tree.
- PowerShell execution.
- External connection.
- New executable creation.

Expected severity: High.

### Scenario 2 - Registry Persistence

```text
Unknown executable
        ↓
T1547.001 Modify Run Key
        ↓
User logs in again
        ↓
Executable starts automatically
```

Expected severity: High.

### Scenario 3 - Scheduled Task Persistence

```text
Unknown process
        ↓
T1053.005 Create Scheduled Task
        ↓
Task executes suspicious binary
```

Expected severity: High.

### Scenario 4 - Discovery to C2

```text
Unknown executable
        ↓
T1082 System Discovery
        ↓
T1083 File Discovery
        ↓
T1071.001 Web Protocol communication
```

Expected severity: Medium to High when correlated.

### Scenario 5 - Security Agent Tampering

```text
Unknown process
        ↓
T1562.001 Disable or Modify Tools
        ↓
Endpoint agent stopped/disabled
```

Expected severity: Critical.

### Scenario 6 - Ransomware-like Behavior

```text
Unknown executable
        ↓
T1083 File Discovery
        ↓
Large file modification activity
        ↓
T1486 Data Encrypted for Impact
```

Expected severity: Critical.

## 8. Risk Priority v1

| Threat | Likelihood | Impact | Priority |
|---|---|---|---|
| Suspicious process execution | High | High | P1 |
| PowerShell abuse | High | High | P1 |
| Registry persistence | Medium | High | P1 |
| Agent termination | Medium | Critical | P1 |
| Ransomware-like behavior | Medium | Critical | P1 |
| Suspicious file execution | High | High | P1 |
| Tool download | Medium | High | P2 |
| Scheduled task persistence | Medium | High | P2 |
| C2 communication | Medium | High | P2 |
| Discovery commands | High | Low | P3 |
| File deletion | Medium | Medium | P3 |
| LOLBin abuse | Medium | Medium | P3 |

## 9. Threat Model Principle

Threat Model v1 is behavior-oriented.

A single process or event is not automatically malicious. Detection confidence should increase when multiple related events form a suspicious chain.
