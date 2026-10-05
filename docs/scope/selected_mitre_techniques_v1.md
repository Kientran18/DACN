# Selected MITRE ATT&CK Techniques v1

## Objective

Select a focused set of MITRE ATT&CK techniques relevant to Phase 1 of the Windows endpoint security project.

Phase 1 focuses on:
- A single Windows endpoint.
- Endpoint telemetry collection.
- Rule-based and behavior-based detection.
- Alert generation.
- Basic investigation context.
- Basic endpoint response.

## Relevant ATT&CK Tactics

The tactics most relevant to the current project scope are:

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Stealth
- Defense Impairment
- Discovery
- Command and Control
- Impact

The highest-priority areas for the prototype are:
- Execution
- Persistence
- Defense Impairment
- Impact

## Selected Techniques

| # | Technique | Tactic | Priority | Reason |
|---|---|---|---|---|
| 1 | T1204.002 - Malicious File | Execution | High | Common initial user-driven execution path |
| 2 | T1059.001 - PowerShell | Execution | High | Frequently abused scripting environment on Windows |
| 3 | T1059.003 - Windows Command Shell | Execution | High | Common command execution mechanism |
| 4 | T1218 - System Binary Proxy Execution | Stealth | Medium | Abuse of trusted Windows binaries |
| 5 | T1547.001 - Registry Run Keys / Startup Folder | Persistence | High | Practical persistence mechanism to detect |
| 6 | T1053.005 - Scheduled Task | Execution / Persistence / Privilege Escalation | High | Common persistence and execution mechanism |
| 7 | T1562.001 - Disable or Modify Tools | Defense Impairment | High | Directly relevant to protecting the endpoint agent |
| 8 | T1082 - System Information Discovery | Discovery | Medium | Common system reconnaissance behavior |
| 9 | T1083 - File and Directory Discovery | Discovery | Medium | Useful for behavior correlation |
| 10 | T1105 - Ingress Tool Transfer | Command and Control | High | Detects downloaded payload/tool behavior |
| 11 | T1071.001 - Web Protocols | Command and Control | Medium | Common HTTP/HTTPS-based C2 behavior |
| 12 | T1070.004 - File Deletion | Stealth | Medium | Useful for detecting cleanup/evasion behavior |
| 13 | T1486 - Data Encrypted for Impact | Impact | Critical | Core ransomware-like behavior |

## Scope Notes

The project does not attempt to cover the full MITRE ATT&CK matrix.

The selected techniques were chosen because they:
- Apply directly to Windows endpoints.
- Produce observable endpoint behavior.
- Can be supported by telemetry available to the Phase 1 prototype.
- Can be tested with safe simulations.
- Fit within the 12-week project scope.

## References

- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK Techniques: https://attack.mitre.org/techniques/
- T1059.001 PowerShell: https://attack.mitre.org/techniques/T1059/001/
- T1059.003 Windows Command Shell: https://attack.mitre.org/techniques/T1059/003/
- T1547.001 Registry Run Keys / Startup Folder: https://attack.mitre.org/techniques/T1547/001/
- T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
