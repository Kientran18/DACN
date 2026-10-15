# Security Behavior List

## Objective

Document observable endpoint behavior for each selected MITRE ATT&CK technique.

| Technique | Observable Behavior | Required Telemetry | Initial Detection Direction |
|---|---|---|---|
| T1204.002 - Malicious File | File appears in Downloads/Temp/Desktop, then is executed; suspicious child process may follow | File events, process creation, parent process, hash, command line | Correlate downloaded file execution with suspicious child process |
| T1059.001 - PowerShell | powershell.exe/pwsh.exe runs with suspicious parent, encoded command, network activity, or file creation | Process, command line, parent-child, network, file events | Detect suspicious PowerShell parent/arguments and correlate with network/file actions |
| T1059.003 - Windows Command Shell | cmd.exe or batch file is launched by suspicious parent and spawns additional executables/scripts | Process creation, parent process, command line, user | Detect unusual parent-child chains involving cmd.exe |
| T1218 - System Binary Proxy Execution | Trusted Windows binaries such as rundll32.exe, regsvr32.exe or msiexec.exe execute unusual payloads | Process, command line, module load, network, file path | Detect trusted binaries loading or executing content from unusual locations |
| T1547.001 - Registry Run Keys / Startup Folder | Process modifies Run/RunOnce keys or Startup locations to reference suspicious executable | Registry events, process, path, value | Alert on persistence entries pointing to Temp/AppData/Downloads or unknown binary |
| T1053.005 - Scheduled Task | New scheduled task is created and points to suspicious executable/script | Process, command line, task events, user, executable path | Alert on suspicious task creation, especially from user-controlled paths |
| T1562.001 - Disable or Modify Tools | Security agent/process/service is stopped, killed, disabled, or configuration is changed | Process termination, service events, registry/config change, heartbeat | Critical alert on unexpected agent/service termination or security config changes |
| T1082 - System Information Discovery | systeminfo, hostname or similar commands are executed by suspicious process | Process, parent process, command line | Correlate discovery commands with unknown or suspicious parent process |
| T1083 - File and Directory Discovery | Recursive or large-scale file/directory enumeration | Process, command line, file access pattern | Detect high-volume enumeration when combined with other suspicious behavior |
| T1105 - Ingress Tool Transfer | Process connects externally and creates a new executable/script | Process, network, destination, file creation, hash | Correlate external connection with new executable creation |
| T1071.001 - Web Protocols | Unknown process repeatedly communicates using HTTP/HTTPS | Process, destination IP/domain, port, DNS, timestamp | Detect repeated external communication from unusual process |
| T1070.004 - File Deletion | File is created, executed, then deleted soon afterward | File create/delete, process, path, hash, timestamp | Correlate create -> execute -> delete sequence |
| T1486 - Data Encrypted for Impact | Same process rapidly modifies/renames many files across multiple extensions | Process, file write/rename/delete, path, extension, timestamp | Detect high-rate file modification behavior in short time window |

## Behavior Correlation Principle

A single event should not automatically be treated as an attack.

Example:

```text
powershell.exe started
```

is not sufficient by itself.

A stronger behavioral chain is:

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
external network connection
    ↓
executable created in Temp
```

The Phase 1 detection engine should therefore support correlation between multiple related events.
