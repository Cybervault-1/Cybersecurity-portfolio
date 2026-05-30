# DFIR Report — Case 01: NexaCore Endpoint Compromise

## Report Metadata

| Field | Detail |
|---|---|
| Case ID | DFIR-CASE-01 |
| Report Title | NexaCore Endpoint Compromise — Fileless PowerShell Attack and Persistent Scheduled Task |
| Analyst | Adedeji Adetayo |
| Date of Investigation | 2026-05-30 |
| Date of Report | 2026-05-30 |
| Classification | Confidential |
| Status | Complete |

---

## Executive Summary

A fileless PowerShell attack was executed on endpoint NEXACORE-WS01 on 2026-05-30. The attacker ran a base64 encoded PowerShell command that created a backdoor local user account named `cybervault` and added it to the local Administrators group. No malicious files were written to disk. The entire payload executed in memory.

During the investigation a second pre-existing threat was discovered — a scheduled task named `NexaCoreUpdater` that had been persisting on the machine since 2026-05-20, ten days prior to this investigation. The task was configured to run `cmd.exe` as `NT AUTHORITY\SYSTEM` at every user logon and had executed successfully multiple times without detection.

Both threats were confirmed through live memory forensics using Volatility3 and corroborated through Windows Security event log analysis in Splunk.

---

## Incident Timeline

| Time | Event |
|---|---|
| 2026-05-20 19:47:12 | wsmprovhost.exe spawned schtasks.exe — NexaCoreUpdater task created via Evil-WinRM session |
| 2026-05-20 to 2026-05-30 | NexaCoreUpdater task persisted undetected for 10 days |
| 2026-05-30 09:35:12 | NexaCoreUpdater task executed as SYSTEM at user logon |
| 2026-05-30 16:36:02 | Fileless PowerShell attack executed — cybervault user created |
| 2026-05-30 16:36:02 | cybervault added to Users group automatically |
| 2026-05-30 16:36:21 | cybervault added to Administrators group — full system access granted |
| 2026-05-30 16:46:00 | Memory acquisition initiated using WinPmem |
| 2026-05-30 16:48:00 | Memory dump completed — 4.83GB captured |
| 2026-05-30 17:00:00 | Volatility3 analysis commenced on Kali Linux |

---

## Environment

| Component | Detail |
|---|---|
| Compromised Host | NEXACORE-WS01 |
| Operating System | Windows Server 2019 — Build 19041 |
| Domain | nexacore.local |
| IP Address | 192.168.10.10 |
| RAM | 3GB |
| Monitoring | Sysmon v15.20, Splunk Universal Forwarder |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell command found in memory via cmdscan |
| Defence Evasion | Obfuscated Files or Information | T1027 | Base64 encoded payload used to hide command intent |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | NexaCoreUpdater task running as SYSTEM at logon |
| Privilege Escalation | Valid Accounts: Local Accounts | T1078.003 | cybervault added to Administrators group |
| Persistence | Create Account: Local Account | T1136.001 | cybervault backdoor account created |

---

## Investigation Methodology

This investigation followed the NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response and the NIST SP 800-61 Rev 2 Computer Security Incident Handling Guide.

### Phase 1 — Evidence Acquisition

A live memory dump was captured from NEXACORE-WS01 while the attack was in progress using WinPmem v1.0-rc2. The acquisition captured 4,831,838,208 bytes of physical memory in 1 minute 37 seconds. The memory dump file `nexacore-ws01-dfir.raw` was transferred to the analyst workstation for offline analysis.

### Phase 2 — Memory Analysis

Volatility3 Framework v2.28.0 was used to analyse the memory dump. The following plugins were executed:

| Plugin | Purpose | Finding |
|---|---|---|
| windows.info | Identify OS version and capture time | Windows 10 build 19041, captured 2026-05-30 08:45:10 |
| windows.pslist | List all running processes | PowerShell PID 4820 confirmed running |
| windows.pstree | Show parent-child process relationships | WinRM service confirmed active |
| windows.cmdline | Extract process command lines | cmd.exe and PowerShell instances identified |
| windows.cmdscan | Extract console command history | Encoded PowerShell command and net localgroup command found |
| windows.netscan | List active network connections | WinRM port 5985 listening, SMB port 445 open |
| windows.malfind | Identify suspicious memory regions | PAGE_EXECUTE_READWRITE region found in PowerShell PID 4820 |
| windows.registry.hashdump | Extract password hashes | Failed — SAM hive not active in memory |
| windows.registry.hivelist | List registry hives | SAM hive located but marked Disabled |

### Phase 3 — Disk Analysis

Windows Security event logs were analysed in Splunk and the Task Scheduler was queried directly on the endpoint.

---

## Memory Forensics Findings

### Finding 1 — Encoded PowerShell Command In Memory

Volatility3 `windows.cmdscan` recovered the following commands from the console history buffer of conhost.exe PID 4776:

```
powershell -EncodedCommand bgBlAHQAIAB1AHMAZQByACAAYwB5AGIAZQByAHYAYQB1AGwAdAAgAFAAYQBzAHMAdwBvAHIAZAAkADEAMgAzACEAIAAvAGEAZABkAA==
net localgroup administrators cybervault /add
```

The base64 encoded command decodes to:
```
net user cybervault Password$123! /add
```

This confirms a fileless attack where the malicious command was obfuscated using base64 encoding and executed entirely in memory.

![Command History Evidence](../../../screenshots/dfir-cmdscan-evidence.png)

### Finding 2 — Suspicious Memory Region In PowerShell

Volatility3 `windows.malfind` identified a memory region in PowerShell PID 4820 with the following characteristics:

```
PID:         4820
Process:     powershell.exe
Address:     0x197fdf20000
Protection:  PAGE_EXECUTE_READWRITE
Type:        VaDs
```

A `PAGE_EXECUTE_READWRITE` protection flag on a dynamically allocated memory region is a strong indicator of fileless code execution. Legitimate code loaded from disk is typically marked `PAGE_EXECUTE_READ` only.

![Malfind Evidence](../../../screenshots/dfir-malfind-evidence.png)

### Finding 3 — WinRM Attack Vector Confirmed Open

Volatility3 `windows.netscan` confirmed port 5985 listening on all interfaces under the System process — confirming the WinRM remote access attack vector remains active on this endpoint.

![Network Scan Evidence](../../../screenshots/dfir-netscan-evidence.png)

---

## Disk Forensics Findings

### Finding 4 — Backdoor Account Creation Confirmed In Event Logs

Splunk query against Windows Security Event Log returned three events confirming the account creation sequence:

| Time | Event ID | Description |
|---|---|---|
| 2026-05-30 16:36:02 | 4720 | User account cybervault created by Administrator |
| 2026-05-30 16:36:02 | 4732 | cybervault added to Users group |
| 2026-05-30 16:36:21 | 4732 | cybervault added to Administrators group |

![Account Creation Evidence](../../../screenshots/dfir-account-creation-splunk.png)

### Finding 5 — NexaCoreUpdater Scheduled Task Confirmed Active

Direct query of Task Scheduler on NEXACORE-WS01 confirmed the following persistent threat:

```
TaskName:      NexaCoreUpdater
Status:        Ready
Task To Run:   cmd.exe /c whoami > C:\Windows\Temp\out.txt
Run As User:   SYSTEM
Schedule Type: At logon time
Last Run Time: 2026-05-30 09:35:12
```

This task was created on 2026-05-20 via an Evil-WinRM remote session and persisted undetected for 10 days. It has full SYSTEM privileges and executes at every user logon.

![Scheduled Task Evidence](../../../screenshots/dfir-scheduled-task-evidence.png)

---

## Containment Actions

| Priority | Action | Command |
|---|---|---|
| Immediate | Isolate NEXACORE-WS01 from network | Disconnect network adapter in VirtualBox |
| Immediate | Disable cybervault account | `net user cybervault /active:no` |
| Immediate | Delete NexaCoreUpdater scheduled task | `schtasks /delete /tn "NexaCoreUpdater" /f` |
| High | Disable WinRM service | `net stop winrm` then set to Disabled |
| High | Reset Administrator password | Change via Active Directory |
| High | Block port 5985 on firewall | Windows Firewall inbound rule |
| High | Block port 445 on firewall | Unless required for business operations |

---

## Eradication Actions

| Action | Detail |
|---|---|
| Delete cybervault user account | `net user cybervault /delete` |
| Remove NexaCoreUpdater task | `schtasks /delete /tn "NexaCoreUpdater" /f` |
| Audit all local user accounts | Verify no other backdoor accounts exist |
| Audit all scheduled tasks | Review every task on NEXACORE-WS01 and DC01 |
| Review WinRM access policy | Restrict WinRM to authorised IP addresses only |
| Scan for additional encoded PowerShell | Review PowerShell Script Block Logs in Splunk |

---

## Recovery Actions

| Action | Detail |
|---|---|
| Restore from clean backup | If available — restore NEXACORE-WS01 to pre-compromise state |
| Reimage if no clean backup | Full OS reinstall recommended given SYSTEM level persistence |
| Reset all service account passwords | svc_sql and any other accounts with SPNs |
| Enable PowerShell Constrained Language Mode | Reduces effectiveness of fileless attacks |
| Deploy AppLocker | Restrict execution of unsigned scripts |

---

## Recommendations

| Priority | Recommendation |
|---|---|
| Critical | Disable WinRM on endpoints that do not require remote management |
| Critical | Implement PowerShell Script Block Logging and forward to SIEM |
| High | Deploy scheduled task creation alerting — Sysmon EventCode 1 with schtasks.exe |
| High | Alert on Event ID 4720 user account creation in real time |
| High | Alert on Event ID 4732 addition to Administrators group in real time |
| Medium | Enforce PowerShell execution policy — AllSigned or Constrained |
| Medium | Implement Just Enough Administration (JEA) for WinRM sessions |
| Low | Review and harden firewall rules — close unused ports |

---

## Tools Used

| Tool | Version | Purpose |
|---|---|---|
| WinPmem | v1.0-rc2 | Live memory acquisition from Windows endpoint |
| Volatility3 | v2.28.0 | Memory dump analysis and artefact extraction |
| Splunk Enterprise | v9.x | Windows Security event log analysis |
| Sysmon | v15.20 | Endpoint telemetry and process monitoring |

---

## Evidence Index

| ID | Description | File |
|---|---|---|
| E01 | Memory dump — captured during active attack | nexacore-ws01-dfir.raw |
| E02 | Memory acquisition confirmation | dfir-acquisition-complete.png |
| E03 | Volatility windows.info output | volatility-windows-info.png |
| E04 | Encoded command found in console buffer | dfir-cmdscan-evidence.png |
| E05 | Suspicious PAGE_EXECUTE_READWRITE region | dfir-malfind-evidence.png |
| E06 | Active network connections | dfir-netscan-evidence.png |
| E07 | Backdoor account creation events in Splunk | dfir-account-creation-splunk.png |
| E08 | NexaCoreUpdater scheduled task details | dfir-scheduled-task-evidence.png |
| E09 | Backdoor user confirmed on endpoint | dfir-backdoor-user-confirmed.png |

---

## References

- NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response
- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1027 — Obfuscated Files or Information
- MITRE ATT&CK T1053.005 — Scheduled Task
- MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts
- MITRE ATT&CK T1136.001 — Create Account: Local Account
- Volatility3 Documentation — https://volatility3.readthedocs.io
- WinPmem — https://github.com/Velocidex/WinPmem
