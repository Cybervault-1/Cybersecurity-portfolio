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
| 2026-05-20 19:47:12 | NexaCoreUpdater scheduled task created via Evil-WinRM remote session |
| 2026-05-20 to 2026-05-30 | Scheduled task persisted undetected for 10 days |
| 2026-05-30 09:35:12 | NexaCoreUpdater task executed as SYSTEM at user logon |
| 2026-05-30 16:36:02 | Fileless PowerShell payload executed — cybervault user created |
| 2026-05-30 16:36:21 | cybervault added to Administrators group |
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
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell command recovered from memory |
| Defence Evasion | Obfuscated Files or Information | T1027 | Base64 encoding used to hide payload |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | NexaCoreUpdater task running as SYSTEM at logon |
| Privilege Escalation | Valid Accounts: Local Accounts | T1078.003 | cybervault added to Administrators group |
| Persistence | Create Account: Local Account | T1136.001 | cybervault backdoor account created |

---

## Investigation Methodology

This investigation followed the NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response and the NIST SP 800-61 Rev 2 Computer Security Incident Handling Guide across three phases:

| Phase | Description | Link |
|---|---|---|
| Phase 1 — Acquisition | Live memory capture from NEXACORE-WS01 using WinPmem | [View](../01-acquisition/README.md) |
| Phase 2 — Memory Analysis | Volatility3 analysis of memory dump | [View](../02-memory-analysis/README.md) |
| Phase 3 — Disk Analysis | Windows event log and scheduled task analysis | [View](../03-disk-analysis/README.md) |

---

## Key Findings

### Finding 1 — Fileless PowerShell Attack Confirmed (Critical)

Volatility3 `windows.cmdscan` recovered the attacker command sequence from the console history buffer in memory. The encoded command and its decoded payload confirm a fileless attack where no files were written to disk.

**Commands recovered from memory:**
```
powershell -EncodedCommand bgBlAHQAIAB1AHMAZQByACAAYwB5AGIAZQByAHYAYQB1AGwAdAAgAFAAYQBzAHMAdwBvAHIAZAAkADEAMgAzACEAIAAvAGEAZABkAA==
net localgroup administrators cybervault /add
```

**Decoded payload:**
```
net user cybervault Password$123! /add
```

Full technical details: [Phase 02 — Memory Analysis](../02-memory-analysis/README.md)

---

### Finding 2 — Suspicious Memory Region Confirms Fileless Execution (High)

Volatility3 `windows.malware.malfind` identified a `PAGE_EXECUTE_READWRITE` memory region in PowerShell PID 4820 — a dynamically allocated region not backed by any file on disk. This is consistent with fileless code execution directly in memory.

Full technical details: [Phase 02 — Memory Analysis](../02-memory-analysis/README.md)

---

### Finding 3 — Backdoor Account Created With Administrator Privileges (Critical)

Windows Security Event IDs 4720 and 4732 confirmed the `cybervault` account was created and added to the Administrators group at 16:36 on 2026-05-30. The account was directly verified on the endpoint using `net user`.

**Confirmation:**
```
User accounts for \\NEXACORE-WS01:
Administrator    cybervault    DefaultAccount
employee01       Guest         WDAGUtilityAccount
```

Full technical details: [Phase 03 — Disk Analysis](../03-disk-analysis/README.md)

---

### Finding 4 — Persistent Scheduled Task Active For 10 Days (Critical)

The `NexaCoreUpdater` scheduled task was found on disk running as SYSTEM at every logon. Created on 2026-05-20, it persisted undetected for 10 days and last executed at 09:35 on the day of this investigation.

**Task configuration:**
```
TaskName:      NexaCoreUpdater
Task To Run:   cmd.exe /c whoami > C:\Windows\Temp\out.txt
Run As User:   SYSTEM
Schedule Type: At logon time
Last Run Time: 2026-05-30 09:35:12
Status:        Ready
```

Full technical details: [Phase 03 — Disk Analysis](../03-disk-analysis/README.md)

---

### Finding 5 — WinRM Attack Vector Remains Open (High)

Volatility3 `windows.netscan` confirmed port 5985 listening on all interfaces. The endpoint remains accessible via Evil-WinRM to any attacker with valid credentials.

Full technical details: [Phase 02 — Memory Analysis](../02-memory-analysis/README.md)

---

## Containment Actions

| Priority | Action | Command |
|---|---|---|
| Immediate | Isolate NEXACORE-WS01 from network | Disconnect network adapter |
| Immediate | Disable cybervault account | `net user cybervault /active:no` |
| Immediate | Delete NexaCoreUpdater task | `schtasks /delete /tn "NexaCoreUpdater" /f` |
| High | Disable WinRM | `net stop winrm` |
| High | Reset Administrator password | Change via Active Directory |
| High | Block port 5985 on firewall | Windows Firewall inbound rule |

---

## Eradication Actions

| Action | Detail |
|---|---|
| Delete cybervault account | `net user cybervault /delete` |
| Remove NexaCoreUpdater task | `schtasks /delete /tn "NexaCoreUpdater" /f` |
| Audit all local accounts | Verify no other backdoor accounts exist |
| Audit all scheduled tasks | Review every task on NEXACORE-WS01 and DC01 |
| Review PowerShell Script Block Logs | Identify any additional encoded commands |

---

## Recovery Actions

| Action | Detail |
|---|---|
| Restore from clean backup | Restore NEXACORE-WS01 to pre-compromise state if available |
| Reimage if no clean backup | Full OS reinstall recommended |
| Reset service account passwords | svc_sql and all accounts with SPNs |
| Enable PowerShell Constrained Language Mode | Reduces fileless attack effectiveness |

---

## Recommendations

| Priority | Recommendation |
|---|---|
| Critical | Disable WinRM on endpoints that do not require remote management |
| Critical | Implement PowerShell Script Block Logging forwarded to SIEM |
| High | Alert on Event ID 4720 user account creation in real time |
| High | Alert on Event ID 4732 addition to Administrators group |
| High | Alert on scheduled task creation via Sysmon EventCode 1 |
| Medium | Enforce PowerShell execution policy — AllSigned or Constrained |
| Low | Review and harden firewall rules |

---

## Evidence Index

| ID | Description | File |
|---|---|---|
| E01 | Memory dump captured during active attack | nexacore-ws01-dfir.raw |
| E02 | Memory acquisition confirmation | [01-acquisition](../01-acquisition/README.md) |
| E03 | Volatility3 memory analysis findings | [02-memory-analysis](../02-memory-analysis/README.md) |
| E04 | Windows event log and disk artefact findings | [03-disk-analysis](../03-disk-analysis/README.md) |

---

## References

- NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-86.pdf
- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1027 — Obfuscated Files or Information
- MITRE ATT&CK T1053.005 — Scheduled Task
- MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts
- MITRE ATT&CK T1136.001 — Create Account: Local Account
- Volatility3 — https://volatility3.readthedocs.io
- WinPmem — https://github.com/Velocidex/WinPmem
