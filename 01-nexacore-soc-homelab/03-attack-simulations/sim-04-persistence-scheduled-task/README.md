# SIM-04 — Persistence via Scheduled Task

## Overview

| Field | Detail |
|---|---|
| **Simulation ID** | SIM-04 |
| **Date** | 2026-05-20 |
| **Tactic** | Persistence |
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Attacker Machine** | Kali Linux |
| **Target Machine** | NEXACORE-WS01 |
| **Prerequisite** | Active Evil-WinRM session from SIM-03 |
| **Tool Used** | schtasks.exe (native Windows binary) |

---

## Attack Narrative

Following successful remote code execution via Evil-WinRM in SIM-03, the attacker established persistence on NEXACORE-WS01 by creating a scheduled task designed to survive system reboots. The task was named NexaCoreUpdater to blend in with legitimate Windows maintenance activity. It was configured to execute a command as SYSTEM on every user logon.

This simulation represents the fourth stage of the NexaCore attack chain:

| Stage | Simulation | Action |
|---|---|---|
| 1 | SIM-02 | Nmap reconnaissance identifies open ports 445 and 5985 |
| 2 | SIM-01 | SMB brute force recovers Administrator credential |
| 3 | SIM-03 | Evil-WinRM session established, reconnaissance performed |
| 4 | SIM-04 | Scheduled task created for persistent access |

---

## Prerequisites

- Completed SIM-03 with an active Evil-WinRM session on NEXACORE-WS01
- Administrator credential recovered from SIM-01
- Sysmon64 running on NEXACORE-WS01 with Event ID 1 logging enabled
- Audit policy for Other Object Access Events set to Success
- Splunk Universal Forwarder configured with renderXml = true for Sysmon log

---

## Execution

### Step 1 — Establish Evil-WinRM Session

The attacker opened an Evil-WinRM session from Kali Linux using the Administrator credential recovered during SIM-01.

```bash
evil-winrm -i 192.168.10.10 -u Administrator -p '@Nexacore2026'
```

*Screenshot: sim04-01-evilwinrm-session.png*

---

### Step 2 — Create Scheduled Task

The attacker created a scheduled task named NexaCoreUpdater inside the Evil-WinRM session. The task was configured to run as SYSTEM on every user logon.

```powershell
schtasks /create /tn "NexaCoreUpdater" /tr "cmd.exe /c whoami > C:\Windows\Temp\out.txt" /sc onlogon /ru SYSTEM
```

*Screenshot: sim04-02-schtask-created.png*

---

### Step 3 — Verify Task Creation

The attacker confirmed the task was successfully registered on the system.

```powershell
schtasks /query /tn "NexaCoreUpdater"
```

*Screenshot: sim04-03-schtask-query.png*

---

## Evidence Collected

### Windows Event ID 4698 — Scheduled Task Created

Windows Security log recorded the task creation event including the task name, author, trigger configuration, and full command embedded in the task definition.

*Screenshot: sim04-04-eventid-4698.png*
*Screenshot: sim04-04b-eventid-4698-taskcontent.png*

| Field | Value |
|---|---|
| Event ID | 4698 |
| Account Name | Administrator |
| Account Domain | NEXACORE |
| Task Name | \NexaCoreUpdater |
| Author | NEXACORE\Administrator |
| Trigger | LogonTrigger |
| Command | cmd.exe /c whoami > C:\Windows\Temp\out.txt |
| Timestamp | 2026-05-20T18:41:17 |

*Screenshot: sim04-06-splunk-eventid-4698.png*

---

### Sysmon Event ID 1 — Process Creation

Sysmon recorded the execution of schtasks.exe including the full command line and parent process. The parent process wsmprovhost.exe confirms the task was created from within a WinRM session.

| Field | Value |
|---|---|
| Event ID | 1 (Process Creation) |
| Image | C:\Windows\System32\schtasks.exe |
| CommandLine | schtasks.exe /create /tn NexaCoreUpdater /tr "cmd.exe /c whoami > C:\Windows\Temp\out.txt" /sc onlogon /ru SYSTEM |
| ParentImage | C:\Windows\System32\wsmprovhost.exe |
| User | NEXACORE\Administrator |
| Computer | NEXACORE-WS01.nexacore.local |
| Timestamp | 2026-05-20T18:47:19 |

*Screenshot: sim04-07-splunk-sysmon-eventid1-schtasks.png*

---

## MITRE ATT&CK

| Field | Detail |
|---|---|
| **Tactic** | Persistence |
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tool** | schtasks.exe |
| **Living off the Land** | Yes — native Windows binary, no malware dropped |
