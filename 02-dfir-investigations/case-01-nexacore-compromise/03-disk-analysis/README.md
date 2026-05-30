# Phase 03 — Disk Analysis

## Analysis Metadata

| Field | Detail |
|---|---|
| Case ID | DFIR-CASE-01 |
| Analyst | Adedeji Adetayo |
| Date | 2026-05-30 |
| Target Host | NEXACORE-WS01 |
| Tools Used | Splunk Enterprise, Windows Task Scheduler, Windows Command Prompt |
| Log Source | WinEventLog:Security |

---

## Objective

Identify persistent artefacts left on disk by the attacker that survive system reboots. Memory forensics captured what was happening at the moment of acquisition. Disk analysis confirms what was permanently written to the system — user accounts, scheduled tasks, and event log entries.

---

## Why Disk Analysis Follows Memory Analysis

Memory forensics reveals the attack in progress. Disk analysis confirms the lasting impact. Together they answer two critical questions:

- **Memory** — what did the attacker do and how did they do it
- **Disk** — what did the attacker leave behind permanently

A fileless attack does not write malware to disk but the results of the attack — new user accounts, scheduled tasks, and event log entries — are permanently recorded on disk and survive reboots.

---

## Finding 1 — Backdoor Account Creation Confirmed In Windows Event Logs

### Purpose

Windows Security Event Logs record every account creation and group membership change. Querying these logs confirms whether the backdoor account created during the fileless attack was successfully written to disk.

### Tool

Splunk Enterprise — querying Windows Security Event Logs forwarded from NEXACORE-WS01 via Splunk Universal Forwarder.

### Event IDs Used

| Event ID | Description |
|---|---|
| 4720 | A user account was created |
| 4732 | A member was added to a security-enabled local group |

### Splunk Query

The following query was run in Splunk to retrieve account creation and group membership events from NEXACORE-WS01:

```
index=main host="NEXACORE-WS01" source="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| table _time, EventCode, Account_Name, Subject_Account_Name, Group_Name
| sort -_time
```

The screenshot below shows the Splunk query and the three events returned:

![Account Creation Evidence](../screenshots/dfir-account-creation-splunk.png)

### Results

Three events were returned confirming the complete account creation sequence:

| Time | Event ID | Account | Group | Performed By |
|---|---|---|---|---|
| 2026-05-30 16:36:02 | 4720 | cybervault | N/A | Administrator |
| 2026-05-30 16:36:02 | 4732 | cybervault | Users | Administrator |
| 2026-05-30 16:36:21 | 4732 | cybervault | Administrators | Administrator |

### Interpretation

The three events occurred within 19 seconds confirming an automated or scripted account creation sequence. The Administrator account was used to create `cybervault` and immediately escalate it to the Administrators group. This matches exactly the decoded payload recovered during memory analysis:

```
net user cybervault Password$123! /add
net localgroup administrators cybervault /add
```

The Windows Security Event Log provides permanent disk-based evidence of the account creation — corroborating what was found in memory.

---

## Finding 2 — Backdoor Account Confirmed On Endpoint

### Purpose

Directly query the local user account database on NEXACORE-WS01 to confirm the backdoor account exists on disk in the SAM database.

### Tool

Windows Command Prompt on NEXACORE-WS01 — run as Administrator.

### Command

The following command was run directly on NEXACORE-WS01 to list all local user accounts:

```cmd
net user
```

The screenshot below shows the command output confirming the cybervault account:

![Backdoor User Confirmed](../screenshots/dfir-backdoor-user-confirmed.png)

### Result

```
User accounts for \\NEXACORE-WS01:
Administrator    cybervault    DefaultAccount
employee01       Guest         WDAGUtilityAccount
```

### Interpretation

The `cybervault` account is confirmed as a permanent local user on NEXACORE-WS01. It is stored in the SAM database on disk and will survive system reboots. The account was created by the fileless PowerShell payload and provides the attacker with persistent privileged access to the endpoint.

---

## Finding 3 — NexaCoreUpdater Scheduled Task Confirmed Active

### Purpose

Query the Windows Task Scheduler to confirm the NexaCoreUpdater persistence mechanism created during SIM-04 still exists on disk and remains active.

### Tool

Windows Command Prompt on NEXACORE-WS01 — run as Administrator.

### Command

The following command was run directly on NEXACORE-WS01 to query the specific scheduled task:

```cmd
schtasks /query /tn "NexaCoreUpdater" /fo LIST /v
```

The screenshot below shows the command output with the full task configuration:

![Scheduled Task Evidence](../screenshots/dfir-scheduled-task-evidence.png)

### Result

```
HostName:       NEXACORE-WS01
TaskName:       \NexaCoreUpdater
Status:         Ready
Last Run Time:  2026-05-30 09:35:12
Last Result:    0
Author:         NEXACORE\Administrator
Task To Run:    cmd.exe /c whoami > C:\Windows\Temp\out.txt
Run As User:    SYSTEM
Schedule Type:  At logon time
```

### Interpretation

This scheduled task was created on 2026-05-20 via an Evil-WinRM remote session — confirmed by Sysmon EventCode 1 logs showing `wsmprovhost.exe` spawning `schtasks.exe`. Key observations:

- **Run As User: SYSTEM** — highest privilege level on the machine
- **Schedule Type: At logon time** — executes at every user logon automatically
- **Last Run Time: 2026-05-30 09:35:12** — executed this morning before this investigation began
- **Status: Ready** — will execute again at the next logon
- **Age: 10 days** — persisted undetected from May 20 to May 30

The task output file `C:\Windows\Temp\out.txt` was confirmed on disk containing `nt authority\system` — proof of successful SYSTEM-level execution.

---

## Disk Analysis Summary

| Finding | Tool Used | Command | Severity |
|---|---|---|---|
| cybervault user account created | Splunk | EventCode=4720 query | Critical |
| cybervault added to Administrators | Splunk | EventCode=4732 query | Critical |
| cybervault account on endpoint | Command Prompt | `net user` | Critical |
| NexaCoreUpdater task active | Command Prompt | `schtasks /query /tn NexaCoreUpdater` | Critical |
| Task running as SYSTEM at logon | Task Scheduler | Task configuration review | Critical |
| Task persisted 10 days undetected | Cross-reference | Sysmon logs vs investigation date | Critical |

---

## Key Indicators of Compromise

| Indicator | Type | Description |
|---|---|---|
| cybervault | Local user account | Backdoor account with Administrator privileges — created by fileless payload |
| NexaCoreUpdater | Scheduled task | Persistence mechanism running as SYSTEM at every logon |
| C:\Windows\Temp\out.txt | File | Attacker recon output confirming SYSTEM-level execution |
| cmd.exe /c whoami | Command | Reconnaissance command executed as SYSTEM via scheduled task |

---

## References

- NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response
- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- MITRE ATT&CK T1053.005 — Scheduled Task
- MITRE ATT&CK T1136.001 — Create Account: Local Account
- MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts
