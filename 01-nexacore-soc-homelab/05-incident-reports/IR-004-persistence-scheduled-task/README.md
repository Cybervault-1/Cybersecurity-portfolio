# Incident Response Report 004 — Persistence via Scheduled Task

## Incident Metadata

| Field | Detail |
|---|---|
| Incident ID | IR-004 |
| Date Detected | 20 May 2026 |
| Author | Adedeji Adetayo |
| Status | Resolved |
| Severity | High |
| MITRE Technique | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Linked Simulation | SIM-04 — Persistence via Scheduled Task |
| Linked Detection | DET-04 — Persistence via Scheduled Task |

---

## Incident Summary

On 20 May 2026, a threat actor established persistence on NEXACORE-WS01 by creating a scheduled task named NexaCoreUpdater from within an active Evil-WinRM session. The scheduled task was configured to execute a command as SYSTEM on every user logon, ensuring the attacker could regain access to the machine automatically after any reboot without needing to re-authenticate or redeploy their initial access tools.

The attack was detected through Splunk across two independent log sources — Windows Security Log Event ID 4698 and Sysmon Event ID 1. The presence of wsmprovhost.exe as the parent process of schtasks.exe confirmed that persistence was planted from inside a remote WinRM session. The incident was contained and remediated. All persistence mechanisms were removed.

---

## Severity Assessment

| Factor | Detail |
|---|---|
| Severity | High |
| Affected Machine | NEXACORE-WS01 |
| Affected Account | Administrator |
| Persistence Mechanism | Scheduled Task — survives system reboots |
| Attack Vector | Remote WinRM session (Evil-WinRM) |
| Privilege Level Obtained | SYSTEM |
| Persistence Identified | Scheduled task NexaCoreUpdater |
| Recovery Requirement | Task removal and credential reset |

---

## Environment

| Role | Machine | IP Address | OS |
|---|---|---|---|
| Attacker | Kali Linux | 192.168.10.20 | Kali Linux 2025.4 |
| Target | NEXACORE-WS01 | 192.168.10.10 | Windows Server 2019 |
| Domain Controller | NexaCore-DC01 | 192.168.10.1 | Windows Server 2019 |
| SIEM | Splunk Enterprise | 192.168.56.1 | Host Machine |

---

## Attack Timeline

| Time | Event |
|---|---|
| 18:41:17 | Scheduled task NexaCoreUpdater created on NEXACORE-WS01 |
| 18:47:12 | schtasks.exe used to delete previous task version |
| 18:47:19 | schtasks.exe used to register NexaCoreUpdater with SYSTEM privileges and LogonTrigger |
| 18:47:25 | Splunk alert triggered on Sysmon Event ID 1 wsmprovhost parent process |

---

## Detection Evidence

| Source | Event ID | Observation |
|---|---|---|
| Windows Security Log | 4698 | Scheduled task NexaCoreUpdater created by NEXACORE\Administrator with embedded command |
| Windows Security Log | 4698 | Task definition captured full XML showing LogonTrigger and cmd.exe payload |
| Sysmon Operational Log | 1 | schtasks.exe spawned by wsmprovhost.exe confirming remote session origin |
| Sysmon Operational Log | 1 | Full command line captured: schtasks.exe /create /tn NexaCoreUpdater /tr cmd.exe /c whoami /sc onlogon /ru SYSTEM |

---

## Containment Actions

The following actions were taken immediately upon detection to stop the attack and prevent the scheduled task from executing:

- Disabled the NexaCoreUpdater scheduled task on NEXACORE-WS01 to prevent execution on next logon
- Terminated the active Evil-WinRM session on NEXACORE-WS01 to close the attacker's current access vector
- Blocked source IP 192.168.10.20 at the network firewall to prevent re-establishment of WinRM connections from the attacker
- Locked the Administrator account on NEXACORE-WS01 to prevent the attacker from authenticating with compromised credentials

---

## Eradication Actions

The following actions were taken to remove all attacker persistence and verify the machine was clean:

- Deleted the NexaCoreUpdater scheduled task from NEXACORE-WS01 completely
- Reviewed all scheduled tasks on NEXACORE-WS01 via schtasks /query /v — no additional attacker-created tasks identified
- Audited Windows Event ID 4698 logs for the past 7 days — only NexaCoreUpdater found, no other persistence mechanisms
- Reviewed Sysmon logs for scheduled task creation events from wsmprovhost.exe parent — only the NexaCoreUpdater creation identified
- Verified no additional persistence mechanisms were planted including registry run keys, startup folders, or Windows services

---

## Recovery Actions

The following actions were taken to restore normal operations securely:

- Reset the Administrator password on NEXACORE-WS01 to a strong credential not present in any wordlist
- Verified all scheduled tasks on NEXACORE-WS01 were legitimate Windows components
- Re-enabled WinRM only on authorised management hosts with IP-based firewall restrictions
- Rebooted NEXACORE-WS01 to confirm the scheduled task did not re-execute at startup
- Verified NEXACORE-WS01 was operating normally with no signs of compromise before returning to production

---

## Remediation Recommendations

| Recommendation | Priority |
|---|---|
| Enable alerting on Windows Event ID 4698 for all scheduled task creation across all endpoints | Critical |
| Alert on schtasks.exe spawned by wsmprovhost.exe, powershell.exe, or cmd.exe outside maintenance windows | Critical |
| Restrict WinRM access to authorised management IP addresses only using Windows Firewall rules | Critical |
| Audit all scheduled tasks on all endpoints monthly for tasks with embedded commands pointing to temporary directories | High |
| Apply least privilege principles to limit which accounts can create SYSTEM-level scheduled tasks | High |
| Enable the Other Object Access Events audit subcategory on all endpoints to ensure Event ID 4698 is captured | High |
| Disable WinRM on all endpoints where remote management is not operationally required | High |
| Conduct quarterly reviews of all privileged account activities via PowerShell Script Block Logging | Medium |

---

## Lessons Learned

The attack succeeded because the attacker already had a foothold via Evil-WinRM from SIM-03 and was able to leverage native Windows tooling to plant persistence without triggering application whitelisting controls or requiring external malware.

Scheduled tasks are particularly effective persistence mechanisms because they survive system reboots, execute with full system context, and are managed through native Windows binaries that appear legitimate in process listings.

The detection was successful because two independent log sources captured the persistence mechanism — Event ID 4698 recorded the full task definition including the embedded command, and Sysmon Event ID 1 recorded the process execution with wsmprovhost.exe as the parent confirming the origin was a remote session.

The combination of Sysmon process parent tracking and Windows Security event logging provided conclusive evidence that the persistence was planted maliciously. Legitimate administrators creating scheduled tasks would use the Task Scheduler GUI spawning mmc.exe, not remote PowerShell sessions spawning schtasks.exe.

---

## References

- Simulation: SIM-04 — Persistence via Scheduled Task
- Detection: DET-04 — Persistence via Scheduled Task
- MITRE ATT&CK T1053.005: https://attack.mitre.org/techniques/T1053/005/
