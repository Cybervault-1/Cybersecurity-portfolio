# Incident Response Report 003 — PowerShell Execution via Evil-WinRM

## Incident Metadata

| Field | Detail |
|---|---|
| Incident ID | IR-003 |
| Date Detected | 19 May 2026 at 13:58:07 |
| Author | Adedeji Adetayo |
| Status | Resolved |
| Severity | High |
| MITRE Technique | T1059.001 — PowerShell |
| Linked Simulation | SIM-03 — PowerShell Execution via Evil-WinRM |
| Linked Detection | DET-03 — PowerShell Execution via Evil-WinRM |

---

## Incident Summary

On 19 May 2026 13:58:07 , an unauthorised remote PowerShell session was established on NEXACORE-WS01 by a threat actor operating from 192.168.10.20. The attacker performed an SMB brute force attack against the Administrator account, generating 67 failed logon attempts before successfully authenticating. Using the discovered credentials, the attacker connected to WinRM port 5985 via Evil-WinRM and executed a series of post-exploitation reconnaissance commands inside a remote PowerShell session.

The attack was detected through Splunk across four independent log sources — Windows Security Log, PowerShell Operational Log, and Sysmon Operational Log. No data exfiltration or persistence mechanisms were identified during the investigation. The incident was contained and remediated.

---

## Severity Assessment

| Factor | Detail |
|---|---|
| Severity | High |
| Affected Machine | NEXACORE-WS01 |
| Affected Account | Administrator |
| Attack Vector | Network — WinRM port 5985 |
| Attacker IP | 192.168.10.20 |
| Privilege Level Obtained | Local Administrator |
| Data Exfiltration | None identified |
| Persistence Identified | None identified |

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
| 13:58:07 | First successful Administrator logon from 192.168.10.20 via WinRM |
| 19:46:20 | Evil-WinRM session established on NEXACORE-WS01 |
| 19:46:28 | Attacker executed hostname inside remote PowerShell session |
| 19:46:35 | Attacker executed ipconfig — network reconnaissance performed |
| 19:46:43 | Attacker executed net user — local accounts enumerated |
| 19:46:52 | Attacker executed Get-Process — running processes surveyed |
| 20:12:05 | Additional reconnaissance session detected via Sysmon |

---

## Detection Evidence

| Source | Event ID | Observation |
|---|---|---|
| Windows Security Log | 4625 | 67 failed logon attempts against Administrator from 192.168.10.20 |
| Windows Security Log | 4624 | Successful network logon by Administrator from 192.168.10.20 Logon Type 3 |
| PowerShell Operational Log | 4104 | Script Block Logging captured whoami, hostname, ipconfig, net user, Get-Process |
| Sysmon Operational Log | 1 | Process creation with wsmprovhost.exe as parent confirming remote WinRM execution |

---

## Containment Actions

The following actions were taken immediately upon detection to stop the active attack and prevent further unauthorised access:

- Blocked source IP 192.168.10.20 at the network firewall to terminate all inbound connections from the attacker machine
- Disabled WinRM on NEXACORE-WS01 to close port 5985 and prevent further remote PowerShell sessions
- Locked the Administrator account on NEXACORE-WS01 to prevent further authentication attempts
- Terminated all active WinRM sessions on NEXACORE-WS01

---

## Eradication Actions

The following actions were taken to remove attacker presence and verify the machine was clean:

- Reviewed all commands executed during the session via Event ID 4104 logs — no malicious scripts, file drops, or payload execution identified
- Audited local user accounts on NEXACORE-WS01 via net user output captured in logs — no new accounts were created by the attacker
- Reviewed Sysmon logs for scheduled task creation, registry modifications, and file creation events — no persistence mechanisms identified
- Confirmed no lateral movement occurred to other machines on the network

---

## Recovery Actions

The following actions were taken to restore normal operations securely:

- Reset the Administrator password on NEXACORE-WS01 to a strong credential not present in any wordlist
- Re-enabled WinRM only after network restrictions were confirmed in place
- Verified NEXACORE-WS01 was operating normally with no signs of compromise before returning to production

---

## Remediation Recommendations

| Recommendation | Priority |
|---|---|
| Enable account lockout policy on all endpoints to block brute force credential discovery | Critical |
| Restrict WinRM access to authorised management IP addresses only using Windows Firewall rules | Critical |
| Disable WinRM on all endpoints where remote management is not operationally required | High |
| Deploy a Splunk alert for high volume Event ID 4625 failures from a single source IP | High |
| Deploy a Splunk alert for wsmprovhost.exe spawning child processes | High |
| Enforce strong password policy across all accounts to resist brute force attacks | High |
| Enable and monitor PowerShell Script Block Logging across all endpoints | Medium |
| Conduct regular audits of open ports and exposed services on all endpoints | Medium |

---

## Lessons Learned

The attack succeeded because WinRM was left enabled and exposed with no access restrictions, and the Administrator account had no lockout policy in place. These two misconfigurations together allowed the attacker to brute force credentials and then immediately leverage them for remote access without any barrier.

The detection was successful because Sysmon, Windows Security Logging, and PowerShell Script Block Logging were all operational on NEXACORE-WS01 and forwarding to Splunk. The combination of these three log sources provided complete visibility into the attack chain from credential discovery through to post-exploitation reconnaissance.

Without Script Block Logging in particular, the specific commands executed by the attacker inside the PowerShell session would not have been captured, significantly reducing the quality of the forensic evidence.

---

## References

- Simulation: SIM-03 — PowerShell Execution via Evil-WinRM
- Detection: DET-03 — PowerShell Execution via Evil-WinRM
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1021.006: https://attack.mitre.org/techniques/T1021/006/
