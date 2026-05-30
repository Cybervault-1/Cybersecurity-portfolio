# Incident Response Report 001 — SMB Brute Force Attack

## Incident Metadata

| Field | Detail |
|---|---|
| Incident ID | IR-001 |
| Date Detected | 18 May 2026 |
| Author | Adedeji Adetayo |
| Status | Resolved |
| Severity | High |
| MITRE Technique | T1110.001 — Password Guessing |
| Linked Simulation | [SIM-01 — SMB Brute Force](../../03-attack-simulations/sim-01-smb-brute-force/README.md) |
| Linked Detection | [DET-01 — SMB Brute Force](../../04-detections/detection-01-brute-force/README.md) |

---

## Incident Summary

On 18 May 2026, an unauthorised brute force attack was conducted against the built-in administrator account on NEXACORE-WS01 from an external machine operating at 192.168.10.20. The attack consisted of 8 consecutive password guessing attempts over the SMB protocol on port 445, completing in under one second. All attempts failed and no accounts were compromised.

The activity was detected through Splunk monitoring of Windows Security Event ID 4625 failed logon logs. Although the attack was unsuccessful, it demonstrated that the administrator account had no lockout protection and that SMB access was unrestricted from untrusted machines on the network.

---

## Severity Assessment

| Factor | Detail |
|---|---|
| Severity | High |
| Affected Machine | NEXACORE-WS01 |
| Affected Account | Administrator |
| Attack Vector | Network — SMB port 445 |
| Attacker IP | 192.168.10.20 |
| Attacker Workstation Name | KALI |
| Privilege Level Targeted | Local Administrator |
| Successful Logons | None |
| Systems Compromised | None |
| Data Accessed | None |

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
| 14:03:49 | First failed logon attempt against Administrator account recorded on NEXACORE-WS01 |
| 14:03:50 | Seven additional failed logon attempts recorded within the same second |
| 14:03:50 | Final failed attempt — brute force completed with no successful authentication |
| Post-attack | All Event ID 4625 entries forwarded to Splunk via Universal Forwarder |
| Post-attack | Brute force pattern identified through DET-01 threshold detection |
| Post-attack | Source IP confirmed, investigation completed, incident resolved |

---

## Detection Evidence

| Source | Event ID | Observation |
|---|---|---|
| Windows Security Log | 4625 | 8 failed logon attempts against the Administrator account from 192.168.10.20 |
| Windows Security Log | 4625 | All attempts used Logon Type 3 confirming network-based authentication |
| Windows Security Log | 4625 | Failure reason consistent across all events — unknown username or bad password |
| Windows Security Log | 4624 | No successful logons from 192.168.10.20 before, during or after the attack window |

---

## Containment Actions

The following actions were taken immediately upon detection to stop the active attack and prevent further unauthorised access attempts:

- Blocked source IP 192.168.10.20 at the network firewall to terminate all inbound connections from the attacker machine
- Temporarily locked the Administrator account on NEXACORE-WS01 to prevent any further authentication attempts
- Reviewed all active sessions on NEXACORE-WS01 to confirm no unauthorised access had been established

---

## Eradication Actions

The following actions were taken to verify the machine was clean and no compromise occurred:

- Verified no successful logons occurred from 192.168.10.20 by reviewing all Event ID 4624 logs within the attack window
- Audited the Administrator account for any unauthorised session activity — no sessions identified
- Reviewed Sysmon process creation logs on NEXACORE-WS01 — no malicious process execution identified
- Confirmed no lateral movement attempts followed the brute force activity

---

## Recovery Actions

The following actions were taken to restore normal operations securely:

- Reset the Administrator password to a strong credential not present in any wordlist
- Unlocked the Administrator account after password rotation was complete
- Verified NEXACORE-WS01 was operating normally with no signs of compromise before returning to production
- Maintained continued monitoring through the DET-01 detection rule

---

## Remediation Recommendations

| Recommendation | Priority |
|---|---|
| Enable account lockout policy across all endpoints to lock accounts after 5 failed attempts within 10 minutes for a 30 minute duration | Critical |
| Restrict inbound access to SMB port 445 on NEXACORE-WS01 using Windows Firewall rules to authorised machines only | Critical |
| Deploy a Splunk alert for source IPs generating 5 or more Event ID 4625 failures within a 15 minute window | High |
| Rename the built-in Administrator account to a non-obvious name to remove a predictable target | High |
| Enforce strong password policy across all accounts to resist password guessing attacks | High |
| Disable SMBv1 and enforce SMB signing across all endpoints | Medium |
| Conduct regular audits of open ports and exposed services on all endpoints | Medium |

---

## Lessons Learned

The attack succeeded in completing 8 password guessing attempts because no account lockout policy was in place on NEXACORE-WS01. An attacker with a larger wordlist could have continued indefinitely with no automated interruption from the operating system.

The detection was successful because Windows Security Logging was operational on NEXACORE-WS01 and forwarding to Splunk. The volume of Event ID 4625 events from a single source IP within a short time window provided a clear signature of automated brute force activity.

The attack was directly enabled by the reconnaissance documented in IR-002, where the same attacker machine identified port 445 as open during a port scan moments before launching the brute force. This demonstrates the typical attack progression from network discovery to credential attack and reinforces the value of detecting reconnaissance activity early.

---

## References

- Simulation: [SIM-01 — SMB Brute Force](../../03-attack-simulations/sim-01-smb-brute-force/README.md)
- Detection: [DET-01 — SMB Brute Force](../../04-detections/detection-01-brute-force/README.md)
- Related Incident: [IR-002 — Nmap Reconnaissance](../../05-incident-reports/IR-002-nmap-reconnaissance/README.md)
- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- Microsoft Event ID 4625: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Event ID 4624: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
