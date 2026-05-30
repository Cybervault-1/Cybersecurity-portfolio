# Incident Response Report 002 — Nmap Reconnaissance

## Incident Metadata

| Field | Detail |
|---|---|
| Incident ID | IR-002 |
| Date Detected | 18 May 2026 |
| Author | Adedeji Adetayo |
| Status | Resolved |
| Severity | Medium |
| MITRE Technique | T1046 — Network Service Discovery |
| Linked Simulation | [SIM-02 — Nmap Reconnaissance](../../03-attack-simulations/sim-02-nmap-reconnaissance/README.md) |
| Linked Detection | [DET-02 — Nmap Reconnaissance](../../04-detections/detection-02-nmap-reconnaissance/README.md) |

---

## Incident Summary

On 18 May 2026, an unauthorised network port scan was conducted against NEXACORE-WS01 from an external machine operating at 192.168.10.20. The scan covered ports 1 through 1000 and completed within 11 seconds, generating 37 inbound connection events captured by the Windows Filtering Platform. Three open ports were identified during the scan: 135, 139 and 445.

The activity was detected through Splunk monitoring of Windows Filtering Platform Event ID 5156 logs. No data was accessed and no systems were compromised. The reconnaissance directly preceded a subsequent SMB brute force attack documented in IR-001, demonstrating a clear attack progression from discovery to exploitation.

---

## Severity Assessment

| Factor | Detail |
|---|---|
| Severity | Medium |
| Affected Machine | NEXACORE-WS01 |
| Attack Vector | Network — TCP ports 1 to 1000 |
| Attacker IP | 192.168.10.20 |
| Tool Used | Nmap version 7.99 |
| Privilege Level Obtained | None |
| Data Accessed | None |
| Systems Compromised | None |
| Follow-up Activity | SMB brute force attack against discovered port 445 (IR-001) |

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
| 16:49:10 | First inbound connection from 192.168.10.20 recorded on NEXACORE-WS01 |
| 16:49:10 — 16:49:21 | 37 inbound connection events recorded across multiple ports |
| 16:49:21 | Final connection event — scan completed |
| Post-scan | All Event ID 5156 entries forwarded to Splunk via Universal Forwarder |
| Post-scan | Scanning pattern identified through DET-02 threshold detection |
| Post-scan | Source IP confirmed, investigation completed, incident resolved |

---

## Detection Evidence

| Source | Event ID | Observation |
|---|---|---|
| Windows Filtering Platform | 5156 | 37 inbound connection events from 192.168.10.20 within 11 seconds |
| Windows Filtering Platform | 5156 | 31 of the 37 connection attempts targeted port 445 (SMB) |
| Windows Filtering Platform | 5156 | 3 connection attempts targeted port 135 (RPC) |
| Windows Filtering Platform | 5156 | 3 connection attempts targeted port 139 (NetBIOS) |

---

## Containment Actions

The following actions were taken immediately upon detection to stop the active scan and prevent further reconnaissance:

- Blocked source IP 192.168.10.20 at the network firewall to terminate all inbound connections from the attacker machine
- Reviewed all active connections on NEXACORE-WS01 to confirm no follow-up activity beyond the initial scan
- Notified the security team to begin investigation of the source

---

## Eradication Actions

The following actions were taken to verify the machine was clean and no follow-up activity occurred:

- Reviewed Sysmon process creation logs on NEXACORE-WS01 — no malicious process execution identified
- Verified no inbound authentication attempts followed the scan
- Confirmed no data was accessed and no services on the discovered ports were exploited during the scan window

---

## Recovery Actions

The following actions were taken to restore normal operations securely:

- Verified NEXACORE-WS01 was operating normally with no signs of compromise
- Confirmed all network services were functioning as expected
- Maintained continued monitoring through the DET-02 detection rule

---

## Remediation Recommendations

| Recommendation | Priority |
|---|---|
| Implement network segmentation to isolate untrusted machines from internal endpoints | Critical |
| Restrict inbound access to ports 135, 139 and 445 on NEXACORE-WS01 using Windows Firewall rules | Critical |
| Deploy a Splunk alert for source IPs generating high volumes of Event ID 5156 connection logs in a short time window | High |
| Disable SMBv1 and ensure SMB signing is enforced across all endpoints | High |
| Conduct regular audits of open ports and exposed services on all endpoints | Medium |
| Deploy an intrusion detection system to identify scanning activity in real time | Medium |

---

## Lessons Learned

The scan succeeded because no network segmentation or firewall restrictions were in place to prevent the attacker machine from reaching internal workstation ports. An unknown Kali Linux machine should not have had unrestricted access to ports 135, 139 and 445 on NEXACORE-WS01.

The detection was successful because Windows Filtering Platform logging was operational on NEXACORE-WS01 and forwarding to Splunk. The volume of connection events from a single source IP within a short time window provided a clear signature of automated scanning activity.

The reconnaissance directly enabled the SMB brute force attack documented in IR-001. Detecting reconnaissance activity early provides a critical opportunity to investigate and block the source before exploitation begins.

---

## References

- Simulation: [SIM-02 — Nmap Reconnaissance](../../03-attack-simulations/sim-02-nmap-reconnaissance/README.md)
- Detection: [DET-02 — Nmap Reconnaissance](../../04-detections/detection-02-nmap-reconnaissance/README.md)
- Related Incident: [IR-001 — SMB Brute Force](../../05-incident-reports/IR-001-smb-brute-force/README.md)
- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- Microsoft Event ID 5156: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156
- NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
