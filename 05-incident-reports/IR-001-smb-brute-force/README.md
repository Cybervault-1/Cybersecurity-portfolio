# Incident Report — IR-001: SMB Brute Force Attack

## Incident Metadata

| Field | Detail |
| --- | --- |
| Incident ID | IR-001 |
| Date | 18 May 2026 |
| Analyst | Adedeji Adetayo |
| Severity | High |
| Status | Resolved |
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Linked Simulation | [SIM-01 — SMB Brute Force](../../03-attack-simulations/sim-01-smb-brute-force/README.md) |
| Linked Detection | [DET-01 — SMB Brute Force](../../04-detections/detection-01-brute-force/README.md) |

---

## Executive Summary

On 18 May 2026 an unauthorised machine at 192.168.10.20 attempted to gain access to the NexaCore workstation NEXACORE-WS01 by repeatedly attempting authentication against the administrator account over SMB. All 8 attempts failed and no accounts or systems were compromised. The attack was detected through Splunk monitoring using Event ID 4625, the source IP was identified and the incident was investigated and resolved.

---

## Incident Details

| Field | Detail |
| --- | --- |
| Incident ID | IR-001 |
| Date and Time | 18 May 2026, 14:03:49 to 14:03:50 |
| Attack Type | SMB Brute Force |
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Attacker IP | 192.168.10.20 |
| Attacker Machine | KALI |
| Target Machine | NEXACORE-WS01 |
| Target Account | administrator |
| Total Attempts | 8 |
| Successful Logins | 0 |
| Systems Compromised | None |

---

## Timeline of Events

| Time | Event |
| --- | --- |
| 14:03:49.892 | First failed login attempt recorded on NEXACORE-WS01 from 192.168.10.20 |
| 14:03:50.025 | Second failed attempt |
| 14:03:50.091 | Third failed attempt |
| 14:03:50.164 | Fourth failed attempt |
| 14:03:50.238 | Fifth failed attempt |
| 14:03:50.332 | Sixth failed attempt |
| 14:03:50.443 | Seventh failed attempt |
| 14:03:50.529 | Eighth and final failed attempt |
| Post-attack | All 8 events forwarded to Splunk via Universal Forwarder |
| Post-attack | Attack detected via Event ID 4625 threshold alert |
| Post-attack | Source IP identified, investigation completed, incident resolved |

---

## Affected Systems

| Machine | Role | Impact |
| --- | --- | --- |
| NEXACORE-WS01 | Primary target endpoint | Targeted but not compromised |
| NexaCore-DC01 | Domain Controller | Authentication requests forwarded, no compromise |
| Splunk Enterprise | SIEM | Successfully detected the attack |

---

## Attack Description

The attacker used smbclient running on Kali Linux to repeatedly attempt authentication against the administrator account on NEXACORE-WS01 over the SMB protocol on port 445. A custom wordlist of commonly used weak passwords was cycled through in rapid succession with all 8 attempts completing within under 1 second. This speed and pattern is characteristic of automated brute force tooling.

The attack was made possible by two security gaps. No account lockout policy was configured on NEXACORE-WS01, meaning Windows permitted unlimited failed login attempts without locking the targeted account. Additionally port 445 was accessible from the attacker machine without firewall restriction, providing unrestricted access to the SMB service.

---

## Detection

The attack was detected in Splunk through the DET-01 threshold detection which monitors for Event ID 4625 failed login events. The detection query grouped failed logins by source IP and flagged any IP exceeding 5 failures within 15 minutes.

```
index=main EventCode=4625 earliest=-15m | stats count by Source_Network_Address | where count > 5
```

The query returned 192.168.10.20 with a count of 8, exceeding the threshold and triggering the alert. The rapid succession of 8 failures from a single external IP with no successful login confirmed automated brute force activity.

![Detection Results](screenshots/IR-001-detection-results.png)

---

## Investigation Findings

All 8 Event ID 4625 entries were examined in Splunk. The following fields were extracted and analysed to confirm the nature and scope of the attack.

| Field | Value | Significance |
| --- | --- | --- |
| Account_Name | administrator | The highest privilege account on the machine was targeted |
| Logon_Type | 3 — Network | The attempt originated remotely over the network |
| Failure_Reason | Unknown user name or bad password | Incorrect credentials on every attempt confirming brute force |
| Source_Network_Address | 192.168.10.20 | The Kali Linux attacker machine |
| Workstation_Name | KALI | Confirms the attacker machine name |

A follow-on check against Event ID 4624 confirmed that 192.168.10.20 recorded no successful logins before, during or after the attack window. The administrator account was not compromised.

![Investigation Table](screenshots/IR-001-investigation-table.png)

---

## Root Cause

Two misconfigurations on NEXACORE-WS01 allowed the attack to proceed without interruption:

**No account lockout policy** — Windows was configured to permit unlimited failed login attempts. A lockout policy set to 5 failed attempts within 10 minutes would have blocked the attack after the fifth attempt.

**Unrestricted SMB access** — Port 445 was reachable from the attacker machine without firewall restriction. Restricting SMB access to only authorised hosts would have prevented the connection entirely.

---

## Remediation Actions Taken

**Splunk alert configured** — A scheduled alert named NexaCore — SMB Brute Force Detection was created in Splunk. The alert runs every 5 minutes, evaluates the last 15 minutes of Event ID 4625 data and fires when any source IP exceeds 5 failures within that window. Throttle is set to 10 minutes to prevent duplicate alerts for the same incident.

**Account lockout policy recommended** — A Group Policy Object should be configured to lock accounts after 5 failed attempts within 10 minutes with a 30 minute lockout duration. This was identified as a critical gap during this incident.

**Firewall restriction recommended** — Access to port 445 on NEXACORE-WS01 should be restricted to only machines that require SMB connectivity. Kali Linux at 192.168.10.20 should have no legitimate reason to reach this port.

**Administrator account hardening recommended** — The built-in administrator account should be renamed to a non-obvious name to remove a predictable target for brute force attacks.

---

## Lessons Learned

The incident confirmed that a failed brute force attack still reveals significant security gaps. The attacker made 8 attempts without any automated interruption because no lockout policy was in place. In a production environment with a larger password list such as rockyou.txt this attack could have succeeded.

Splunk detection performed as expected. The 8 failed logins were captured by Event ID 4625 monitoring, grouped by source IP and surfaced within the alert window. The attacker IP was identified and the investigation was completed without ambiguity. This validates the value of threshold-based detection over simple event counting.

---

## References

- [Attack Simulation SIM-01](../../03-attack-simulations/sim-01-smb-brute-force/README.md)
- [Detection DET-01](../../04-detections/detection-01-brute-force/README.md)
- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Microsoft Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
