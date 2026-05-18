# Detection 01 — SMB Brute Force (Event ID 4625)

## Detection Metadata

| Field | Detail |
| --- | --- |
| Detection ID | DET-01 |
| Date | 18 May 2026 |
| Author | Adedeji Adetayo |
| Status | Active |
| MITRE Technique | T1110.001 — Password Guessing |
| Linked Simulation | [SIM-01 — SMB Brute Force](../../03-attack-simulations/sim-01-smb-brute-force/README.md) |
| Linked Incident Report | [IR-001 — SMB Brute Force](../../05-incident-reports/IR-001-smb-brute-force/README.md) |

---

## Overview

This detection identifies brute force authentication attempts against Windows machines by monitoring for a high volume of failed login events (Event ID 4625) originating from the same source IP within a short timeframe. It was built and validated against the SMB brute force simulation documented in SIM-01.

---

## MITRE ATT&CK Mapping

| Field | Detail |
| --- | --- |
| Tactic | Credential Access |
| Technique | Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Reference | https://attack.mitre.org/techniques/T1110/001/ |

---

## Data Source Requirements

For this detection to work the following must be configured on the target endpoint:

| Requirement | Detail |
| --- | --- |
| Windows Security Auditing | Audit Logon Failures must be enabled under Security Settings — Advanced Audit Policy — Logon/Logoff |
| Splunk Universal Forwarder | Must be installed and running on the target endpoint and forwarding Security logs to Splunk |
| Splunk Index | Logs must be landing in the main index |

Without these in place Event ID 4625 will not be generated or will not reach Splunk and the detection will produce no results.

---

## Detection Logic

A single failed login is normal. A user mistyping their password generates one or two Event ID 4625 entries followed by a successful login. What distinguishes brute force activity is a sustained pattern of failures from the same source IP within a short window with no successful login recorded at any point.

This detection surfaces that pattern by grouping failed login events by source IP and applying a count threshold. Any IP exceeding 5 failures within 15 minutes is considered suspicious and warrants investigation.

---

## Threshold Detection Query

This query groups failed logins by source IP and surfaces only those exceeding the threshold of 5 failures. The Splunk alert runs this query every 5 minutes against the last 15 minutes of log data.

```
index=main EventCode=4625 earliest=-15m | stats count by Source_Network_Address | where count > 5
```

| Part | Meaning |
| --- | --- |
| index=main | Opens the main log storage bucket where all endpoint logs are kept |
| EventCode=4625 | Windows Security event for a failed logon attempt |
| earliest=-15m | Scopes the search to the last 15 minutes of data |
| stats count by Source_Network_Address | Groups failed logins by source IP and counts them |
| where count > 5 | Filters to only IPs that have exceeded the threshold |

During SIM-01 validation the query returned 192.168.10.20 with a count of 8, exceeding the threshold of 5 and confirming brute force activity originating from the Kali Linux attacker machine.

![Threshold Query Result](screenshots/detection-01-threshold-query.png)

---

## Timechart — Visual Spike Pattern

A timechart provides a visual representation of failed login activity over time grouped by source IP. Legitimate failed logins appear as a low flat baseline spread randomly across the timeline. Brute force activity produces a sharp isolated spike as all failures occur within a very short window.

```
index=main EventCode=4625 earliest=-15m | timechart span=1m count by Source_Network_Address
```

The chart produced during SIM-01 validation shows a single spike at 2:03 PM on 18 May 2026 from 192.168.10.20 with a completely flat baseline before and after, consistent with automated brute force tooling rather than normal user behaviour.

![Timechart Spike](screenshots/detection-01-timechart-spike.png)

---

## Investigation Query

Following a threshold breach this query provides a broader view of all source IPs generating failed logins within the last hour, grouped by account name and workstation. The query is dynamic and not scoped to a specific IP, ensuring all concurrent threats in the environment are surfaced rather than only the known attacker.

```
index=main EventCode=4625 earliest=-1h | stats count by Source_Network_Address, Account_Name, Workstation_Name | sort -count
```

---

## Key Fields To Examine

Each Event ID 4625 entry contains several fields that together build a complete picture of the attack. The following fields were examined across the events captured during the SIM-01 simulation.

---

### Account_Name

The Account_Name field identifies the account that was targeted. High privilege accounts such as administrator are the most common targets because a successful compromise yields full system control. A consistent account name appearing across all failed login events indicates the attacker had a specific target rather than cycling through multiple accounts.

![Account Name](screenshots/02-4625-account-name.png)

---

### Logon_Type

The Logon_Type field identifies the method of authentication used. A value of 3 indicates a network logon, meaning the attempt originated from a remote machine rather than a local interactive session. Repeated network logon failures from an unfamiliar external IP are a reliable indicator of remote brute force activity.

![Logon Type](screenshots/03-4625-logon-type.png)

---

### Failure_Reason

The Failure_Reason field records why the authentication failed. When the same failure reason appears repeatedly across multiple events from the same source with no successful login, the pattern is consistent with automated credential guessing rather than a genuine user error. Legitimate user mistakes typically result in a small number of failures followed by a successful login or a password reset.

![Failure Reason](screenshots/04-4625-failure-reason.png)

---

### Source_Network_Address

The Source_Network_Address field records the IP address from which the authentication attempt originated. This field is central to response, as it identifies the machine responsible for the failed logins and provides the basis for firewall blocking, network tracing and threat intelligence lookups.

![Source IP](screenshots/05-4625-source-ip.png)

---

### Workstation_Name

The Workstation_Name field records the hostname of the machine from which the attempt was made. When combined with Source_Network_Address, two independent pieces of evidence point to the same origin, strengthening the confidence of the attribution and supporting escalation decisions.

![Workstation Name](screenshots/06-4625-workstation-name.png)

---

## Follow-On Query — Confirming Attack Success or Failure

After a brute force threshold breach is confirmed the next step is to determine whether any authentication attempt succeeded. Event ID 4624 records successful Windows logon events. The presence of the attacker IP in 4624 events within the same timeframe as the 4625 failures indicates a compromised account and warrants escalation to Critical severity.

The following query returns all successful logins within the last hour grouped by source IP and account name. Any overlap between these results and the source IP identified in the threshold query indicates a successful breach.

```
index=main EventCode=4624 earliest=-1h | stats count by Source_Network_Address, Account_Name | sort -count
```

During the SIM-01 simulation 192.168.10.20 returned no Event ID 4624 entries, confirming the brute force failed completely and no accounts were compromised.

![Success Check 4624](screenshots/detection-01-success-check-4624.png)

---

## False Positive Analysis

| Scenario | How To Distinguish From Attack |
| --- | --- |
| User genuinely mistyping password | A small number of failures followed by a successful login. No sustained pattern from the same IP. |
| Password sync issue on a service account | Failures originate from a known internal IP associated with a service account rather than an external or unfamiliar host. |
| Automated script with wrong credentials | Pattern resembles brute force but the source is a known internal trusted IP. The script rather than an external attacker is the likely cause. |

The threshold value of 5 failures can be adjusted based on observed baseline behaviour in the environment. Higher thresholds reduce false positive rates but increase the risk of missing lower volume attacks.

---

## Splunk Alert Configuration

A scheduled alert has been configured in Splunk to fire automatically when the threshold is breached. The alert runs every 5 minutes and remains silent until a genuine threshold breach is detected.

| Setting | Value |
| --- | --- |
| Title | NexaCore — SMB Brute Force Detection |
| Alert Type | Scheduled |
| Cron Schedule | */5 * * * * (every 5 minutes) |
| Time Range | Last 15 minutes |
| Trigger Condition | Number of results greater than 0 |
| Trigger | For each result |
| Throttle | 10 minutes |
| Severity | High |
| Action | Add to Triggered Alerts |

![Alert Configuration](screenshots/detection-01-alert-config.png)

---

## Limitations

- This detection requires the Splunk Universal Forwarder to be running on the target endpoint. If the forwarder is offline events will not reach Splunk and the detection will produce no results.
- Correlation between 4625 failures and subsequent 4624 successes is not automated. The follow-on check is a manual investigation step.
- Attackers using low and slow techniques that deliberately keep their failure rate below the threshold will not trigger this detection.

---

## References

- [Attack Simulation SIM-01](../../03-attack-simulations/sim-01-smb-brute-force/README.md)
- [Incident Report IR-001](../../05-incident-reports/IR-001-smb-brute-force/README.md)
- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Microsoft Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
