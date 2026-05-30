# Incident Response Report 005 — Kerberoasting

## Incident Metadata

| Field | Detail |
|---|---|
| Incident ID | IR-005 |
| Date Detected | 21 May 2026 |
| Author | Adedeji Adetayo |
| Status | Resolved |
| Severity | High |
| MITRE Technique | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| Linked Simulation | SIM-05 — Kerberoasting |
| Linked Detection | DET-05 — Kerberoasting |

---

## Incident Summary

On 21 May 2026, a threat actor operating from 192.168.10.20 successfully harvested credentials for the svc_sql service account on the NexaCore domain through Kerberoasting. The attacker authenticated to NexaCore-DC01 using the previously compromised Administrator credential and requested a Kerberos service ticket for the svc_sql account. The Domain Controller issued the ticket using RC4-HMAC encryption, which the attacker extracted and cracked offline using hashcat mode 13100 against a password wordlist. The plain text password Password123! was recovered in 9 seconds.

The attack was detected through Splunk via Windows Event ID 4769 on NexaCore-DC01. The Ticket Encryption Type field showed 0x17 (RC4-HMAC), which is the signature indicator of Kerberoasting in modern Active Directory environments that default to AES encryption. The incident was contained and remediated. The compromised service account credentials were rotated and all SPNs reviewed.

---

## Severity Assessment

| Factor | Detail |
|---|---|
| Severity | High |
| Affected Account | svc_sql (service account with MSSQLSvc SPN) |
| Affected Service | Simulated SQL Server service on nexacore-sql01 |
| Attack Vector | Kerberos protocol abuse — service ticket request |
| Attacker IP | 192.168.10.20 |
| Privilege Level Obtained | svc_sql service account credentials |
| Credential Cracking Time | 9 seconds |
| Lateral Movement Potential | High — credentials valid wherever svc_sql is authorised |

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
| 10:41:12 | Administrator account requested Kerberos service ticket for svc_sql with RC4 encryption from Kali Linux |
| 10:41:13 | Ticket hash extracted by attacker to kerberoast-hashes.txt |
| 10:51:20 | Offline cracking of ticket hash initiated on Kali Linux using hashcat mode 13100 |
| 10:51:29 | Plain text password Password123! recovered for svc_sql in 9 seconds |
| 10:54:22 | Splunk detection triggered on Event ID 4769 with Ticket Encryption Type 0x17 |

---

## Detection Evidence

| Source | Event ID | Observation |
|---|---|---|
| Windows Security Log (DC01) | 4769 | Service ticket requested for svc_sql with RC4-HMAC encryption from 192.168.10.20 |
| Windows Security Log (DC01) | 4769 | Account requesting ticket was Administrator@NEXACORE.LOCAL |
| Windows Security Log (DC01) | 4769 | Service Principal Name targeted was MSSQLSvc/nexacore-sql01.nexacore.local:1433 |
| Out-of-band evidence | N/A | Offline cracking of the extracted hash recovered the plain text password Password123! |

---

## Containment Actions

The following actions were taken immediately upon detection to stop the attack and prevent the compromised credentials from being used:

- Disabled the svc_sql service account on NexaCore-DC01 to prevent authentication with the cracked credential
- Blocked source IP 192.168.10.20 at the network firewall to prevent further Kerberos ticket requests from the attacker machine
- Locked the Administrator account on NEXACORE-WS01 to prevent the attacker from requesting additional service tickets
- Reviewed all active Kerberos sessions on NexaCore-DC01 and terminated any associated with the compromised accounts

---

## Eradication Actions

The following actions were taken to remove attacker impact and verify no additional compromise occurred:

- Identified all accounts with SPNs registered via Get-ADUser filter on ServicePrincipalNames and reviewed each for legitimacy
- Audited Windows Event ID 4769 logs for the past 30 days on NexaCore-DC01 to identify any other RC4 ticket requests that may indicate prior Kerberoasting
- Verified the svc_sql account had no recent successful authentications using the cracked credential by reviewing Event ID 4624 logs
- Confirmed no other service accounts were targeted during the attack window by filtering 4769 events from the attacker source IP

---

## Recovery Actions

The following actions were taken to restore secure operations:

- Reset the svc_sql service account password to a 25 character random string not present in any wordlist
- Configured the svc_sql account to use AES-128 and AES-256 encryption only by setting the msDS-SupportedEncryptionTypes attribute to disable RC4
- Removed the SPN from svc_sql temporarily and re-evaluated whether the service truly required Kerberos authentication
- Re-enabled the svc_sql account only after the password was rotated and encryption types restricted
- Reset the NEXACORE\Administrator password on the domain since the attacker used it to initiate the attack

---

## Remediation Recommendations

| Recommendation | Priority |
|---|---|
| Migrate all service accounts to Group Managed Service Accounts (gMSA) for automatic password rotation and 128 character complexity | Critical |
| Configure all service accounts to use AES encryption only by setting msDS-SupportedEncryptionTypes attribute to remove RC4 support | Critical |
| Alert on Event ID 4769 with Ticket Encryption Type 0x17 across all Domain Controllers | Critical |
| Enforce minimum 25 character passwords on all service accounts that cannot be migrated to gMSA | High |
| Alert on accounts requesting more than 5 service tickets within a 1 minute window | High |
| Audit all accounts with SPNs registered monthly and remove SPNs from accounts that do not require them | High |
| Disable RC4-HMAC encryption domain-wide by configuring the DefaultDomainPolicy GPO if no legacy systems require it | High |
| Monitor for Kerberos ticket requests originating from non-Windows hosts which is highly unusual in most environments | Medium |

---

## Lessons Learned

The attack succeeded because three weaknesses existed together. The svc_sql service account was assigned a weak password that existed in common wordlists. The account was configured to allow RC4 encryption when modern Active Directory should default to AES only. And no monitoring was in place to alert on RC4 ticket requests, which are abnormal in a properly hardened environment.

The detection was successful because the Domain Controller was forwarding Security logs to Splunk and Event ID 4769 was being captured. Without this logging, the attack would have been completely invisible because Kerberoasting generates no failed authentication attempts and the offline cracking phase produces zero evidence on the network.

Service accounts represent some of the highest value targets in Active Directory because they often have elevated privileges, weak passwords, and rarely rotate. Treating service account security as critical infrastructure rather than an administrative afterthought is the single most effective defence against Kerberoasting. Group Managed Service Accounts solve the password rotation and complexity problem automatically and should be the default standard for all new service deployments.

The 9 second crack time demonstrates how quickly weak service account passwords fall against modern cracking hardware. Any password under 15 characters that contains dictionary words or predictable patterns should be considered compromised the moment a ticket hash is requested for it.

---

## References

- Simulation: SIM-05 — Kerberoasting
- Detection: DET-05 — Kerberoasting
- MITRE ATT&CK T1558.003: https://attack.mitre.org/techniques/T1558/003/
- NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
