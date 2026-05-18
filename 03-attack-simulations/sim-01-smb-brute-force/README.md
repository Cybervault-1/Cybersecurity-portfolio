# Attack Simulation 01 — SMB Brute Force

## Simulation Metadata

| Field | Detail |
| --- | --- |
| Simulation ID | SIM-01 |
| Date | 15 May 2026 |
| Author | Adedeji Adetayo |
| Status | Complete |
| MITRE Technique | T1110.001 — Password Guessing |

---

## Objective

The objective of this simulation was to perform a brute force attack against the SMB service on NEXACORE-WS01 using Kali Linux by repeatedly attempting authentication with a custom password list. The simulation generates real Windows Event ID 4625 failed login entries that are forwarded to Splunk for detection and analysis.

---

## Environment

| Role | Machine | IP Address | OS |
| --- | --- | --- | --- |
| Attacker | Kali Linux | 192.168.10.20 | Kali Linux 2025.4 |
| Target | NEXACORE-WS01 | 192.168.10.10 | Windows Server 2019 |
| Domain Controller | NexaCore-DC01 | 192.168.10.1 | Windows Server 2019 |
| SIEM | Splunk Enterprise | 192.168.56.1 | Host Machine |

---

## MITRE ATT&CK Mapping

| Field | Detail |
| --- | --- |
| Tactic | Credential Access |
| Technique | Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Reference | https://attack.mitre.org/techniques/T1110/001/ |

---

## Prerequisites — Security Gaps That Allowed This Attack

The following controls were deliberately left unconfigured to allow the simulation to succeed. These represent real security gaps that exist in poorly configured environments.

| Gap | Detail |
| --- | --- |
| No account lockout policy | Windows allowed unlimited failed login attempts with no lockout, meaning the attacker could try as many passwords as needed without consequence |
| Unrestricted SMB access | Port 445 was accessible from the attacker machine without any firewall restriction, giving unrestricted access to the SMB service |
| Weak password list viable | No password complexity enforcement meant common passwords from a small wordlist were worth attempting |

---

## Attack Flow Architecture

```
Kali Linux (192.168.10.20)
        |
        | Brute force attack over Internal Network (port 445)
        |
        v
NEXACORE-WS01 (192.168.10.10) -----> NexaCore-DC01 (192.168.10.1)
        |                              (authentication requests
        |                               forwarded to DC01)
        |
        | Windows Security and Sysmon logs forwarded
        | via Splunk Universal Forwarder (port 9997)
        |
        v
Splunk Enterprise (192.168.56.1) — centralized log monitoring
```

---

## Tools Used

| Tool | Version | Purpose |
| --- | --- | --- |
| smbclient | 4.23.3-Debian | Repeatedly attempt SMB authentication against NEXACORE-WS01 using a password list inside a bash loop |
| netcat (nc) | Built-in | Verify port 445 was open and reachable before launching the attack |
| bash | Built-in | Loop through each password in the list and pass it to smbclient |

---

## Attack Steps

### Step 1 — Confirm SMB port is open on the target

Before launching the attack, netcat was used to verify port 445 was reachable from Kali. Confirming the port is open before attacking is standard attacker reconnaissance. There is no point attempting a brute force if the service is not listening.

```
nc -zv 192.168.10.10 445
```

Expected output: `Connection to 192.168.10.10 445 port [tcp/microsoft-ds] succeeded`

![SMB Port Open](screenshots/03-smb-port-open.png)

---

### Step 2 — Create a password list

A small custom password list was created on Kali containing common weak passwords. In a real world attack an adversary would use a much larger wordlist such as rockyou.txt which contains over 14 million commonly used passwords. A small list was used here to keep the simulation clean and the evidence easy to read in Splunk.

```
cat ~/passwords.txt
```

Expected output: 8 weak passwords printed to the terminal, one per line.

![Password List](screenshots/02-password-list-created.png)

---

### Step 3 — Launch the brute force attack

A bash loop was used to pass each password from the list to smbclient, attempting to authenticate as the administrator account on NEXACORE-WS01. Each failed attempt returned NT_STATUS_LOGON_FAILURE confirming Windows rejected the credentials. All 8 attempts completed in under 2 seconds.

```
for pass in $(cat ~/passwords.txt); do echo "Trying password: $pass"; smbclient -L //192.168.10.10 -U administrator%$pass 2>&1 | grep -E "NT_STATUS|session setup"; done
```

Expected output: 8 lines of `NT_STATUS_LOGON_FAILURE`, one per password attempt.

![Brute Force Attack Running](screenshots/00-brute-force-attack-smbclient.png)

---

## Outcome

8 failed authentication attempts were generated against the administrator account on NEXACORE-WS01. Each attempt produced a Windows Security Event ID 4625 entry with the source IP recorded as 192.168.10.20. All events were forwarded to Splunk via the Universal Forwarder.

The attack succeeded in running without interruption because no account lockout policy was configured and port 445 was unrestricted. In a hardened environment the attack would have been blocked after the first 5 attempts.

---

## References

- Detection writeup: [detection-01-brute-force](../../04-detections/detection-01-brute-force/README.md)
- Incident report: [IR-001-smb-brute-force](../../05-incident-reports/IR-001-smb-brute-force/README.md)
- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
