# Attack Simulation 01 — SMB Brute Force

## Objective

The objective of this simulation was to perform a brute force attack against the SMB service on NEXACORE-WS01 using Kali Linux by repeatedly attempting authentication with a custom password list. The simulation generates real Windows Event ID 4625 failed login entries that are forwarded to Splunk for detection and analysis.

## Attack Background

SMB (Server Message Block) is the protocol Windows uses to share files and printers across a network. It runs on port 445 and is one of the most commonly targeted services in real world attacks because it is open by default on most Windows machines.

A brute force attack works by repeatedly trying different passwords against a target account until one succeeds. Every failed attempt generates Windows Security Event ID 4625 which records the source IP, the targeted account, the logon type and the reason for failure.

## MITRE ATT&CK Mapping

| Field | Detail |
| --- | --- |
| Tactic | Credential Access |
| Technique | Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Reference | https://attack.mitre.org/techniques/T1110/001/ |

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

| Role | Machine | IP Address |
| --- | --- | --- |
| Attacker | Kali Linux | 192.168.10.20 |
| Target | NEXACORE-WS01 | 192.168.10.10 |
| Domain Controller | NexaCore-DC01 | 192.168.10.1 |
| SIEM | Splunk Enterprise | 192.168.56.1 |

## Tools Used

- **smbclient** — a Linux command line tool for interacting with Windows SMB shares. Used inside a bash loop to repeatedly attempt authentication against NEXACORE-WS01 using a custom password list, generating a failed login event on the target for each incorrect password.

## Attack Steps

**Step 1 — Confirm SMB port is open on the target:**

Before launching the attack, netcat was used to verify port 445 was reachable from Kali. Confirming the port is open before attacking is standard attacker reconnaissance.

```
nc -zv 192.168.10.10 445
```

![SMB Port Open](screenshots/03-smb-port-open.png)

---

**Step 2 — Create a password list:**

A small custom password list was created on Kali containing common weak passwords. In a real world attack an adversary would use a much larger wordlist such as rockyou.txt which contains over 14 million commonly used passwords. A small list was used here to keep the simulation clean and the evidence easy to read in Splunk.

```
cat ~/passwords.txt
```

![Password List](screenshots/02-password-list-created.png)

---

**Step 3 — Launch the brute force attack:**

A bash loop was used to pass each password from the list to smbclient, attempting to authenticate as the administrator account on NEXACORE-WS01. Each failed attempt returned NT_STATUS_LOGON_FAILURE confirming Windows rejected the credentials. All 8 attempts completed in under 2 seconds.

```
for pass in $(cat ~/passwords.txt); do echo "Trying password: $pass"; smbclient -L //192.168.10.10 -U administrator%$pass 2>&1 | grep -E "NT_STATUS|session setup"; done
```

![Brute Force Attack Running](screenshots/00-brute-force-attack-smbclient.png)

---

## Outcome

8 failed authentication attempts were generated against the administrator account on NEXACORE-WS01. Each attempt produced a Windows Security Event ID 4625 entry with the source IP recorded as 192.168.10.20. All events were forwarded to Splunk via the Universal Forwarder.

Detection writeup: [detection-01-brute-force](../../04-detections/detection-01-brute-force/README.md)

Incident report: [IR-001-smb-brute-force](../../05-incident-reports/IR-001-smb-brute-force/README.md)

