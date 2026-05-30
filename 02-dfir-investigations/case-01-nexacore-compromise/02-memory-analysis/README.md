# Phase 02 — Memory Analysis

## Analysis Metadata

| Field | Detail |
|---|---|
| Case ID | DFIR-CASE-01 |
| Analyst | Adedeji Adetayo |
| Date | 2026-05-30 |
| Analysis Tool | Volatility3 Framework v2.28.0 |
| Memory Image | nexacore-ws01-dfir.raw |
| Image Size | 4,831,838,208 bytes |
| OS Identified | Windows 10 Build 19041 |
| Capture Time | 2026-05-30 08:45:10 UTC |

---

## Objective

Analyse the memory dump captured from NEXACORE-WS01 to identify attacker artefacts, suspicious processes, malicious commands, and active network connections that existed in RAM at the time of capture.

---

## Tool — Volatility3

Volatility3 is an open source memory forensics framework written in Python. It parses raw memory images and extracts structured information using OS-specific symbol files. It was run on the Kali Linux analyst workstation.

Installation:
```bash
pip3 install volatility3 --break-system-packages
```

---

## System Identification

The first step was confirming the OS version to ensure Volatility3 loaded the correct symbol file.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.info
```

| Field | Value |
|---|---|
| OS | Windows 10 |
| Build | 19041 |
| Architecture | 64-bit |
| Processors | 2 |
| System Time | 2026-05-30 08:45:10 UTC |
| System Root | C:\Windows |

![System Info](../screenshots/volatility-windows-info.png)

---

## Plugin Execution and Findings

### Plugin 1 — windows.pslist

**Purpose:** List all processes running at time of capture.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.pslist > ~/dfir/analysis/dfir-pslist.txt
```

**Key Findings:**

| PID | Process | Parent | Significance |
|---|---|---|---|
| 4820 | powershell.exe | - | Active PowerShell session — investigation target |
| 3356 | Sysmon64.exe | 664 | Sysmon monitoring active |
| 3220 | splunkd.exe | 664 | Splunk forwarder running |
| 1736 | svchost.exe -s WinRM | 664 | WinRM service active — attack vector open |
| 7644 | cmd.exe | 1844 | Command Prompt used to run attack commands |

---

### Plugin 2 — windows.pstree

**Purpose:** Show parent-child process relationships to identify suspicious spawning patterns.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.pstree > ~/dfir/analysis/dfir-pstree.txt
```

**Key Finding:**

WinRM service confirmed running as svchost.exe with `-s WinRM` flag. This confirms the remote access attack vector was active at time of capture. The full process tree showed a normal Windows hierarchy with no obvious process masquerading.

---

### Plugin 3 — windows.cmdline

**Purpose:** Extract command line arguments for each running process.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.cmdline > ~/dfir/analysis/dfir-cmdline.txt
```

**Key Finding:**

Three cmd.exe instances identified with PIDs 7644, 3056, and 3752. Command lines showed basic `cmd.exe` invocation without arguments — meaning the malicious commands were typed interactively inside the shell rather than passed as arguments at launch.

---

### Plugin 4 — windows.cmdscan

**Purpose:** Extract command history from console buffers in memory — recovers commands typed interactively even after the process exits.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.cmdscan > ~/dfir/analysis/dfir-cmdscan.txt
```

**Critical Finding — Attacker Commands Recovered:**

```
powershell -EncodedCommand bgBlAHQAIAB1AHMAZQByACAAYwB5AGIAZQByAHYAYQB1AGwAdAAgAFAAYQBzAHMAdwBvAHIAZAAkADEAMgAzACEAIAAvAGEAZABkAA==
net localgroup administrators cybervault /add
```

The base64 encoded command decodes to:
```
net user cybervault Password$123! /add
```

Both commands were recovered from the console history buffer of conhost.exe PID 4776. This confirms the full attack sequence — user creation followed by privilege escalation — was executed on this endpoint.

![Command History Evidence](../screenshots/dfir-cmdscan-evidence.png)

---

### Plugin 5 — windows.netscan

**Purpose:** List all active and listening network connections at time of capture.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.netscan > ~/dfir/analysis/dfir-netscan.txt
```

**Key Findings:**

| Finding | Detail | Significance |
|---|---|---|
| Port 5985 LISTENING | WinRM HTTP port | Remote access attack vector open |
| Port 445 LISTENING | SMB port | Additional attack vector open |
| 192.168.56.30:50130 → 192.168.56.1:9997 ESTABLISHED | splunkd.exe | Splunk actively forwarding logs |

No active connection from the attacker IP was found because the attack was executed locally rather than via a live remote session at time of capture.

![Network Scan Evidence](../screenshots/dfir-netscan-evidence.png)

---

### Plugin 6 — windows.malfind

**Purpose:** Identify memory regions with characteristics consistent with injected or dynamically generated code.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.malfind > ~/dfir/analysis/dfir-malfind.txt
```

**Critical Finding — Suspicious Memory Region In PowerShell:**

```
PID:         4820
Process:     powershell.exe
Address:     0x197fdf20000
Protection:  PAGE_EXECUTE_READWRITE
Type:        VaDs
```

A memory region marked `PAGE_EXECUTE_READWRITE` in a dynamically allocated area of PowerShell is a strong indicator of fileless code execution. Legitimate code loaded from disk is marked `PAGE_EXECUTE_READ` only. The combined presence of write and execute permissions on a non-file-backed region is consistent with a fileless payload executing in memory.

![Malfind Evidence](../screenshots/dfir-malfind-evidence.png)

---

### Plugin 7 — windows.registry.hashdump

**Purpose:** Extract Windows password hashes from the SAM database in memory.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.registry.hashdump > ~/dfir/analysis/dfir-hashdump.txt
```

**Result:** Failed — Hbootkey not valid. The SAM hive was not fully active in memory at time of capture. Hash extraction was not possible from this memory image.

---

### Plugin 8 — windows.registry.hivelist

**Purpose:** List all registry hives present in memory.

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.registry.hivelist > ~/dfir/analysis/dfir-hivelist.txt
```

**Finding:** SAM hive located at address `0x860802fc8000` but marked as Disabled — confirming why hashdump failed.

---

## Memory Analysis Summary

| Finding | Plugin | Severity |
|---|---|---|
| Encoded PowerShell command recovered from console buffer | cmdscan | Critical |
| Privilege escalation command recovered from console buffer | cmdscan | Critical |
| Suspicious PAGE_EXECUTE_READWRITE region in PowerShell | malfind | High |
| WinRM port 5985 listening — attack vector open | netscan | High |
| SMB port 445 listening | netscan | Medium |
| Multiple cmd.exe instances running | pslist/cmdline | Medium |

---

## References

- NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response
- Volatility3 Documentation — https://volatility3.readthedocs.io
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1027 — Obfuscated Files or Information
