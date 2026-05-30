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

## Tool

Volatility3 Framework v2.28.0 was installed on the Kali Linux analyst workstation and used for all memory analysis. Each plugin output was saved to a text file for filtering and review.

```bash
pip3 install volatility3 --break-system-packages
```

---

## Analysis Methodology

Each plugin was run using the following pattern:

```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw [plugin] > ~/dfir/analysis/[output-file].txt
```

Key findings were then extracted by filtering the output file using grep. Screenshots capture both the grep command used and the filtered results returned — showing exactly how each finding was identified.

---

## Step 1 — System Identification

**Purpose:** Confirm the OS version and build number so Volatility3 loads the correct symbol file for parsing memory structures.

**Command:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.info
```

**Key Output:**

| Field | Value |
|---|---|
| OS | Windows 10 |
| Build | 19041 |
| Architecture | 64-bit |
| Processors | 2 |
| System Time | 2026-05-30 08:45:10 UTC |
| System Root | C:\Windows |

**Finding:** Volatility3 successfully identified the memory image and loaded the correct symbol file. The system time confirms the exact moment of capture.

![System Info](../screenshots/volatility-windows-info.png)

---

## Step 2 — Process List

**Purpose:** List all processes running at the moment of memory capture to identify suspicious or attacker-controlled processes.

**Commands:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.pslist > ~/dfir/analysis/dfir-pslist.txt
grep -i "powershell\|winrm\|cmd\|splunk\|sysmon" ~/dfir/analysis/dfir-pslist.txt
```

**Key Output:**

| PID | Process | Significance |
|---|---|---|
| 4820 | powershell.exe | Active PowerShell session — investigation target |
| 3356 | Sysmon64.exe | Endpoint monitoring active |
| 3220 | splunkd.exe | Log forwarding active to SIEM |
| 1736 | svchost.exe -s WinRM | WinRM service running — attack vector confirmed open |
| 7644 | cmd.exe | Command Prompt used during attack |

**Finding:** PowerShell was actively running at time of capture. The WinRM service was confirmed active — the remote access attack vector remains open on this endpoint.

---

## Step 3 — Process Tree

**Purpose:** Map parent-child process relationships to identify suspicious spawning patterns such as LOLBin abuse or process masquerading.

**Commands:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.pstree > ~/dfir/analysis/dfir-pstree.txt
grep -i "cmd\|powershell\|winrm\|winpmem" ~/dfir/analysis/dfir-pstree.txt
```

**Key Output:**
```
664   services.exe
 └── 1736  svchost.exe  -k NetworkService -p -s WinRM
 └── 3220  splunkd.exe
 └── 3356  Sysmon64.exe
1844  explorer.exe
 └── 7644  cmd.exe
      └── 6040  go-winpmem_amd64  (forensic acquisition tool)
```

**Finding:** The process tree confirmed a normal Windows hierarchy with no process masquerading detected. The WinRM service is correctly hosted under services.exe. The cmd.exe and WinPmem chain at the bottom represents the analyst forensic footprint during memory acquisition.

---

## Step 4 — Command Line Arguments

**Purpose:** Extract the full command line for each running process to identify how processes were launched and what arguments were passed.

**Commands:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.cmdline > ~/dfir/analysis/dfir-cmdline.txt
grep -i "powershell\|cmd\|administrator" ~/dfir/analysis/dfir-cmdline.txt
```

**Key Output:**
```
4820  powershell.exe  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
7644  cmd.exe         "C:\Windows\system32\cmd.exe"
3056  cmd.exe         "C:\Windows\system32\cmd.exe"
3752  cmd.exe         "C:\Windows\system32\cmd.exe"
```

**Finding:** Three cmd.exe instances were identified. None carried command line arguments — meaning the malicious commands were typed interactively inside the shell rather than passed at launch. This is consistent with an attacker operating manually through a live session.

---

## Step 5 — Command History (Critical Finding)

**Purpose:** Extract command history from console buffers in memory. This recovers commands that were typed interactively — including commands from processes that have already exited — because the console buffer persists in memory after process termination.

**Commands:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.cmdscan > ~/dfir/analysis/dfir-cmdscan.txt
grep -i "powershell\|encoded\|cybervault\|net user\|net localgroup\|administrator" ~/dfir/analysis/dfir-cmdscan.txt
```

The screenshot below shows the grep command used to filter the cmdscan output and the attacker commands recovered:

![cmdscan Evidence](../screenshots/dfir-cmdscan-evidence.png)

**Key Output Extracted:**
```
4776  conhost.exe  powershell -EncodedCommand bgBlAHQAIAB1AHMAZQByACAAYwB5AGIAZQByAHYAYQB1AGwAdAAgAFAAYQBzAHMAdwBvAHIAZAAkADEAMgAzACEAIAAvAGEAZABkAA==
4776  conhost.exe  net localgroup administrators cybervault /add
6624  conhost.exe  powershell.exe
```

**Decoded Payload:**
```
net user cybervault Password$123! /add
```

**Finding (Critical):** The full attacker command sequence was recovered from the console history buffer of conhost.exe PID 4776. The encoded PowerShell command was retrieved from memory even though the PowerShell process had already completed and exited before memory capture. Base64 encoding was used to obfuscate the payload from basic detection. This is the primary evidence of the fileless attack.

---

## Step 6 — Network Connections (Critical Finding)

**Purpose:** List all active and listening network connections at time of capture to identify open attack vectors and active attacker communications.

**Commands:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.netscan > ~/dfir/analysis/dfir-netscan.txt
grep -i "powershell\|4820\|192.168\|winrm\|5985\|ESTABLISHED\|LISTENING" ~/dfir/analysis/dfir-netscan.txt
```

The screenshot below shows the grep command used to filter the netscan output and the key connections identified:

![netscan Evidence](../screenshots/dfir-netscan-evidence.png)

**Key Output Extracted:**
```
TCPv4  0.0.0.0:5985        0.0.0.0:0              LISTENING    System
TCPv4  0.0.0.0:445         0.0.0.0:0              LISTENING    System
TCPv4  192.168.56.30:50130 192.168.56.1:9997      ESTABLISHED  splunkd.exe
```

**Finding:** Port 5985 (WinRM) is actively listening on all interfaces — confirming the remote access attack vector remains open. Port 445 (SMB) is also listening. The only established outbound connection is the Splunk Universal Forwarder shipping logs to the SIEM at 192.168.56.1:9997. No active attacker connection was present at time of capture because the attack was executed locally rather than via a live remote session.

---

## Step 7 — Suspicious Memory Regions (Critical Finding)

**Purpose:** Identify memory regions with characteristics consistent with injected or dynamically generated code — the primary indicator of fileless malware execution.

**Commands:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.malware.malfind > ~/dfir/analysis/dfir-malfind.txt
grep -i "powershell\|cmd\|4820\|cybervault\|suspicious" ~/dfir/analysis/dfir-malfind.txt
```

The screenshot below shows the grep command used to filter the malfind output and the suspicious memory region identified:

![malfind Evidence](../screenshots/dfir-malfind-evidence.png)

**Key Output Extracted:**
```
PID   Process         Address        Protection             Type
4820  powershell.exe  0x197fdf20000  PAGE_EXECUTE_READWRITE VaDs
```

**Finding (Critical):** A memory region in PowerShell PID 4820 was flagged with `PAGE_EXECUTE_READWRITE` protection on a dynamically allocated region not backed by any file on disk. Legitimate code loaded from disk carries `PAGE_EXECUTE_READ` only. The presence of both write and execute permissions on a non-file-backed region is a strong indicator of fileless code execution — the attacker's payload was written into memory and executed directly from there.

---

## Step 8 — Password Hash Extraction

**Purpose:** Attempt to extract Windows NTLM password hashes from the SAM database loaded in memory for offline cracking or further investigation.

**Command:**
```bash
vol -f ~/dfir/nexacore-ws01-dfir.raw windows.registry.hashdump
```

**Result:**
```
WARNING: Hbootkey is not valid
```

**Finding:** The SAM registry hive was not fully loaded into active memory at time of capture — the hive was located at address `0x860802fc8000` but marked as Disabled. Password hash extraction was not possible from this memory image. This is a known limitation when the SAM hive is paged out to disk at the moment of capture.

---

## Memory Analysis Summary

| Step | Plugin | Key Finding | Severity |
|---|---|---|---|
| 1 | windows.info | Windows 10 build 19041 confirmed | Informational |
| 2 | windows.pslist | PowerShell PID 4820 and WinRM service active | High |
| 3 | windows.pstree | Normal process hierarchy — no masquerading | Informational |
| 4 | windows.cmdline | Three interactive cmd.exe sessions identified | Medium |
| 5 | windows.cmdscan | Encoded PowerShell payload and privilege escalation command recovered | Critical |
| 6 | windows.netscan | WinRM port 5985 and SMB port 445 listening | High |
| 7 | windows.malware.malfind | PAGE_EXECUTE_READWRITE region in PowerShell — fileless execution confirmed | Critical |
| 8 | windows.registry.hashdump | Failed — SAM hive not active in memory | Informational |

---

## References

- NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response
- Volatility3 Documentation — https://volatility3.readthedocs.io
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1027 — Obfuscated Files or Information
