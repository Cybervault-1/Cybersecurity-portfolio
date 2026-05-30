# DFIR Investigations

## Project Overview

This project documents hands-on Digital Forensics and Incident Response investigations conducted on the NexaCore SOC homelab environment. Each case follows the NIST SP 800-86 forensic investigation methodology combined with the NIST SP 800-61 incident response lifecycle.

The investigations demonstrate the complete DFIR workflow — from live memory acquisition through forensic analysis to formal reporting — using industry standard tools including WinPmem and Volatility3.

---

## DFIR Methodology

Each case follows this investigation structure:

```
Incident Occurs
       ↓
Phase 1 — Evidence Acquisition
       └── Live memory capture using WinPmem
       └── Chain of custody documentation
       ↓
Phase 2 — Memory Analysis
       └── Volatility3 process analysis
       └── Command history recovery
       └── Network connection mapping
       └── Suspicious memory region detection
       ↓
Phase 3 — Disk Analysis
       └── Windows Security event log analysis in Splunk
       └── Scheduled task investigation
       └── User account verification
       ↓
Phase 4 — DFIR Report
       └── Formal investigation report
       └── Containment and eradication recommendations
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| WinPmem v1.0-rc2 | Live memory acquisition from Windows endpoints |
| Volatility3 v2.28.0 | Memory dump analysis and artefact extraction |
| Splunk Enterprise | Windows Security event log analysis |
| Sysmon v15.20 | Endpoint telemetry and process monitoring |
| Kali Linux | Analyst workstation for forensic analysis |

---

## Frameworks Referenced

| Framework | Application |
|---|---|
| NIST SP 800-86 | Guide to Integrating Forensic Techniques into Incident Response |
| NIST SP 800-61 Rev 2 | Computer Security Incident Handling Guide |
| MITRE ATT&CK | Adversary technique mapping for each case |

---

## Cases

| Case ID | Title | Attack Type | Status |
|---|---|---|---|
| [DFIR-CASE-01](case-01-nexacore-compromise/04-dfir-report/README.md) | NexaCore Endpoint Compromise | Fileless PowerShell Attack and Scheduled Task Persistence | Complete |

---

## References

- NIST SP 800-86 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-86.pdf
- NIST SP 800-61 Rev 2 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- Volatility3 — https://volatility3.readthedocs.io
- WinPmem — https://github.com/Velocidex/WinPmem
