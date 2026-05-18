# Lab Architecture

## Overview

The NexaCore SOC homelab runs on a Windows laptop using VirtualBox, with Splunk Enterprise installed directly on the host machine at 192.168.56.1 to act as the central SIEM for the entire environment.

The diagram below shows the full network architecture including machine roles, IP addressing, network adapters, attack flow and log forwarding flow.

![NexaCore SOC Homelab Architecture](screenshots/nexacore-architecture-diagram.png)

---

## Virtual Machines and Roles

| Machine | Role | OS | Internal IP | Host-Only IP |
| --- | --- | --- | --- | --- |
| Host Laptop | Splunk SIEM | Windows 10 | N/A | 192.168.56.1 |
| NEXACORE-WS01 | Target Endpoint | Windows Server 2019 | 192.168.10.10 | 192.168.56.30 |
| NexaCore-DC01 | Domain Controller | Windows Server 2019 | 192.168.10.1 | 192.168.56.10 |
| Kali Linux | Attacker | Kali Linux 2025.4 | 192.168.10.20 | N/A |

---

## Network Design

Two VirtualBox adapter types were used to segment the network.

The **Host-Only adapter** connects NEXACORE-WS01 and NexaCore-DC01 to the host machine, allowing the Splunk Universal Forwarder on each machine to ship logs to Splunk Enterprise over the 192.168.56.0/24 range.

The **Internal Network adapter** connects all three virtual machines together in an isolated environment named NexaCoreNet on the 192.168.10.0/24 range. This allows attack simulations to run between Kali and the Windows machines while keeping all attack traffic off the real network.

Kali Linux uses a NAT adapter for internet access to download tools.

---

## Log Forwarding

The Splunk Universal Forwarder is installed on both NEXACORE-WS01 and NexaCore-DC01. Both machines generate critical security events including Windows Security logs, Sysmon activity and Active Directory authentication events that are forwarded to Splunk Enterprise on port 9997 for centralised monitoring and detection.

---

## Screenshots

The following screenshot confirms all three virtual machines were running simultaneously during the lab build and testing phase.

![VirtualBox VMs Running](screenshots/infra-01-virtualbox-vms.png)
