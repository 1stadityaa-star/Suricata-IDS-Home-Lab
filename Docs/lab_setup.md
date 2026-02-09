# 🚀 Overview

This project is hosted in a **virtualized home lab environment** designed for **security monitoring, threat detection, and attack simulation**.  
The infrastructure is fully isolated within a **VirtualBox NAT Network**, enabling secure internal communication between attacker and victim machines while being continuously monitored by a centralized **Intrusion Detection System (IDS)**.

---

## 🌐 Network Configuration

- **Network Type:** VirtualBox NAT Network  
- **Subnet:** `192.168.10.0/24`  
- **Traffic Capture:**  
  The Ubuntu Server is configured in **Promiscuous Mode** to allow **Suricata** to sniff traffic traversing the network segment between other hosts.

---

## 🖥️ Virtual Machine Inventory

| Host Role        | Operating System | IP Address        | Primary Tools                              |
|------------------|------------------|------------------|--------------------------------------------|
| SOC / IDS        | Ubuntu Server    | `192.168.10.10`  | Suricata, Splunk Enterprise                |
| Victim PC        | Windows          | `192.168.10.100` | Sysmon, Splunk Universal Forwarder         |
| Attacker         | Kali Linux       | `192.168.10.250` | Nmap, Hydra, Metasploit                    |

---

## 🔧 Component Roles

### 1. Security Operations Center (Ubuntu Server)

This machine serves as the **central monitoring and analysis node** of the lab.

#### Suricata IDS
- Monitors the `enp0s3` interface in real time
- Uses a custom `local.rules` file
- Detects:
  - SYN scans
  - Port scans
  - Brute-force attempts
  - Suspicious network behavior

#### Splunk Enterprise
- Ingests Suricata logs:
  - `eve.json`
  - `fast.log`
- Acts as the **SIEM search head**
- Used for:
  - Alert visualization
  - Threat investigation
  - Security analytics

---

### 2. Target Endpoint (Windows)

A standard Windows workstation acting as the **victim system**.

#### Log Forwarding
- Splunk Universal Forwarder installed
- Forwards:
  - Windows Event Logs
  - Sysmon telemetry
- Logs are indexed on the Ubuntu Server

#### Attack Surface
- Exposed services used for simulation:
  - SMB
  - RDP
  - ICMP
- Enables realistic attack detection scenarios

---

### 3. Adversary Platform (Kali Linux)

The primary system used to **simulate attacker behavior**.

#### Reconnaissance
- Uses **Nmap** for:
  - Port scanning
  - Service enumeration
  - OS detection

#### Exploitation
- **Hydra** for credential attacks
- **Metasploit Framework** for:
  - Exploitation attempts
  - Payload delivery
  - Post-exploitation simulation

---

## 🛠️ Core Setup Logic

### Network Definition
- The `HOME_NET` variable in Suricata is set to:
  ```text
  192.168.10.0/24
