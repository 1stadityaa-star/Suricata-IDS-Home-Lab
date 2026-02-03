📌 Project Overview
This project demonstrates the setup and operation of a Network Intrusion Detection System (IDS) using Suricata. The lab environment simulates real-world cyber attacks from a Kali Linux machine against a Windows target, with all telemetry being ingested, parsed, and visualized through Splunk.

🛠️ Lab Architecture
The environment consists of three Virtual Machines (VMs) connected via a dedicated NAT Network:

Attacker: Kali Linux (192.168.10.250) - Used for network scanning, brute forcing, and exploit delivery.

IDS/IPS: Ubuntu Server (192.168.10.10) - Running Suricata to inspect traffic on interface enp0s3.

Victim: Windows 10 (192.168.10.100) - The target of the simulated attacks.

SIEM: Splunk Enterprise (Windows) - Receives eve.json logs via a Universal Forwarder on Ubuntu.

🚀 Key Features & Exercises
This lab documents the detection of several common attack vectors:

Nmap Stealth Scan Detection: Identifying TCP SYN scans targeting multiple ports within a short time frame.

SSH Brute Force Detection: Monitoring for high-frequency login attempts on port 22.

ICMP Flood Detection (In Progress): Detecting Denial of Service (DoS) attempts via ping flooding.

Log Aggregation: Real-time ingestion of Suricata alerts into Splunk for centralized analysis.

📂 Repository Structure
Plaintext
.
├── README.md               # Project overview and lab diagram
├── rules/
│   └── local.rules         # Custom Suricata rule library
├── configs/
│   ├── suricata.yaml       # Optimized Suricata configuration
│   └── inputs.conf         # Splunk Universal Forwarder configuration
└── documentation/          # Detailed walkthroughs of each exercise
📊 Splunk Visualization
By utilizing the suricata:json sourcetype, all alerts are indexed with rich metadata, allowing for the creation of security dashboards.

🏁 Conclusion
This lab provides hands-on experience in Detection Engineering, SIEM Management, and Linux System Administration. It bridges the gap between offensive security tools and defensive monitoring strategies.
