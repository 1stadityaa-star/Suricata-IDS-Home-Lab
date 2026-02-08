This guide outlines the core configuration steps taken to deploy Suricata as a Network Intrusion Detection System (NIDS). The setup ensures that Suricata is correctly monitoring the home network interface and applying custom detection logic for various attack vectors.

## 🛠️ Environment Details
Operating System: Ubuntu Server (Running in Oracle VirtualBox)

- **Configuration Path**: /etc/suricata/suricata.yaml

- **Rules Path**: /etc/suricata/rules/local.rules

- **Primary Interface**: enp0s3

## 1. Network Variable Configuration
To ensure Suricata accurately distinguishes between internal and external traffic, the HOME_NET variable was defined to match the lab's IP scheme.

= **File**: /etc/suricata/suricata.yaml

```
vars:
  address-groups:
    HOME_NET: "[192.168.10.0/24]"
    EXTERNAL_NET: "any"
```
- **HOME_NET**: Set to your local subnet (192.168.10.0/24) to focus monitoring on lab assets.

- **EXTERNAL_NET**: Set to any to capture traffic originating from outside the defined home network.

## 2. Interface Binding (AF_PACKET)
Suricata is configured to utilize the AF_PACKET engine for high-speed packet capture on the primary virtual network interface.

- **File**: /etc/suricata/suricata.yaml

```
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
interface: Bound to enp0s3 to sniff traffic from the VirtualBox network.
```

- **cluster-id**: Defined as 99 for flow load balancing.

## 3. Custom Detection Rules
I implemented a set of custom rules in local.rules to detect specific malicious activities, including reconnaissance and exploitation attempts.

- **File**: /etc/suricata/rules/local.rules

- **1. Nmap Stealth Scan Detection**
```
alert tcp 192.168.10.250 any -> 192.168.10.100 any (msg:"Nmap Stealth Scan Detected"; flags:S; threshold: type threshold...)
```

- **2. SSH Brute Force Detection**
- ```
alert tcp 192.168.10.250 any -> 192.168.10.10 22 (msg:"SSH Brute Force Attempt Detected"; flags:S; threshold: type threshold...)
```

-**3. Metasploit Reverse Shell Detection**
```
alert tcp any any -> 192.168.10.100 any (msg:"Metasploit Reverse TCP Shell Detected"; content:"|bf 00 00 00 00 56 57 89|")
```

- **4. SQL Injection (SQLi) Detection**
```
alert http any any -> any any (msg:"SQL Injection Attempt Detected"; content:"UNION SELECT"; nocase; http_uri; sid:1000...)
```
- **Stealth & Brute Force**: These rules target specific source IPs (like your Kali machine at .250) and use TCP flags to identify suspicious connection patterns.

- **Payload Inspection**: The Metasploit and SQLi rules use the content keyword to inspect packet payloads for known attack signatures.

## 4. Verification Commands
To ensure the configuration is valid and the service is running correctly, the following commands are used:

- **Test configuration for syntax errors**
```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

- **Restart Suricata to apply changes**
```
sudo systemctl restart suricata
```

- **Verify Suricata is active**
```
sudo systemctl status suricata
```
