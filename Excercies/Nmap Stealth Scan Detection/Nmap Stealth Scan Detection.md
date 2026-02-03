## 1. Objective
The goal of this exercise is to detect a TCP SYN (Stealth) Scan—a common reconnaissance technique—using custom Suricata rules and visualizing the resulting alerts within Splunk.

## 2. Attack Simulation (Kali Linux)
In this step, we use Nmap to perform a "half-open" scan. This is considered "stealthy" because it never completes the TCP three-way handshake, often bypassing simple logging systems.

**Command Executed:**

 ```yaml
sudo nmap -sS -p 1-20 192.168.10.100
```
- -sS: Specifies a TCP SYN (Stealth) scan.
- -p 1-20: Targets the first 20 ports to keep the scan focused for the lab.

- 192.168.10.100: The target IP address.

[!NOTE] As seen in your Kali terminal, the scan returned several "filtered" ports. This indicates that while the host is up, a firewall or IDS is likely dropping the packets or preventing a direct response.

## 3. Detection Rule (Suricata)
To detect this specific behavior, we use a Suricata rule that identifies a high volume of SYN packets from a single source in a short period.

**Custom Rule added to local.rules:**

 ```yaml
alert tcp any any -> $HOME_NET any (msg:"Nmap Stealth Scan Detected"; flags:S; threshold: type threshold, track by_src, count 5, seconds 10; sid:1000001; rev:1;)
```
- **flags:S:** Looks specifically for the SYN flag.

- **threshold:** Prevents log flooding by requiring 5 occurrences within 10 seconds from the same source before alerting.

## 4. Log Analysis (Splunk)
Once the scan is performed, Suricata generates an alert in eve.json. By ingesting this into Splunk, we can perform deeper analysis.

**Splunk Search Query:**

**Code snippet**
```yaml
index="suricata" sourcetype="suricata:fast" "Nmap Stealth Scan Detected"
```
**Observations from Logs:**

- **Source IP:** 192.168.10.250 (The Kali attacker machine).

- **Destination IP:** 192.168.10.100 (The victim/IDS interface).

- **Alert Signature:** The msg field correctly identifies the activity as an "Nmap Stealth Scan Detected."

- **Frequency:** The timeline in your Splunk dashboard shows a spike in events corresponding to the exact time the Nmap command was run.

## 5. Conclusion
By implementing a threshold-based rule, we successfully differentiated between a single legitimate connection attempt and an automated port scan. Even though the scan is "stealthy" at the OS level, the network-level signature (repeated SYN flags) makes it easily detectable by Suricata.
