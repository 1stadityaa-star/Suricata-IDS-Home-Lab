# Exercise: Detecting SSH Brute Force Attacks
## 🚀 Overview
This exercise demonstrates how to identify and alert on SSH Brute Force attempts. By using Hydra to simulate a high-frequency login attack, I configured Suricata to trigger alerts based on connection thresholds, providing real-time visibility through Splunk.

## 🛠️ Environment Configuration
- **Attacker Machine**: Kali Linux (192.168.10.250)

- **Target Machine**: Ubuntu Server (192.168.10.10)

- **Tools**: Hydra, Suricata, Splunk

## 1. Attack Simulation (Hydra)
I used Hydra, a powerful network login cracker, to perform a dictionary attack against the SSH service of the target machine. This involves rapid-fire login attempts using a list of common passwords.

## Command Executed:

```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt 192.168.10.10 ssh
```
- **-l root**: Specifies the target username.
- **-P [path]**: Points to the password wordlist used for the attack.

- **ssh**: Defines the protocol being targeted.

## 2. Detection Logic (Suricata)
Standard SSH traffic is encrypted, but the behavior of a brute force attack—multiple connection attempts in a short window—is a clear network signature. I utilized a Suricata rule to track these attempts by source IP.

- **Custom Rule added to local.rules**:

```
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt Detected"; flow:to_server; flags:S; threshold: type both, track by_src, count 5, seconds 30; sid:1000002; rev:1;)
```
- **flow**:to_server: Monitors traffic heading toward the SSH server.

- **threshold**: Triggers an alert only when 5 or more SYN packets reach port 22 from the same source within 30 seconds.

## 3. Splunk Analysis & Evidence
The Suricata logs (in JSON format) were forwarded to Splunk. By querying the alert.signature, I was able to isolate the specific timeframe and origin of the attack.

- **Search Query**:

```
index=suricata sourcetype="suricata:json" alert.signature="SSH Brute Force Attempt Detected"
| table _time, src_ip, dest_ip, alert.category, alert.severity
```
**Analysis from Logs** :

- **Total Events**: 6 high-confidence alerts within the specified timeframe.

- **Attacker IP**: 192.168.10.250.

- **Target IP**: 192.168.10.10.

- **Severity**: Level 3 (indicating a high-priority security event).

## 🔍 Key Findings
- **Threshold Importance**: Without the threshold keyword, Suricata would generate an alert for every single login attempt, leading to "alert fatigue." Tracking by src_ip ensures we only flag aggressive behavior.

- **Hydra Performance**: As seen in the terminal, Hydra warned about parallel task limits; reducing the number of tasks can help an attacker bypass simple IDS rules, but a well-tuned Suricata rule still catches the persistent attempts.

- **SOC Visibility**: Splunk provides a clear timeline of the attack, which is essential for documenting a security incident or correlating it with other suspicious activity from the same IP.
