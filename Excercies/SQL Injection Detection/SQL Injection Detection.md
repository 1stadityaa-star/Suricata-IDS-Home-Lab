## 1. Objective
To detect "In-Band" SQL Injection attempts by monitoring HTTP GET request URIs for malicious SQL keywords like UNION SELECT.

## 2. Detection Strategy (The Rule)
I configured a custom Suricata rule to inspect the http_uri buffer. This target-specific inspection is more efficient than a general payload search.

```
alert http any any -> any any (msg:"SQL Injection Attempt Detected"; content:"UNION SELECT"; nocase; http_uri; sid:100004; rev:1;)
```
## 3. Attack Simulation (The Challenge)
The attack was simulated from a Kali Linux machine (192.168.10.250).

- ** Initial Hurdle ** : Direct curl requests failed because the target Ubuntu server was not running an active web service on port 80.

- ** The Fix ** : I utilized Netcat on the Ubuntu server (sudo nc -l -p 80) to act as a temporary listener, allowing the TCP handshake to complete so Suricata could inspect the full HTTP header.

## 4. Attack Execution
I used curl with URL Encoding to deliver the payload. Replacing spaces with %20 ensured the terminal handled the string correctly while the IDS decoded it for matching.

Bash
curl -v "http://192.168.10.10/login.php?user='%20UNION%20SELECT%20NULL,NULL,NULL--"
## 5. Evidence & Analysis
Ubuntu Side: The attack was successfully captured by the netcat listener.

Splunk Side: As seen in Screenshot (326).jpg, the alert was successfully indexed.

Index: suricata

Source: /var/log/suricata/fast.log

Key Finding: The alert correctly identified the source IP (192.168.10.250) and the destination port (80).

🛠️ Pro-Tip for your Project Summary
In your documentation, emphasize that you had to pivot from a standard attack to a manual listener setup. This demonstrates that you understand:

The OSI Model: You knew that without a Layer 4 (TCP) connection, the Layer 7 (HTTP) payload would never be sent.

Traffic Normalization: You proved that Suricata can decode URL encoding to find hidden malicious strings.
