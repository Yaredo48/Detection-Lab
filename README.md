# 🧪 Detection Lab

## 🎯 Objective

The **Detection Lab** project simulates real-world cyber attacks to enhance detection and analysis capabilities using a SIEM setup. It focuses on log ingestion, threat detection, adversary emulation, and rule writing — all within a safe, controlled environment.

---

## 🧠 Skills Gained

- 📊 Deploying and configuring a SIEM (Wazuh + ELK Stack)
- 🔍 Analyzing endpoint logs using Sysmon & Winlogbeat
- 🧨 Emulating attacks using tools like Atomic Red Team
- 🛡️ Writing detection rules and responding to alerts
- 🧠 Threat hunting and forensic investigation skills

---

## 🛠️ Tools Used

- **Wazuh** – SIEM platform
- **Elastic Stack** – Kibana, Logstash, Elasticsearch
- **Sysmon** – Windows event logging
- **Winlogbeat** – Log shipper for Windows logs
- **Atomic Red Team** – Simulated attacks
- **Wireshark** – Packet capture & traffic inspection

---

## 🖥️ Lab Topology

> A simulated network with an attacker (Kali), domain controller, endpoint (Windows 10), and SIEM (Wazuh/ELK).

![Lab Topology](https://i.imgur.com/FIb2qJW.png)

---

## 📥 Log Ingestion & Visualization

> Windows logs collected by Sysmon and Winlogbeat were shipped to Wazuh, parsed, and visualized in Kibana dashboards.

![Log Ingestion Dashboard](https://i.imgur.com/WVul7P6.png)

---

## 💣 Simulated Attack: Mimikatz Credential Dump

> Used Atomic Red Team to simulate a credential theft. Detection was triggered based on unusual memory access patterns and process behavior.

![Mimikatz Detection](https://i.imgur.com/XTibZ2M.png)

---

## 🔍 Investigating a Suspicious PowerShell Script

> Detected PowerShell obfuscation using encoded commands (`-enc`) via custom detection rules.

![PowerShell Alert](https://i.imgur.com/4jHgslk.png)

---

## ⚙️ Custom Detection Rule

> Wrote a custom rule to alert on common obfuscation flags and suspicious parent/child process chains (e.g., `powershell.exe` from `explorer.exe`).

![Detection Rule](https://i.imgur.com/9En0Eow.png)

---

## ✅ Summary

This project simulated realistic attacks and allowed deep, hands-on experience with:

- 🧠 Threat detection and alert triage
- ⚙️ SIEM rule creation and tuning
- 🕵️ Investigating event timelines
- 🚨 Building defensive cybersecurity intuition

---

## 📂 Bonus Resources

- 📁 [Download Lab Report (PDF)](https://example.com/fake-report)
- 💻 [View GitHub Repository](https://github.com/yourname/detection-lab)
- 🧠 [Wazuh Docs](https://documentation.wazuh.com/)
