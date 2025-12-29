# 📖 THE SOC ANALYST'S BIBLE: COMMAND MASTER REFERENCE
*Version 1.0 - High Intensity Edition*

This document contains every critical command, search query, and configuration snippet required for the 112-Day SOC Intensive.

---

## 🛠️ MONTH 1: LOG ANALYSIS & FORENSICS

### 🪟 Windows Execution & Triage
| Task | Command |
| :--- | :--- |
| **List Processes with Owners** | `Get-WmiObject -Query "Select * from Win32_Process" | Select-Object Name, ProcessId, @{Name="Owner";Expression={$_.GetOwner().User}}` |
| **Check Network Connections** | `netstat -ano | findstr LISTENING` |
| **Parse Prefetch Files** | `.\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Triage\Prefetch"` |
| **Extract Chrome History** | `copy "C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History" C:\Triage\` |
| **Search Event Logs (PS)** | `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50` |
| **Sysmon Installation** | `.\Sysmon64.exe -i .\sysmon_config.xml -accepteula` |

### 🐧 Linux Hardening & Investigation
| Task | Command |
| :--- | :--- |
| **Check Active Connections** | `ss -atpu` |
| **Monitor Audit Logs** | `ausearch -m USER_LOGIN -sv no` |
| **List Listening Ports** | `lsof -i -P -n | grep LISTEN` |
| **Check Cron Persistence** | `ls -la /etc/cron.* /var/spool/cron/crontabs/` |
| **Find SUID Binaries** | `find / -perm -4000 -type f 2>/dev/null` |
| **Verify File Integrity** | `sha256sum /usr/bin/ssh` |

### 🌐 Network Traffic Analysis
| Task | Command |
| :--- | :--- |
| **Capture Traffic (tcpdump)** | `tcpdump -i eth0 -w traffic.pcap` |
| **Extract Files from PCAP** | `tshark -r traffic.pcap --export-objects http,./files` |
| **Search for Cleartext Passwords** | `tshark -r traffic.pcap -Y "http.request.method == POST" -T fields -e http.file_data` |
| **Zeek PCAP Processing** | `zeek -r traffic.pcap` |
| **Suricata Live Run** | `suricata -c /etc/suricata/suricata.yaml -i eth0` |

---

## 🔍 MONTH 2: SIEM OPERATIONS (SPLUNK/ELK)

### 📈 Splunk (SPL) Power Queries
- **Detect Mimikatz (Sysmon 1):**
  `index=windows EventCode=1 (CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*")`
- **Lateral Movement (WMI):**
  `index=windows EventCode=1 CommandLine="*wmic* /node:* process call create *"`
- **Account Lockout Chain:**
  `index=windows EventCode=4740 | transaction TargetUserName maxspan=5m`
- **DNS Exfiltration Check:**
  `index=network sourcetype=dns | eval query_len=len(query) | where query_len > 100`

### 📊 ELK (KQL) & Lucene
- **Find Failed Logins:** `event.code: 4625`
- **Detect Rundll32 to Web:** `process.name: "rundll32.exe" AND destination.port: (80 OR 443)`
- **Unexpected Parent (Excel -> CMD):** `process.parent.name: "excel.exe" AND process.name: "cmd.exe"`

---

## 🚑 MONTH 3: IR & THREAT HUNTING

### 🧠 Volatility 3 (Memory Forensics)
- **Identify OS Profile:** `python3 vol.py -f mem.dmp windows.info`
- **List Hidden Processes:** `python3 vol.py -f mem.dmp windows.psscan`
- **Extract Injected Code:** `python3 vol.py -f mem.dmp windows.malfind --dump`
- **Scan for Sockets:** `python3 vol.py -f mem.dmp windows.netstat`

### 🏹 Threat Hunting Hypotheses
- **Hypothesis 1:** "Attackers are using non-standard ports for C2."
  `Query: index=firewall dest_port NOT IN (80, 443, 53, 22) | stats count by dest_port | sort - count`
- **Hypothesis 2:** "Lolbins are being used to download payloads."
  `Query: index=endpoint (process_name="certutil.exe" OR process_name="bitsadmin.exe") CommandLine="*http*"`

---

## ☁️ MONTH 4: CLOUD & AUTOMATION

### 🌩️ Cloud Security (AWS/Azure)
- **AWS S3 Public Access:** `aws s3api get-public-access-block --bucket <bucket-name>`
- **List IAM Users without MFA:** `aws iam get-account-summary | grep "MFADevices"`
- **Azure Log Search (KQL):** `SigninLogs | where AppDisplayName == "Azure Portal" | where ResultType != 0`

### 🐍 Python for Security
```python
# Quick IP enrichment from command line
import requests
ip = input("IP: ")
print(requests.get(f"https://ipinfo.io/{ip}/json").json())
```

---

## 📜 THE GOLDEN IR RULES
1. **Never** analyze malware on a machine connected to the production network.
2. **Always** check hashes before and after evidence collection.
3. **Document** every command you run during a live incident.
4. **Assume** the attacker is still in the network until proven otherwise.

---
