# 📖 THE MITRE-POWERED ANALYST'S BIBLE: TACTICAL FIELD MANUAL
*Version 2.0 - Industry Aligned Edition*

This manual maps every tactical operation to the MITRE ATT&CK framework.

---

## 🛠️ THE DEFENSIVE TOOLSET BY TACTIC

### 🚩 RECONNAISSANCE & INITIAL ACCESS (T1595, T1566)
| Technique | Command / Search | D3FEND Countermeasure (DID) |
| :--- | :--- | :--- |
| **Active Scanning (T1595)** | `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Nmap Option Scan"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000001;)` | **D3-NSM** (Network Surveillance) |
| **Phishing Payload (T1566)** | `index=email sourcetype=office365_logs | where attachment_ext IN ("iso", "lnk", "zip", "exe")` | **D3-MSI** (Message Segment Inspection) |
| **Exploit Public App (T1190)** | `index=web_logs | search "jndi:ldap" OR "../../../etc/passwd" OR "select * from"` | **D3-WAF** (Web Application Filtering) |

### ⚡ EXECUTION & PERSISTENCE (T1059, T1547)
| Technique | Command / Search | D3FEND Countermeasure (DID) |
| :--- | :--- | :--- |
| **PowerShell (T1059.001)** | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104}` | **D3-SFL** (Script File Logging) |
| **Registry Run Keys (T1547.001)** | `sysmon.exe -i config.xml (Check Event ID 13 for HKCU\Software\Microsoft\Windows\CurrentVersion\Run)` | **D3-RIA** (Registry Ingestion Analysis) |
| **Scheduled Task (T1053.005)** | `schtasks /create /tn "SOC_Persist" /tr "powershell.exe -enc ..." /sc onlogon` | **D3-PSA** (Process Spawn Analysis) |

### 🛡️ DEFENSE EVASION (T1562, T1070)
| Technique | Command / Search | D3FEND Countermeasure (DID) |
| :--- | :--- | :--- |
| **Log Clearing (T1562.002)** | `wevtutil cl Security` (Check for Event ID 1102) | **D3-ELA** (Event Log Analysis) |
| **Indicator Removal (T1070)** | `find / -name ".bash_history" -exec rm -rf {} \;` | **D3-FMA** (File Modification Analysis) |
| **Timestomping (T1070.006)** | `powershell -command "$(Get-Item evil.exe).lastwritetime=$(Get-Date '2020-01-01')"` | **D3-FMA** (File Modification Analysis) |

### 🔑 PRIVILEGE ESCALATION & CREDENTIAL ACCESS (T1548, T1003)
| Technique | Command / Search | D3FEND Countermeasure (DID) |
| :--- | :--- | :--- |
| **UAC Bypass (T1548.002)** | `fodhelper.exe` (Monitor for auto-elevated process tree) | **D3-PSA** (Process Spawn Analysis) |
| **LSASS Dumping (T1003.001)** | `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full` | **D3-LPA** (Lsass Process Analysis) |
| **NTDS.dit Theft (T1003.003)** | `ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q` | **D3-FMA** (File Modification Analysis) |

### 🏹 DISCOVERY & LATERAL MOVEMENT (T1087, T1021)
| Technique | Command / Search | D3FEND Countermeasure (DID) |
| :--- | :--- | :--- |
| **Account Discovery (T1087)** | `net user /domain` or `Get-ADUser -Filter *` | **D3-LAA** (Local Account Analysis) |
| **Remote Services (T1021.001)** | `psexec.exe \\target_host cmd.exe` (Check for Event ID 4624 Type 3) | **D3-PSA** (Process Spawn Analysis) |
| **WMI Movement (T1047)** | `wmic /node:"target" process call create "evil.exe"` | **D3-PSA** (Process Spawn Analysis) |

### 📡 COMMAND & CONTROL (T1071, T1090)
| Technique | Command / Search | D3FEND Countermeasure (DID) |
| :--- | :--- | :--- |
| **Application Layer (T1071)** | `index=network | streamstats time_window=1m count as beacon_count by src, dest | where beacon_count > 100` | **D3-HBA** (HTTP Beacon Analysis) |
| **DNS Tunneling (T1132)** | `tshark -r traffic.pcap -Y "dns.qry.name.len > 100"` | **D3-DT** (DNS Tunneling Detection) |

---

## 📈 MITRE CTI ENGINEERING (Python)
*Use these scripts with your cloned `cti` repo.*

```python
import json
import os

# Find all techniques used by a specific APT Group
def get_apt_techniques(group_name, cti_path):
    # Logic to parse STIX JSON files in cti/enterprise-attack/
    pass
```

---

## 🛡️ THE D3FEND DEFENSIVE MATRIX
*Mapping Countermeasure Tactics to Strategic Defense.*

| D3FEND Tactic | Description | Key Countermeasures (DIDs) |
| :--- | :--- | :--- |
| **Model** | Understanding the environment and assets. | **D3-AAM** (Asset Inventory), **D3-MPA** (Model Process Activity) |
| **Harden** | Reducing the attack surface. | **D3-APH** (App Path Hardening), **D3-PER** (Process Execution Restriction) |
| **Detect** | Identifying offensive behaviors. | **D3-PSA** (Process Spawn Analysis), **D3-NSM** (Network Surveillance) |
| **Isolate** | Limiting the blast radius. | **D3-HBI** (Host-based Isolation), **D3-NI** (Network Isolation) |
| **Deceive** | Misleading the attacker. | **D3-DA** (Deceptive Artifact), **D3-DP** (Decoy Process) |
| **Evict** | Removing the attacker's foothold. | **D3-ET** (Endpoint Termination), **D3-FT** (File Termination) |

---
