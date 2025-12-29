# 🛡️ THE ULTIMATE 112-DAY SOC ANALYST ELITE TRAINING REGIME
*Version 3.5 - The Definitive Industry Aligned Edition*
*Consolidated Master Reference & Lab Manual*

---

## 📋 EXECUTIVE SUMMARY
This document outlines the most intensive SOC training program in the industry. It transitions a candidate from zero knowledge to a Tier-3 SOC Professional over 112 days (16 weeks). The curriculum is built on the philosophy of **"Tactical Defensive Engineering"**, where students do not just watch dashboards, but build the logic, hunt the threats, and engineer the countermeasures.

### **Core Frameworks:**
1. **MITRE ATT&CK®:** Understanding the adversary's playbook.
2. **MITRE D3FEND™:** Architecting the defensive countermeasure matrix.
3. **NIST SP 800-61:** Standardized Incident Handling.
4. **SANS PICERL:** The industry-standard IR lifecycle.

---

## 🔧 THE SOC RANGE: LAB ARCHITECTURE
Before Day 1, the following environment must be deployed:

### **1. The Victim Infrastructure (Windows)**
- **OS:** Windows 10/11 Pro (Evaluation)
- **Telemetry:** Sysmon 15.0+ (SwiftOnSecurity Config), Advanced Audit Policies.
- **Vulnerabilities:** DVWA (Web), Legacy Services for PrivEsc labs.

### **2. The Security Stack (Ubuntu 22.04 LTS)**
- **SIEM:** Splunk Free / Elastic Stack (ELK 8.x)
- **EDR:** Wazuh Manager & Velociraptor Server.
- **NDR:** Zeek, Suricata, and RITA.
- **Traffic:** Wireshark & Tcpdump for raw packet analysis.

### **3. The Developer Toolchain**
- **Language:** Python 3.10+, PowerShell 7.x.
- **Tools:** VS Code, Git, CyberChef, Mimikatz (Lab only), BloodHound.

---

## 📅 MONTH 1: PRACTICAL LOG MASTERY & FORENSICS (Days 1-28)
*Objective: Mastering the Source of Truth - Telemetry.*

### **WEEK 1: THE WINDOWS DEFENSIVE FRONT**
*Focus: Mastering Windows Telemetry through attack-defense cycles.*

#### **Day 1: Telemetry Sensor Deployment (T1595/T1059)**
**Objective:** Configure high-fidelity logging on the Windows target.
- **D3FEND Countermeasure:** **[D3-BI](https://d3fend.mitre.org/technique/d3f:BootIntegrity)** (Boot Integrity)
- **Hourly Ops:**
  - **09:00 - 10:30:** Host Hardening: Disable unnecessary services (LLMNR, NetBIOS) to reduce noise.
  - **10:30 - 12:30:** Deploying Windows 10/11 Evaluation.
  - **13:30 - 15:00:** Configuring Advanced Audit Policies (`secpol.msc`).
  - **15:00 - 17:00:** Deploying [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config).
- **Practical Drill:** Run `sysmon.exe -i config.xml`. Verify Event ID 1 (Process Create) in Event Viewer.

#### **Day 2: The Brute Force Challenge (T1110)**
**Objective:** Identify, distinguish, and document authentication attacks.
- **D3FEND Countermeasure:** **[D3-LAP](https://d3fend.mitre.org/technique/d3f:LogonAuthenticationAnalysis)** (Logon Authentication Analysis)
- **Hourly Ops:**
  - **09:00:** Study Event ID 4624 (Success) vs 4625 (Failure).
  - **11:00:** **Lab Exercise:** Use `hydra` on Kali to brute-force a local Windows user via SMB.
  - **13:30:** Analyze Logon Types (Type 2: Local, Type 3: Network, Type 10: RDP).
  - **15:00:** Triage: Identify the "Attacker Hostname" and "Source IP" from the logs.

#### **Day 3: Privilege Escalation Lab (T1548/T1068)**
**Objective:** Detect unauthorized account creation and privilege assignment.
- **D3FEND Countermeasure:** **[D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis)** (Process Spawn Analysis)
- **Hourly Ops:**
  - **09:00:** Monitor ID 4720 (User Created) and 4732 (Group Assigned).
  - **11:00:** **Lab Exercise:** Create a "hidden" user via CMD and add to Administrators.
  - **13:30:** Hunt for Event ID 4672 (Special Privileges Assigned).
  - **15:00:** Identify the `SeDebugPrivilege` assignment.

#### **Day 4: Living Off The Land (LOLBAS) Hunt (T1218)**
**Objective:** Detect suspicious tool usage (`certutil`, `bitsadmin`, `powershell -enc`).
- **D3FEND Countermeasure:** **[D3-SFL](https://d3fend.mitre.org/technique/d3f:ScriptFileLogging)** (Script File Logging)
- **Hourly Ops:**
  - **09:00:** Introduction to [LOLBAS Project](https://lolbas-project.github.io/).
  - **11:00:** **Lab Exercise:** Execute a base64 encoded PowerShell script.
  - **13:30:** Use Sysmon ID 1 to find the decoded command line.
  - **15:00:** Hunt for `certutil -urlcache -f` network connection logs (Sysmon ID 3).

---

### **WEEK 2: THE LINUX PERSISTENCE CHALLENGE**
#### **Day 8: Auditd & The Rules of Strategic Monitoring (T1053)**
**Objective:** Establish granular file and process monitoring on Linux.
- **D3FEND Countermeasure:** **[D3-MPA](https://d3fend.mitre.org/technique/d3f:ModelProcessActivity)** (Model Process Activity)
- **Hourly Ops:**
  - **09:00:** Overview of the Linux Audit Framework (`auditd`).
  - **11:00:** **Lab Exercise:** Configure rules to monitor `/etc/shadow` and `/etc/passwd`.
  - **13:30:** Real-time Log Streaming: Use `tail -f /var/log/auth.log`.
  - **15:00:** Design a rule to detect "Execution of suspicious shells" (e.g., `nc`, `nmap`).

#### **Day 10: The Sudo Ninja Lab (T1548.003)**
**Objective:** Detect privilege escalation via GTFOBins.
- **Lab:** `sudo find . -exec /bin/sh \; -quit`.
- **Detection:** Analyze `auth.log` for the elevation token and the subsequent command execution as root.

---

## 📅 MONTH 2: PRACTICAL SIEM OPERATIONS & ALERT ENGINEERING (Days 29-56)
*Objective: Mastering the Central Nervous System of the SOC.*

### **WEEK 5: THE SPLUNK POWER USER MASTERCLASS**
*Focus: Mastering SPL (Search Processing Language) & Visualization.*

#### **Day 29: Splunk Ingestion & Architecture (T1059)**
**Objective:** Understand the data pipeline from Source to Index.
- **D3FEND:** **[D3-AAM]** (Asset Inventory)
- **Tasks:** Install Splunk Distributed environment. Configure the UF on Windows to send logs via port 9997.

#### **Day 30: SPL Mastery I - Transformation Commands**
**Objective:** Building analytical results from raw data.
- **Commands:** `stats`, `chart`, `timechart`, `top`, `rare`.
- **Lab:** Calculate the "Peak Login Hour" and "Top 5 Attacked Users".
- **SPL:** `index=windows EventCode=4625 | bin _time span=1h | stats count by _time | sort - count`

---

## 📅 MONTH 3: INCIDENT RESPONSE & THREAT HUNTING (Days 57-84)
*Objective: Proactive Defense & Decisive Response.*

### **WEEK 9: INCIDENT RESPONSE DYNAMICS (PICERL)**
#### **Day 57: Applying Frameworks to Technical Incidents**
- **SANS PICERL:** Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.
- **Lab:** Identification - Scope a breach using "Pivot Analysis".
- **SPL:** `index=endpoint [search index=endpoint hash="BAD_HASH" | fields hostname] | stats count by dest_ip`

---

## 📅 MONTH 4: CLOUD, AUTOMATION & CTI (Days 85-112)
*Focus: Scaling Security with Software.*

### **WEEK 13: CLOUD SECURITY OPERATIONS (AWS/AZURE)**
#### **Day 85: AWS S3 Security & Exfiltration**
- **Objective:** Detect public access and data theft in cloud storage.
- **D3FEND:** **[D3-AAM]** (Asset Inventory)
- **Hourly Ops:**
  - **09:00:** AWS CloudTrail log structure.
  - **11:00:** **Lab:** Simulate an S3 bucket leakage via configuration mistake.
  - **13:30:** Detect `PutBucketPublicAccessBlock` deletion in logs.

---

## 📅 PHASE 6: MITRE D3FEND ENGINEERING REGIME (Days 141-160)
*Focus: Architecting the Defensive Countermeasure Matrix.*

### **WEEK 21: ONTOLOGY & SEMANTIC MAPPING**
#### **Day 141: The D3FEND Knowledge Graph**
- **Objective:** Navigate the D3FEND ontology using SPARQL and Python.
- **Lab:** Querying `d3fend-protege.ttl` for all countermeasures related to "Process Execution".

---

## 📖 THE ANALYST'S BIBLE: COMPLETE COMMAND MASTER REFERENCE

### **1. WINDOWS EXECUTION & TRIAGE**
| Task | Command |
| :--- | :--- |
| **List Processes with Owners** | `Get-WmiObject -Query "Select * from Win32_Process" | Select-Object Name, ProcessId, @{Name="Owner";Expression={$_.GetOwner().User}}` |
| **Check Network Connections** | `netstat -ano | findstr LISTENING` |
| **Parse Prefetch Files** | `.\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Triage\Prefetch"` |
| **Extract Chrome History** | `copy "C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History" C:\Triage\` |
| **Search Event Logs (PS)** | `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50` |
| **Sysmon Installation** | `.\Sysmon64.exe -i .\sysmon_config.xml -accepteula` |

### **2. LINUX HARDENING & INVESTIGATION**
| Task | Command |
| :--- | :--- |
| **Check Active Connections** | `ss -atpu` |
| **Monitor Audit Logs** | `ausearch -m USER_LOGIN -sv no` |
| **List Listening Ports** | `lsof -i -P -n | grep LISTEN` |
| **Check Cron Persistence** | `ls -la /etc/cron.* /var/spool/cron/crontabs/` |
| **Find SUID Binaries** | `find / -perm -4000 -type f 2>/dev/null` |
| **Verify File Integrity** | `sha256sum /usr/bin/ssh` |

### **3. NETWORK TRAFFIC ANALYSIS**
| Task | Command |
| :--- | :--- |
| **Capture Traffic (tcpdump)** | `tcpdump -i eth0 -w traffic.pcap` |
| **Extract Files from PCAP** | `tshark -r traffic.pcap --export-objects http,./files` |
| **Search for Cleartext Passwords** | `tshark -r traffic.pcap -Y "http.request.method == POST" -T fields -e http.file_data` |

---

## 🧪 FULL LAB MANUAL: 112+ TACTICAL DRILLS

### **LAB 1: THE WINDOWS TELEMETRY SENSORY GRID**
1. **Objective:** Deploy a hardened sensor grid.
2. **Steps:**
   - Install Sysmon.
   - Configure Event Log rotation to 512MB.
   - Deploy "SwiftOnSecurity" XML.
3. **Verification:** Generate a 'calc.exe' launch and confirm it appears in Sysmon ID 1.

### **LAB 16: DNS TUNNELING DISCOVERY**
1. **Objective:** Detect data leaving the corp network via Port 53.
2. **Steps:**
   - Launch `dnscat2` on the victim.
   - Capture traffic on the bridge.
   - Use `tshark` to analyze the frequency of `TXT` records.
3. **Detection Rule:** `if count(dns_qry_name > 100) > 20 in 1min: TRIGGER ALERT`.

---

## 🛡️ D3FEND DEFENSIVE MATRIX

| D3FEND Tactic | Description | Key Countermeasures (DIDs) |
| :--- | :--- | :--- |
| **Model** | Understanding the environment and assets. | **D3-AAM** (Asset Inventory), **D3-MPA** (Model Process Activity) |
| **Harden** | Reducing the attack surface. | **D3-APH** (App Path Hardening), **D3-PER** (Process Execution Restriction) |
| **Detect** | Identifying offensive behaviors. | **D3-PSA** (Process Spawn Analysis), **D3-NSM** (Network Surveillance) |
| **Isolate** | Limiting the blast radius. | **D3-HBI** (Host-based Isolation), **D3-NI** (Network Isolation) |
| **Deceive** | Misleading the attacker. | **D3-DA** (Deceptive Artifact), **D3-DP** (Decoy Process) |
| **Evict** | Removing the attacker's foothold. | **D3-ET** (Endpoint Termination), **D3-FT** (File Termination) |

---

## 📜 GRADUATION: THE GRAND CAPSTONE
**Day 106-112: Scenario: "The Lazarus Shadow"**
- A full 7-day emulation of an APT kill-chain.
- Must Detect: Phish -> Persistence -> PrivEsc -> Lateral Movement -> Exfil.
- **Success Criteria:** Zero false negatives on critical tactic transitions.
- **Deliverable:** **"The MITRE Master Portfolio"** (PDF technical showcase).

---
*End of Document - (c) 2025 SOC Elite Training*
