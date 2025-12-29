# 🛡️ THE 112-DAY MITRE-POWERED SOC ANALYST ELITE TRAINING
## **Tactical Defensive Engineering: From Tactic to Detection**

---

## 📋 BOOTCAMP ARCHITECTURE: THE MITRE SHIFT
- **Philosophy:** "Detect the behavior, not just the tool."
- **Standard:** Aligned 1:1 with the [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/).
- **Engine:** Powered by STIX/JSON data from the MITRE CTI repository.
- **Goal:** Master every Tactic from Reconnaissance to Impact.

---

## 🔧 THE SOC RANGE: LAB SETUP (DAY 0)
*Objective: Deploying the Defensive Infrastructure & MITRE Data Hub.*

**Hourly Ops:**
- **09:00 - 10:30:** Host Hardening & Hypervisor Install (VMware Player 17+ / VirtualBox 7.0).
- **10:30 - 12:30:** Windows 10/11 Deployment (Target) & Ubuntu 22.04 LTS (Security Onion / ELK).
- **13:30 - 15:00:** MITRE Repo Integration: Cloning `attack-website` and `cti` for local reference.
- **15:00 - 17:00:** Toolchain: Python 3.10+, VS Code, Git, Wireshark, and `mitreattack-python` library.

---

## 📅 MONTH 1: THE ENTRY & STEALTH PHASE
*Focus: Reconnaissance, Initial Access, Execution, Persistence.*

### **WEEK 1: INITIAL ACCESS & EXTERNAL RECON (T1595, T1566)**
*Focus: Detecting the first ripple in the water.*

#### **Day 1: Reconnaissance Detection (T1595)**
**Objective:** Detect active scanning and vulnerability research.
- **D3FEND Countermeasure:** **[D3-NSM](https://d3fend.mitre.org/technique/d3f:NetworkSurveillance)** (Network Surveillance)
- **09:00:** Analyzing Firewall & Web Server logs for Nmap/Nikto signatures.
- **11:00:** **Lab Exercise:** Launch an `nmap -sV -A` scan against your range.
- **13:30:** Detecting "User-Agent" anomalies (e.g., `Nmap Scripting Engine`).
- **15:00:** Technical Drill: Map scanning IPs to known "Good" vs "Bad" infrastructure using CTI.

#### **Day 2: Phishing & Payload Delivery (T1566)**
**Objective:** Analyze the delivery of malicious document payloads.
- **D3FEND Countermeasure:** **[D3-MSI](https://d3fend.mitre.org/technique/d3f:MessageSegmentInspection)** (Message Segment Inspection)
- **09:00:** Incident Analysis: Extracting headers from "Phishing Emails" (EML files).
- **11:00:** **Lab Exercise:** Simulate a malicious attachment download (ISO/LNK/ZIP).
- **13:30:** Tracking "Mark-of-the-Web" (MotW) bypass techniques.
- **15:00:** Triage: Identify the `src_ip` and `download_url` from Sysmon Event ID 3/15.

#### **Day 3: Execution via CMD & Scripting (T1059)**
**Objective:** Detect malicious interpreter usage (PowerShell, Bash, Python).
- **D3FEND Countermeasure:** **[D3-SFL](https://d3fend.mitre.org/technique/d3f:ScriptFileLogging)** (Script File Logging)
- **09:00:** Mastering PowerShell Script Block Logging (Event ID 4104).
- **11:00:** **Lab Exercise:** Execute an obfuscated IEX (Invoke-Expression) script.
- **13:30:** De-obfuscation: Use CyberChef to reveal the true intent of the script.
- **15:00:** Verification Drill: Hunt for "Hidden Window" and "-EncodedCommand" flags in Sysmon ID 1.

#### **Day 4: Exploit Public-Facing Applications (T1190)**
**Objective:** Detect SQLi and RCE attempts in web logs.
- **D3FEND Countermeasure:** **[D3-WAF](https://d3fend.mitre.org/technique/d3f:WebApplicationFiltering)** (Web Application Filtering)
- **09:00:** Analyzing Log4j and ProxyLogon style exploit signatures.
- **11:00:** **Lab Exercise:** Attack a local vulnerable web app (DVWA) via SQLi.
- **13:30:** Tracking "Web Shell" creation (Writing `.jsp`/`.php` to disk).
- **15:00:** Triage: Mapping the "Post-Exploitation" command to the Web Server process.

---

### **WEEK 2: PERSISTENCE & AUTOSTART (T1547, T1037)**
*Focus: Detecting the "Stay" in the network.*

#### **Day 8: Registry & Services Persistence (T1547)**
**Objective:** Detect attackers staying in the network after a reboot.
- **D3FEND Countermeasure:** **[D3-RIA](https://d3fend.mitre.org/technique/d3f:RegistryIngestionAnalysis)** (Registry Ingestion Analysis)
- **09:00:** Deep dive into `ASEPs` (Auto-Start Extension Points).
- **11:00:** **Lab Exercise:** Create a "Run Key" and a "New Service" for a reverse shell.
- **13:30:** Monitoring Registry changes with Sysmon ID 12/13.
- **15:00:** Hunt: Find unauthorized services using the `sc query` and `Get-Service` commands.

#### **Day 9: Boot or Logon Autostart (T1037)**
**Objective:** Detect persistence via Logon Scripts and Boot execute.
- **D3FEND Countermeasure:** **[D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis)** (Process Spawn Analysis)
- **09:00:** Understanding `Winlogon` and `UserInit` registry values.
- **11:00:** **Lab Exercise:** Inject a script into the `userinit.exe` sequence.
- **13:30:** Detecting abnormal "Process Parent" for shell executions.
- **15:00:** Verification Drill: Hunt for modifications in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.

---

## 📅 MONTH 2: THE FOOTHOLD & ESCALATION PHASE
*Focus: Privilege Escalation, Credential Access, Defense Evasion.*

### **WEEK 5: PRIVILEGE ESCALATION COMBAT (T1548, T1068)**
*Focus: Elevating from User to SYSTEM.*

#### **Day 29: UAC Bypass & Elevation (T1548)**
**Objective:** Detect techniques used to bypass User Account Control.
- **D3FEND Countermeasure:** **[D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis)** (Process Spawn Analysis)
- **09:00:** The architecture of UAC and "Auto-Elevate" binaries.
- **11:00:** **Lab Exercise:** Use `Fodhelper` to gain an Admin token.
- **13:30:** Detecting abnormal process integrity levels in Sysmon.
- **15:00:** Verification Drill: Hunt for registry modifications in `ms-settings`.

#### **Day 30: Kernel & Service Exploits (T1068)**
**Objective:** Detect kernel exploits and service vulnerabilities.
- **09:00:** Analyzing Event ID 4673 (Sensitive Privilege Use).
- **11:00:** **Lab Exercise:** Run a "PrintNightmare" simulation.
- **13:30:** Tracking "Service Creation" with SYSTEM accounts.
- **15:00:** Triage: Identify the "Vulnerable Binary" that was abused.

---

### **WEEK 7: CREDENTIAL ACCESS MASTERCLASS (T1003, T1555)**
*Focus: Stealing the "Keys to the Kingdom".*

#### **Day 43: LSASS Memory Dumping (T1003.001)**
**Objective:** Detect the extraction of passwords from memory.
- **D3FEND Countermeasure:** **[D3-LPA](https://d3fend.mitre.org/technique/d3f:LsassProcessAnalysis)** (Lsass Process Analysis)
- **09:00:** Understanding LSASS memory and `comsvcs.dll` dumps.
- **11:00:** **Lab Exercise:** Simulate an LSASS dump using `rundll32`.
- **13:30:** Detecting Process Access to LSASS: Sysmon ID 10.
- **15:00:** Verification Drill: Analyze "GrantedAccess" masks in your SIEM.

#### **Day 44: Stealing Browser Credentials (T1555.003)**
**Objective:** Detect theft from Chrome/Edge password managers.
- **09:00:** Analyzing file access to SQLite `Login Data` files.
- **11:00:** **Lab Exercise:** Use a Python script to extract passwords from the local profile.
- **13:30:** Detecting "Unusual Process Access" to AppData.
- **15:00:** Triage: Mapping the "Data Access" event to an signature-less execution.

---

## 📅 MONTH 3: THE MOVEMENT & COMMAND PHASE
*Focus: Internal Discovery, Lateral Movement, C2, Collection.*

### **WEEK 9: INTERNAL RECONNAISSANCE & DISCOVERY (T1087, T1082)**
*Focus: Attacker mapping the internal network.*

#### **Day 57: Account Discovery (T1087)**
**Objective:** Detect enumeration of local and domain accounts.
- **D3FEND Countermeasure:** **[D3-LAA](https://d3fend.mitre.org/technique/d3f:LocalAccountAnalysis)** (Local Account Analysis)
- **09:00:** Distinguishing between Admin `net user` calls vs Malicious Discovery.
- **11:00:** **Lab Exercise:** Use `AdFind` or `BloodHound` to map AD relationships.
- **13:30:** Detecting unauthorized LDAP queries in the Domain Controller logs.
- **15:00:** Triage: Tracking the "Source Account" used for mass enumeration.

#### **Day 58: System Information Discovery (T1082)**
**Objective:** Detect attackers gathering host metadata.
- **09:00:** Monitoring for `systeminfo`, `hostname`, and `net config` usage.
- **11:00:** **Lab Exercise:** Launch a discovery script that collects OS, CPU, and Disk info.
- **13:30:** Detecting "Process Environment" enumeration.
- **15:00:** Verification Drill: Hunt for the `whoami` command in Sysmon ID 1.

---

### **WEEK 10: LATERAL MOVEMENT COMBAT (T1021, T1570)**
*Focus: Attacker moving across the enterprise.*

#### **Day 64: Remote Services - RDP & SMB (T1021)**
**Objective:** Detect unauthorized remote access and file shares.
- **D3FEND Countermeasure:** **[D3-LAP](https://d3fend.mitre.org/technique/d3f:LogonAuthenticationAnalysis)** (Logon Authentication Analysis)
- **09:00:** Analyzing Event ID 4624 (Logon Type 3 vs 10).
- **11:00:** **Lab Exercise:** Move from System A to System B using `PsExec`.
- **13:30:** Detecting "Service Installation" with remote source paths.
- **15:00:** Triage: Mapping the "Lateral Hop" across multiple hosts in the SIEM.

#### **Day 65: Lateral Tool Transfer (T1570)**
**Objective:** Detect file transfers across the internal network.
- **D3FEND Countermeasure:** **[D3-FMA](https://d3fend.mitre.org/technique/d3f:FileModificationAnalysis)** (File Modification Analysis)
- **09:00:** Auditing SMB `IPC$` share access and administrative shares (`C$`).
- **11:00:** **Lab Exercise:** Transfer a binary from workstation to server via SMB.
- **13:30:** Detecting "Bitsadmin" and "Certutil" for internal downloads.
- **15:00:** Verification Drill: Identify the "Originating Host" of the binary.

---

### **WEEK 11: COMMAND & CONTROL (C2) INFRASTRUCTURES (T1071, T1090)**
*Focus: The umbilical cord of the attack.*

#### **Day 71: Application Layer Protocol - HTTP/DNS (T1071)**
**Objective:** Detect beaconing behavior in common protocols.
- **D3FEND Countermeasure:** **[D3-HBA](https://d3fend.mitre.org/technique/d3f:HTTPBeaconAnalysis)** (HTTP Beacon Analysis)
- **09:00:** Identifying "Fixed Interval" beacons through statistical analysis.
- **11:00:** **Lab Exercise:** Setup a `Sliver` or `Empire` C2 beacon.
- **13:30:** Analyzing "Jitter" and packet size deltas in Wireshark.
- **15:00:** Triage: Mapping reaching out to "New Domains" with high entropy.

---

## 📅 MONTH 4: THE IMPACT & INTELLIGENCE PHASE
*Focus: Exfiltration, Impact, and MITRE CTI Engineering.*

### **WEEK 13: EXFILTRATION DYNAMICS (T1048, T1041)**
*Focus: Data leaving the building.*

#### **Day 85: Exfiltration Over Alternative Protocol (T1048)**
**Objective:** Detect data leaving via DNS, ICMP, or SSH tunnels.
- **D3FEND Countermeasure:** **[D3-NSM](https://d3fend.mitre.org/technique/d3f:NetworkSurveillance)** (Network Surveillance)
- **09:00:** Understanding "Large Outbound Spikes" in flow data.
- **11:00:** **Lab Exercise:** Use `DNSCat2` to exfiltrate a 1MB file.
- **13:30:** Detecting "High Byte Count" in ICMP Echo requests.
- **15:00:** Triage: Identifying the "Destination IP" and "Data Volume".

---

### **WEEK 15: CTI ENGINEERING WITH MITRE (STIX/JSON)**
*Focus: Operationalizing the MITRE CTI Repository.*

#### **Day 99: Traversing the CTI Repo**
**Objective:** Extracting Group and Software data from the `cti` repo.
- **09:00:** Understanding STIX 2.1 JSON structure.
- **11:00:** **Lab Exercise:** Write a Python script to extract all IPs associated with **APT29** from the `cti` folder.
- **13:30:** Mapping the extracted IOCs to your SIEM lookup tables.
- **15:00:** Verification Drill: Trigger an alert based on an IOC from a real-world APT report.

#### **Day 100: Tactic Visualization (Attack Website)**
**Objective:** Building internal documentation from the `attack-website` repo.
- **09:00:** Navigating the local `attack-website` structure.
- **11:00:** **Lab Exercise:** Create a "Technique Cheat Sheet" for your SOC team.
- **13:30:** Mapping "Mitigations" to "Detection Capabilities".
- **15:00:** Final Reflection: Scoring your SOC visibility using the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

---

### **WEEK 16: THE GRAND CAPSTONE - FULL CHAIN APT EMULATION**
*Focus: The Ultimate Test of a Job-Ready SOC Analyst.*

#### **Day 106-112: Scenario: "The Lazarus Shadow"**
- Complete 7-day emulation of a full APT kill-chain.
- Must Detect: Phish -> Persistence -> PrivEsc -> Lateral Movement -> Exfil.
- **D3FEND Challenge:** Map every detection to a D3FEND countermeasure.
- Final Deliverable: **"The MITRE Master Portfolio"**.

---

## 📅 PHASE 6: MITRE D3FEND ENGINEERING REGIME (Days 141-160)
*Focus: Architecting the Defensive Countermeasure Matrix.*

### **WEEK 21: ONTOLOGY & SEMANTIC MAPPING**
*Focus: Understanding why a defense works.*

#### **Day 141: The D3FEND Knowledge Graph**
**Objective:** Navigate the D3FEND ontology using SPARQL and Python.
- **09:00:** Deep dive into `d3fend-protege.ttl`. Understanding Classes vs Restrictions.
- **11:00:** **Lab Exercise:** Run a SPARQL query to find all countermeasures for "Process Execution".
- **13:30:** Semantic Linkage: How `D3-PSA` links to `T1053` via the `executes` property.
- **15:00:** Engineering Drill: Build a local JSON map of DIDs to TIDs.

#### **Day 142: Artifact Correlation Engineering**
**Objective:** Map offensive artifacts to defensive functions.
- **09:00:** Analyzing Digital Artifacts: File, Process, Hive, Network.
- **11:00:** **Lab Exercise:** Correlate "Sysmon ID 1" fields to D3FEND `ProcessSpawnAnalysis` attributes.
- **13:30:** Identifying Gaps: Which ATT&CK techniques in your lab have NO D3FEND countermeasure?
- **15:00:** Reporting: Create a "Defensive Coverage Gap Analysis" for your range.

### **WEEK 22: DECEPTIVE ENGINEERING & TACTICAL LABS**
*Focus: Advanced Countermeasures and Deception.*

#### **Day 148: Deceptive Artifact Deployment (D3-DA)**
**Objective:** Engineer "Canary" tokens and Honeypots.
- **09:00:** Architecture of Decoy Files and Honey-Users.
- **11:00:** **Lab Exercise:** Create a "Honey-Registry-Key" that alerts when accessed (Sysmon ID 13).
- **13:30:** Honey-Credentials: Injecting "Fake" tokens into LSASS for retrieval detection.
- **15:00:** Triage: Designing a "P0" High-Fidelity alert for Deceptive Artifact access.

#### **Day 149: Hardening & Isolation Strategies**
**Objective:** Operationalizing D3FEND "Harden" and "Isolate" tactics.
- **09:00:** Application Path Hardening (**D3-APH**) and Boot Integrity (**D3-BI**).
- **11:00:** **Lab Exercise:** Configure "Process Execution Restrictions" using AppLocker (D3-PER).
- **13:30:** Host-Based Isolation: Implementing micro-segmentation for high-risk workstations.
- **15:00:** Final Reflection: Scaling D3FEND across an Enterprise SOC.

---
