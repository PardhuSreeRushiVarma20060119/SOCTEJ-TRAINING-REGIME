# 🛡️ THE 112-DAY ULTIMATE PRACTICAL SOC ANALYST BOOTCAMP
## **Mission-Ready Training: From Zero to SOC Operator**

---

## 📋 BOOTCAMP ARCHITECTURE
- **Philosophy:** "Break to learn, analyze to master."
- **Structure:** 16 Weeks, 112 Days.
- **Delivery:** Practical Labs + Hourly Ops + Tactical Playbooks.
- **Resources:** 500+ Verified Links & Field Manuals.

---

## 🔧 THE SOC RANGE: LAB SETUP (DAY 0)

### **Objective: Deploying the Defensive Infrastructure**
**Hourly Ops:**
- **09:00 - 10:30:** Host Hardening & Hypervisor Install (VMware Player 17+ / VirtualBox 7.0).
- **10:30 - 12:30:** Windows 10/11 Deployment (Target) & Ubuntu 22.04 LTS (Collection Server).
- **13:30 - 15:00:** Internal Network Isolation: Set VMs to "Host-Only" or "NAT".
- **15:00 - 16:00:** Toolchain Install: Python 3.10+, VS Code, Git, and Wireshark.

**Operator Command (Ubuntu):**
```bash
sudo apt update && sudo apt install git python3-pip wireshark tcpdump -y
```

**Field Manuals:**
1. [VMware Player Setup Guide](https://docs.vmware.com/en/VMware-Workstation-Player-for-Windows/index.html)
2. [Windows 11 Security Baseline](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
3. [VirtualBox Networking Deep Dive](https://www.virtualbox.org/manual/ch06.html)

---

## 📅 MONTH 1: PRACTICAL LOG MASTERY (Days 1-28)

### **WEEK 1: THE WINDOWS BREACH SCENARIO**
*Focus: Mastering Windows Telemetry through attack-defense cycles.*

#### **Day 1: Telemetry Sensor Deployment**
**Objective:** Configure high-fidelity logging on the Windows target.
**Hourly Ops:**
- **09:00:** Configure Advanced Audit Policies (`secpol.msc`). Focus: Process, Account, Object.
- **11:00:** Deploy [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config).
- **13:30:** Enable PowerShell Script Block Logging (Event ID 4104).
- **15:00:** Verification Drill: Check `Event Viewer` for ID 4688 and Sysmon ID 1.

**Tactical Playbook:**
1. Open PowerShell as Admin and run: `sysmon64.exe -i sysmonconfig-export.xml -accepteula`.
2. GPO Path: `Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`.

**Deliverables:**
- [ ] Screenshot: Event ID 4688 with "Command Line" enabled.
- [ ] Screenshot: Sysmon Operational log populated.

---

#### **Day 2: The Brute Force Challenge**
**Objective:** Identify, distinguish, and document authentication attacks.
**Hourly Ops:**
- **09:00:** Study Event ID 4624 (Success) vs 4625 (Failure).
- **11:00:** **Lab Exercise:** Use a Bash script on Ubuntu or Hydra on Kali to brute-force a local Windows user.
- **13:30:** Analyze Logon Types (Type 2: Local, Type 3: Network, Type 10: RDP).
- **15:00:** Triage: Identify the "Attacker Hostname" and "Source IP" from the logs.

**Operator Command (Kali/Ubuntu):**
```bash
hydra -l operator -p P@ssword123 smb://[Target_IP]
```

**Ref Links:**
1. [Ultimate Windows Security - 4625](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625)
2. [Microsoft: Monitoring for Brute Force](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)

---

#### **Day 3: Privilege Escalation Lab**
**Objective:** Detect unauthorized account creation and privilege assignment.
**Hourly Ops:**
- **09:00:** Monitor ID 4720 (User Created) and 4732 (Group Assigned).
- **11:00:** **Lab Exercise:** Create a "hidden" user via CMD and add to Administrators.
- **13:30:** Hunt for Event ID 4672 (Special Privileges Assigned).
- **15:00:** Identify the `SeDebugPrivilege` assignment.

**Operator Command (Windows CMD):**
```cmd
net user support $Password123 /add
net localgroup administrators support /add
```

**Ref Links:**
1. [SANS: Windows Logging for Security](https://www.sans.org/posters/windows-logging-and-it-compliance-cheat-sheet/)
2. [SpecterOps: Detecting PrivEsc](https://posts.specterops.io/host-based-detection-of-privilege-escalation-eb79498d5c4b)

---

#### **Day 4: Living Off The Land (LOLBAS) Hunt**
**Objective:** Detect suspicious tool usage (`certutil`, `bitsadmin`, `powershell -enc`).
**Hourly Ops:**
- **09:00:** Introduction to [LOLBAS Project](https://lolbas-project.github.io/).
- **11:00:** **Lab Exercise:** Execute a base64 encoded PowerShell script.
- **13:30:** Use Sysmon ID 1 to find the decoded command line.
- **15:00:** Hunt for `certutil -urlcache -f` network connection logs (Sysmon ID 3).

**Operator Command:**
```powershell
powershell.exe -EncodedCommand BASE64_STRING_HERE
```

**Deliverables:**
- [ ] Decoded PowerShell command captured in Sysmon logs.

---

#### **Day 5: Anti-Forensics & Log Tampering**
**Objective:** Detect log clearing and service interference.
**Hourly Ops:**
- **09:00:** Study Event ID 1102 (The Log was Cleared).
- **11:00:** **Lab Exercise:** Use `wevtutil` to wipe the Security, System, and Sysmon logs.
- **13:30:** Identify the user/process that executed the log clear.
- **15:00:** Define a detection rule hypothesis for "Rapid Log Clearing".

**Ref Links:**
1. [MITRE ATT&CK: Indicator Removal (T1070)](https://attack.mitre.org/techniques/T1070/)
2. [Elastic: Detecting Windows Log Clearing](https://www.elastic.co/blog/detecting-windows-log-clearing-with-suricata)

---

#### **Day 6: The Full Kill-Chain Simulation**
**Objective:** Reconstruct a multi-stage attack from raw logs.
**Scenario:**
1. Brute force entry (ID 4625 -> 4624).
2. Persistence creation (Hidden User/Net User).
3. Privilege Escalation (Net Localgroup).
4. Malicious Download (Certutil/Sysmon 3).
5. Evidence Removal (Wevtutil).

**Task:** Create a minute-by-minute Attack Timeline.

---

#### **Day 7: WEEK 1 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Echo Case File"**
- A technical IR report including screenshots of every Event ID triggered in Day 6.
- Analysis of the "Attacker IP" and "Malicious URLs" found.

---

### **WEEK 2: THE LINUX PERSISTENCE CHALLENGE**
*Focus: Tactical Operating System Auditing & Forensic Awareness.*

#### **Day 8: Auditd & The Rules of Engagement**
**Objective:** Establish granular file and process monitoring on Linux.
**Hourly Ops:**
- **09:00:** Overview of the Linux Audit Framework (`auditd`).
- **11:00:** **Lab Exercise:** Configure rules to monitor `/etc/shadow`, `/etc/passwd`, and `/etc/sudoers`.
- **13:30:** Real-time Log Streaming: Use `tail -f /var/log/auth.log` and `ausearch`.
- **15:00:** Design a rule to detect "Execution of suspicious shells" (e.g., `nc`, `nmap`).

**Operator Command (Ubuntu):**
```bash
# Add rule to watch sudoers
echo "-w /etc/sudoers -p wa -k sudoers_mod" | sudo tee -a /etc/audit/rules.d/audit.rules
sudo systemctl restart auditd
# Search for events
sudo ausearch -k sudoers_mod
```

**Ref Links:**
1. [DigitalOcean: Linux Auditd Implementation](https://www.digitalocean.com/community/tutorials/how-to-write-custom-system-audit-rules-on-centos-7)
2. [RedHat: Configuring System Auditing](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/configuring-and-managing-networking-auditing_security-hardening)

---

#### **Day 9: SSH Behavioral Analysis**
**Objective:** Detect and analyze high-volume authentication failures.
**Hourly Ops:**
- **09:00:** Deep dive into `auth.log` format. Identify "Failed password" vs "Accepted password".
- **11:00:** **Lab Exercise:** Launch a parallel SSH brute force from Kali using Hydra.
- **13:30:** Scripting for SOC: Write a Python script to extract unique IPs from `auth.log`.
- **15:00:** Analysis: Distinguish between "Normal User Mistake" vs "Attack Pattern".

**Operator Command (Python Snippet):**
```python
import re
with open("/var/log/auth.log", "r") as f:
    for line in f:
        if "Failed password" in line:
            print(re.findall(r"\d+\.\d+\.\d+\.\d+", line))
```

**Deliverables:**
- [ ] CSV list of Top 10 Attacking IPs from the lab.

---

#### **Day 10: The Sudo Ninja Lab**
**Objective:** Detect privilege escalation through binary abuse.
**Hourly Ops:**
- **09:00:** Understanding `sudo` logging and `visudo` auditing.
- **11:00:** **Lab Exercise:** Execute a command from [GTFOBins](https://gtfobins.github.io/) (e.g., `sudo find . -exec /bin/sh \; -quit`).
- **13:30:** Identifying the "Audit ID" in `auth.log` to track the user pivot.
- **15:00:** Hunt for `sudoers` file tampering via Auditd.

**Field Manual:**
1. [GTFOBins: Sudo Category](https://gtfobins.github.io/#+sudo)
2. [Sudo Security Documentation](https://www.sudo.ws/docs/security/)

---

#### **Day 11: Hunting Persistence (Cron & Systemd)**
**Objective:** Detect backdoors in system scheduling and services.
**Hourly Ops:**
- **09:00:** Auditing user crontabs (`/var/spool/cron/crontabs`).
- **11:00:** **Lab Exercise:** Create a malicious Systemd service that spawns a reverse shell.
- **13:30:** Detect the service creation in `syslog` and `journalctl`.
- **15:00:** Hunting for "Hidden" cron files in `/etc/cron.d/`.

**Operator Command:**
```bash
# Check startup services
systemctl list-unit-files --state=enabled
# Check all crontabs
for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user; done
```

**Ref Links:**
1. [Elastic: Linux Persistence Mechanisms](https://www.elastic.co/blog/linux-persistence-mechanisms)
2. [MITRE ATT&CK: Cron (T1053.003)](https://attack.mitre.org/techniques/T1053/003/)

---

#### **Day 12: Binary Log Forensics (last/wtmp)**
**Objective:** Analyze binary system logs for session metadata.
**Hourly Ops:**
- **09:00:** Understanding `wtmp` (logins) and `btmp` (failures).
- **11:00:** **Lab Exercise:** Use `utmpdump` to convert binary logs to readable format.
- **13:30:** Map a specific "Time of Entry" to a "Time of Persistence Creation".
- **15:00:** Documenting the "Terminal (pts)" associated with suspicious root activity.

---

#### **Day 13: THE LINUX "DARK-ROOT" SIMULATION**
**Objective:** Perform a forensic reconstruction of a complex Linux breach.
**Scenario:**
1. Brute pulse entry.
2. Sudo pivot using `vim` or `find`.
3. Persistence via Systemd.
4. Bash history tampering (Log cleaning).

**Task:** Complete the "Indicator of Compromise (IOC)" table for the breach.

---

#### **Day 14: WEEK 2 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Citadel Case Report"**
- A 5-page report documenting the "Dark-Root" scenario.
- Must include the `auditctl` rules used to detect the breach.
- Root Cause Analysis (RCA) and Mitigation steps.

---

### **WEEK 3: NETWORK INTRUSION DISCOVERY**
*Focus: Traffic Forensics & Real-Time Protocol Analysis.*

#### **Day 15: Deep Packet Capture & Flow Analysis**
**Objective:** Master `tcpdump` for efficient head-less packet capture.
**Hourly Ops:**
- **09:00:** Difference between Capture Filters (`-f`) and Display Filters.
- **11:00:** **Lab Exercise:** Capture traffic on the target network while simulating a large file transfer.
- **13:30:** Analyzing Protocol Hierarchy in Wireshark. Identify "High Entropy" flows.
- **15:00:** Verification Drill: Extract "Cleartext Password" from a Telnet/FTP pcap.

**Operator Command:**
```bash
# Capture only HTTP traffic
sudo tcpdump -i eth0 port 80 -w http_traffic.pcap
# Extract flow details
tshark -r traffic.pcap -q -z conv,ip
```

**Ref Links:**
1. [Wireshark: Analysis of Common Protocols](https://www.wireshark.org/docs/wsug_html_chunked/ChAnalyseMenuSection.html)
2. [SANS: TCPDUMP Cheat Sheet](https://www.sans.org/posters/tcpdump-cheat-sheet/)

---

#### **Day 16: The DNS Tunneling Lab**
**Objective:** Detect data exfiltration over the Domain Name System.
**Hourly Ops:**
- **09:00:** Understanding "Large TXT Records" and "Domain Entropy".
- **11:00:** **Lab Exercise:** Use `dnscat2` or `iodine` to create a DNS tunnel.
- **13:30:** Analyze PCAPs for NXDOMAIN spikes and "Long Subdomains".
- **15:00:** Triage: Identify the "Tunneling Subdomain" used by the attacker.

**Ref Links:**
1. [Active Countermeasures: Hunting DNS Tunneling](https://www.activecountermeasures.com/blog/dns-analysis/)
2. [Cisco: DNS Security Best Practices](https://www.cisco.com/c/en/us/about/security-center/dns-best-practices.html)

---

#### **Day 17: Web Attack Signature Lab**
**Objective:** Detect SQLi and XSS in raw HTTP traffic.
**Hourly Ops:**
- **09:00:** Analyzing HTTP GET/POST parameters for attack strings.
- **11:00:** **Lab Exercise:** Attack a local "Juice Shop" or "DVWA" instance.
- **13:30:** Identifying "User-Agent" anomalies (e.g., `sqlmap`, `nmap`, `dirb`).
- **15:00:** Mapping 404/403 status codes to a "Directory Brute Force" attack.

**Operator Command (Identifying sqlmap):**
```bash
tshark -r traffic.pcap -Y "http.user_agent contains 'sqlmap'"
```

---

#### **Day 18: Zeek (Bro) Forensic Lab**
**Objective:** Convert bulk PCAPs into high-level metadata logs.
**Hourly Ops:**
- **09:00:** Installing and processing traffic with Zeek.
- **11:00:** **Lab Exercise:** Identify the "Top 5 Talkers" using `conn.log`.
- **13:30:** Analyzing `dns.log` for anomalous query frequencies.
- **15:00:** Lab: Track a single file download through `http.log` and `files.log`.

**Ref Links:**
1. [Zeek: Getting Started Guide](https://docs.zeek.org/en/master/getting-started.html)
2. [Corelight: Zeek Training Resources](https://www.corelight.com/resources/zeek-training)

---

#### **Day 19: Suricata Rule Combat**
**Objective:** Write and tune IDS signatures for specific threats.
**Hourly Ops:**
- **09:00:** Understanding Suricata Header and Options syntax.
- **11:00:** **Lab Exercise:** Write a rule to detect a specific C2 User-Agent.
- **13:30:** Testing the rule against a PCAP using `suricata -r`.
- **15:00:** Tuning: Decrease "False Positive" noise from a vulnerability scanner.

**Operator Command (Custom Rule):**
```bash
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ALRT: Malicious UA Detected"; content:"EvilBot/1.0"; http_user_agent; sid:1000001; rev:1;)
```

---

#### **Day 20: Hunting C2 Beacons (RITA)**
**Objective:** Use statistical analysis to find interval-based traffic.
**Hourly Ops:**
- **09:00:** Intro to "Beaconing" and "Jitter".
- **11:00:** **Lab Exercise:** Run RITA against the Month 1 Week 3 traffic logs.
- **13:30:** Analyzing the "Score" based on frequency and size delta.
- **15:00:** Visualizing beacons using the RITA HTML report.

---

#### **Day 21: WEEK 3 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Signal-to-Noise Portfolio"**
- A report documenting the discovery of a DNS Tunnel and a C2 beacon.
- Must include the `Zeek` log snippets as evidence.

---

### **WEEK 4: EDR & LIVE RESPONSE**
*Focus: Real-Time Endpoint Monitoring & Threat Remediation.*

#### **Day 22: Wazuh Manager & Fleet Management**
**Objective:** Deploy a centralized detection engine and manage endpoints.
**Hourly Ops:**
- **09:00:** Wazuh Architecture: Manager, Indexer, and Dashboard.
- **11:00:** **Lab Exercise:** Install the Wazuh Manager on the SIEM server VM.
- **13:30:** Fleet Deployment: Deploy agents to your Windows and Linux VMs.
- **15:00:** Verification Drill: Confirm agents are "Active" in the Wazuh UI.

**Operator Command (Agent Install - Windows):**
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi -OutFile wazuh-agent.msi; msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='[MANAGER_IP]'
```

**Ref Links:**
1. [Wazuh Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html)
2. [Wazuh: Managing Agents](https://documentation.wazuh.com/current/user-manual/agents/index.html)

---

#### **Day 23: Wazuh Rule Tuning & Alerting**
**Objective:** Customizing detection logic for your environment.
**Hourly Ops:**
- **09:00:** Understanding Decoders and Rules (`/var/ossec/etc/rules`).
- **11:00:** **Lab Exercise:** Write a rule to alert when a new user is added to the "Remote Desktop Users" group.
- **13:30:** Implementing Alert Throttling and Email/Slack notifications.
- **15:00:** Triage: Investigating a "High Severity" alert in the Wazuh Dashboard.

**Operator Command (Custom Rule Snippet):**
```xml
<rule id="100001" level="5">
  <if_sid>60118</if_sid>
  <field name="win.system.eventID">^4732$</field>
  <description>New Member Added to Sensitive Group</description>
</rule>
```

---

#### **Day 24: Velociraptor Hunting Lab**
**Objective:** Perform live, host-based forensics at scale.
**Hourly Ops:**
- **09:00:** Deploying the Velociraptor Server and Client.
- **11:00:** **Lab Exercise:** Run the `Windows.System.Pslist` artifact to find hidden processes.
- **13:30:** Forensic Hunt: Identify all systems containing a specific malicious file hash.
- **15:00:** Verification Drill: Use VQL (Velociraptor Query Language) to find persistence in the Registry.

**Field Manual:**
1. [Velociraptor: VQL Reference](https://docs.velociraptor.app/vql/reference/)
2. [Velociraptor Artifact Exchange](https://docs.velociraptor.app/exchange/)

---

#### **Day 25: Hunting Fileless Malware (EDR)**
**Objective:** Detect PowerShell script execution and memory-only threats.
**Hourly Ops:**
- **09:00:** Tracking PowerShell parent-child relationships in Wazuh.
- **11:00:** **Lab Exercise:** Simulate a Beacon or Reverse Shell using "PowerShell IEX".
- **13:30:** Searching for "EncodedCommand" in the EDR telemetry.
- **15:00:** Lab: Hunt for Living off the Land (LOLBAS) execution via Velociraptor.

---

#### **Day 26: File Integrity Monitoring (FIM) Practice**
**Objective:** Track unauthorized changes to critical system files.
**Hourly Ops:**
- **09:00:** Configuring Wazuh Syscheck for `/etc/` and `C:\Windows\System32`.
- **11:00:** **Lab Exercise:** Modify a sensitive config file and analyze the "Who-What-When" log.
- **13:30:** Tuning FIM to ignore authorized system updates (Noise reduction).
- **15:00:** Audit: Reviewing the FIM summary for the past 24 hours.

---

#### **Day 27: Remediation & Host Isolation**
**Objective:** Neutralize threats through tactical host isolation.
**Hourly Ops:**
- **09:00:** Intro to "Active Response" in Wazuh.
- **11:00:** **Lab Exercise:** Configure an automatic "IP Block" when an SSH brute force is detected.
- **13:30:** Manual Isolation: Isolating a compromised Windows host from the network via EDR.
- **15:00:** Verification Drill: Confirming no traffic reaches the isolated host except to the SIEM.

**Operator Command (Wazuh Active Response):**
```bash
# Script location on agent
/var/ossec/active-response/bin/host-deny.sh
```

---

#### **Day 28: MONTH 1 FINAL PRACTICAL ASSESSMENT**
**Deliverable:** **"The Unified Defense Strategy"**
- A comprehensive document outlining how you integrated Windows/Linux logs, Network traffic (Zeek/Suricata), and EDR (Wazuh) into a single SOC visibility strategy.
- Must include a flowchart of an alert's lifecycle from detection to remediation.

---

## 📅 MONTH 2: PRACTICAL SIEM OPS (Days 29-56)

### **WEEK 5: SPLUNK POWER SEARCH & DASHBOARDS**
*Focus: Mastering SPL (Search Processing Language) & Visualization.*

#### **Day 29: Splunk Ingestion & Architecture Lab**
**Objective:** Understand the data pipeline from Source to Index.
**Hourly Ops:**
- **09:00:** Splunk Architecture: UFs, Indexers, and Search Heads.
- **11:00:** **Lab Exercise:** Install Splunk Free on the SIEM Server VM.
- **13:30:** Data Onboarding: Config an "Upload" for the Windows/Linux logs collected in Month 1.
- **15:00:** Basic Search: Using `index=*`, `sourcetype`, and `host`.

**Ref Links:**
1. [Splunk: Getting Data In (GDI)](https://docs.splunk.com/Documentation/Splunk/latest/Data/WhatSplunkcanmonitor)
2. [Splunk Free Infrastructure Guide](https://www.splunk.com/en_us/resources/splunk-architecture.html)

---

#### **Day 30: SPL Mastery I - Transformation Commands**
**Objective:** Building analytical results from raw data.
**Hourly Ops:**
- **09:00:** Mastering `stats`: `count`, `distinct_count (dc)`, `values`, `list`.
- **11:00:** **Lab Exercise:** Calculate the "Peak Login Hour" for the Windows VM.
- **13:30:** Using `chart`, `timechart`, and `top/rare`.
- **15:00:** Verification Drill: Sort the Top 5 processes by Sysmon Event Count.

**Operator Command (SPL):**
```splunk
index=main sourcetype="WinEventLog:Security" EventCode=4625 | stats count by TargetUserName | sort - count
```

---

#### **Day 31: SPL Mastery II - Eval & Regex Drills**
**Objective:** Extracting and manipulating fields on-the-fly.
**Hourly Ops:**
- **09:00:** Introduction to `eval` functions: `if`, `case`, `match`, `lower`.
- **11:00:** **Lab Exercise:** Use `rex` to extract a custom "Source IP" from a semi-structured log.
- **13:30:** Formatting timestamps with `strftime`.
- **15:00:** Triage: Creating a "Risk Score" field based on event severity.

**Operator Command (REGEX SPL):**
```splunk
index=main | rex field=_raw "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)" | table src_ip, _time
```

---

#### **Day 32: Common Information Model (CIM) Lab**
**Objective:** Normalizing data for enterprise search.
**Hourly Ops:**
- **09:00:** What is CIM and why do we need it?
- **11:00:** **Lab Exercise:** Install the "Splunk InfoSec App" or "CIM Validator".
- **13:30:** Normalizing the Month 1 Linux `auth.log` to the "Authentication" model.
- **15:00:** Triage: Search across both Windows and Linux data using a single CIM field (e.g., `user`).

**Ref Links:**
1. [Splunk CIM Documentation](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
2. [Splunkbase: CIM Validator](https://splunkbase.splunk.com/app/2968/)

---

#### **Day 33: Alert Engineering & Throttling**
**Objective:** Build high-fidelity alerts that don't cause fatigue.
**Hourly Ops:**
- **09:00:** Alert Triggers: "Greater than X", "Relative to Average".
- **11:00:** **Lab Exercise:** Build a "Brute Force" alert: 10 failed logins followed by 1 success within 5 mins.
- **13:30:** Configuring "Suppression/Throttling" to prevent alert storms.
- **15:00:** Verification Drill: Trigger the alert and check the "Triggered Alerts" dashboard.

---

#### **Day 34: Dashboard Studio: The SOC Wallboard**
**Objective:** Visualizing complex threats at a glance.
**Hourly Ops:**
- **09:00:** Intro to "Dashboard Studio" (Classic vs Studio).
- **11:00:** **Lab Exercise:** Create a "Global Attack Map" using the `iplocation` command.
- **13:30:** Adding Dropdowns and Time Range Pickers for interactivity.
- **15:00:** Design: Build a "Malware Overview" panel showing Sysmon ID 1 outbreaks.

**Field Manual:**
1. [Splunk: Dashboard Studio Examples](https://docs.splunk.com/Documentation/Splunk/latest/Dash Studio/StudioExamples)
2. [Splunk: Using iplocation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Iplocation)

---

#### **Day 35: WEEK 5 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Splunk Operator Dashboard"**
- A shared link or export of a dashboard containing:
  - Account Lockout trends.
  - Top 10 blocked IPs.
  - Suspicious parent-child process tree.

---

### **WEEK 6: ADVANCED SIEM ENGINEERING & ES**
*Focus: Enterprise-Scale Correlation & Security Intelligence.*

#### **Day 36: Advanced Correlation Commands**
**Objective:** Correlate disparate events across different data sources.
**Hourly Ops:**
- **09:00:** Mastering `join`, `map`, and `transaction`.
- **11:00:** **Lab Exercise:** Correlate a Firewall "Accept" event with a Windows "Successful Login" (ID 4624).
- **13:30:** Performance Audit: Why `transaction` is expensive and how to use `stats` instead.
- **15:00:** Verification Drill: Build a flow showing "File Created" (Sysmon 11) -> "Network Connect" (Sysmon 3).

**Operator Command (Correlation SPL):**
```splunk
index=main (EventCode=4625 OR EventCode=4624) | stats min(_time) as first_attempt max(_time) as last_attempt count by TargetUserName | where count > 5
```

---

#### **Day 37: Macros & Data Model Acceleration**
**Objective:** Optimize SIEM performance for high-volume logs.
**Hourly Ops:**
- **09:00:** Reusable Logic: Creating and calling `macros`.
- **11:00:** **Lab Exercise:** Accelerate the "Authentication" Data Model.
- **13:30:** Using `tstats` to query accelerated data in milliseconds.
- **15:00:** Triage: Investigating a search that takes > 60 seconds and optimizing it.

---

#### **Day 38: Introduction to Splunk Enterprise Security (ES)**
**Objective:** Managing incidents within the ES framework.
**Hourly Ops:**
- **09:00:** Navigating the "Incident Review" dashboard.
- **11:00:** **Lab Exercise:** Triage a "Notable Event" and assign it to an "Owner".
- **13:30:** Understanding Risk-Based Alerting (RBA).
- **15:00:** Lab: Increase a user's "Risk Score" based on a detected PowerShell exploit.

**Ref Links:**
1. [Splunk ES User Manual](https://docs.splunk.com/Documentation/ES/7.1.0/User/Overview)
2. [Splunk: Risk-Based Alerting Guide](https://www.splunk.com/en_us/blog/security/risk-based-alerting-a-new-era-of-detection.html)

---

#### **Day 39-41: Search Optimization & ES Dashboards**
- **Day 39:** Job Inspector Deep Dive: Finding bottlenecks in SPL.
- **Day 40:** Building Custom Security Posture dashboards in ES.
- **Day 41:** Threat Intel Integration: Adding an IOC feed to ES.

---

#### **Day 42: WEEK 6 PRACTICAL ASSESSMENT**
**Deliverable:** **"The ES Investigation Journal"**
- A step-by-step documentation of resolving 3 "Notable Events" in a simulated ES environment.

---

### **WEEK 7: THE ELK STACK (Elasticsearch, Logstash, Kibana)**
*Focus: Open-Source SIEM Engineering & Big Data Visualization.*

#### **Day 43: ELK Architecture & Installation Lab**
**Objective:** Deploying a multi-node Elastic stack.
**Hourly Ops:**
- **09:00:** Elasticsearch Nodes, Shards, and Replicas.
- **11:00:** **Lab Exercise:** Install Elasticsearch and Kibana (8.x) using Docker or APT.
- **13:30:** Configuring `elasticsearch.yml` for TLS/SSL security.
- **15:00:** Verification Drill: Ping the Elasticsearch API and check for "Green" status.

**Operator Command:**
```bash
curl -u elastic:[PASSWORD] -X GET "https://localhost:9200/_cluster/health?pretty"
```

---

#### **Day 44: Logstash Pipeline Engineering**
**Objective:** Transforming raw logs into JSON-structured events.
**Hourly Ops:**
- **09:00:** Input, Filter (Grok/Mutate), and Output stages.
- **11:00:** **Lab Exercise:** Create a Logstash pipeline for custom CSV malware logs.
- **13:30:** Using GeoIP filters to map attacking IPs.
- **15:00:** Triage: Debugging a Logstash pipeline using `stdout { codec => rubydebug }`.

**Field Manual:**
1. [Elastic: Grok Filter Reference](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html)
2. [Elastic: Logstash Configuration Examples](https://www.elastic.co/guide/en/logstash/current/config-examples.html)

---

#### **Day 45: Kibana Lens & Visualizations**
**Objective:** Building drag-and-drop analytics.
**Hourly Ops:**
- **09:00:** Mastering Kibana Query Language (KQL).
- **11:00:** **Lab Exercise:** Build a "Network Throughput" chart using Kibana Lens.
- **13:30:** Creating TSVB (Time Series) charts for anomaly detection.
- **15:00:** Dashboard: Build an "Elastic Security Overview" page.

---

#### **Day 46: Elastic Security SIEM App**
**Objective:** Proactive detection using the Elastic Security framework.
**Hourly Ops:**
- **09:00:** Navigating the "Hosts" and "Network" tabs.
- **11:00:** **Lab Exercise:** Enable pre-built MITRE ATT&CK rules.
- **13:30:** Creating a custom detection rule for "Suspicious Cron Modification".
- **15:00:** Lab: Perform a "Timeline Investigation" for a malware event.

---

#### **Day 47-48: Fleet, Elastic Agent & Final ELK Polish**
- **Day 47:** Deploying Elastic Agents via Fleet for centralized management.
- **Day 48:** Building "Cases" in Elastic Security and adding evidence.

---

#### **Day 49: WEEK 7 PRACTICAL ASSESSMENT**
**Deliverable:** **"The ELK Visibility Report"**
- A PDF export of a Kibana Dashboard showing real-time host and network telemetry.

---

### **WEEK 8: ALERT TUNING & THE SOC WORKFLOW**
*Focus: Noise Reduction & Standard Operating Procedures (SOPs).*

#### **Day 50: False Positive Reduction Lab**
**Objective:** Effectively tune out authorized activity from high-fidelity alerts.
**Hourly Ops:**
- **09:00:** The "Signal-to-Noise" ratio concept.
- **11:00:** **Lab Exercise:** Analyze a noisy "Suspicious PowerShell" alert and identify "Authorized Admin Tasks".
- **13:30:** Implementing "Exclusion Macros" in Splunk or "Suppression Filters" in Elastic.
- **15:00:** Verification Drill: Confirm the alert only triggers on non-whitelisted activity.

**Ref Links:**
1. [SANS: Successful SIEM Tuning](https://www.sans.org/blog/successful-siem-and-log-management-strategies/)
2. [Splunk: Best practices for alert tuning](https://docs.splunk.com/Documentation/Splunk/latest/Alert/Bestpracticesforalerting)

---

#### **Day 51: Standard Deviation & Behavioral Outliers**
**Objective:** Detect anomalies based on statistical deviations.
**Hourly Ops:**
- **09:00:** Calculating baselines using `stats avg` and `stdev`.
- **11:00:** **Lab Exercise:** Build a search to find users who download > 3 standard deviations above their 7-day average.
- **13:30:** Understanding "High Cardinality" fields and their impact on performance.
- **15:00:** Triage: Investigating a "Volume Anomaly" in network egress traffic.

---

#### **Day 52: Use Case Documentation (SANS Template)**
**Objective:** Professionally documenting the "Why" and "How" of a detection.
**Hourly Ops:**
- **09:00:** Overview of the SANS Use Case Documentation framework.
- **11:00:** **Lab Exercise:** Write a formal Use Case for "Ransomware-linked Domain Discovery".
- **13:30:** Mapping the Use Case to MITRE ATT&CK Tactic and Technique IDs.
- **15:00:** Verification Drill: Peer-review your Use Case against the "Field Manual".

**Field Manual:**
1. [SANS: SIEM Use Case Guide](https://www.sans.org/white-papers/37735/)

---

#### **Day 53-54: Playbook Engineering & Intel Enrichment**
- **Day 53:** Writing a Triage SOP for "Unauthorized Sudo Usage".
- **Day 54:** Automating "AbuseIPDB" and "VirusTotal" API lookups for every new alert.

---

#### **Day 55: SIEM Comparative Analysis Lab**
**Objective:** Evaluate Splunk vs ELK for specific SOC mission profiles.
**Hourly Ops:**
- **09:00:** Feature-by-feature comparison (Search, Alerting, Visualization, Cost).
- **11:00:** **Lab Exercise:** Deploy the SAME detection in both Splunk and ELK.
- **13:30:** Measuring "Time-to-Insight" for both platforms.
- **15:00:** Reflection: Choosing the right tool for a specific budget/team size.

---

#### **Day 56: MONTH 2 FINAL PRACTICAL ASSESSMENT**
**Deliverable:** **"The SIEM Operator Portfolio"**
- A collection of 5 Custom SPL/KQL alerts.
- 1 Tuned Dashboard.
- 1 High-Fidelity Use Case Document.

---

## 📅 MONTH 3: INCIDENT RESPONSE & THREAT HUNTING (Days 57-84)

### **WEEK 9: THE IR LIFE CYCLE & TRIAGE**
*Focus: Tactical Response Frameworks & Decision Under Pressure.*

#### **Day 57: NIST vs SANS - The Incident Responder's Map**
**Objective:** Apply high-level frameworks to granular technical incidents.
**Hourly Ops:**
- **09:00:** Comparing NIST SP 800-61 vs SANS PICERL.
- **11:00:** **Lab Exercise:** Take a raw incident (e.g., "Suspicious Admin Login") and map it to each phase of PICERL.
- **13:30:** Understanding the "Criticality Matrix": Determining P1 (Critical) vs P4 (Low).
- **15:00:** Verification Drill: Fill out an "Incident Intake Form" based on a mock alert.

**Ref Links:**
1. [NIST: Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
2. [SANS: Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)

---

#### **Day 58: Data Scoping & Blast Radius Lab**
**Objective:** Identifying "What else is broken?" during an active breach.
**Hourly Ops:**
- **09:00:** Pivot Analysis: Using common fields (IP, User, Host) to scope an attack.
- **11:00:** **Lab Exercise:** Given a single bad process hash, find all other hosts in the SIEM that have seen that hash.
- **13:30:** Identifying "Shared Infrastructure" (e.g., same C2 domain used across multiple hosts).
- **15:00:** Triage: Calculate the "Impacted User Count" and "Data Volume Leaked".

**Operator Command (Splunk Pivot):**
```splunk
index=main [search index=main malicious_hash="XYZ" | fields src_ip] | stats count by dest_ip
```

---

#### **Day 59: Tactical Containment Drills**
**Objective:** Execution of emergency host and user isolation.
**Hourly Ops:**
- **09:00:** Isolation types: Physical (Pulling cable) vs Logical (VLAN/EDR).
- **11:00:** **Lab Exercise:** Disable a compromised user account via PowerShell and verify they are kicked from active sessions.
- **13:30:** Host Isolation: Applying a "Quarantine Policy" in your Wazuh or EDR lab.
- **15:00:** Verification Drill: Confirm the isolated host can only talk to the SIEM manager.

**Operator Command (Active Directory / Local PS):**
```powershell
Set-LocalUser -Name "compromised_user" -Enabled $False
```

---

#### **Day 60-61: Eradication & Recovery Tactics**
- **Day 60:** Identifying and removing "Persistence Clusters" (Scheduled tasks + Registry keys).
- **Day 61:** Validating system integrity post-reboot. Monitoring for "Re-infection" indicators.

---

#### **Day 62: After Action Reviews (AAR) & Lessons Learned**
**Objective:** Transforming failure into defensive resilience.
**Hourly Ops:**
- **09:00:** Structure of a professional Post-Mortem.
- **11:00:** **Lab Exercise:** Conduct a mock AAR for the "Echo Case" from Month 1.
- **13:30:** Identifying "Control Gaps" (Why didn't the SIEM catch this earlier?).
- **15:00:** Deliverable: Create a "Defensive Improvement Roadmap".

---

#### **Day 63: WEEK 9 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Combat Triage Portfolio"**
- Complete documentation of a P1 incident from "Intake" to "Containment".
- Must include the specific commands used for isolation.

---

### **WEEK 10: DIGITAL FORENSICS (DFIR) FOR SOC**
*Focus: Extracting Truth from Artifacts & Memory.*

#### **Day 64: Forensic Preservation & Memory Acquisition**
**Objective:** Securely collect evidence without contaminating the "Crime Scene".
**Hourly Ops:**
- **09:00:** The "Order of Volatility": Why Memory (RAM) comes first.
- **11:00:** **Lab Exercise:** Use `DumpIt` or `Magnet RAM Capture` to take a memory dump of your Windows VM.
- **13:30:** Calculating Hashes (SHA-256) for the image to ensure integrity.
- **15:00:** Verification Drill: Verify the hash of your dump before and after moving it to the SIEM.

**Field Manual:**
1. [SANS: Forensic Acquisition Cheat Sheet](https://www.sans.org/posters/forensic-acquisition-cheat-sheet/)

---

#### **Day 65: Memory Analysis with Volatility 3**
**Objective:** Identifying malicious injections and network connections in RAM.
**Hourly Ops:**
- **09:00:** Volatility 3 Architecture and Plugin system.
- **11:00:** **Lab Exercise:** Use `windows.pslist` and `windows.pstree` to find hidden processes.
- **13:30:** Detecting Hollowed Processes: Using `windows.malfind` to find injected code.
- **15:00:** Verification Drill: Extract the "Command Line" of a suspicious process from memory.

**Operator Command:**
```bash
python3 vol.py -f memory.dmp windows.netscan
python3 vol.py -f memory.dmp windows.malfind --dump
```

**Ref Links:**
1. [Volatility Foundation: Plugin Guide](https://github.com/volatilityfoundation/volatility/wiki)
2. [SANS: Volatility Cheat Sheet](https://www.sans.org/posters/volatility-3-cheat-sheet/)

---

#### **Day 66: Windows Execution Artifacts**
**Objective:** Finding "Evidence of Execution" after a process has closed.
**Hourly Ops:**
- **09:00:** Deep dive into Prefetch (`.pf`) and Shimcache.
- **11:00:** **Lab Exercise:** Use [Eric Zimmerman's PECmd](https://ericzimmerman.github.io/#!index.md) to parse Prefetch files.
- **13:30:** Mapping "First Run" and "Last Run" times for a malicious tool.
- **15:00:** Triage: Tracking `certutil.exe` usage through Prefetch forensics.

---

#### **Day 67: Registry Forensics Lab**
**Objective:** Recovering configuration, persistence, and recent file activity.
**Hourly Ops:**
- **09:00:** Understanding User Hives (`NTUSER.DAT`) vs System Hives.
- **11:00:** **Lab Exercise:** Use `Registry Explorer` to find "RunKeys" and "UserAssist" artifacts.
- **13:30:** Tracking "Recent Docs" and "ShellBags" to find exfiltrated folder names.
- **15:00:** Verification Drill: Document the exact Registry Key used by a common piece of malware for persistence.

---

#### **Day 68: Linux Forensic Artifacts**
**Objective:** Analyzing the "Footprints" left on a Linux server.
**Hourly Ops:**
- **09:00:** Analyzing `.bash_history` (and detecting its deletion).
- **11:00:** **Lab Exercise:** Recover deleted files from a Linux partition using `extundelete` or `fls`.
- **13:30:** Auditing Log File gaps: Identify missing entries in `syslog` or `journald`.
- **15:00:** Triage: Mapping a "Cron Job" creation to a "SSH Session" start time.

---

#### **Day 69: The Sleuth Kit (TSK) & Autopsy**
**Objective:** Unified forensic analysis using an open-source GUI.
**Hourly Ops:**
- **09:00:** Creating a "Case" in Autopsy.
- **11:00:** **Lab Exercise:** Import a `.vmdk` or `.raw` image of your target machine.
- **13:30:** Running ingest modules: Keyword Search, Email Analysis, and Web History.
- **15:00:** Verification Drill: Generate a "Case Summary PDF" from Autopsy.

---

#### **Day 70: WEEK 10 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Forensic Evidence Log"**
- A report containing evidence found in RAM (Volatility) and Disk (Autopsy) for a specific attack.
- Must include the "Chain of Custody" for the handled images.

---

### **WEEK 11: THREAT INTELLIGENCE & MITRE ATT&CK**
*Focus: Strategic Foreknowledge & Tactical Mapping.*

#### **Day 71: The Threat Intel Lifecycle Lab**
**Objective:** Operationalize raw intelligence for the SOC floor.
**Hourly Ops:**
- **09:00:** Direction, Collection, Processing, Analysis, and Dissemination.
- **11:00:** **Lab Exercise:** Use [AlienVault OTX](https://otx.alienvault.com/) to find indicators for a known ransomware group (e.g., LockBit).
- **13:30:** Creating "Watchlists" in the SIEM based on downloaded IOCs (IPs/Hashes).
- **15:00:** Verification Drill: Trigger an alert by simulating a connection to a "Known Bad" IP.

**Ref Links:**
1. [CrowdStrike: What is Threat Intelligence?](https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/)
2. [SANS: Cyber Threat Intelligence Cheat Sheet](https://www.sans.org/posters/cyber-threat-intelligence-cheat-sheet/)

---

#### **Day 72: MITRE ATT&CK Navigator Mastery**
**Objective:** Visualize your detection coverage against attacker techniques.
**Hourly Ops:**
- **09:00:** Navigating the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
- **11:00:** **Lab Exercise:** Create a Layer that highlights all techniques covered by your Month 1 & 2 SIEM rules.
- **13:30:** Identifying "Blind Spots": Which tactics (e.g., Exfiltration) are you not monitoring?
- **15:00:** Deliverable: An exported JSON layer showing current SOC visibility.

---

#### **Day 73: IOC Management (MISP Basics)**
**Objective:** Centralizing and sharing intelligence data.
**Hourly Ops:**
- **09:00:** Introduction to MISP (Malware Information Sharing Platform).
- **11:00:** **Lab Exercise:** Import a "Threat Bulletin" into your lab environment.
- **13:30:** Scripting: Use a Python script to pull IOCs from a MISP API into a SIEM lookup table.
- **15:00:** Triage: Compare recent `syslog` entries against the MISP "Technical Indicators".

---

#### **Day 74-76: Actor Dossiers & Rule Mapping**
- **Day 74:** Creating a "Threat Actor Dossier" for a specific APT (e.g., APT29).
- **Day 75:** Mapping SIEM alert descriptions to ATT&CK Technique IDs (e.g., T1059).
- **Day 76:** Technical Lab: Building a "Tactic-Specific" dashboard in Splunk.

---

#### **Day 77: WEEK 11 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Intelligence Blueprint"**
- A report containing a MITRE Navigator layer and a dossier for one active threat group.

---

### **WEEK 12: PROACTIVE THREAT HUNTING LABS**
*Focus: Hypothesis-Driven Discovery of Stealthy Threats.*

#### **Day 78: Hunting for Persistence - The Hypothesis Drill**
**Objective:** Search for threats that bypass automated alerts.
**Hourly Ops:**
- **09:00:** Hypothesis Generation (e.g., "Attackers use WMI for persistence").
- **11:00:** **Lab Exercise:** Search your environment for anomalous WMI subscriptions or Scheduled Tasks.
- **13:30:** Filtering "Known Good" system tasks to find the outlier.
- **15:00:** Verification Drill: Document the SPL/KQL query used for the hunt.

**Ref Links:**
1. [Microsoft: Threat Hunting in the SOC](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/threat-hunting-scenarios)
2. [SANS: Threat Hunting Cheat Sheet](https://www.sans.org/posters/threat-hunting-cheat-sheet/)

---

#### **Day 79: Lateral Movement Discovery**
**Objective:** Detect attackers moving across your network using native tools.
**Hourly Ops:**
- **09:00:** Analyzing Event ID 4624 (Type 3) and `PsExec` activity.
- **11:00:** **Lab Exercise:** Use `PsExec` to move from System A to System B in your lab.
- **13:30:** Hunt for "Service Installation" events (ID 7045) on the destination host.
- **15:00:** Triage: Mapping the "Source Workstation" to the "Target User".

---

#### **Day 80: Exfiltration & C2 Hunting**
- **Day 80:** Hunting for "Beaconing" in Firewall logs (Large Byte counts, high frequency).
- **Day 81:** Searching for "Outbound Data" spikes to unusual ports (e.g., 443 to raw IPs).
- **Day 82:** Lab: Use the "Pyramid of Pain" to grade your hunting successes.

---

#### **Day 84: MONTH 3 FINAL PRACTICAL ASSESSMENT**
**Deliverable:** **"The Proactive Hunt Report"**
- A detailed log of 3 successfully executed hunts, including the hypothesis, data searched, and findings.

---

## 📅 MONTH 4: CLOUD SOC, AUTOMATION & CAREER (Days 85-112)

### **WEEK 13: CLOUD SOC (AWS & AZURE)**
*Focus: Logging and Monitoring in Dynamic Cloud Environments.*

#### **Day 85: Cloud Logging Fundamentals (AWS CloudTrail)**
**Objective:** Mastering the primary audit trail for AWS modifications.
**Hourly Ops:**
- **09:00:** Understanding "Management" vs "Data" events.
- **11:00:** **Lab Exercise:** Use the AWS CLI or Console to create a Trail and store logs in S3.
- **13:30:** Search for "IAM Policy Modifications" in CloudTrail using `athena` or SIEM.
- **15:00:** Verification Drill: Identify which API call caused a specific "S3 Bucket Public" event.

**Ref Links:**
1. [AWS: CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
2. [SANS: AWS Security Persistence](https://www.sans.org/blog/how-to-hunt-for-persistence-in-aws/)

---

#### **Day 86: Azure Monitor & Sentinel Basics**
**Objective:** Establishing visibility in the Microsoft Cloud.
**Hourly Ops:**
- **09:00:** Navigating "Monitor", "Log Analytics", and "Microsoft Sentinel".
- **11:00:** **Lab Exercise:** Configure the "Activity Log" to stream events to a workspace.
- **13:30:** Hunt for "Virtual Machine Creation" and "Admin Role Assignment" events.
- **15:00:** Triage: Investigating a suspicious login to the Azure Portal from a new Geo-Location.

---

#### **Day 87: Detecting Cloud-Identity (IAM) Abuse**
**Objective:** Identifying "Privilege Escalation" in the cloud.
**Hourly Ops:**
- **09:00:** Understanding "Cross-Account" access and "Role Assumption".
- **11:00:** **Lab Exercise:** Simulate an attacker creating a new Access Key for a compromised user.
- **13:30:** Detecting "Credential Stuffing" attempts against Azure AD (Entra ID).
- **15:00:** Verification Drill: Map an IAM abuse event to the MITRE ATT&CK Cloud Matrix.

---

#### **Day 88-90: Storage Exposure & Container Logs**
- **Day 88:** Hunting for "Public Read" modifications on S3 or Azure Blobs.
- **Day 89:** Introduction to Kubernetes (K8s) Audit Logs.
- **Day 90:** Lab: Detecting "Container Escape" attempts through system logs.

---

#### **Day 91: WEEK 13 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Cloud Visibility Blueprint"**
- A technical doc showing an AWS/Azure monitoring plan, including 3 high-fidelity cloud alerts.

---

### **WEEK 14: SOC AUTOMATION (PYTHON & SOAR)**
*Focus: Scaling the SOC through Code & Orchestration.*

#### **Day 92: Python for Security - The Tactical Basics**
**Objective:** Writing scripts to parse and filter security data.
**Hourly Ops:**
- **09:00:** Python for String manipulation and Log parsing.
- **11:00:** **Lab Exercise:** Write a Python script to extract all URLs from a suspicious `.json` log file.
- **13:30:** Using the `requests` library to talk to external APIs.
- **15:00:** Verification Drill: Generate a "Summary Report" of failed logins using Python.

**Operator Command (Python Snippet):**
```python
import json
with open("alerts.json", "r") as f:
    data = json.load(f)
    print([x['url'] for x in data if 'malicious' in x['category']])
```

---

#### **Day 93: Automated IOC Enrichment Script**
**Objective:** Saving analyst time through auto-lookup of bad IPs/Hashes.
**Hourly Ops:**
- **09:00:** Understanding API Keys and Rate Limits.
- **11:00:** **Lab Exercise:** Build a script that takes a list of IPs and checks them against [VirusTotal API](https://developers.virustotal.com/).
- **13:30:** Outputting the results to a structured CSV file.
- **15:00:** Verification Drill: Auto-flag "High Confidence" malicious IPs in your SIEM.

**Ref Links:**
1. [Python: Official Requests Library](https://requests.readthedocs.io/en/latest/)
2. [VirusTotal: Python SDK](https://github.com/VirusTotal/vt-py)

---

#### **Day 94: Introduction to SOAR Playbooks**
**Objective:** Automating the "Incident Response" workflow.
**Hourly Ops:**
- **09:00:** What is SOAR (Security Orchestration, Automation, and Response)?
- **11:00:** **Lab Exercise:** Design a "Visual Playbook" for an "Account Lockout" event.
- **13:30:** Steps: Enrichment -> Triage -> User Confirmation -> Auto-Unlock (or Reset).
- **15:00:** Triage: When to NOT automate a response (The "Human-in-the-loop").

---

#### **Day 95-97: API Integration & ChatOps**
- **Day 95:** Building a simple Slack/Discord bot to notify the SOC of P1 alerts.
- **Day 96:** Automating "Host Isolation" via EDR APIs (Wazuh/CrowdStrike).
- **Day 97:** Technical Lab: Building a "Daily Health Check" script for the SIEM nodes.

---

#### **Day 98: WEEK 14 PRACTICAL ASSESSMENT**
**Deliverable:** **"The SOC Automation Toolkit"**
- A GitHub repo (or local folder) containing 3 functioning Python scripts: Enrichment, Reporting, and Isolation.

---

### **WEEK 15: MALWARE ANALYSIS FOR THE SOC**
*Focus: Deconstructing the "Payload" without getting infected.*

#### **Day 99: Basic Static Analysis Lab**
**Objective:** Identifying malware characteristics without executing the code.
**Hourly Ops:**
- **09:00:** Safe handling of malware in a disconnected "Sandbox".
- **11:00:** **Lab Exercise:** Use [Pestudio](https://www.winitor.com/) to find suspicious strings and imports in a sample.
- **13:30:** Calculating Hashes and checking against Malware Repositories.
- **15:00:** Verification Drill: Identify if the sample is "Packed" or "Obfuscated".

**Ref Links:**
1. [Practical Malware Analysis: Essentials](https://nostarch.com/malware)
2. [SANS: Malware Analysis Cheat Sheet](https://www.sans.org/posters/malware-analysis-cheat-sheet/)

---

#### **Day 100: Basic Dynamic Analysis Lab**
**Objective:** Observing malware behavior in a controlled runtime environment.
**Hourly Ops:**
- **09:00:** Setting up `Procmon` and `Wireshark` for behavioral capture.
- **11:00:** **Lab Exercise:** Execute the malware and track its File, Registry, and Network changes.
- **13:30:** Identifying the "C2 Callback" IP and port.
- **15:00:** Triage: Mapping the observed behavior to the MITRE ATT&CK techniques.

---

#### **Day 101-103: Automated Analysis & Extraction**
- **Day 101:** Using [Any.Run](https://any.run/) or [Joe Sandbox] for automated triage.
- **Day 102:** Extracting "Configuration" data from a RAT (Remote Access Trojan).
- **Day 103:** Lab: Writing a "Malware Triage Report" for a SOC Manager.

---

#### **Day 105: WEEK 15 PRACTICAL ASSESSMENT**
**Deliverable:** **"The Malware Triage Report"**
- A 2-page report detailing the Static and Dynamic findings for a provided malware sample.

---

### **WEEK 16: CAPSTONE & CAREER READINESS**
*Focus: Proving your worth and landing the job.*

#### **Day 106-110: THE FINAL CAPSTONE SIMULATION**
**Scenario:** "The Enterprise Breach"
- **Day 106:** Detection: Identify the initial entry point via Email/Web logs.
- **Day 107:** Analysis: Trace the attacker's lateral movement and privilege escalation.
- **Day 108:** Forensics: Conduct RAM analysis on the "Domain Controller" image.
- **Day 109:** Response: Draft the full Incident Timeline and Remediation Plan.
- **Day 110:** Reporting: Present the findings in a "Technical Executive Summary".

---

#### **Day 111: SOC INTERVIEW DRILLS**
**Objective:** Practical, high-pressure interview preparation.
**Hourly Ops:**
- **09:00:** Answering "The Technical Trio": 3-way handshake, OSI model, and the Incident IR steps.
- **11:00:** The "Scenario Question": How would you handle a Ransomware alert at 4 AM?
- **13:30:** Reviewing "Red Flags" in your personal portfolio.
- **15:00:** Mock Interview session with a peer or mentor.

---

#### **Day 112: CURRICULUM GRADUATION & PORTFOLIO EXPORT**
**Final Deliverable:** 
- A unified PDF/DOCX of your **"SOC Analyst Practical Portfolio"**, containing all 16 weekly assessments.
- **CELEBRATE:** You have completed 112 days of intensive, hands-on training.

---

# 🚀 END OF CURRICULUM
