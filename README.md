# 🛡️ SOCTEJ : The 112-Day SOC Analyst Training Regime

![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=for-the-badge) ![MITRE D3FEND](https://img.shields.io/badge/Framework-MITRE%20D3FEND-blue?style=for-the-badge) ![Status](https://img.shields.io/badge/Status-MISSION%20ACTIVE-darkgreen?style=for-the-badge)

Welcome to the **most intensive, practical, and framework-aligned SOC training program** publicly available. This repository contains a structured **112-Day (16-Week)** curriculum designed to transition a candidate from zero knowledge to a **Tier-3 SOC Threat Hunter & Engineer**.

---

## 🚀 The Core Curriculum
The training is built on a **"Dual-Framework"** philosophy:
1.  **Offense:** Every day is mapped to **MITRE ATT&CK®** Techniques (TIDs) to understand the adversary.
2.  **Defense:** Every countermeasure is mapped to **MITRE D3FEND™** Artifacts (DIDs) to engineer the solution.

### 📚 Master Documentation
- **[📜 112-Day Master PDF Corpus](TRAINING%20REGIME/MISC/SOC_ELITE_112_DAY_TRAINING_CORPUS.pdf)**: The complete, offline-ready manual containing every lab, command, and theory lesson.
- **[📊 Master Task Table (DOCX)](TRAINING%20REGIME/MISC/SOC_112_DAY_MASTER_CONSOLIDATED_TABLE.docx)**: A consolidated view of all 112 days, objectives, and mappings in a professional table format.
- **[📖 The Analyst's Bible](TRAINING%20REGIME/MISC/ANALYSTS_BIBLE.md)**: A field manual of 500+ commands for Windows, Linux, and Network Forensics.

---

## 📂 Repository Structure

| Directory | Description |
| :--- | :--- |
| **[`TRAINING REGIME/`](TRAINING%20REGIME/)** | **The Core Curriculum.** Contains the daily breakdown, lab guides, and theoretical modules for Months 1-4. |
| **[`SOC-Analyst-Playbooks/`](SOC-Analyst-Playbooks/)** | **Tactical Playbooks.** Step-by-step SOPs for Phishing, Ransomware, and lateral movement triage. |
| **[`SOC-Automation-Lab/`](SOC-Automation-Lab/)** | **Python & SOAR.** Automation scripts, API integrations (VirusTotal/AbuseIPDB), and containment tools. |
| **[`DFIR-LABS/`](DFIR-LABS/)** | **Forensic Scenarios.** Evidence files (memory dumps, PCAPs) for deep-dive investigation labs. |
| **[`d3fend-ontology/`](d3fend-ontology/)** | **The Defensive Matrix.** Raw D3FEND ontology files and the custom Python correlation engine. |

---

## 📅 The 16-Week Phase Breakdown

### **Phase 1: The Initial Entry & Stealth (Month 1)**
*Focus: Mastering the Source of Truth - Telemetry.*
- **Week 1:** Windows Defender & Telemetry (Sysmon, Auditd).
- **Week 2:** Linux Persistence & Hardening.
- **Week 3:** Network Surveillance (Zeek/Suricata).
- **Week 4:** EDR Combat (Wazuh/Velociraptor).

### **Phase 2: The Foothold & Escalation (Month 2)**
*Focus: SIEM Engineering & Logic.*
- **Week 5:** Splunk Power User & SPL.
- **Week 6:** ELK Stack Engineering.
- **Week 7:** Alert Tuning & False Positive Reduction.
- **Week 8:** The Shadow Hunt (Behavioral Analysis).

### **Phase 3: The Movement & Command (Month 3)**
*Focus: Incident Response & Threat Hunting.*
- **Week 9:** The IR Lifecycle (PICERL).
- **Week 10:** Digital Forensics (Memory & Disk).
- **Week 11:** Threat Intelligence (MITRE & CTI).
- **Week 12:** Proactive Threat Hunting.

### **Phase 4: The Impact & Engineering (Month 4)**
*Focus: Cloud SOC & Automation.*
- **Week 13:** Cloud Security (AWS/Azure).
- **Week 14:** SOC Automation (Python/SOAR).
- **Week 15:** Malware Analysis (Static/Dynamic).
- **Week 16:** **The Grand Capstone: Full Chain Emulation.**

---

## 🛠️ The SOC Range Lab
To complete this regime, you are required to build the **"Sentinel Range"**:
- **Target:** Windows 10/11 Enterprise (Evaluation).
- **Attack:** Kali Linux.
- **Monitor:** Ubuntu 22.04 LTS (running Splunk/ELK/Wazuh).
- **Network:** Security Onion or pfSense.

> *"The only difference between a **novice** and a **master** is that the master has failed more times than the novice has ever tried."*

---
*(C) 2025 Pardhu Sree Rushi Varma | SOC Elite Training For Tejaswini*
