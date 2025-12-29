# 🤖 SOC Automation Lab

Welcome to the **Engineering Wing** of the training. This directory focuses on **Security Orchestration, Automation, and Response (SOAR)** using Python and various APIs.

## 🛠️ The Toolkit

### **1. Enrichment Automations**
- **`Enrichment_VT.py`**: Queries VirusTotal API v3 to check IP/Hash reputation.
- **`AbuseIPDB_Check.py`**: Bulk checks IPs against AbuseIPDB confidence scores.

### **2. Response Automations**
- **`Wazuh_Active_Response/`**: Custom scripts to automatically block IPs on the firewall when a high-severity alert triggers.
- **`CrowdStrike_Containment.py`**: Using the Falcon API to network-isolate an endpoint.

### **3. Utility Scripts**
- **`Log_Parser.py`**: A fast Python script to convert messy JSON logs into CSV for Excel analysis.
- **`IOC_Extractor.py`**: Regex-based script to pull IPs, Emails, and URLs from raw text dumps.

## ⚡ Quick Start
1.  **Install Requirements:** `pip install -r requirements.txt` (requests, pandas).
2.  **API Keys:** Rename `config_sample.py` to `config.py` and add your keys (VirusTotal, AlienVault, etc.).
3.  **Run:** `python Enrichment_VT.py --ip 8.8.8.8`

> *"If you do it more than twice, automate it."*
