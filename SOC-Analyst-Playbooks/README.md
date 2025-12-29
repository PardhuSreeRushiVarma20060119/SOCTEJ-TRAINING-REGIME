# 📖 SOC Analyst Tactical Playbooks

This directory contains **Standard Operating Procedures (SOPs)** and **Playbooks** for handling the most critical incidents a SOC Analyst will face. These documents are designed to minimize "mean-time-to-decision" (MTTD).

## 🚀 Playbook Collection

### **High Severity Incidents**
- **`Phishing_Analysis_SOP.md`**: Guide for dissecting email headers, analyzing attachments, and URL reputation checks.
- **`Ransomware_Containment_Playbook.md`**: The emergency checklist: Isolation -> Preservation -> Eradication.
- **`Active_Directory_Compromise.md`**: Handling Domain Admin takeover and Golden Ticket attacks.

### **Routine Operations**
- **`Suspicious_Login_Triage.md`**: Investigating "Impossible Travel" and "Brute Force" alerts.
- **`Malware_Outbreak_Response.md`**: Handling EDR alerts for C2 beaconing.

## 🛠️ How to Use These
1.  **Print & Laminate**: In a real SOC, these should be physically accessible.
2.  **Logic Maps**: Many playbooks include a "Logic Flow" (e.g., *Is IP Internal? Yes -> Check Asset DB. No -> Check GeoIP.*).
3.  **Command References**: Specific SPL/KQL queries are embedded in the playbooks for rapid searching.
