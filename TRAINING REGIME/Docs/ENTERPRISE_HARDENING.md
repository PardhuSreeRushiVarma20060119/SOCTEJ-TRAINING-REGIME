# 🏢 ENTERPRISE HARDENING & AUDIT POLICY GUIDE
*SOC Engineering Master Checklist*

To detect advanced threats, the default Windows logging is insufficient. You must implement these configurations via GPO.

---

## 🛡️ 1. ADVANCED AUDIT POLICY CONFIGURATION
*Location: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration*

| Category | Sub-Category | Setting | Rationale |
| :--- | :--- | :--- | :--- |
| **Account Logon** | Audit Kerberos Service Ticket Operations | Success/Failure | Detect Golden Ticket / Silver Ticket. |
| **Account Management** | Audit Security Group Management | Success | Detect unauthorized Domain Admin additions. |
| **Detailed Tracking** | Audit Process Creation | Success | Critical for process visibility (Event ID 4688). |
| **Detailed Tracking** | Audit Process Termination | Success | Detect process kills by attackers. |
| **Logon/Logoff** | Audit Logon | Success/Failure | Detect Brute Force and Lateral Movement. |
| **Object Access** | Audit Registry | Success/Failure | Monitor sensitive registry key changes. |
| **Policy Change** | Audit Audit Policy Change | Success | Detect attackers trying to turn off logging. |
| **Privilege Use** | Audit Sensitive Privilege Use | Success/Failure | Detect `SeDebugPrivilege` abuse (T1134). |

---

## 📜 2. GPO: PROCESS COMMAND LINE LOGGING
*Location: Computer Configuration > Administrative Templates > System > Audit Process Creation*

- **Include command line in process creation events**: **Enabled**
- **Impact**: Populates the `CommandLine` field in Event ID 4688. Without this, you only see the program name, not the execution parameters.

---

## ⚡ 3. GPO: POWERSHELL LOGGING (THE "BIG THREE")
*Location: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell*

1.  **Turn on PowerShell Script Block Logging**: **Enabled** (ID 4104)
    - Captures the actual code executed, even if obfuscated.
2.  **Turn on PowerShell Transcription**: **Enabled**
    - Saves all console input/output to text files for forensic review.
3.  **Turn on Module Logging**: **Enabled**
    - Logs the loading of specific modules (e.g., ActiveDirectory).

---

## 🚧 4. WINDOWS DEFENDER & FIREWALL
- **Turn on Attack Surface Reduction (ASR) Rules**:
  - `Block credential stealing from the Windows local security authority subsystem (lsass.exe)`
  - `Block process creations originating from Office communication apps`
- **Enable Firewall Logging**:
  - Log dropped packets for both Inbound and Outbound.

---

## 🧹 5. CLEANUP & ROTATION
- **Max Log Size (Security)**: Set to at least **1024 MB**.
- **Log Retention**: Set to "Archive logs when full, do not overwrite".

---
