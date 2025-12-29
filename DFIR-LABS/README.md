# 🕵️ DFIR Training Labs

This directory contains **Digital Forensics and Incident Response (DFIR)** scenarios. These are "Case Files" containing evidence (memory dumps, disk images, PCAPs, and logs) for deep analysis.

## 📂 Active Scenarios

### **Scenario 1: The Insider**
- **Difficulty:** ⭐⭐
- **Type:** Data Exfiltration
- **Evidence:** `USB_Image.dd`, `Windows_Registry_Hives`
- **Objective:** Determine what files were copied to the USB drive and when.

### **Scenario 2: The Ransomware Patient Zero**
- **Difficulty:** ⭐⭐⭐
- **Type:** Malware Analysis / Root Cause Analysis
- **Evidence:** `Memory.dmp`, `MFT.csv`
- **Objective:** Find the initial entry vector (phishing email?) and the process that spawned the encryption.

### **Scenario 3: The APT Beacon**
- **Difficulty:** ⭐⭐⭐⭐
- **Type:** Network Forensics / C2 Hunting
- **Evidence:** `Traffic_Capture.pcap` (2GB)
- **Objective:** Identify the C2 IP, the beaconing interval (jitter), and decode the C2 data channel.

## 🔬 Tools Required
- **Memory:** Volatility 3
- **Disk:** Autopsy, FTK Imager, Eric Zimmerman's Tools (EZ Tools)
- **Network:** Wireshark, Zeek/RITA

## ⚠️ Warning
Some of these folders may contain **LIVE MALWARE** (password protected with `infected`). **DO NOT EXECUTE** these outside of your isolated Sandbox VM.