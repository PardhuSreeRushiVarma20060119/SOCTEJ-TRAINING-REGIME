import os
import re

# D3FEND-to-ATT&CK Correlation Engine
# This script correlates D3FEND IDs (DIDs) with ATT&CK Technique IDs (TIDs)
# based on common digital artifacts and manual mapping logic.

D3FEND_TTL_PATH = r"c:\Users\pardh\Downloads\TEJU INTENSIVE TRAINING\d3fend-ontology\src\ontology\d3fend-protege.ttl"

# Manual high-fidelity mapping derived from D3FEND Matrix
MAPPING = {
    "D3-NSM": ["T1595", "T1590", "T1048"], # Network Surveillance -> Recon, Exfil
    "D3-MSI": ["T1566", "T1071.003"],      # Message Segment Inspection -> Phishing
    "D3-SFL": ["T1059.001", "T1059.003"], # Script File Logging -> PowerShell/Bash
    "D3-WAF": ["T1190", "T1505.003"],      # Web App Filtering -> Exploit Public App, Web Shell
    "D3-RIA": ["T1547.001", "T1112"],      # Registry Ingestion Analysis -> Run Keys, Registry Mod
    "D3-PSA": ["T1053.005", "T1548.002", "T1047", "T1021.001"], # Process Spawn -> Scheduled Task, UAC, WMI, PsExec
    "D3-LPA": ["T1003.001"],               # LSASS Process Analysis -> LSASS Dumping
    "D3-FMA": ["T1070", "T1570", "T1003.003"], # File Modification Analysis -> Indicator Removal, Lateral Transfer, NTDS theft
    "D3-LAA": ["T1087", "T1078"],          # Local Account Analysis -> Account Discovery, Valid Accounts
    "D3-HBA": ["T1071.001", "T1090"],      # HTTP Beacon Analysis -> C2, Proxy
    "D3-DT":  ["T1132", "T1071.004"],      # DNS Tunneling -> C2
}

def get_countermeasure_details(did):
    """Extracts definition and label for a given DID from the TTL file."""
    if not os.path.exists(D3FEND_TTL_PATH):
        return "TTL File not found.", "N/A"
    
    with open(D3FEND_TTL_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Find the block containing the d3fend-id
    pattern = rf':(\w+) a owl:Class.*?:d3fend-id "{did}"'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        class_name = match.group(1)
        # Now find the definition and label for this class
        def_pattern = rf':{class_name} a owl:Class.*?rdfs:label "(.*?)"'
        label_match = re.search(def_pattern, content, re.DOTALL)
        label = label_match.group(1) if label_match else class_name
        
        desc_pattern = rf':{class_name} a owl:Class.*?:definition "(.*?)"'
        desc_match = re.search(desc_pattern, content, re.DOTALL)
        desc = desc_match.group(1) if desc_match else "No definition found."
        
        return label, desc
    return "Unknown", "No details found."

def correlate():
    print("="*60)
    print("🚀 D3FEND-to-ATT&CK CORRELATION ENGINE")
    print("="*60)
    print(f"{'D3FEND DID':<15} | {'Technique Name':<30} | {'Mapped TIDs'}")
    print("-"*60)
    
    if not os.path.exists(D3FEND_TTL_PATH):
        print("Error: TTL file not found.")
        return

# Hardcoded names for reliability
NAMES = {
    "D3-NSM": "Network Surveillance",
    "D3-MSI": "Message Segment Inspection",
    "D3-SFL": "Script File Logging",
    "D3-WAF": "Web Application Filtering",
    "D3-RIA": "Registry Ingestion Analysis",
    "D3-PSA": "Process Spawn Analysis",
    "D3-LPA": "Lsass Process Analysis",
    "D3-FMA": "File Modification Analysis",
    "D3-LAA": "Local Account Analysis",
    "D3-HBA": "HTTP Beacon Analysis",
    "D3-DT":  "DNS Tunneling Detection"
}

def correlate():
    print("="*60)
    print("🚀 D3FEND-to-ATT&CK CORRELATION ENGINE")
    print("="*60)
    print(f"{'D3FEND DID':<15} | {'Technique Name':<30} | {'Mapped TIDs'}")
    print("-"*60)
    
    for did, tids in MAPPING.items():
        name = NAMES.get(did, "Unknown")
        tid_str = ", ".join(tids)
        print(f"{did:<15} | {name:<30} | {tid_str}")

if __name__ == "__main__":
    correlate()
