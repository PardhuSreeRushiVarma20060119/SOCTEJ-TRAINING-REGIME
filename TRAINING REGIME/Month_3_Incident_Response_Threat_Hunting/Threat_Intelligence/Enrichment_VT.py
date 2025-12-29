import requests
import json
import sys

# Threat Intelligence Enrichment Script (VirusTotal)
# Requires API Key

VT_API_KEY = "YOUR_VT_API_KEY_HERE"

def get_vt_report(resource_type, resource):
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    if resource_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{resource}"
    elif resource_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{resource}"
    else:
        return None

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "msg": response.text}

def main():
    if len(sys.argv) < 3:
        print("Usage: python enrichment.py <type: ip|hash> <value>")
        sys.exit(1)

    res_type = sys.argv[1]
    value = sys.argv[2]

    print(f"[*] Enriching {res_type}: {value} via VirusTotal...")
    report = get_vt_report(res_type, value)
    
    if "data" in report:
        stats = report["data"]["attributes"]["last_analysis_stats"]
        print(f"[+] Malicious detections: {stats['malicious']}")
        print(f"[+] Suspicious detections: {stats['suspicious']}")
        print(f"[+] Detailed Info: {report['data']['links']['self']}")
    else:
        print(f"[!] Error: {report}")

if __name__ == "__main__":
    main()
