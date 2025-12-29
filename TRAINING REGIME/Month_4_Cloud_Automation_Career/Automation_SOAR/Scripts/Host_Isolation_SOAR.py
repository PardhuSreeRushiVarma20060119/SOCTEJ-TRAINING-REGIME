import requests
import json

# Simple SOAR Playbook: Automated Host Isolation via EDR API
# Example for a generic EDR API

EDR_API_URL = "https://your-edr.api.com/v1"
API_KEY = "YOUR_API_KEY"

def isolate_host(hostname):
    print(f"[*] Attempting to isolate host: {hostname}")
    
    # 1. Get Device ID from Hostname
    search_url = f"{EDR_API_URL}/devices?filter=hostname:'{hostname}'"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    try:
        response = requests.get(search_url, headers=headers)
        device_id = response.json()["resources"][0]
        
        # 2. Trigger Isolation
        isolate_url = f"{EDR_API_URL}/devices/actions/contain/v1"
        payload = {"ids": [device_id], "comment": "Automated isolation via SOAR script"}
        
        isolate_response = requests.post(isolate_url, headers=headers, json=payload)
        
        if isolate_response.status_code == 202:
            print(f"[+] Successfully triggered isolation for {hostname}")
        else:
            print(f"[!] Failed to isolate: {isolate_response.text}")
            
    except Exception as e:
        print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    target = input("Enter hostname to isolate: ")
    isolate_host(target)
