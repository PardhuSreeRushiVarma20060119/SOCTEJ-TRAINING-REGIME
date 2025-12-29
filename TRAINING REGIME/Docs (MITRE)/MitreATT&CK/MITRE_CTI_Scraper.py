import json
import os
import glob
from pathlib import Path

class MitreIntelligenceScraper:
    def __init__(self, cti_path):
        self.cti_path = cti_path
        self.enterprise_path = os.path.join(cti_path, "enterprise-attack", "enterprise-attack.json")

    def load_data(self):
        print(f"[*] Loading MITRE CTI data from {self.enterprise_path}...")
        with open(self.enterprise_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def get_group_id(self, group_name):
        for obj in self.data["objects"]:
            if obj["type"] == "intrusion-set" and group_name.lower() in obj["name"].lower():
                return obj["id"], obj["name"]
        return None, None

    def get_techniques_for_group(self, group_name):
        group_id, full_name = self.get_group_id(group_name)
        if not group_id:
            print(f"[!] Group '{group_name}' not found.")
            return []

        print(f"[*] Found Group: {full_name} ({group_id})")
        
        # Find relationships where group uses technique
        techniques = []
        technique_ids = []
        
        # Get relationships
        for obj in self.data["objects"]:
            if obj["type"] == "relationship" and obj["source_ref"] == group_id and obj["target_ref"].startswith("attack-pattern"):
                technique_ids.append(obj["target_ref"])

        # Map IDs to Names
        for tid in technique_ids:
            for obj in self.data["objects"]:
                if obj["id"] == tid:
                    techniques.append({
                        "id": obj["external_references"][0]["external_id"],
                        "name": obj["name"],
                        "description": obj.get("description", "")[:100] + "..."
                    })
        
        return techniques

    def generate_soc_playbook(self, group_name):
        techniques = self.get_techniques_for_group(group_name)
        if not techniques:
            return

        filename = f"Playbook_{group_name.replace(' ', '_')}.md"
        with open(filename, "w") as f:
            f.write(f"# 🛡️ SOC COMBAT PLAYBOOK: {group_name.upper()}\n")
            f.write(f"*Extracted from MITRE CTI Repository*\n\n")
            f.write("| MITRE ID | Technique Name | Description |\n")
            f.write("| :--- | :--- | :--- |\n")
            for t in techniques:
                f.write(f"| {t['id']} | {t['name']} | {t['description']} |\n")
        
        print(f"[+] Playbook generated: {filename}")

if __name__ == "__main__":
    # Path to the user's cloned CTI repo
    CTI_REPO_PATH = "c:\\Users\\pardh\\Downloads\\TEJU INTENSIVE TRAINING\\cti"
    
    scraper = MitreIntelligenceScraper(CTI_REPO_PATH)
    scraper.load_data()
    
    # Example: Generate playbook for APT29
    scraper.generate_soc_playbook("APT29")
    # Example: Generate playbook for Lazarus Group
    scraper.generate_soc_playbook("Lazarus Group")
