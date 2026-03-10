import json
import os

def calculate_pvs(vuln: dict) -> float:
    """
    Calculate Point Vulnerability Score using the formula:
    PVS = cvss_score * exploit_multiplier * asset_criticality * exposure_factor * temporal_decay
    """
    cvss = vuln.get('cvss_score', 0.0)
    exploit = vuln.get('exploit_multiplier', 1.0)
    criticality = vuln.get('asset_criticality', 1.0)
    exposure = vuln.get('exposure_factor', 1.0)
    decay = vuln.get('temporal_decay', 1.0)
    
    pvs = cvss * exploit * criticality * exposure * decay
    # Cap at theoretical maximum 72.0 (optional)
    pvs = min(round(pvs, 2), 72.0)
    return pvs

def score_all(input_file: str = "data/enriched/enriched_vulns.json",
              output_file: str = "data/scored/scored_vulns.json"):
    """
    Load enriched vulnerabilities, calculate PVS, sort, and save.
    """
    with open(input_file, 'r') as f:
        vulns = json.load(f)
    
    for vuln in vulns:
        vuln['pvs'] = calculate_pvs(vuln)
    
    # Sort by PVS descending
    vulns.sort(key=lambda x: x['pvs'], reverse=True)
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(vulns, f, indent=2)
    
    print(f"Scored {len(vulns)} vulnerabilities.")
    print(f"Top PVS: {vulns[0]['pvs'] if vulns else 'N/A'}")
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    score_all()