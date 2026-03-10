from typing import Dict

def enrich_with_temporal(vuln: Dict) -> Dict:
    # For now, use a fixed decay factor (you can enhance later)
    vuln['temporal_decay'] = 1.0
    return vuln