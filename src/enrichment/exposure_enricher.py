from typing import Dict

def enrich_with_exposure(vuln: Dict) -> Dict:
    if vuln.get('is_internet_facing', False):
        vuln['exposure_factor'] = 2.0
    elif vuln.get('is_isolated', False):
        vuln['exposure_factor'] = 0.5
    else:
        vuln['exposure_factor'] = 1.0
    return vuln