import csv
from typing import Dict, List

# Criticality multipliers (from your proposal)
CRITICALITY_MAP = {
    "domain_controller": 1.8,
    "pci_data": 1.6,
    "phi_data": 1.6,
    "email_server": 1.3,
    "web_server": 1.2,
    "database_server": 1.2,
    "file_server": 1.1,
    "workstation": 0.8,
    "development": 0.6,
    "test_lab": 0.4,
    "unknown": 1.0
}

def load_asset_inventory(inventory_path: str) -> Dict[str, Dict]:
    """
    Load asset inventory CSV and return a dictionary keyed by IP.
    Each value contains role, is_internet_facing, is_isolated, data_sensitivity.
    """
    assets = {}
    with open(inventory_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['asset_ip']
            assets[ip] = {
                'role': row['role'],
                'is_internet_facing': row['is_internet_facing'].upper() == 'TRUE',
                'is_isolated': row['is_isolated'].upper() == 'TRUE',
                'data_sensitivity': row['data_sensitivity']
            }
    return assets

def enrich_with_asset(vuln: Dict, assets: Dict[str, Dict]) -> Dict:
    """
    Add asset context to a single vulnerability record.
    """
    ip = vuln.get('asset_ip')
    asset_info = assets.get(ip, {})
    role = asset_info.get('role', 'unknown')
    
    vuln['asset_role'] = role
    vuln['asset_criticality'] = CRITICALITY_MAP.get(role, 1.0)
    vuln['data_sensitivity'] = asset_info.get('data_sensitivity', '')
    vuln['is_internet_facing'] = asset_info.get('is_internet_facing', False)
    vuln['is_isolated'] = asset_info.get('is_isolated', False)
    return vuln