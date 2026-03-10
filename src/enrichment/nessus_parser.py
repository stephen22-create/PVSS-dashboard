import csv
from typing import List, Dict

def parse_nessus_csv(file_path: str) -> List[Dict]:
    """
    Reads a Nessus CSV export and returns a list of vulnerability records.
    Each record is a dictionary with normalized field names.
    """
    records = []
    with open(file_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Build a normalized record (Universal Vulnerability Record - UVR)
            record = {
                "vuln_id": f"Nessus-{row['Plugin ID']}-{row['Host']}",
                "cve_id": row.get('CVE', '') if row.get('CVE') else None,
                "scanner": "nessus",
                "scanner_severity": row.get('Risk', ''),
                "cvss_score": float(row.get('CVSS', 0) or 0),
                "asset_ip": row.get('Host', ''),
                "protocol": row.get('Protocol', ''),
                "port": row.get('Port', ''),
                "name": row.get('Name', ''),
                "description": row.get('Synopsis', ''),
                "solution": row.get('Solution', ''),
                "first_seen": row.get('First Discovered', ''),
                "last_seen": row.get('Last Discovered', ''),
                "plugin_id": row.get('Plugin ID', '')
            }
            records.append(record)
    return records