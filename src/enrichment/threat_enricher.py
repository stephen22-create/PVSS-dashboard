import csv
from typing import Set, Dict

def load_kev_set(kev_path: str) -> Set[str]:
    kev_set = set()
    with open(kev_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get('cveID', '') or row.get('CVE ID', '')
            if cve:
                kev_set.add(cve.strip())
    return kev_set

def load_poc_set(poc_path: str) -> Set[str]:
    poc_set = set()
    with open(poc_path, mode='r', encoding='utf-8') as f:
        for line in f:
            cve = line.strip()
            if cve:
                poc_set.add(cve)
    return poc_set

def enrich_with_threat_intel(vuln: Dict, kev_set: Set[str], poc_set: Set[str]) -> Dict:
    cve = vuln.get('cve_id', '')
    if cve in kev_set:
        vuln['is_actively_exploited'] = True
        vuln['has_public_poc'] = False
        vuln['exploit_multiplier'] = 2.0
    elif cve in poc_set:
        vuln['is_actively_exploited'] = False
        vuln['has_public_poc'] = True
        vuln['exploit_multiplier'] = 1.5
    else:
        vuln['is_actively_exploited'] = False
        vuln['has_public_poc'] = False
        vuln['exploit_multiplier'] = 1.0
    return vuln