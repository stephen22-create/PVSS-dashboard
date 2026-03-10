import os
import json
from src.enrichment.asset_enricher import load_asset_inventory, enrich_with_asset
from src.enrichment.threat_enricher import load_kev_set, load_poc_set, enrich_with_threat_intel
from src.enrichment.exposure_enricher import enrich_with_exposure
from src.enrichment.temporal_enricher import enrich_with_temporal

def run_enrichment(
    input_file: str = "data/normalized/normalized_vulns.json",
    asset_inventory_path: str = "data/asset_inventory.csv",
    kev_path: str = "data/threat_intel/kev.csv",
    poc_path: str = "data/threat_intel/poc_cves.txt",
    output_file: str = "data/enriched/enriched_vulns.json"
):
    # Load asset inventory
    assets = load_asset_inventory(asset_inventory_path)
    
    # Load threat intel
    kev_set = load_kev_set(kev_path)
    poc_set = load_poc_set(poc_path)
    
    # Load normalized vulnerabilities
    with open(input_file, 'r') as f:
        vulns = json.load(f)
    
    enriched_vulns = []
    for vuln in vulns:
        vuln = enrich_with_asset(vuln, assets)
        vuln = enrich_with_threat_intel(vuln, kev_set, poc_set)
        vuln = enrich_with_exposure(vuln)
        vuln = enrich_with_temporal(vuln)
        enriched_vulns.append(vuln)
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(enriched_vulns, f, indent=2)
    
    print(f"Enriched {len(enriched_vulns)} vulnerabilities -> {output_file}")

if __name__ == "__main__":
    run_enrichment()