import os
import json
from .nessus_parser import parse_nessus_csv

def normalize_all(raw_dir: str = "data/raw", output_dir: str = "data/normalized"):
    """
    Process all CSV files in raw_dir and save normalized JSON to output_dir.
    """
    os.makedirs(output_dir, exist_ok=True)
    all_records = []

    for filename in os.listdir(raw_dir):
        if filename.endswith(".csv"):
            file_path = os.path.join(raw_dir, filename)
            print(f"Processing {filename}...")
            if "nessus" in filename.lower():
                records = parse_nessus_csv(file_path)
                all_records.extend(records)
            # Add more parsers later (Qualys, etc.)

    # Save all normalized records as JSON
    output_file = os.path.join(output_dir, "normalized_vulns.json")
    with open(output_file, 'w') as f:
        json.dump(all_records, f, indent=2)
    print(f"Saved {len(all_records)} normalized records to {output_file}")

if __name__ == "__main__":
    normalize_all()