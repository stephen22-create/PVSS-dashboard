import csv
import random
from datetime import datetime, timedelta

# Sample CVE list (mix of real and fake)
CVES = [
    "CVE-2021-44228", "CVE-2022-22965", "CVE-2023-23397", "CVE-2024-6387",
    "CVE-2025-1234", "CVE-2025-5678", "CVE-2026-0222", "CVE-2026-1111",
    "CVE-2025-9012", "CVE-2024-12345"
]
ASSETS = [
    "192.168.1.100", "192.168.1.101", "10.0.0.50", "10.0.0.51",
    "172.16.1.10", "172.16.1.20", "192.168.2.5", "10.10.10.10"
]
RISKS = ["Critical", "High", "Medium", "Low"]
PROTOCOLS = ["tcp", "udp"]
PORTS = [22, 80, 443, 3389, 445, 1433, 3306, 8080]
PLUGIN_IDS = list(range(10000, 11000))

def random_date(start, end):
    return start + timedelta(days=random.randint(0, (end - start).days))

start_date = datetime(2025, 1, 1)
end_date = datetime(2026, 2, 1)

with open("data/raw/large_nessus.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Plugin ID", "CVE", "CVSS", "Risk", "Host", "Protocol", "Port",
                     "Name", "Synopsis", "Description", "Solution", "First Discovered", "Last Discovered"])
    for i in range(1000):
        row = [
            random.choice(PLUGIN_IDS),
            random.choice(CVES),
            round(random.uniform(4.0, 10.0), 1),
            random.choice(RISKS),
            random.choice(ASSETS),
            random.choice(PROTOCOLS),
            random.choice(PORTS),
            f"Vulnerability {i}",
            "Synopsis here",
            "Description here",
            "Upgrade software",
            random_date(start_date, end_date).strftime("%Y-%m-%d"),
            random_date(start_date, end_date).strftime("%Y-%m-%d")
        ]
        writer.writerow(row)
print("Generated 1000 test vulnerabilities in data/raw/large_nessus.csv")