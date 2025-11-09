#!/usr/bin/env python3
"""
Threat Intel Collector - Beginner API Project
Reads IPs from findings.csv, enriches them using AbuseIPDB and/or AlienVault OTX,
and outputs an enriched CSV with a "malicious" flag plus basic threat intel fields.
"""

import csv
import os
import sys
import time
import ipaddress
from typing import Dict, Any
import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_URL_TEMPLATE = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (addr.is_private or addr.is_loopback or addr.is_reserved)
    except ValueError:
        return False

def query_abuseipdb(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY or not is_public_ip(ip):
        return {}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        d = r.json().get("data", {})
        return {
            "abuseipdb_score": d.get("abuseConfidenceScore", 0),
            "abuseipdb_reports": d.get("totalReports", 0),
        }
    except Exception as e:
        return {"abuseipdb_error": str(e)}

def query_otx(ip: str) -> Dict[str, Any]:
    if not OTX_API_KEY or not is_public_ip(ip):
        return {}
    url = OTX_URL_TEMPLATE.format(ip=ip)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        d = r.json()
        pulses = d.get("pulse_info", {}).get("count", 0)
        return {"otx_pulses": pulses}
    except Exception as e:
        return {"otx_error": str(e)}

def enrich_ip(ip: str) -> Dict[str, Any]:
    data = {}
    data.update(query_abuseipdb(ip))
    data.update(query_otx(ip))
    score = data.get("abuseipdb_score", 0)
    pulses = data.get("otx_pulses", 0)
    data["malicious"] = (score >= 50 or pulses >= 1)
    return data

def main():
    if not (ABUSEIPDB_API_KEY or OTX_API_KEY):
        print("[!] Missing API keys.")
        sys.exit(1)

    infile = "findings.csv"
    outfile = "findings_enriched.csv"

    # Read input CSV
    with open(infile, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        print("[!] No data rows found in findings.csv")
        sys.exit(1)

    # Enrich each row
    for r in rows:
        ip = (r.get("ip") or "").strip()
        if ip:
            info = enrich_ip(ip)
            r.update(info)

    # Build header from ALL keys across ALL rows
    fieldnames = []
    seen = set()
    # Keep original CSV columns first (if available)
    original_fields = reader.fieldnames or []
    for col in original_fields:
        if col not in seen:
            seen.add(col)
            fieldnames.append(col)
    # Then add any new enrichment/error fields
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.add(k)
                fieldnames.append(k)

    # Write enriched CSV
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] Wrote enriched file to {outfile}")


if __name__ == "__main__":
    main()
