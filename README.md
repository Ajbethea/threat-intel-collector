# Threat Intel Collector (Beginner API Project)

This project is a simple, real-world style security automation tool.

It reads IP addresses from a CSV file (`findings.csv`), queries public threat intelligence APIs, and outputs an enriched CSV (`findings_enriched.csv`) with a `malicious` flag and supporting intel fields.

---

## What it Does

- Ingests IPs from `findings.csv`
- Queries:
  - AbuseIPDB (`/api/v2/check`)
  - AlienVault OTX (`/api/v1/indicators/IPv4/{ip}/general`)
- Enriches each IP with:
  - `abuseipdb_score`
  - `abuseipdb_reports`
  - `otx_pulses`
  - `malicious` (True/False based on simple rules)
  - Error fields (e.g., `otx_error`) when APIs time out or fail
- Writes results to `findings_enriched.csv`

---

## 🧪 End-to-End Threat Analysis Pipeline

This project simulates a full SOC workflow, starting with raw logs and ending with enriched threat intelligence.

### 1. Log Parsing (`log_parser.py`)

- Reads SSH logs from `sample_logs/ssh.log`
- Applies configurable detection rules from `config.json`
- Flags suspicious behavior (e.g., repeated failed SSH logins)
- Writes structured findings to:

```bash
python log_parser.py --config config.json --report_csv output/findings.csv




