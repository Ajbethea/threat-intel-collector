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
  - `malicious` (True/False based on rules)
  - Error fields (`otx_error`) when APIs fail or time out
- Outputs final results to `findings_enriched.csv`

---

## 🧪 End-to-End Threat Analysis Pipeline

This project simulates a full SOC workflow, starting with raw logs and ending with enriched threat intelligence.

---

### 1. Log Parsing (`log_parser.py`)

- Reads SSH logs from `sample_logs/ssh.log`
- Applies configurable detection rules from `config.json`
- Flags suspicious behavior (e.g., repeated failed SSH logins)
- Writes structured findings to:

```bash
python log_parser.py --config config.json --report_csv output/findings.csv
```

---

### 2. Threat Intelligence Enrichment (`threat_checker.py`)

- Reads parsed detections from `findings.csv`
- Queries threat intel sources:
  - **AbuseIPDB** → reputation score + report count  
  - **AlienVault OTX** → pulse associations  
- Adds enrichment fields:
  - `abuseipdb_score`
  - `abuseipdb_reports`
  - `otx_pulses`
  - `otx_error`
  - `malicious`
- Writes: `findings_enriched.csv`

Run with:

```bash
python threat_checker.py
```

Example enriched row:

```
timestamp,source,ip,abuseipdb_score,abuseipdb_reports,otx_error,malicious
2025-11-09,...,185.220.101.1,100,181,"HTTPSConnectionPool... timed out",True
```

---

## 📊 Architecture Diagram

```
                   ┌───────────────────────────┐
                   │       Raw Log Files       │
                   │  (sample_logs/ssh.log)    │
                   └──────────────┬────────────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │      Log Parser        │
                     │    (log_parser.py)     │
                     ├────────────────────────┤
                     │ - Applies rules        │
                     │ - Extracts indicators  │
                     │ - Flags SSH brute force│
                     └──────────────┬─────────┘
                                  │
                                  ▼
                   ┌──────────────────────────┐
                   │       findings.csv       │
                   │ Parsed security events   │
                   └──────────────┬──────────┘
                                  │
                                  ▼
                  ┌───────────────────────────┐
                  │   Threat Intel Collector  │
                  │     (threat_checker.py)   │
                  ├───────────────────────────┤
                  │ - AbuseIPDB reputation    │
                  │ - OTX pulse lookups       │
                  │ - Error/timeout handling  │
                  │ - Malicious verdict       │
                  └──────────────┬────────────┘
                                  │
                                  ▼
                 ┌────────────────────────────┐
                 │    findings_enriched.csv   │
                 │ Final threat-enriched IOCs │
                 └────────────────────────────┘
```

---

## 📂 Project Files

| File                     | Purpose                                               |
|--------------------------|-------------------------------------------------------|
| `log_parser.py`          | Parses raw SSH logs using defined detection rules     |
| `config.json`            | Defines log sources, patterns, rules                  |
| `sample_logs/ssh.log`    | Sample SSH log input used to simulate brute-force     |
| `findings.csv`           | Structured detections from log parser                 |
| `threat_checker.py`      | Enriches IPs via AbuseIPDB & OTX                      |
| `findings_enriched.csv`  | Final enriched IOC output                             |
| `api_sample_output.json` | Example API output (safe for GitHub)                  |
| `README.md`              | Project documentation                                 |

---

## 🛠️ Skills Demonstrated

- Python scripting (3.11+)
- Log parsing & regex
- Security alert detection logic
- API integration (AbuseIPDB & OTX)
- Error handling & timeouts
- CSV processing & pipeline building
- Threat intelligence analysis
- Building end-to-end SOC automation workflows

---

## 🚀 How to Run the Entire Pipeline

### **1. Parse logs**
```bash
python log_parser.py --config config.json --report_csv output/findings.csv
```

### **2. Copy parsed CSV to project root**
```bash
copy output/findings.csv findings.csv
```

### **3. Enrich with threat intel**
```bash
python threat_checker.py
```

### **4. View enriched results**
```bash
Get-Content findings_enriched.csv
```

---

## 📅 Project Metadata (For LinkedIn / Resume)

- **Project Name:** Threat Intel Collector (Beginner API Project)
- **Start Date:** November 2025  
- **End Date:** November 2025  
- **Role:** Security Analyst / Automations Developer  
- **Skills:** Python, Threat Intelligence, API Integration, Log Analysis, SOC Automation  
- **Associated Experience:** *Mr. B’s Cybersecurity Projects / SOC Portfolio Build*  
- **Contributors:** Altion Bethea (Ajbethea)

---


