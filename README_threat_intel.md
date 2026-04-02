# 🌐 Threat Intel Aggregator Dashboard

> **Single command. Multiple threat intel sources. Unified IOC scoring.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-red)](https://abuseipdb.com)
[![OTX](https://img.shields.io/badge/API-AlienVault%20OTX-green)](https://otx.alienvault.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## What it does

Aggregates threat intelligence from **AbuseIPDB** and **AlienVault OTX** for any IP, domain, or file hash. Outputs a color-coded terminal dashboard with unified severity scoring, and exports to CSV or JSON for SIEM ingestion or shift-log documentation.

---

## Features

- **Multi-source lookup** — AbuseIPDB + AlienVault OTX in a single command
- **Auto-detects IOC type** — IP address, domain, or file hash
- **Unified severity scoring** — 0–100 score aggregated from both sources
- **Batch mode** — feed a text file with one IOC per line
- **TOR exit node detection** — flagged automatically via AbuseIPDB
- **OTX pulse correlation** — shows which threat intel campaigns the IOC appears in
- **CSV export** — shift-log and SIEM-ready format
- **JSON export** — raw data for SOAR playbook integration

---

## Quickstart

```bash
git clone https://github.com/vinith-sec/threat-intel-dashboard.git
cd threat-intel-dashboard
pip install -r requirements.txt

# Set API keys (both are free)
export ABUSEIPDB_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"

# Single IOC lookup
python threat_intel.py --ioc 91.108.4.18

# Domain lookup
python threat_intel.py --ioc malicious-domain.ru

# File hash lookup
python threat_intel.py --ioc 44d88612fea8a8f36de82e1278abb02f

# Batch lookup from file
python threat_intel.py --file iocs.txt

# Export results
python threat_intel.py --file iocs.txt --export-csv results.csv --export-json results.json
```

---

## Example output

```
======================================================================
  THREAT INTEL AGGREGATOR DASHBOARD
  Generated: 2025-04-01 14:41 UTC
======================================================================

🔴 [CRITICAL] 91.108.4.18  (Score: 92/100)
   Type: IP
   ⚠  AbuseIPDB confidence 96% (HIGH)
   ⚠  TOR exit node
   ⚠  Found in 14 OTX threat intelligence pulse(s)
   [AbuseIPDB] Confidence: 96% | ISP: Frantech Solutions | Country: NL | TOR: True
   [OTX] Pulses: 14 | Related: Cobalt Strike C2, APT28 Infrastructure

🟡 [MEDIUM] suspicious-domain.ru  (Score: 35/100)
   Type: DOMAIN
   ⚠  Found in 3 OTX threat intelligence pulse(s)
   [OTX] Pulses: 3 | Related: Phishing Campaign Q1 2025

  SUMMARY — 2 IOCs analyzed
  🔴 CRITICAL: 1
  🟡 MEDIUM: 1
======================================================================
```

---

## Free API keys

| Source | Free tier | Signup |
|---|---|---|
| AbuseIPDB | 1,000 checks/day | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| AlienVault OTX | Unlimited (rate limited) | [otx.alienvault.com](https://otx.alienvault.com/accounts/register) |

---

## IOC file format

```
# iocs.txt — one per line, # for comments
185.220.101.47
malicious-cdn.ru
44d88612fea8a8f36de82e1278abb02f
91.108.4.18
```

---

## Project structure

```
threat-intel-dashboard/
├── threat_intel.py    # Main engine
├── iocs_sample.txt    # Sample IOC list for testing
├── requirements.txt
└── README.md
```

---

## Author

**Vinith Kumaragurubaran** — SOC Analyst | CompTIA Security+ | Cisco CCNA  
[linkedin.com/in/vinith-kumaragurubaran](https://linkedin.com/in/vinith-kumaragurubaran) · [github.com/vinith-sec](https://github.com/vinith-sec)
