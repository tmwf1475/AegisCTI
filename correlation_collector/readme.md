# Threat Intelligence Correlation & Enrichment Toolkit

### *OpenCTI + OSINT + External Intelligence APIs*

This repository provides a modular and automated framework for **collecting, enriching, correlating, and analyzing IP and domain threat intelligence**.
It integrates data from:

* **OpenCTI** (Indicators, Observables, Reports)
* **OSINT URL/Domain Feeds** (OpenPhish, URLhaus, BlockListProject, etc.)
* **External Intelligence APIs** (VirusTotal, AbuseIPDB, AlienVault OTX)

The toolkit produces enriched datasets, analytics reports, and can write intelligence **back into OpenCTI**.


## Core Features

* **Automated IP intelligence enrichment** (VT / AbuseIPDB / OTX)
* **Domain intelligence pipeline** (OSINT collection → DNS/WHOIS → scoring → external enrichment → clustering)
* **Rate-limit aware backlog processors** with API key rotation
* **Risk scoring (DMS), verdict classification, prioritization**
* **Consolidated JSON enrichment output**
* **Statistical reports + clustering + time-series analysis**
* **Optional OpenCTI write-back (Indicators, Observables, Reports)**

Designed for high-volume, continuously updated threat data environments.

## Repository Structure

```
correlation_collector/
│
├── Backlog_Data/                     ← External API backlog processors (IP)
│     ├── backlog_abuse.py
│     ├── backlog_alienvault.py
│     └── backlog_virustotal.py
│
├── Collect_Data/                     ← OpenCTI data extraction
│     ├── opencti_enrich.py
│     └── plan_ips.py
│
├── Data_Compilation/                 ← Consolidation & OpenCTI write-back
│     ├── build_enriched_json_all.py
│     └── write_back.py
│
├── Data_Count/                       ← Statistical counting scripts
│     ├── indicators_count.py
│     └── ioc_count.py
│
└── Domain_Data/                      ← Domain intelligence pipeline (NEW)
      ├── domain_collector.py         ← OSINT feed collection + local analysis
      ├── enrich_domain.py            ← VT + OTX + AbuseIPDB enrichment
      └── domain_analyze.py           ← Clustering + time-series + report
```

## Module Overview

### 1. Collect_Data — OpenCTI Extraction

| File                  | Description                                                                        |
| --------------------- | ---------------------------------------------------------------------------------- |
| **plan_ips.py**       | Pulls newly created/updated IP observables from OpenCTI within a time window.      |
| **opencti_enrich.py** | Exports OpenCTI objects (Indicators, Observables, Reports) for offline enrichment. |


### 2. Backlog_Data — External API Backlog (IP Enrichment)

Each script reads pending IPs from backlog storage (SQLite), calls APIs respecting rate limits, rotates keys when needed, and stores results in daily JSONL files.

| Module                    | Intelligence Source                              |
| ------------------------- | ------------------------------------------------ |
| **backlog_abuse.py**      | AbuseIPDB (IP reputation, reports, ISP metadata) |
| **backlog_alienvault.py** | AlienVault OTX (pulses, tags, reputation)        |
| **backlog_virustotal.py** | VirusTotal IP analysis                           |

**Features:**

* Automatic API key rotation
* Caching (skip previously enriched IPs)
* Prioritized enrichment (risk-based, freshness-based)
* Daily output logs

### 3. Domain_Data — Domain Intelligence Pipeline (New)

#### 3.1 domain_collector.py — OSINT Collection + Local Analysis

Collects URLs/domains from:

* OpenPhish
* URLhaus
* BlockListProject (phishing, malware)
* AdGuard Malware
* Disconnect.me
* StevenBlack hosts

Extracts domains and performs:

* WHOIS lookup (age)
* DNS A/NS/MX resolution
* Domain entropy calculation
* Phishing keyword detection
* TLD risk evaluation

Computes **DMS (Domain Malicious Score)** + verdict
Outputs:

```
domains_with_data.jsonl
domains_no_data.jsonl
domains_all.jsonl
```

#### 3.2 enrich_domain.py — VT / AbuseIPDB / OTX Domain Enrichment

Enhances domains using:

* **VirusTotal** (domain reputation, analysis stats)
* **AbuseIPDB** (based on A-record IPs; Cloudflare NS skipped)
* **AlienVault OTX** (general domain info)

Key features:

* API key rotation
* Refresh intervals
* Risk-based prioritization
* Output saved to:

```
domains_all_enriched.jsonl
```

#### 3.3 domain_analyze.py — Clustering & Reporting

Outputs:

* **clusters.csv** (KMeans on DMS, entropy, URL count, VT stats, etc.)
* **timeseries.csv** (IOC/first-seen trends)
* **domain_report.md** (summary + stats)


### 4. Data_Compilation — Merging & OpenCTI Write-Back

| File                           | Description                                                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------ |
| **build_enriched_json_all.py** | Merges all IP enrichment results (VT + OTX + AbuseIPDB) into a single `enriched_ips.json`. |
| **write_back.py**              | Writes enriched intelligence back into OpenCTI (Observables, Indicators, Reports).         |


### 5. Data_Count — Statistics & Utilities

* **indicators_count.py** — count indicators by type
* **ioc_count.py** — observable statistics

## End-to-End Workflows

### A. IP Enrichment Workflow

```bash
# 1. Fetch new IPs from OpenCTI
python3 plan_ips.py

# 2. Run backlogs for external enrichment
python3 backlog_abuse.py
python3 backlog_alienvault.py
python3 backlog_virustotal.py

# 3. Merge results
python3 build_enriched_json_all.py

# 4. Write enriched data back into OpenCTI
python3 write_back.py
```

### B. Domain Intelligence Workflow

```bash
# 1. Collect OSINT domains + perform local analysis
python3 domain_collector.py

# 2. Enrich high-risk domains with VT / OTX / AbuseIPDB
python3 enrich_domain.py

# 3. Run clustering + reporting
python3 domain_analyze.py
```

## Installation

```
pip install -r requirements.txt
```

Required Python packages include:

```
requests
pycti
python-dotenv
tldextract
dnspython
python-whois
pandas
scikit-learn
```

## Environment Variables

```
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your_token
```

#### External API keys:

* VirusTotal
* AbuseIPDB
* AlienVault OTX

##  Output Files

```
opencti_output/
  ├── ip_out/
  ├── domain_out/
  │     ├── domains_all.jsonl
  │     ├── domains_all_enriched.jsonl
  │     ├── clusters.csv
  │     ├── timeseries.csv
  │     └── domain_report.md
  ├── enriched_ips.json
  └── reports.json
```

## Summary

This repository implements a complete pipeline for **IP and Domain Threat Intelligence**, providing:

* Automated multi-source data collection
* Smart risk-based enrichment
* Consolidated intelligence datasets
* Domain clustering & analytics
* Integration with OpenCTI

It is designed for security research teams, CTI analysts, SOC automation, and large-scale threat hunting operations.
