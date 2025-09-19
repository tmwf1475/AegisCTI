# AegisCTI  
**WeiDun-Hub (威盾匯)** — An OpenCTI enrichment hub for large-scale IOC collection, multi-source IP enrichment, and reintegration.

---

## Overview
AegisCTI (WeiDun-Hub) extends OpenCTI with a customized enrichment pipeline designed to process thousands of new observables daily.  
The system focuses on extracting raw IP indicators from OpenCTI, enriching them with external intelligence sources such as **AbuseIPDB**, **AlienVault OTX**, and **VirusTotal**, and reinjecting the consolidated results back into OpenCTI.  

This workflow enables **higher-quality contextualized threat intelligence**, improved tagging for indicators, and better downstream threat hunting and analysis.

---

## Key Features
- **Automated IOC Collection**  
  Fetches new observables from OpenCTI with configurable time windows.  

- **Multi-Source Enrichment**  
  Integrates AbuseIPDB, AlienVault, and VirusTotal for IP reputation and tagging.  

- **Data Consolidation**  
  Merges, deduplicates, and normalizes enrichment results into JSON/CSV formats.  

- **OpenCTI Reintegration**  
  Pushes enriched indicators back into OpenCTI, with dry-run mode supported.  

- **Extensible Architecture**  
  Modular connectors and adapters allow easy integration of new intelligence sources.  

---

## System Workflow
1. **Fetch** observables from OpenCTI.  
2. **Extract** IPv4 addresses for enrichment.  
3. **Enrich** IPs with AbuseIPDB, AlienVault, and VirusTotal.  
4. **Merge & Deduplicate** results, assign tags and metadata.  
5. **Reinject** enriched observables into OpenCTI.  

---

## Quickstart

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/AegisCTI.git
cd AegisCTI
