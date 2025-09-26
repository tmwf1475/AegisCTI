# Threat Intelligence Enrichment Toolkit (OpenCTI + External Feeds)

This repository provides a modular Python-based toolkit for **collecting, enriching, and pushing IP threat intelligence** into OpenCTI.
It integrates with external sources like **AbuseIPDB**, **AlienVault OTX**, and **VirusTotal**, and consolidates results into enriched JSON for further use in OpenCTI.

## Components

| File                           | Purpose                                                                                                                                |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| **backlog_abuse.py**           | Fetches and stores AbuseIPDB enrichment data for IPs. Uses a SQLite backlog to manage pending queries and rate limits.                 |
| **backlog_alienvault.py**      | Fetches AlienVault OTX enrichment data for IPs. Stores results in a SQLite backlog and daily JSONL logs.                               |
| **backlog_virustotal.py**      | Queries VirusTotal for IP reputation and enrichment data. Uses SQLite for backlog and JSONL output.                                    |
| **build_enriched_json_all.py** | Merges daily results from AbuseIPDB, VirusTotal, and AlienVault into a single `enriched_ips.json` file with deduplication and scoring. |
| **indicator_count.py**         | Queries OpenCTI GraphQL for global indicator counts and sample distributions by observable type.                                       |
| **opencti_enrich.py**          | Exports reports, indicators, and observables from OpenCTI (IOC timelines, enrichment input files).                                     |
| **plan_ips.py**                | Extracts newly created or updated IPs from OpenCTI within a time window and saves them as input for enrichment.                        |
| **write_back.py**              | Pushes enriched IP intelligence (`enriched_ips.json`) back into OpenCTI as Observables, Indicators, and Reports.                       |

## Workflow

1. **Plan enrichment targets**

   ```bash
   python3 plan_ips.py
   ```

   * Collects IPs from OpenCTI (based on creation/update window).
   * Saves list of IPs into `ip_output/`.

2. **Run enrichment backlogs**
   For each source, run its backlog processor (can be scheduled via cron):

   ```bash
   python3 backlog_abuse.py
   python3 backlog_alienvault.py
   python3 backlog_virustotal.py
   ```

   * Reads pending IPs.
   * Queries the API (respecting daily caps).
   * Saves results into daily JSONL + SQLite backlog.

3. **Merge enrichments**

   ```bash
   python3 build_enriched_json_all.py
   ```

   * Reads JSONL files from all sources.
   * Deduplicates per IP, selects latest records.
   * Outputs consolidated `enriched_ips.json`.

4. **Write back to OpenCTI**

   ```bash
   python3 write_back.py
   ```

   * Reads `enriched_ips.json`.
   * Creates/updates Observables, Indicators, Reports in OpenCTI.
   * Adds labels (categories, confidence, source refs).

## Requirements

* Python 3.8+
* Install dependencies:

  ```bash
  pip install requests pycti python-dotenv
  ```
* API keys:

  * AbuseIPDB API key(s) in `backlog_abuse.py`
  * AlienVault OTX API key(s) in `backlog_alienvault.py`
  * VirusTotal API key(s) in `backlog_virustotal.py`
* OpenCTI token in `.env` or environment variables:

  ```env
  OPENCTI_URL=http://localhost:8080
  OPENCTI_TOKEN=xxxx
  ```
## Outputs

* **AbuseIPDB** → `AbuseIPDB/abuse_results/abuse_YYYY-MM-DD.jsonl`
* **OTX** → `AlienVault/otx_results/otx_YYYY-MM-DD.jsonl`
* **VirusTotal** → `VirusTotal/vt_results/vt_YYYY-MM-DD.jsonl`
* **Merged** → `enriched_ips.json` (final enriched dataset)
* **OpenCTI exports** → JSONL files under `opencti_output/`

## Example Run

```bash
# Step 1: Fetch IPs from OpenCTI
python3 plan_ips.py

# Step 2: Enrich with AbuseIPDB
python3 backlog_abuse.py

# Step 3: Enrich with AlienVault OTX
python3 backlog_alienvault.py

# Step 4: Enrich with VirusTotal
python3 backlog_virustotal.py

# Step 5: Merge all sources
python3 build_enriched_json_all.py

# Step 6: Push enriched intelligence back to OpenCTI
python3 write_back.py
```

## Notes

* Each backlog script uses SQLite to avoid duplicate queries and to track rate limits.
* Merging keeps **latest valid records** and calculates confidence based on reports/metrics.
* All scripts can be scheduled via **cron** or task schedulers for full automation.
