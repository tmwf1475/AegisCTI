# OpenCTI Data Export Scripts

This folder contains multiple **OpenCTI GraphQL fetching scripts** designed to automate the export of various threat intelligence entities and extract relevant IoCs (Indicators of Compromise). These scripts help researchers, SOC teams, and CTI analysts quickly collect structured threat intelligence data, save it as JSON reports, and extract IPs or other observables for further enrichment or integration.

---

## Overview

| File Name              | Description                                                                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Indicators.py**      | Exports all Indicators and extracts IPv4, IPv6, Domains, URLs, Emails, and Hashes.                                                            |
| **Indicators_ip.py**   | Exports Indicators created within the last 24 hours, focusing on IPv4 addresses (including duplicates), and generates timestamped JSON files. |
| **Intrusion_sets.py**  | Exports all Intrusion Sets and extracts IPv4 addresses from names, descriptions, and labels.                                                  |
| **malwares.py**        | Exports all Malware entries and extracts IPv4 addresses from descriptions, labels, and related fields.                                        |
| **reports.py**         | Exports all Reports and extracts IPv4 addresses from multiple fields (name, description, labels, markings, authors).                          |
| **vulnerabilities.py** | Exports all Vulnerabilities and extracts IPv4 addresses from descriptions and labels.                                                         |

---

## Requirements

* Python 3.8+
* Dependencies:

  ```bash
  pip install requests
  ```

---

## Usage

1. **Set API URL and Token**
   Each script includes a `__main__` section with:

   ```python
   API_URL = "http://localhost:8080"
   API_TOKEN = "your-opencti-token"
   ```

   Replace with your actual OpenCTI API URL and token.

2. **Run the script**
   Example: export all Indicators

   ```bash
   python3 Indicators.py
   ```

   Example: daily IPv4 updates

   ```bash
   python3 Indicators_ip.py
   ```

3. **Output**

   * `*.json`: Full raw data from OpenCTI
   * `*_ips.json`, `indicators_ipv4_addresses.json`, etc.: Extracted IoCs

---

## Example Outputs

From `Indicators.py` you will get:

* `indicators.json` – full list of Indicators
* `indicators_ipv4_addresses.json` – extracted IPv4 addresses
* `indicators_domains.json` – extracted Domains
* `indicators_hashes.json` – extracted Hashes
  …and more, depending on the IoC type.

---

## Notes

* Do **not** commit real API tokens to GitHub; use `.env` files or environment variables.
* Each GraphQL query uses a default pagination size (`first=200` or `1000`), which can be adjusted.
* Output directories and filenames can be configured via `output_path`, `ip_output_path`, or `output_dir`.

Do you want me to also create a **unified `fetch_all.py` script** where you can pass an argument (e.g., `--indicators`, `--reports`, `--malware`) instead of running six separate scripts? That would make automation and maintenance easier.
