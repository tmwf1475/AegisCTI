import requests
import json
import os
import re

class OpenCTIIndicatorFetcher:
    def __init__(self, api_url, api_token, output_dir="./opencti_exports/indicators"):
        self.api_url = api_url.rstrip("/") + "/graphql"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def fetch_indicators(self):
        all_indicators = []
        has_next = True
        after_cursor = None

        print("[*] Starting indicator fetch...")

        while has_next:
            query = '''
            query GetIndicators($first: Int, $after: ID) {
              indicators(first: $first, after: $after) {
                pageInfo {
                  endCursor
                  hasNextPage
                }
                edges {
                  node {
                    id
                    standard_id
                    name
                    description
                    pattern_type
                    pattern
                    indicator_types
                    created
                    modified
                    valid_from
                    valid_until
                    revoked
                    confidence
                    x_opencti_detection
                    createdBy {
                      name
                    }
                    objectLabel {
                      value
                    }
                    objectMarking {
                      definition
                    }
                  }
                }
              }
            }
            '''

            variables = {
                "first": 1000,
                "after": after_cursor
            }

            try:
                response = requests.post(
                    self.api_url,
                    headers=self.headers,
                    json={"query": query, "variables": variables}
                )
                result = response.json()
            except Exception as e:
                print(f"[!] Failed to fetch or parse: {e}")
                break

            if "errors" in result:
                print("[!] GraphQL returned errors:")
                print(json.dumps(result["errors"], indent=2))
                break

            indicators = result.get("data", {}).get("indicators", {})
            edges = indicators.get("edges", [])
            page_info = indicators.get("pageInfo", {})

            for edge in edges:
                all_indicators.append(edge["node"])

            print(f"[-] Fetched {len(edges)} indicators (Total: {len(all_indicators)})")
            has_next = page_info.get("hasNextPage", False)
            after_cursor = page_info.get("endCursor")

        if all_indicators:
            self._save_json("indicators.json", all_indicators)
            print(f"[✓] Saved {len(all_indicators)} indicators to indicators.json")
            self.extract_iocs(all_indicators)
        else:
            print("[!] No indicators fetched.")

    def extract_iocs(self, indicators):
        print("[*] Extracting IoCs...")
        ipv4_pattern = re.compile(r"\b(?:(?:2(?:5[0-5]|[0-4]\d))|1\d{2}|[1-9]?\d)(?:\.(?:(?:2(?:5[0-5]|[0-4]\d))|1\d{2}|[1-9]?\d)){3}\b")
        ipv6_pattern = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}\b")
        domain_pattern = re.compile(r"value\s*=\s*'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'")
        url_pattern = re.compile(r"value\s*=\s*'((http|https):\/\/[^\s']+)'")
        email_pattern = re.compile(r"value\s*=\s*'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'")
        hash_pattern = re.compile(r"value\s*=\s*'([A-Fa-f0-9]{32,})'")

        ipv4s, ipv6s, domains, urls, emails, hashes = set(), set(), set(), set(), set(), set()

        for ind in indicators:
            pattern = ind.get("pattern", "")

            ipv4s.update(ipv4_pattern.findall(pattern))
            ipv6s.update(ipv6_pattern.findall(pattern))
            domains.update(domain_pattern.findall(pattern))
            urls.update(url_pattern.findall(pattern))
            emails.update(email_pattern.findall(pattern))
            hashes.update(hash_pattern.findall(pattern))

        self._save_json("indicators_ipv4_addresses.json", sorted(ipv4s))
        self._save_json("indicators_ipv6_addresses.json", sorted(ipv6s))
        self._save_json("indicators_domains.json", sorted(domains))
        self._save_json("indicators_urls.json", sorted(urls))
        self._save_json("indicators_emails.json", sorted(emails))
        self._save_json("indicators_hashes.json", sorted(hashes))

        print("[✓] Extracted:")
        print(f"    IPv4:    {len(ipv4s)}")
        print(f"    IPv6:    {len(ipv6s)}")
        print(f"    Domains: {len(domains)}")
        print(f"    URLs:    {len(urls)}")
        print(f"    Emails:  {len(emails)}")
        print(f"    Hashes:  {len(hashes)}")

    def _save_json(self, filename, data):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    API_URL = "http://localhost:8080"
    API_TOKEN = "change_me"

    fetcher = OpenCTIIndicatorFetcher(API_URL, API_TOKEN)
    fetcher.fetch_indicators()
