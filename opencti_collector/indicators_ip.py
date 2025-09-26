import requests
import json
import os
import re
from datetime import datetime, timedelta, timezone


class OpenCTIIndicatorFetcher:
    def __init__(self, api_url, api_token, output_dir="./opencti_exports/indicators"):
        self.api_url = api_url.rstrip("/") + "/graphql"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        now = datetime.now(timezone.utc)
        self.time_to = now
        self.time_from = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

        print(f"Fetching indicators from {self.time_from.isoformat()} to {self.time_to.isoformat()}")

    def fetch_indicators(self):
        all_indicators = []
        has_next = True
        after_cursor = None

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
                print(f"Request failed: {e}")
                break

            if "errors" in result:
                print("GraphQL returned errors:")
                print(json.dumps(result["errors"], indent=2))
                break

            indicators_data = result.get("data", {}).get("indicators", {})
            edges = indicators_data.get("edges", [])
            page_info = indicators_data.get("pageInfo", {})

            for edge in edges:
                node = edge["node"]
                created = node.get("created")
                if created:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if self.time_from <= created_dt <= self.time_to:
                        all_indicators.append(node)

            print(f"Fetched {len(edges)} entries (Filtered matching: {len(all_indicators)})")
            has_next = page_info.get("hasNextPage", False)
            after_cursor = page_info.get("endCursor")

        if all_indicators:
            self._save_json("indicators_raw.json", all_indicators)
            print(f"Extracting IPv4 addresses (with duplicates)...")
            self.extract_ipv4s(all_indicators)
        else:
            print("No indicators fetched in the specified time range.")

    def extract_ipv4s(self, indicators):
        ipv4_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?\d{1,2})$"
        )

        ipv4_list = []

        for ind in indicators:
            name = ind.get("name", "")
            if ipv4_pattern.match(name):
                record = {
                    "ip": name,
                    "indicator_id": ind.get("id"),
                    "standard_id": ind.get("standard_id"),
                    "description": ind.get("description"),
                    "pattern_type": ind.get("pattern_type"),
                    "pattern": ind.get("pattern"),
                    "indicator_types": ind.get("indicator_types"),
                    "created": ind.get("created"),
                    "modified": ind.get("modified"),
                    "valid_from": ind.get("valid_from"),
                    "valid_until": ind.get("valid_until"),
                    "revoked": ind.get("revoked"),
                    "confidence": ind.get("confidence"),
                    "x_opencti_detection": ind.get("x_opencti_detection"),
                    "source": ind.get("createdBy", {}).get("name", "unknown"),
                    "labels": [label["value"] for label in ind.get("objectLabel", [])],
                    "marking": [mark["definition"] for mark in ind.get("objectMarking", [])]
                }
                ipv4_list.append(record)

        now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._save_json(f"ip_dailyupdate/indicators_ipv4_dailyupdate_{now_str}.json", ipv4_list)
        print(f"Extracted {len(ipv4_list)} IPv4 entries (with duplicates)")

    def _save_json(self, filename, data):
        path = os.path.join(self.output_dir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    API_URL = "http://localhost:8080"
    API_TOKEN = "change_me"

    fetcher = OpenCTIIndicatorFetcher(API_URL, API_TOKEN)
    fetcher.fetch_indicators()
