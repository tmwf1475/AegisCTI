import requests
import json
import os
import re

class OpenCTIIntrusionSetFetcher:
    def __init__(self, api_url, api_token, output_path="intrusion_sets.json", ip_output_path="intrusion_ips.json"):
        self.api_url = api_url.rstrip("/") + "/graphql"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.output_path = output_path
        self.ip_output_path = ip_output_path

    def fetch_intrusion_sets(self, limit=10000):
        all_sets = []
        has_next = True
        after_cursor = None

        while has_next and len(all_sets) < limit:
            query = '''
            query GetIntrusionSets($first: Int, $after: ID) {
              intrusionSets(first: $first, after: $after) {
                pageInfo {
                  endCursor
                  hasNextPage
                }
                edges {
                  node {
                    id
                    name
                    description
                    confidence
                    created
                    modified
                    createdBy {
                      name
                    }
                    objectLabel {
                      value
                    }
                  }
                }
              }
            }
            '''

            variables = {
                "first": 200,
                "after": after_cursor
            }

            response = requests.post(
                self.api_url,
                headers=self.headers,
                json={"query": query, "variables": variables}
            )

            try:
                result = response.json()
            except Exception as e:
                print("[!] Failed to parse response as JSON:")
                print(response.text)
                break

            if "errors" in result:
                print("[!] GraphQL returned errors:")
                print(json.dumps(result["errors"], indent=2))
                break

            if "data" not in result or "intrusionSets" not in result["data"]:
                print("[!] Invalid GraphQL response format:")
                print(json.dumps(result, indent=2))
                break

            data = result["data"]["intrusionSets"]
            edges = data["edges"]

            for edge in edges:
                all_sets.append(edge["node"])

            print(f"[-] Fetched {len(edges)} intrusion sets (Total: {len(all_sets)})")

            page_info = data["pageInfo"]
            has_next = page_info["hasNextPage"]
            after_cursor = page_info["endCursor"]

        if all_sets:
            os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(all_sets, f, ensure_ascii=False, indent=2)
            print(f"[✓] Saved {len(all_sets)} intrusion sets to {self.output_path}")
            self.extract_ips(all_sets)
        else:
            print("[!] No intrusion sets fetched.")

    def extract_ips(self, intrusion_sets):
        ip_pattern = re.compile(
            r"\b(?:(?:2(?:5[0-5]|[0-4]\d))|(?:1\d{2})|(?:[1-9]?\d))"
            r"(?:\.(?:(?:2(?:5[0-5]|[0-4]\d))|(?:1\d{2})|(?:[1-9]?\d))){3}\b"
        )

        ip_set = set()

        for entry in intrusion_sets:
            fields_to_check = [
                entry.get("name", ""),
                entry.get("description", ""),
            ]

            if entry.get("createdBy"):
                fields_to_check.append(entry["createdBy"].get("name", ""))

            for label in entry.get("objectLabel", []):
                fields_to_check.append(label.get("value", ""))

            # 找出所有 IP
            for field in fields_to_check:
                text = str(field) if field else ""
                found_ips = ip_pattern.findall(text)
                ip_set.update(found_ips)

        ip_list = sorted(ip_set)

        with open(self.ip_output_path, "w", encoding="utf-8") as f:
            json.dump(ip_list, f, ensure_ascii=False, indent=2)

        print(f"[✓] Extracted {len(ip_list)} unique IPv4 addresses from Intrusion Sets to {self.ip_output_path}")


if __name__ == "__main__":
    API_URL = "http://localhost:8080"
    API_TOKEN = "change_me"
    OUTPUT_PATH = "your_path"
    IP_OUTPUT_PATH = "your_path"

    fetcher = OpenCTIIntrusionSetFetcher(API_URL, API_TOKEN, OUTPUT_PATH, IP_OUTPUT_PATH)
    fetcher.fetch_intrusion_sets()
