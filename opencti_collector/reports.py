import requests
import json
import os
import re

class OpenCTIGraphQLFetcher:
    def __init__(self, api_url, api_token, output_path="report.json", ip_output_path="extracted_ips.json"):
        self.api_url = api_url.rstrip("/") + "/graphql"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.output_path = output_path
        self.ip_output_path = ip_output_path

    def fetch_reports(self, limit=10000):
        all_reports = []
        has_next = True
        after_cursor = None

        while has_next and len(all_reports) < limit:
            query = '''
            query GetReports($first: Int, $after: ID) {
              reports(first: $first, after: $after) {
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
                    published
                    created
                    createdBy {
                      name
                    }
                    objectMarking {
                      definition
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

            if "data" not in result or "reports" not in result["data"]:
                print("[!] Invalid GraphQL response format:")
                print(json.dumps(result, indent=2))
                break

            report_data = result["data"]["reports"]
            edges = report_data["edges"]

            for edge in edges:
                all_reports.append(edge["node"])

            print(f"[-] Fetched {len(edges)} reports (Total: {len(all_reports)})")

            page_info = report_data["pageInfo"]
            has_next = page_info["hasNextPage"]
            after_cursor = page_info["endCursor"]

        if all_reports:
            os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(all_reports, f, ensure_ascii=False, indent=2)
            print(f"[✓] Saved {len(all_reports)} reports to {self.output_path}")

            self.extract_ips(all_reports)
        else:
            print("[!] No reports fetched.")

    def extract_ips(self, reports):
        ip_pattern = re.compile(
            r"\b(?:(?:2(?:5[0-5]|[0-4]\d))|(?:1\d{2})|(?:[1-9]?\d))"
            r"(?:\.(?:(?:2(?:5[0-5]|[0-4]\d))|(?:1\d{2})|(?:[1-9]?\d))){3}\b"
        )

        ip_set = set()

        for report in reports:
            fields_to_check = []

            # Basic fields
            fields_to_check.append(report.get("name", ""))
            fields_to_check.append(report.get("description", ""))

            # createdBy.name
            if report.get("createdBy"):
                fields_to_check.append(report["createdBy"].get("name", ""))

            # objectMarking[].definition
            for marking in report.get("objectMarking", []):
                fields_to_check.append(marking.get("definition", ""))

            # objectLabel[].value
            for label in report.get("objectLabel", []):
                fields_to_check.append(label.get("value", ""))

            # Search IPs in all extracted text fields
            for text in fields_to_check:
                found_ips = ip_pattern.findall(text)
                ip_set.update(found_ips)

        ip_list = sorted(ip_set)

        with open(self.ip_output_path, "w", encoding="utf-8") as f:
            json.dump(ip_list, f, ensure_ascii=False, indent=2)

        print(f"[✓] Extracted {len(ip_list)} unique IPv4 addresses from all fields to {self.ip_output_path}")


if __name__ == "__main__":
    API_URL = "http://localhost:8080"
    API_TOKEN = "change_me"
    OUTPUT_PATH = "your_path"
    IP_OUTPUT_PATH = "your_path"

    fetcher = OpenCTIGraphQLFetcher(API_URL, API_TOKEN, OUTPUT_PATH, IP_OUTPUT_PATH)
    fetcher.fetch_reports()
