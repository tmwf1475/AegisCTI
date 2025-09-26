import requests
import csv
import json
from datetime import datetime
from pathlib import Path

def fetch_ipsum(threshold=5, save_format="json", output_path="/home/tmwf/ONIST/docker-compose/test_output"):
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise Exception(f"Failed to fetch ipsum.txt, status code: {response.status_code}")
    
    lines = response.text.splitlines()
    ip_list = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        try:
            ip, score = line.strip().split()
            score = int(score)
            if score >= threshold:
                ip_list.append({"ip": ip, "score": score})
        except ValueError:
            print(f"Skipped invalid line: {line}")
            continue

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ipsum_filtered_{threshold}_{timestamp}.{save_format.lower()}"
    filepath = output_dir / filename

    if save_format == "csv":
        with open(filepath, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["ip", "score"])
            writer.writeheader()
            writer.writerows(ip_list)
    elif save_format == "json":
        with open(filepath, "w") as jsonfile:
            json.dump(ip_list, jsonfile, indent=2)
    else:
        raise ValueError("save_format must be 'csv' or 'json'")

    print(f" Success: Fetched {len(ip_list)} IPs saved to {filepath}")
    return ip_list

if __name__ == "__main__":
    fetch_ipsum(
        threshold=5,
        save_format="json",
        output_path="ipsum_output"
    )

