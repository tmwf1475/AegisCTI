import time
import re
import requests
from datetime import datetime, timezone
from stix2 import IPv4Address, Indicator, Bundle
from pycti import OpenCTIConnectorHelper
from external_import_connector.config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix

class ConnectorIPSUM:
    def __init__(self):
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.config_dict)
        self.converter_to_stix = ConverterToStix(self.config, self.helper)

        identity = self.helper.api.identity.read(name="IPsum")
        if identity is None:
            identity = self.helper.api.identity.create(
                type="Organization",
                name="IPsum",
                description="Imported from Ipsum threat feed"
            )
        self.created_by_ref = identity["id"]


    def _calculate_confidence_and_score(self, count: int) -> int:
        if count >= 10:
            return 90
        elif count == 9:
            return 80
        elif count == 8:
            return 75
        elif count == 7:
            return 70
        elif count == 6:
            return 65
        elif count == 5:
            return 60
        else:
            return 50

    def _collect_intelligence(self) -> list:
        stix_objects = []
        url = "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"
        try:
            response = requests.get(url)
            lines = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            self.helper.log_info(f"[FETCH] Got {len(lines)} lines from Ipsum.")
            self.helper.log_info(f"[FETCH] First 5 lines: {lines[:5]}")
        except Exception as err:
            self.helper.log_error(f"[FETCH ERROR] Failed to fetch or parse Ipsum list: {err}")
            return []

        for line in lines:
            try:
                ip, count_str = line.split("\t")
                count = int(count_str)
                if count < 5:
                    continue
                score = self._calculate_confidence_and_score(count)
                observable = IPv4Address(value=ip)
                indicator = Indicator(
                    name=f"{ip}",
                    description=f"Malicious IP reported by Ipsum. Number of (black) lists is : {count}",
                    indicator_types=["malicious-activity"],
                    pattern_type="stix",
                    pattern=f"[ipv4-addr:value = '{ip}']",
                    valid_from=datetime.utcnow().replace(tzinfo=timezone.utc),
                    confidence=score,
                    labels=["malicious-activity", "ipsum"],
                    custom_properties={
                        "x_opencti_created_by_ref": self.created_by_ref
                    }
                )
                stix_objects.append(observable)
                stix_objects.append(indicator)
            except Exception as err:
                self.helper.log_error(f"[STIX ERROR] Failed to parse or create STIX for line: {line} | {err}")

        return stix_objects

    def process_message(self, data: dict = None) -> None:
        self.helper.log_info("[PROCESS] IPSUM Connector Running...")
        current_state = self.helper.get_state()
        last_run = None
        if current_state is not None and "last_run" in current_state:
            last_run = datetime.fromisoformat(current_state["last_run"])
            self.helper.connector_logger.info(f"[STATE] Last run at: {last_run}")
        else:
            self.helper.connector_logger.info("[STATE] Connector has never run.")

        try:
            self.helper.connector_logger.info("[PROCESS] Fetching and sending STIX indicators...")
            stix_objs = self._collect_intelligence()
            if stix_objs:
                bundle = Bundle(objects=stix_objs, allow_custom=True)
                self.helper.send_stix2_bundle(bundle.serialize(), update=True)
                self.helper.set_state({"last_run": datetime.utcnow().isoformat()})
                self.helper.log_info(f"[UPLOAD] Sent {len(stix_objs)} indicators to OpenCTI.")
            else:
                self.helper.log_info("[UPLOAD] No indicators to send.")
        except Exception as err:
            self.helper.log_error(f"[PROCESS ERROR] {err}")

    def start(self):
        self.helper.log_info("[START] IPSUM connector starting with interval...")
        self.helper.run(self.process_message, self.config.config_dict.get("connector_run_interval", 21600))

    def run(self):
        self.helper.log_info("[RUN] Running IPSUM connector manually...")
        while True:
            self.process_message()
            self.helper.log_info("[SLEEP] Sleeping for 6 hours...")
            time.sleep(21600)
