"""
Standalone OpenCTI IP Pusher (no CLI args)
- Edit the CONFIG section below, then: python opencti_ip_push.py
"""

import os
import sys
import json
import time
import logging
from typing import Dict, Any, List, Optional
from pycti import OpenCTIApiClient  # pip install pycti

# ====================== CONFIG (edit these) ======================
OPENCTI_URL   = os.environ.get("OPENCTI_URL",   "https://your-opencti:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "REPLACE_WITH_YOUR_TOKEN")
INPUT_JSON    = os.environ.get("ENRICHED_IPS_JSON", "/path/to/enriched_ips.json")

CREATOR_ORG   = os.environ.get("CREATOR_ORG", "External Enrichment")
DEFAULT_TLP   = os.environ.get("DEFAULT_TLP", "TLP:GREEN")

VERIFY_SSL    = bool(int(os.environ.get("VERIFY_SSL", "0")))   # 0/1
HTTPS_PROXY   = os.environ.get("HTTPS_PROXY") or None
DRY_RUN       = bool(int(os.environ.get("DRY_RUN", "0")))      # 0/1

LOG_LEVEL     = os.environ.get("LOG_LEVEL", "INFO")            # DEBUG/INFO/WARN/ERROR
MAX_RETRIES   = int(os.environ.get("MAX_RETRIES", "3"))
RETRY_BACKOFF = float(os.environ.get("RETRY_BACKOFF", "0.5"))

# If your OpenCTI is behind a path-based proxy, pycti usually handles it with OPENCTI_URL.

# ---------- logging ----------
LOG = logging.getLogger("opencti_push")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
LOG.addHandler(handler)
LOG.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

def mask(s: Optional[str], keep=6) -> str:
    if not s:
        return ""
    return (s[:keep] + "…") if len(s) > keep else "****"

def load_dotenv_if_exist():
    try:
        from dotenv import load_dotenv  # pip install python-dotenv
        load_dotenv()
        LOG.debug("Loaded .env")
    except Exception:
        pass

def fg(filters=None, mode="and", groups=None):
    """Build FilterGroup compatible with newer OpenCTI schemas (each group has filters & filterGroups)."""
    return {
        "mode": mode if mode in ("and", "or") else "and",
        "filters": [
            {
                "key": f["key"],
                "values": f.get("values", []),
                "operator": f.get("operator", "eq"),
            }
            for f in (filters or [])
        ],
        "filterGroups": groups or [],
    }

class OpenCTIWriter:
    def __init__(
        self,
        url: str,
        token: str,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
        dry_run: bool = False,
        max_retries: int = 3,
        backoff: float = 0.5,
    ):
        self.url = url
        self.token = token
        self.verify_ssl = verify_ssl
        self.dry_run = dry_run
        self.max_retries = max_retries
        self.backoff = backoff

        extra = {}
        if proxy:
            extra["proxies"] = {"http": proxy, "https": proxy}
        extra["ssl_verify"] = verify_ssl

        self.client = OpenCTIApiClient(self.url, self.token, **extra)

        self._label_cache: Dict[str, str] = {}
        self._md_cache: Dict[str, str] = {}
        self._org_cache: Dict[str, str] = {}
        self._indicator_by_pattern: Dict[str, Dict[str, Any]] = {}

    def _call(self, fn, *args, **kwargs):
        if self.dry_run and fn.__name__ not in ("list", "read"):  # safe default
            LOG.debug(f"[DRY-RUN] Skip call {fn.__qualname__} args={args} kwargs={kwargs}")
            return {}
        last_exc = None
        for i in range(self.max_retries):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                last_exc = e
                LOG.warning(f"Call failed ({fn.__qualname__}) try {i+1}/{self.max_retries}: {e}")
                time.sleep(self.backoff * (2 ** i))
        raise last_exc

    # -------- ensure helpers --------
    def ensure_identity_org(self, name: str) -> str:
        if name in self._org_cache:
            return self._org_cache[name]
        found = self._call(
            self.client.identity.list,
            filters=fg([
                {"key": "entity_type", "values": ["Organization"]},
                {"key": "name", "values": [name]},
            ]),
            first=1
        )
        if found:
            self._org_cache[name] = found[0]["id"]
            return self._org_cache[name]
        created = self._call(self.client.identity.create, type="Organization", name=name)
        self._org_cache[name] = created["id"]
        return self._org_cache[name]

    def ensure_label(self, value: str, color="#615EFF") -> str:
        if value in self._label_cache:
            return self._label_cache[value]
        existing = self._call(self.client.label.list, filters=fg([{"key": "value", "values": [value]}]), first=1)
        if existing:
            self._label_cache[value] = existing[0]["id"]
            return self._label_cache[value]
        created = self._call(self.client.label.create, value=value, color=color)
        self._label_cache[value] = created["id"]
        return self._label_cache[value]

    def ensure_marking_id(self, tlp_name: Optional[str]) -> Optional[str]:
        if not tlp_name:
            return None
        if tlp_name in self._md_cache:
            return self._md_cache[tlp_name]
        md = self._call(self.client.marking_definition.list,
                        filters=fg([{"key": "definition", "values": [tlp_name]}]), first=1)
        if md:
            self._md_cache[tlp_name] = md[0]["id"]
            return self._md_cache[tlp_name]
        return None

    # -------- external references --------
    def create_external_ref(self, source_name: Optional[str], url: Optional[str],
                            description: Optional[str] = None, external_id: Optional[str] = None) -> Optional[str]:
        if not (source_name and url):
            return None
        ref = self._call(self.client.external_reference.create,
                         source_name=source_name, url=url, description=description, external_id=external_id)
        return ref.get("id")

    # -------- observables --------
    def get_or_create_ipv4_observable(self, ip: str, description: Optional[str], marking_id: Optional[str]) -> Dict[str, Any]:
        kwargs = {
            "observableData": {"type": "ipv4-addr", "value": ip},
            "x_opencti_description": description,
            "update": True,
        }
        if marking_id:
            kwargs["objectMarking"] = [marking_id]
        obs = self._call(self.client.stix_cyber_observable.create, **kwargs)
        return obs

    def add_labels_to_observable(self, obs_id: str, labels: List[str]):
        seen = set()
        for lb in labels or []:
            lb = (lb or "").strip()
            if not lb or lb in seen:
                continue
            seen.add(lb)
            lid = self.ensure_label(lb)
            self._call(self.client.stix_cyber_observable.add_label, id=obs_id, label_id=lid)

    def add_external_ref_to_observable(self, obs_id: str, external_ref_id: Optional[str]):
        if external_ref_id:
            self._call(self.client.stix_cyber_observable.add_external_reference,
                       id=obs_id, external_reference_id=external_ref_id)

    # -------- indicators --------
    def _find_indicator_by_pattern(self, pattern: str) -> Optional[Dict[str, Any]]:
        if pattern in self._indicator_by_pattern:
            return self._indicator_by_pattern[pattern]
        found = self._call(self.client.indicator.list, filters=fg([{"key": "pattern", "values": [pattern]}]), first=1)
        if found:
            self._indicator_by_pattern[pattern] = found[0]
            return found[0]
        return None

    def upsert_indicator_for_ip(self, ip: str, score: Optional[int], confidence: Optional[int],
                                valid_from: Optional[str], marking_id: Optional[str], description: Optional[str]) -> Dict[str, Any]:
        pattern = f"[ipv4-addr:value = '{ip}']"
        existing = self._find_indicator_by_pattern(pattern)
        if existing:
            ind_id = existing["id"]
            if score is not None:
                self._call(self.client.indicator.update_field, id=ind_id,
                           input={"key": "x_opencti_score", "value": str(int(score))})
            if confidence is not None:
                self._call(self.client.indicator.update_field, id=ind_id,
                           input={"key": "confidence", "value": str(int(confidence))})
            if description:
                self._call(self.client.indicator.update_field, id=ind_id,
                           input={"key": "description", "value": description})
            if marking_id:
                self._call(self.client.stix_domain_object.add_marking_definition,
                           id=ind_id, marking_definition_id=marking_id)
            return existing

            # create new
        kwargs = {
            "name": f"Indicator for {ip}",
            "description": description,
            "pattern_type": "stix",
            "pattern": pattern,
            "x_opencti_main_observable_type": "IPv4-Addr",
        }
        if valid_from:
            kwargs["valid_from"] = valid_from
        if score is not None:
            kwargs["x_opencti_score"] = int(score)
        if confidence is not None:
            kwargs["confidence"] = int(confidence)
        if marking_id:
            kwargs["markingDefinitions"] = [marking_id]
        ind = self._call(self.client.indicator.create, **kwargs)
        self._indicator_by_pattern[pattern] = ind
        return ind

    def link_indicator_based_on_observable(self, indicator_id: str, observable_id: str):
        self._call(self.client.indicator.add_stix_cyber_observable,
                   id=indicator_id, stix_cyber_observable_id=observable_id)

    def add_labels_to_indicator(self, ind_id: str, labels: List[str]):
        seen = set()
        for lb in labels or []:
            lb = (lb or "").strip()
            if not lb or lb in seen:
                continue
            seen.add(lb)
            lid = self.ensure_label(lb)
            self._call(self.client.stix_domain_object.add_label, id=ind_id, label_id=lid)

    def add_external_ref_to_indicator(self, ind_id: str, external_ref_id: Optional[str]):
        if external_ref_id:
            self._call(self.client.stix_domain_object.add_external_reference,
                       id=ind_id, external_reference_id=external_ref_id)

    def add_note(self, target_id: str, content: str, created_by: Optional[str],
                 marking_id: Optional[str], external_ref_id: Optional[str]):
        kwargs = {"content": content, "objects": [target_id]}
        if created_by:
            kwargs["createdBy"] = created_by
        if marking_id:
            kwargs["objectMarking"] = [marking_id]
        if external_ref_id:
            kwargs["externalReferences"] = [external_ref_id]
        self._call(self.client.note.create, **kwargs)

# ====================== MAIN ======================
def main():
    load_dotenv_if_exist()

    # sanity checks
    if not OPENCTI_URL or not OPENCTI_TOKEN or not INPUT_JSON:
        LOG.error("Missing settings. Please set OPENCTI_URL, OPENCTI_TOKEN, INPUT_JSON (or edit constants).")
        sys.exit(2)

    LOG.info(f"OpenCTI URL = {OPENCTI_URL}")
    LOG.info(f"OpenCTI Token = {mask(OPENCTI_TOKEN)}")
    LOG.info(f"Input JSON = {INPUT_JSON}")
    LOG.info(f"Creator Org = {CREATOR_ORG} | Default TLP = {DEFAULT_TLP}")
    LOG.info(f"Verify SSL = {VERIFY_SSL} | Proxy = {HTTPS_PROXY or '-'}")
    LOG.info(f"Dry-run = {DRY_RUN} | Retries = {MAX_RETRIES}, Backoff = {RETRY_BACKOFF}s")

    # load input
    try:
        with open(INPUT_JSON, "r", encoding="utf-8") as f:
            rows: List[Dict[str, Any]] = json.load(f)
    except Exception as e:
        LOG.error(f"Failed to read input JSON: {e}")
        sys.exit(3)

    writer = OpenCTIWriter(
        url=OPENCTI_URL,
        token=OPENCTI_TOKEN,
        verify_ssl=VERIFY_SSL,
        proxy=HTTPS_PROXY,
        dry_run=DRY_RUN,
        max_retries=MAX_RETRIES,
        backoff=RETRY_BACKOFF,
    )

    creator_org_id = writer.ensure_identity_org(CREATOR_ORG)

    total = len(rows)
    ok = 0
    for idx, r in enumerate(rows, 1):
        try:
            ip = (r.get("ip") or "").strip()
            if not ip:
                LOG.warning(f"[{idx}/{total}] Skipped: empty ip")
                continue

            score = r.get("score")
            confidence = r.get("confidence")
            tags = r.get("tags", []) or []
            source_name = r.get("source_name")
            source_url = r.get("source_url")
            last_seen = r.get("last_seen")  # ISO8601 preferred (e.g., 2025-09-01T00:00:00Z)
            comment = r.get("comment")
            tlp_name = r.get("tlp") or DEFAULT_TLP

            marking_id = writer.ensure_marking_id(tlp_name)

            # Observable
            obs = writer.get_or_create_ipv4_observable(ip, description=comment, marking_id=marking_id)
            obs_id = obs["id"]

            # External reference
            ext_id = writer.create_external_ref(
                source_name=source_name,
                url=source_url,
                description=f"{source_name} lookup for {ip}" if source_name and ip else None,
            )
            writer.add_external_ref_to_observable(obs_id, ext_id)

            # Labels
            writer.add_labels_to_observable(obs_id, tags)

            # Indicator (upsert)
            ind = writer.upsert_indicator_for_ip(
                ip=ip,
                score=score,
                confidence=confidence,
                valid_from=last_seen,
                marking_id=marking_id,
                description=f"Auto-generated indicator for {ip}",
            )
            ind_id = ind["id"]

            # link, labels, external ref, note
            writer.link_indicator_based_on_observable(indicator_id=ind_id, observable_id=obs_id)
            writer.add_labels_to_indicator(ind_id, tags)
            writer.add_external_ref_to_indicator(ind_id, ext_id)

            note_text = (
                f"[{source_name}] enrichment for {ip}\n"
                f"Score={score}, Confidence={confidence}\n"
                f"{comment or ''}\n"
                f"{source_url or ''}"
            )
            writer.add_note(target_id=obs_id, content=note_text,
                            created_by=creator_org_id, marking_id=marking_id, external_ref_id=ext_id)

            ok += 1
            LOG.info(f"[{idx}/{total}] OK: {ip} (obs={obs_id}, ind={ind_id})")
        except Exception as e:
            LOG.error(f"[{idx}/{total}] Failed for row: {e}")

    LOG.info(f"Done. Success={ok}/{total} | Dry-run={DRY_RUN}")

if __name__ == "__main__":
    main()
