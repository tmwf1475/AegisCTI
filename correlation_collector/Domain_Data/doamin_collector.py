import csv
import json
import math
import logging
import socket
import contextlib
import io
import datetime
from collections import Counter
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple

import requests
import tldextract
import dns.resolver
import whois

socket.setdefaulttimeout(10)

RUN_TS = datetime.datetime.now(datetime.UTC)
RUN_TS_ISO = RUN_TS.isoformat()
RUN_ID = RUN_TS.strftime("%Y%m%d")


class Config:
    HTTP_TIMEOUT = 20
    MAX_DOMAINS_ENRICH = 10000

    BASE_OUTPUT_DIR = "your_path"

    @staticmethod
    def output_with_data() -> str:
        return f"{Config.BASE_OUTPUT_DIR}/domains_with_data_{RUN_ID}.jsonl"

    @staticmethod
    def output_no_data() -> str:
        return f"{Config.BASE_OUTPUT_DIR}/domains_no_data_{RUN_ID}.jsonl"

    @staticmethod
    def output_all() -> str:
        return f"{Config.BASE_OUTPUT_DIR}/domains_all_{RUN_ID}.jsonl"

    OPENPHISH_URL          = "https://openphish.com/feed.txt"
    URLHAUS_RECENT         = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    BLOCKLIST_PHISHING_URL = "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt"
    BLOCKLIST_MALWARE_URL  = "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt"
    ADGUARD_MALWARE_URL    = "https://adguardteam.github.io/AdGuardSDNSFilter/Malware.txt"
    DISCONNECT_MALWARE_URL = "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"
    STEVENBLACK_HOSTS_URL  = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    HIGH_RISK_TLDS = {
        "xyz", "top", "monster", "click", "cfd", "ml",
        "ga", "gq", "cf", "icu", "info", "loan", "fit",
    }
    PHISH_KEYWORDS = [
        "login", "signin", "verify", "account", "secure",
        "update", "password", "pay", "bank", "wallet", "otp",
        "mail", "outlook", "office365", "paypal"
    ]


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


@dataclass
class DomainLocalFeatures:
    tld: str = ""
    age_days: Optional[int] = None
    entropy: Optional[float] = None
    a_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    url_count: int = 0
    phish_keyword_hits: int = 0

    whois_error: Optional[str] = None
    dns_error: Optional[str] = None


@dataclass
class DomainRecord:
    domain: str
    sources: List[str] = field(default_factory=list)
    sample_urls: List[str] = field(default_factory=list)

    crawl_timestamp: str = ""

    features: DomainLocalFeatures = field(default_factory=DomainLocalFeatures)
    dms_score: int = 0
    verdict: str = "unknown"

    has_enrichment: bool = False
    no_data_reason: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        ext = tldextract.extract(url)
        domain = getattr(ext, "top_domain_under_public_suffix", None)
        if not domain:
            domain = ext.registered_domain
        if not domain:
            return None
        return domain.lower()
    except Exception:
        return None


def fetch_openphish() -> List[str]:
    url = Config.OPENPHISH_URL
    logging.info(f"Fetching OpenPhish feed from {url}")
    try:
        resp = requests.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
        logging.info(f"OpenPhish: {len(lines)} URLs")
        return lines
    except Exception as e:
        logging.error(f"Failed to fetch OpenPhish feed: {e}")
        return []


def fetch_urlhaus() -> List[str]:
    url = Config.URLHAUS_RECENT
    logging.info(f"Fetching URLhaus feed from {url}")
    urls: List[str] = []
    try:
        resp = requests.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        decoded = resp.content.decode("utf-8", errors="ignore").splitlines()
        reader = csv.reader(decoded)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) >= 3:
                urls.append(row[2].strip())
        logging.info(f"URLhaus: {len(urls)} URLs")
    except Exception as e:
        logging.error(f"Failed to fetch URLhaus feed: {e}")
    return urls


def fetch_blocklistproject(url: str, label: str) -> List[str]:
    logging.info(f"Fetching BlockListProject {label} from {url}")
    items: List[str] = []
    try:
        resp = requests.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)
        logging.info(f"BlockListProject-{label}: {len(items)} entries")
    except Exception as e:
        logging.error(f"Failed to fetch BlockListProject {label}: {e}")
    return items


def fetch_adguard_malware() -> List[str]:
    url = Config.ADGUARD_MALWARE_URL
    logging.info(f"Fetching AdGuard Malware list from {url}")
    domains: List[str] = []
    try:
        resp = requests.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("!"):
                continue
            if line.startswith("||"):
                d = line[2:]
                d = d.split("^")[0]
                d = d.strip()
                if d:
                    domains.append(d)
        logging.info(f"AdGuard Malware: {len(domains)} domains")
    except Exception as e:
        logging.error(f"Failed to fetch AdGuard Malware list: {e}")
    return domains


def fetch_disconnect_malware() -> List[str]:
    url = Config.DISCONNECT_MALWARE_URL
    logging.info(f"Fetching Disconnect simple_malware from {url}")
    domains: List[str] = []
    try:
        resp = requests.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
        logging.info(f"Disconnect simple_malware: {len(domains)} domains")
    except Exception as e:
        logging.error(f"Failed to fetch Disconnect simple_malware: {e}")
    return domains


def fetch_stevenblack_hosts() -> List[str]:
    url = Config.STEVENBLACK_HOSTS_URL
    logging.info(f"Fetching StevenBlack hosts from {url}")
    domains: List[str] = []
    try:
        resp = requests.get(url, timeout=Config.HTTP_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip, dom = parts[0], parts[1]
                if ip.startswith("#") or dom in ("localhost", "localhost.localdomain"):
                    continue
                domains.append(dom)
        logging.info(f"StevenBlack hosts: {len(domains)} domains")
    except Exception as e:
        logging.error(f"Failed to fetch StevenBlack hosts: {e}")
    return domains


def get_domain_age_days(domain: str) -> Tuple[Optional[int], Optional[str]]:
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            w = whois.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not isinstance(creation, datetime.datetime):
            return None, "WHOIS creation_date not datetime"

        now = datetime.datetime.now(datetime.UTC)
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=datetime.UTC)

        age_days = (now - creation).days
        return age_days, None

    except Exception as e:
        return None, f"WHOIS error: {e}"


def get_dns_info(domain: str) -> Tuple[List[str], List[str], List[str], Optional[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    a_records: List[str] = []
    ns_records: List[str] = []
    mx_records: List[str] = []
    errors: List[str] = []

    try:
        answers = resolver.resolve(domain, "A")
        a_records = sorted({rdata.address for rdata in answers})
    except Exception as e:
        errors.append(f"A: {e}")

    try:
        answers = resolver.resolve(domain, "NS")
        ns_records = sorted({str(rdata.target).rstrip(".") for rdata in answers})
    except Exception as e:
        errors.append(f"NS: {e}")

    try:
        answers = resolver.resolve(domain, "MX")
        mx_records = sorted({str(rdata.exchange).rstrip(".") for rdata in answers})
    except Exception as e:
        errors.append(f"MX: {e}")

    err_msg = "; ".join(errors) if errors else None
    return a_records, ns_records, mx_records, err_msg


def calc_domain_entropy(domain: str) -> Optional[float]:
    try:
        parts = domain.split(".")
        if len(parts) <= 1:
            core = parts[0]
        else:
            core = ".".join(parts[:-1])
        core = core.replace("-", "").replace("_", "")
        if not core:
            return None

        counts = Counter(core)
        length = len(core)
        entropy = -sum((c / length) * math.log(c / length, 2) for c in counts.values())
        return entropy
    except Exception:
        return None


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) < 2:
        return ""
    return parts[-1].lower()


def is_high_risk_tld(tld: str) -> bool:
    return tld in Config.HIGH_RISK_TLDS


def count_phish_keywords(urls: List[str]) -> int:
    cnt = 0
    for u in urls:
        ul = u.lower()
        if any(kw in ul for kw in Config.PHISH_KEYWORDS):
            cnt += 1
    return cnt


def compute_dms(record: DomainRecord) -> None:
    f = record.features
    score = 0

    # 1. Domain age
    if f.age_days is not None:
        if f.age_days < 7:
            score += 40
        elif f.age_days < 30:
            score += 25
        elif f.age_days < 180:
            score += 10
    else:
        score += 5

    # 2. High-risk TLD
    if is_high_risk_tld(f.tld):
        score += 20

    # 3. Domain entropy
    if f.entropy is not None:
        if f.entropy >= 4.2:
            score += 25
        elif f.entropy >= 3.7:
            score += 15

    # 4. DNS A records / NS / MX
    cf_ns = any("cloudflare.com" in ns for ns in f.ns_records)

    if len(f.a_records) >= 5:
        score += 15
    elif len(f.a_records) >= 3:
        score += 10
    elif not f.a_records:
        if cf_ns and not f.mx_records:
            score += 15
        else:
            score += 5

    if not f.mx_records:
        score += 5

    # 5. Phish keyword hits
    if f.phish_keyword_hits >= 10:
        score += 20
    elif f.phish_keyword_hits >= 3:
        score += 10
    elif f.phish_keyword_hits >= 1:
        score += 5

    # 6. URL count
    if f.url_count >= 50:
        score += 15
    elif f.url_count >= 10:
        score += 10
    elif f.url_count >= 3:
        score += 5

    record.dms_score = score

    if score >= 70:
        record.verdict = "malicious"
    elif score >= 40:
        record.verdict = "suspicious"
    else:
        record.verdict = "unknown"


def collect_domains() -> Dict[str, DomainRecord]:
    url_to_source: Dict[str, List[str]] = {}

    def add_item(raw: str, source: str):
        raw = raw.strip()
        if not raw:
            return
        if "://" in raw:
            url = raw
        else:
            url = f"http://{raw}/"
        url_to_source.setdefault(url, []).append(source)

    # OpenPhish
    for u in fetch_openphish():
        add_item(u, "OpenPhish")

    # URLhaus
    for u in fetch_urlhaus():
        add_item(u, "URLhaus")

    # BlockListProject (phishing / malware)
    for d in fetch_blocklistproject(Config.BLOCKLIST_PHISHING_URL, "phishing"):
        add_item(d, "BlockListProject-phishing")

    for d in fetch_blocklistproject(Config.BLOCKLIST_MALWARE_URL, "malware"):
        add_item(d, "BlockListProject-malware")

    # AdGuard Malware
    for d in fetch_adguard_malware():
        add_item(d, "AdGuard-Malware")

    # Disconnect simple_malware
    for d in fetch_disconnect_malware():
        add_item(d, "Disconnect-simple_malware")

    # StevenBlack hosts
    for d in fetch_stevenblack_hosts():
        add_item(d, "StevenBlack-hosts")

    logging.info(f"Total raw entries (URL/domain) collected = {len(url_to_source)}")

    domain_map: Dict[str, DomainRecord] = {}

    for url, sources in url_to_source.items():
        domain = extract_domain_from_url(url)
        if not domain:
            continue

        if domain not in domain_map:
            rec = DomainRecord(
                domain=domain,
                sources=sorted(set(sources)),
                sample_urls=[url],
                crawl_timestamp=RUN_TS_ISO,
            )
            rec.features.url_count = 1
            domain_map[domain] = rec
        else:
            rec = domain_map[domain]
            rec.sources = sorted(set(rec.sources + sources))
            if url not in rec.sample_urls and len(rec.sample_urls) < 50:
                rec.sample_urls.append(url)
            rec.features.url_count += 1

    logging.info(f"Unique domains extracted = {len(domain_map)}")
    return domain_map


CORE_SOURCES = {
    "OpenPhish",
    "URLhaus",
}

BLP_SOURCES = {
    "BlockListProject-phishing",
    "BlockListProject-malware",
}


def filter_domains_for_enrich(domains: Dict[str, DomainRecord]) -> Dict[str, DomainRecord]:
    kept: Dict[str, DomainRecord] = {}
    dropped = 0

    for d, rec in domains.items():
        f = rec.features
        src = set(rec.sources)
        tld = get_tld(d)

        keep = False

        if src & CORE_SOURCES:
            keep = True

        elif src & BLP_SOURCES:
            if f.url_count >= 5 or is_high_risk_tld(tld):
                keep = True

        else:
            if f.url_count >= 10:
                keep = True
            elif is_high_risk_tld(tld) and f.url_count >= 3:
                keep = True

        if keep:
            kept[d] = rec
        else:
            dropped += 1

    logging.info(
        f"Filter before enrich: keep={len(kept)} domains, "
        f"dropped={dropped} (from {len(domains)})"
    )
    return kept


def should_do_whois(rec: DomainRecord) -> bool:
    f = rec.features
    sources = set(rec.sources)
    tld = f.tld

    if sources & CORE_SOURCES:
        return True

    if sources & BLP_SOURCES:
        if f.url_count >= 5:
            return True
        if is_high_risk_tld(tld) and f.url_count >= 3:
            return True

    if f.url_count >= 15:
        return True
    if is_high_risk_tld(tld) and f.url_count >= 5:
        return True

    return False


def enrich_domains(domains: Dict[str, DomainRecord]) -> None:
    total = len(domains)
    whois_count = 0

    for idx, (domain, rec) in enumerate(domains.items(), start=1):
        logging.info(f"[{idx}/{total}] Enriching {domain}")
        f = rec.features

        f.tld = get_tld(domain)

        a_records, ns_records, mx_records, dns_err = get_dns_info(domain)
        f.a_records = a_records
        f.ns_records = ns_records
        f.mx_records = mx_records
        f.dns_error = dns_err

        f.entropy = calc_domain_entropy(domain)
        f.phish_keyword_hits = count_phish_keywords(rec.sample_urls)

        if should_do_whois(rec):
            if Config.MAX_DOMAINS_ENRICH is not None and whois_count >= Config.MAX_DOMAINS_ENRICH:
                f.age_days = None
                f.whois_error = "WHOIS skipped: reached MAX_DOMAINS_ENRICH"
            else:
                age_days, whois_err = get_domain_age_days(domain)
                f.age_days = age_days
                f.whois_error = whois_err
                whois_count += 1
        else:
            f.age_days = None
            f.whois_error = "WHOIS skipped by filter"

        has_enrichment = (
            (f.age_days is not None)
            or bool(f.a_records)
            or bool(f.ns_records)
            or bool(f.mx_records)
        )
        rec.has_enrichment = has_enrichment

        if not has_enrichment:
            reasons = []
            if f.whois_error:
                reasons.append(f.whois_error)
            if f.dns_error:
                reasons.append(f.dns_error)
            if not reasons:
                reasons.append("WHOIS and DNS returned no data")
            rec.no_data_reason = "; ".join(reasons)

        compute_dms(rec)

    logging.info(f"WHOIS actually performed for {whois_count} domains.")


def save_jsonl_all_only(domains: Dict[str, DomainRecord], path_all: str):
    with open(path_all, "w", encoding="utf-8") as f_all:
        for rec in domains.values():
            f_all.write(rec.to_json() + "\n")

    logging.info(f"Saved all={path_all}")



def main():
    logging.info("=== Domain Collector (NO API, multi-source, filtered, split+all output, time-series ready) START ===")
    logging.info(f"Run timestamp (UTC) = {RUN_TS_ISO}, run_id = {RUN_ID}")

    domains = collect_domains()
    if not domains:
        logging.warning("No domains collected.")
        return

    domains = filter_domains_for_enrich(domains)
    enrich_domains(domains)
    save_jsonl_all_only(
        domains,
        Config.output_all(),
    )

    logging.info("=== Domain Collector DONE ===")


if __name__ == "__main__":
    main()
