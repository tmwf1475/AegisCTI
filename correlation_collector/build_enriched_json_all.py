import os
import re
import ipaddress
import json
import glob
import sys
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Tuple

CONFIG = {
    # Daily JSONL folders for the three sources
    # Expected filename patterns: abuse_YYYY-MM-DD.jsonl / vt_YYYY-MM-DD.jsonl / otx_YYYY-MM-DD.jsonl
    "ABUSE_DIR": "your_path",
    "VT_DIR":    "your_path",
    "OTX_DIR":   "your_path",
    "OUTPUT_JSON": "your_path",

    "DATE_IN_FILENAME": True,
    "DATE_FORMAT": "%Y-%m-%d",   

    # Default TLP label
    "DEFAULT_TLP": "TLP:GREEN",
    "TOPN_CATEGORIES": 3,
    "SINCE_DAYS": 30,

    "THRESHOLDS": {
        # AbuseIPDB
        "HIGH_DISTINCT_USERS": 10,
        "MED_DISTINCT_USERS": 5,
        "HIGH_TOTAL_REPORTS": 50,
        "MED_TOTAL_REPORTS": 20,
        # Confidence range
        "CONF_HIGH": 80,
        "CONF_MED": 60,
        "CONF_LOW": 40,
        "CONF_MIN": 20,
        # VirusTotal
        "VT_CONF_HIGH_MAL": 5,
        "VT_CONF_MED_MAL": 2,
        "VT_CONF_HIGH_TOTAL": 40,
        "VT_CONF_MED_TOTAL": 20,
        # OTX（脈衝數）
        "OTX_CONF_HIGH_PULSES": 5,
        "OTX_CONF_MED_PULSES": 3,
    },

    # Logging level: DEBUG / INFO / WARNING / ERROR
    "LOG_LEVEL": "INFO",
}

# ---------- logging ----------
LOG = logging.getLogger("build_enriched_json_all_agg")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
LOG.addHandler(_handler)
LOG.setLevel(getattr(logging, CONFIG.get("LOG_LEVEL", "INFO").upper(), logging.INFO))

# Mapping AbuseIPDB category IDs → readable labels
ABUSE_CAT_MAP = {
    "3":  "Fraud Orders",
    "4":  "DDoS Attack",
    "5":  "FTP Brute-Force",
    "9":  "Phishing",
    "10": "Fraud VoIP",
    "14": "Port Scan",
    "15": "Hacking",
    "18": "Spam",
    "19": "Web Spam",
    "20": "Email Spam",
    "21": "VPN",
    "22": "Open Proxy",
    "27": "SSH",
    "29": "SQL Injection",
    "30": "Spoofing",
    "31": "Brute-Force",
}

# ---------------- core validators / helpers ----------------
def is_valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False

def recency_bucket(dt_iso: Optional[str]) -> str:
    """Map an ISO datetime to a coarse recency bucket."""
    if not dt_iso:
        return "none"
    try:
        dt = datetime.fromisoformat(dt_iso.replace("Z", "+00:00")).astimezone(timezone.utc)
        days = (datetime.now(timezone.utc) - dt).days
        if days <= 7:   return "7d"
        if days <= 30:  return "30d"
        if days <= 90:  return "90d"
        return "older"
    except Exception:
        return "none"

def files_within_days(dir_glob: str, since_days: int) -> List[str]:
    """Return files matching the pattern, optionally filtered by last N days (based on date in filename)."""
    files = sorted(glob.glob(dir_glob))
    if since_days <= 0:
        return files
    cutoff = datetime.now().date() - timedelta(days=since_days)
    picked = []
    for p in files:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", os.path.basename(p))
        if not m:
            picked.append(p)  # keep if no date in name
            continue
        try:
            d = datetime.strptime(m.group(1), "%Y-%m-%d").date()
            if d >= cutoff:
                picked.append(p)
        except Exception:
            picked.append(p)
    return picked

def pick_latest(records: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
    """Pick the record with the latest ISO timestamp under `key`."""
    def keyfn(rec):
        v = rec.get(key)
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except Exception:
            return datetime.min
    return sorted(records, key=keyfn)[-1] if records else {}

def with_dated_suffix(path: str, date_fmt: str) -> str:
    """/a/b/enriched_ips.json -> /a/b/enriched_ips_YYYY-MM-DD.json"""
    if not date_fmt:
        return path
    today = datetime.now().strftime(date_fmt)
    d, base = os.path.dirname(path), os.path.basename(path)
    if "." in base:
        stem, ext = base.rsplit(".", 1)
        new_base = f"{stem}_{today}.{ext}"
    else:
        new_base = f"{base}_{today}"
    return os.path.join(d or ".", new_base)

# ---------------- loaders for each source ----------------
def load_abuse_records(abuse_dir: str, since_days: int) -> Dict[str, List[Dict[str, Any]]]:
    """Return ip -> list[records] from AbuseIPDB JSONL; 保留同 IP 多天，稍後挑最新。"""
    per_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not abuse_dir or not os.path.isdir(abuse_dir):
        LOG.warning(f"AbuseIPDB dir not found: {abuse_dir}")
        return per_ip
    pattern = os.path.join(abuse_dir, "abuse_*.jsonl")
    files = files_within_days(pattern, since_days)
    LOG.info(f"[AbuseIPDB] Scanning {len(files)} file(s)")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except Exception:
                        continue
                    ip = (rec.get("ip") or "").strip()
                    if not is_valid_ip(ip):
                        continue
                    if int(rec.get("status", 0)) != 200:
                        continue
                    if not isinstance(rec.get("abuseipdb"), dict):
                        continue
                    per_ip[ip].append(rec)
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[AbuseIPDB] Read failed: {path} | {e}")
    LOG.info(f"[AbuseIPDB] Loaded IPs: {len(per_ip)}")
    return per_ip

def load_vt_latest(vt_dir: str, since_days: int) -> Dict[str, Dict[str, Any]]:
    """Return ip -> latest VT record (by `checked_at`)."""
    latest: Dict[str, Dict[str, Any]] = {}
    if not vt_dir or not os.path.isdir(vt_dir):
        LOG.warning(f"VT dir not found: {vt_dir}")
        return latest
    pattern = os.path.join(vt_dir, "vt_*.jsonl")
    files = files_within_days(pattern, since_days)
    LOG.info(f"[VT] Scanning {len(files)} file(s)")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except Exception:
                        continue
                    ip = (rec.get("ip") or "").strip()
                    if not is_valid_ip(ip):
                        continue
                    if int(rec.get("status", 0)) != 200:
                        continue
                    prev = latest.get(ip)
                    if prev is None:
                        latest[ip] = rec
                    else:
                        a = rec.get("checked_at"); b = prev.get("checked_at")
                        try:
                            da = datetime.fromisoformat(str(a).replace("Z", "+00:00"))
                            db_ = datetime.fromisoformat(str(b).replace("Z", "+00:00"))
                            if da >= db_:
                                latest[ip] = rec
                        except Exception:
                            latest[ip] = rec
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[VT] Read failed: {path} | {e}")
    LOG.info(f"[VT] Loaded IPs: {len(latest)}")
    return latest

def load_otx_latest(otx_dir: str, since_days: int) -> Dict[str, Dict[str, Any]]:
    """Return ip -> latest OTX record (by `checked_at`)."""
    latest: Dict[str, Dict[str, Any]] = {}
    if not otx_dir or not os.path.isdir(otx_dir):
        LOG.warning(f"OTX dir not found: {otx_dir}")
        return latest
    pattern = os.path.join(otx_dir, "otx_*.jsonl")
    files = files_within_days(pattern, since_days)
    LOG.info(f"[OTX] Scanning {len(files)} file(s)")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except Exception:
                        continue
                    ip = (rec.get("ip") or "").strip()
                    if not is_valid_ip(ip):
                        continue
                    if int(rec.get("status", 0)) != 200:
                        continue
                    prev = latest.get(ip)
                    if prev is None:
                        latest[ip] = rec
                    else:
                        a = rec.get("checked_at"); b = prev.get("checked_at")
                        try:
                            da = datetime.fromisoformat(str(a).replace("Z", "+00:00"))
                            db_ = datetime.fromisoformat(str(b).replace("Z", "+00:00"))
                            if da >= db_:
                                latest[ip] = rec
                        except Exception:
                            latest[ip] = rec
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[OTX] Read failed: {path} | {e}")
    LOG.info(f"[OTX] Loaded IPs: {len(latest)}")
    return latest

# ---------------- tagging & confidence logic ----------------
def cat_to_tag(c: str) -> str:
    return f"AbuseCat:{ABUSE_CAT_MAP.get(str(c), str(c))}"

def build_tags_from_abuse(payload: Dict[str, Any], topn: int) -> Tuple[List[str], Dict[str,int], List[str]]:
    """
    只從 AbuseIPDB 生成 tags；回傳 (tags, category_counts, top_category_label_list)
    """
    data = (payload or {}).get("data") or {}
    tags: List[str] = []
    cats: List[str] = []

    for rpt in data.get("reports") or []:
        for c in (rpt.get("categories") or []):
            cats.append(str(c))

    counts = Counter(cats)
    top = [c for c,_ in counts.most_common(max(1, topn))]
    top_labels = [cat_to_tag(c) for c in top]
    tags.extend(top_labels)

    if data.get("isTor"): tags.append("Network:TOR")
    if data.get("usageType"): tags.append(f"Usage:{data.get('usageType')}")
    if data.get("isp"): tags.append(f"ISP:{(data.get('isp') or '')[:64]}")
    if data.get("domain"): tags.append(f"Domain:{(data.get('domain') or '').strip().lower()}")

    rb = recency_bucket(data.get("lastReportedAt"))
    tags.append(f"Recency:{rb}")

    cc = (data.get("countryCode") or "").strip()
    if cc: tags.append(f"Country:{cc}")

    return sorted(set(t for t in tags if t and len(t) <= 128)), dict(counts), top_labels

def vt_tags_only(vt_rec: Dict[str, Any]) -> List[str]:
    """只從 VT 生成 tags（不混其它來源）"""
    tags: List[str] = []
    if not vt_rec:
        return tags
    payload = vt_rec.get("virustotal") or {}
    attr = ((payload.get("data") or {}).get("attributes") or {})
    stats = attr.get("last_analysis_stats") or {}

    try:
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
    except Exception:
        mal = susp = harmless = 0

    total = sum(int(stats.get(k,0) or 0) for k in ("malicious","suspicious","harmless","undetected","timeout","failure","type-unsupported"))
    if total > 0: tags.append(f"VT:engines>={total}")
    if mal > 0:
        tags.append("VT:malicious")
    elif susp > 0:
        tags.append("VT:suspicious")
    elif harmless > 0:
        tags.append("VT:harmless")

    last_ts = attr.get("last_analysis_date")
    if isinstance(last_ts, int):
        try:
            dt_iso = datetime.fromtimestamp(int(last_ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
            tags.append(f"RecencyVT:{recency_bucket(dt_iso)}")
        except Exception:
            pass

    asn = attr.get("asn")
    if asn: tags.append(f"ASN:AS{asn}")
    owner = (attr.get("as_owner") or "").strip()
    if owner: tags.append(f"ASOwner:{owner[:64]}")
    country = (attr.get("country") or "").strip().upper()
    if country: tags.append(f"Country:{country}")
    continent = (attr.get("continent") or "").strip().upper()
    if continent: tags.append(f"Continent:{continent}")
    return sorted(set(tags))

def otx_tags_only(otx_rec: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    if not otx_rec:
        return tags
    payload = otx_rec.get("otx") or {}
    pinfo = payload.get("pulse_info") or {}
    cnt = pinfo.get("count") or 0
    if cnt and cnt > 0:
        tags.append("OTX:has_pulse")
        tags.append(f"OTX:pulses={cnt}")

    pulses = pinfo.get("pulses") or []
    times = []
    for p in pulses:
        dt = p.get("modified") or p.get("created")
        if dt:
            try:
                t = datetime.fromisoformat(dt.replace("Z", "+00:00")).astimezone(timezone.utc)
                times.append(t)
            except Exception:
                pass
    if times:
        last = max(times)
        tags.append(f"RecencyOTX:{recency_bucket(last.isoformat().replace('+00:00','Z'))}")
        now = datetime.now(timezone.utc)
        p7 = sum(1 for t in times if (now - t).days <= 7)
        p30 = sum(1 for t in times if (now - t).days <= 30)
        if p7 > 0: tags.append("OTX:pulses_7d>0")
        if p30 > 0: tags.append("OTX:pulses_30d>0")

    rep = payload.get("reputation")
    if isinstance(rep, int):
        tags.append(f"OTX:reputation={rep}")

    geo = payload.get("geo") or {}
    country = (geo.get("country_name") or geo.get("country") or "").strip()
    if country: tags.append(f"Country:{country}")

    hostname = (payload.get("hostname") or "").strip()
    if hostname: tags.append(f"Hostname:{hostname[:64]}")
    return sorted(set(tags))

def vt_estimate_confidence(stats: Dict[str, Any]) -> int:
    T = CONFIG.get("THRESHOLDS", {})
    VT_HIGH_MAL = int(T.get("VT_CONF_HIGH_MAL", 5))
    VT_MED_MAL  = int(T.get("VT_CONF_MED_MAL", 2))
    VT_HIGH_TOT = int(T.get("VT_CONF_HIGH_TOTAL", 40))
    VT_MED_TOT  = int(T.get("VT_CONF_MED_TOTAL", 20))
    CONF_HIGH   = int(T.get("CONF_HIGH", 80))
    CONF_MED    = int(T.get("CONF_MED", 60))
    CONF_LOW    = int(T.get("CONF_LOW", 40))
    CONF_MIN    = int(T.get("CONF_MIN", 20))

    try:
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless   = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        timeout    = int(stats.get("timeout", 0) or 0)
        failure    = int(stats.get("failure", 0) or 0)
        type_unsup = int(stats.get("type-unsupported", 0) or 0)
    except Exception:
        malicious = suspicious = harmless = undetected = timeout = failure = type_unsup = 0

    total = malicious + suspicious + harmless + undetected + timeout + failure + type_unsup
    if malicious >= VT_HIGH_MAL or total >= VT_HIGH_TOT:
        return CONF_HIGH
    if malicious >= VT_MED_MAL or total >= VT_MED_TOT:
        return CONF_MED
    if malicious > 0 or suspicious > 0:
        return CONF_LOW
    return CONF_MIN

def otx_estimate_confidence(otx_payload: Dict[str, Any]) -> int:
    T = CONFIG.get("THRESHOLDS", {})
    CONF_HIGH   = int(T.get("CONF_HIGH", 80))
    CONF_MED    = int(T.get("CONF_MED", 60))
    CONF_LOW    = int(T.get("CONF_LOW", 40))
    CONF_MIN    = int(T.get("CONF_MIN", 20))
    OTX_HIGH    = int(T.get("OTX_CONF_HIGH_PULSES", 5))
    OTX_MED     = int(T.get("OTX_CONF_MED_PULSES", 3))

    pinfo = (otx_payload or {}).get("pulse_info") or {}
    cnt = int(pinfo.get("count") or 0)
    pulses = pinfo.get("pulses") or []
    now = datetime.now(timezone.utc)

    p7 = 0
    for p in pulses:
        dt = p.get("modified") or p.get("created")
        if dt:
            try:
                t = datetime.fromisoformat(dt.replace("Z", "+00:00")).astimezone(timezone.utc)
                if (now - t).days <= 7:
                    p7 += 1
            except Exception:
                pass

    if cnt >= OTX_HIGH:
        return CONF_HIGH
    if cnt >= OTX_MED or p7 > 0:
        return CONF_MED
    if cnt > 0:
        return CONF_LOW
    return CONF_MIN

def estimate_confidence_abuse(total_reports: Optional[int], distinct_users: Optional[int]) -> int:
    T = CONFIG.get("THRESHOLDS", {})
    HIGH_DU   = int(T.get("HIGH_DISTINCT_USERS", 10))
    MED_DU    = int(T.get("MED_DISTINCT_USERS", 5))
    HIGH_TR   = int(T.get("HIGH_TOTAL_REPORTS", 50))
    MED_TR    = int(T.get("MED_TOTAL_REPORTS", 20))
    CONF_HIGH = int(T.get("CONF_HIGH", 80))
    CONF_MED  = int(T.get("CONF_MED", 60))
    CONF_LOW  = int(T.get("CONF_LOW", 40))
    CONF_MIN  = int(T.get("CONF_MIN", 20))

    tr = int(total_reports or 0)
    du = int(distinct_users or 0)
    if du >= HIGH_DU or tr >= HIGH_TR:
        return CONF_HIGH
    if du >= MED_DU or tr >= MED_TR:
        return CONF_MED
    if tr > 0:
        return CONF_LOW
    return CONF_MIN

# ---------------- per-source comments ----------------
def summarize_comment_abuse(ip: str, score: Optional[int], distinct: Optional[int], total: Optional[int], last: Optional[str], top_labels: List[str]) -> str:
    tl = ", ".join(top_labels) if top_labels else "N/A"
    return f"AbuseIPDB for {ip} | abuseConfidenceScore={score}, distinctUsers={distinct}, totalReports={total}, lastReportedAt={last or 'N/A'}, topCats=[{tl}]"

def summarize_comment_vt(ip: str, vt_attr: Dict[str, Any]) -> str:
    stats = (vt_attr or {}).get("last_analysis_stats") or {}
    return f"VirusTotal for {ip} | stats={json.dumps(stats, ensure_ascii=False)}"

def summarize_comment_otx(ip: str, otx_payload: Dict[str, Any]) -> str:
    p = (otx_payload or {}).get("pulse_info") or {}
    return f"OTX for {ip} | pulses={p.get('count',0)}"

# ---------------- main ----------------
def main():
    abuse_dir = CONFIG["ABUSE_DIR"]
    vt_dir    = CONFIG["VT_DIR"]
    otx_dir   = CONFIG["OTX_DIR"]
    output    = CONFIG["OUTPUT_JSON"]
    tlp       = CONFIG["DEFAULT_TLP"]
    topn      = int(CONFIG["TOPN_CATEGORIES"])
    since_days = int(CONFIG["SINCE_DAYS"])

    if not output:
        LOG.error("CONFIG['OUTPUT_JSON'] is empty.")
        sys.exit(2)

    # Load latest/records from sources
    abuse_recs = load_abuse_records(abuse_dir, since_days) if abuse_dir else {}
    vt_latest  = load_vt_latest(vt_dir, since_days) if vt_dir else {}
    otx_latest = load_otx_latest(otx_dir, since_days) if otx_dir else {}

    all_ips = set(abuse_recs.keys()) | set(vt_latest.keys()) | set(otx_latest.keys())
    LOG.info(f"Total unique IPs across sources: {len(all_ips)}")

    rows: List[Dict[str, Any]] = []

    # thresholds for default if no source present
    T = CONFIG.get("THRESHOLDS", {})
    CONF_MIN = int(T.get("CONF_MIN", 20))

    for ip in sorted(all_ips, key=lambda x: (x.count(":"), x)):
        abuse_detail = None
        vt_detail = None
        otx_detail = None
        present = []
        tags_union: set = set()
        confidences: List[int] = []
        top_score: Optional[int] = None  # from AbuseIPDB only

        # Abuse
        if ip in abuse_recs:
            latest = pick_latest(abuse_recs[ip], "checked_at")
            payload = latest.get("abuseipdb") or {}
            data = payload.get("data") or {}
            score = data.get("abuseConfidenceScore")
            total = data.get("totalReports")
            distinct = data.get("numDistinctUsers")
            last = data.get("lastReportedAt") or latest.get("checked_at")
            tags_abuse, _, top_labels = build_tags_from_abuse(payload, topn)
            conf_abuse = estimate_confidence_abuse(total, distinct)
            abuse_detail = {
                "score": int(score) if (isinstance(score, int) or (isinstance(score, str) and str(score).isdigit())) else None,
                "confidence": int(conf_abuse),
                "tags": sorted(tags_abuse),
                "source_name": "AbuseIPDB",
                "source_url": f"https://www.abuseipdb.com/check/{ip}",
                "last_seen": last,
                "comment": summarize_comment_abuse(ip, score, distinct, total, last, top_labels),
            }
            present.append("AbuseIPDB")
            tags_union.update(tags_abuse)
            confidences.append(conf_abuse)
            top_score = abuse_detail["score"]

        # VT
        if ip in vt_latest:
            vt_rec = vt_latest[ip]
            payload = vt_rec.get("virustotal") or {}
            attr = (payload.get("data") or {}).get("attributes", {})
            conf_vt = vt_estimate_confidence(attr.get("last_analysis_stats") or {})
            tags_vt = vt_tags_only(vt_rec)
            vt_detail = {
                "score": None,
                "confidence": int(conf_vt),
                "tags": sorted(tags_vt),
                "source_name": "VirusTotal",
                "source_url": f"https://www.virustotal.com/gui/ip-address/{ip}",
                "last_seen": vt_rec.get("checked_at"),
                "comment": summarize_comment_vt(ip, attr),
            }
            present.append("VirusTotal")
            tags_union.update(tags_vt)
            confidences.append(conf_vt)

        # OTX
        if ip in otx_latest:
            otx_rec = otx_latest[ip]
            payload = otx_rec.get("otx") or {}
            conf_otx = otx_estimate_confidence(payload)
            tags_otx = otx_tags_only(otx_rec)
            otx_detail = {
                "score": None,
                "confidence": int(conf_otx),
                "tags": sorted(tags_otx),
                "source_name": "AlienVault-OTX",
                "source_url": f"https://otx.alienvault.com/indicator/ip/{ip}",
                "last_seen": otx_rec.get("checked_at"),
                "comment": summarize_comment_otx(ip, payload),
            }
            present.append("AlienVault-OTX")
            tags_union.update(tags_otx)
            confidences.append(conf_otx)

        combined_conf = max(confidences) if confidences else CONF_MIN

        rows.append({
            "ip": ip,
            "score": top_score,               
            "confidence": int(combined_conf), 
            "tags": sorted(tags_union),       
            "sources_present": present,       
            "abuse": abuse_detail,            
            "vt": vt_detail,
            "otx": otx_detail,
            "tlp": CONFIG["DEFAULT_TLP"],
        })

    # --- build dated output path ---
    out_path = CONFIG["OUTPUT_JSON"]
    if CONFIG.get("DATE_IN_FILENAME", True):
        out_path = with_dated_suffix(out_path, CONFIG.get("DATE_FORMAT", "%Y-%m-%d"))

    out_dir = os.path.dirname(out_path) or "."
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        LOG.error(f"Failed to create output dir {out_dir}: {e}")
        sys.exit(3)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
    except Exception as e:
        LOG.error(f"Failed to write output JSON: {e}")
        sys.exit(4)

    # Summary
    n_abuse = sum(1 for r in rows if r["abuse"])
    n_vt    = sum(1 for r in rows if r["vt"])
    n_otx   = sum(1 for r in rows if r["otx"])
    LOG.info("==== Summary ====")
    LOG.info(f"Unique IPs (rows)       : {len(rows)}  →  {out_path}")
    LOG.info(f"IPs having AbuseIPDB     : {n_abuse}")
    LOG.info(f"IPs having VirusTotal    : {n_vt}")
    LOG.info(f"IPs having OTX           : {n_otx}")
    LOG.info("Done.")

if __name__ == "__main__":
    main()
