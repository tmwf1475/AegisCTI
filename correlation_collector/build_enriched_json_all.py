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

# =========================== CONFIG ===========================
CONFIG = {
    # Daily JSONL folders 
    # AbuseIPDB: abuse_YYYY-MM-DD.jsonl
    # VT(API)  : vt_YYYY-MM-DD.jsonl
    # VT(UI)   : vtui_YYYY-MM-DD.jsonl
    # OTX      : otx_YYYY-MM-DD.jsonl
    "ABUSE_DIR": "your_path",
    "VT_DIR":    "your_path",
    "VTUI_DIR":  "your_path",
    "OTX_DIR":   "your_path",
    "OUTPUT_JSON": "your_path",
    "DATE_IN_FILENAME": True,
    "DATE_FORMAT": "%Y-%m-%d",
    "DEFAULT_TLP": "TLP:GREEN",
    "TOPN_CATEGORIES": 3,
    "SINCE_DAYS": 30,

    "THRESHOLDS": {
        # AbuseIPDB
        "HIGH_DISTINCT_USERS": 10,
        "MED_DISTINCT_USERS": 5,
        "HIGH_TOTAL_REPORTS": 50,
        "MED_TOTAL_REPORTS": 20,
        # General output confidence interval
        "CONF_HIGH": 80,
        "CONF_MED": 60,
        "CONF_LOW": 40,
        "CONF_MIN": 20,
        # VT
        "VT_CONF_HIGH_MAL": 5,
        "VT_CONF_MED_MAL": 2,
        "VT_CONF_HIGH_TOTAL": 40,
        "VT_CONF_MED_TOTAL": 20,
        # OTX
        "OTX_CONF_HIGH_PULSES": 5,
        "OTX_CONF_MED_PULSES": 3,
    },

    # Logging level: DEBUG / INFO / WARNING / ERROR
    "LOG_LEVEL": "INFO",
}

# ---------- logging ----------
LOG = logging.getLogger("build_enriched_json_all_redesign")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
LOG.addHandler(_handler)
LOG.setLevel(getattr(logging, CONFIG.get("LOG_LEVEL", "INFO").upper(), logging.INFO))

# ---------- AbuseIPDB Category Map ----------
ABUSE_CAT_MAP = {
    "3":  "Fraud Orders", "4":  "DDoS Attack", "5":  "FTP Brute-Force",
    "9":  "Phishing", "10": "Fraud VoIP", "14": "Port Scan", "15": "Hacking",
    "18": "Spam", "19": "Web Spam", "20": "Email Spam", "21": "VPN",
    "22": "Open Proxy", "27": "SSH", "29": "SQL Injection",
    "30": "Spoofing", "31": "Brute-Force",
}

# ---------------- core helpers ----------------
def is_valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False

def to_iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00","Z")

def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

def recency_bucket(dt_iso: Optional[str]) -> str:
    if not dt_iso:
        return "none"
    try:
        dt = datetime.fromisoformat(dt_iso.replace("Z","+00:00")).astimezone(timezone.utc)
        days = (datetime.now(timezone.utc) - dt).days
        if days <= 7: return "7d"
        if days <= 30: return "30d"
        if days <= 90: return "90d"
        return "older"
    except Exception:
        return "none"

def files_within_days(dir_glob: str, since_days: int) -> List[str]:
    files = sorted(glob.glob(dir_glob))
    if since_days <= 0: return files
    cutoff = datetime.now().date() - timedelta(days=since_days)
    picked = []
    for p in files:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", os.path.basename(p))
        if not m:
            picked.append(p); continue
        try:
            d = datetime.strptime(m.group(1), "%Y-%m-%d").date()
            if d >= cutoff: picked.append(p)
        except Exception:
            picked.append(p)
    return picked

def pick_latest(records: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
    def keyfn(rec):
        v = rec.get(key)
        try:
            return datetime.fromisoformat(str(v).replace("Z","+00:00"))
        except Exception:
            return datetime.min
    return sorted(records, key=keyfn)[-1] if records else {}

def with_dated_suffix(path: str, date_fmt: str) -> str:
    if not date_fmt: return path
    today = datetime.now().strftime(date_fmt)
    d, base = os.path.dirname(path), os.path.basename(path)
    if "." in base:
        stem, ext = base.rsplit(".", 1)
        new_base = f"{stem}_{today}.{ext}"
    else:
        new_base = f"{base}_{today}"
    return os.path.join(d or ".", new_base)

# ---------------- VT schema helpers ----------------
def vt_ensure_attributes_from_api(vt_rec: Dict[str, Any]) -> Dict[str, Any]:
    payload = (vt_rec or {}).get("virustotal") or {}
    return ((payload.get("data") or {}).get("attributes") or {})

def _ui_to_last_analysis_stats(vtui_rec: Dict[str, Any]) -> Dict[str, int]:
    ds = (vtui_rec or {}).get("detection_summary") or (vtui_rec or {}).get("stats") or {}
    malicious = int(ds.get("malicious", 0) or 0) + int(ds.get("malware", 0) or 0)
    suspicious = int(ds.get("suspicious", 0) or 0)
    harmless   = int(ds.get("clean", 0) or 0)
    undetected = int(ds.get("unrated", 0) or 0)
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 0,
        "failure": 0,
        "type-unsupported": 0,
    }

def vt_ensure_attributes_from_ui(vtui_rec: Dict[str, Any]) -> Dict[str, Any]:
    if not vtui_rec:
        return {}
    base = {}
    base["last_analysis_stats"] = _ui_to_last_analysis_stats(vtui_rec)
    fa = vtui_rec.get("fetched_at")
    if isinstance(fa, str):
        t = parse_iso(fa)
        if t:
            base["last_analysis_date"] = int(t.timestamp())
    details = vtui_rec.get("details") or {}
    if isinstance(details, dict):
        asn_raw = details.get("asn")
        if asn_raw:
            m = re.search(r"\bAS(\d+)\b", str(asn_raw), flags=re.IGNORECASE)
            if m:
                try: base["asn"] = int(m.group(1))
                except: pass
        as_owner = details.get("as_owner")
        if as_owner and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(as_owner).strip()):
            base["as_owner"] = str(as_owner).strip()[:64]
        country = details.get("country")
        if country:
            c = str(country).strip()
            if 0 < len(c) <= 3 and c.isalpha():
                base["country"] = c.upper()
    return base

def vt_checked_at(rec: Dict[str, Any]) -> Optional[str]:
    if not rec:
        return None
    if rec.get("checked_at"):
        return rec["checked_at"]
    if rec.get("fetched_at"):
        t = parse_iso(rec["fetched_at"])
        if t:
            return to_iso_utc(t)
    attrs = vt_ensure_attributes_from_api(rec) or vt_ensure_attributes_from_ui(rec)
    ts = attrs.get("last_analysis_date")
    if isinstance(ts, int):
        try:
            return to_iso_utc(datetime.fromtimestamp(int(ts), tz=timezone.utc))
        except Exception:
            return None
    return None

# ---------------- provenance helper ----------------
def attach_provenance(record: Dict[str, Any], file_path: str, line_no: Optional[int]=None) -> Dict[str, Any]:
    rec = dict(record)
    rec["__file"] = file_path
    if line_no is not None:
        rec["__line"] = line_no
    return rec

# ---------------- loaders for each source ----------------
def load_abuse_records(abuse_dir: str, since_days: int) -> Dict[str, List[Dict[str, Any]]]:
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
                for idx, ln in enumerate(f, start=1):
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
                    per_ip[ip].append(attach_provenance(rec, path, idx))
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[AbuseIPDB] Read failed: {path} | {e}")
    LOG.info(f"[AbuseIPDB] Loaded IPs: {len(per_ip)}")
    return per_ip

def load_vt_latest(vt_dir: str, since_days: int) -> Dict[str, List[Dict[str, Any]]]:
    per_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not vt_dir or not os.path.isdir(vt_dir):
        LOG.warning(f"VT dir not found: {vt_dir}")
        return per_ip
    pattern = os.path.join(vt_dir, "vt_*.jsonl")
    files = files_within_days(pattern, since_days)
    LOG.info(f"[VT(API)] Scanning {len(files)} file(s)")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for idx, ln in enumerate(f, start=1):
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
                    per_ip[ip].append(attach_provenance(rec, path, idx))
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[VT(API)] Read failed: {path} | {e}")
    LOG.info(f"[VT(API)] Loaded IPs: {len(per_ip)}")
    return per_ip

def load_vtui_latest(vtui_dir: str, since_days: int) -> Dict[str, List[Dict[str, Any]]]:
    per_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not vtui_dir or not os.path.isdir(vtui_dir):
        LOG.warning(f"VT-UI dir not found: {vtui_dir}")
        return per_ip
    pattern = os.path.join(vtui_dir, "vtui_*.jsonl")
    files = files_within_days(pattern, since_days)
    LOG.info(f"[VT(UI)] Scanning {len(files)} file(s)")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for idx, ln in enumerate(f, start=1):
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except Exception:
                        continue
                    # Common fields for UI export:indicator_type=="ip", indicator="<IP>", fetched_at, detection_summary/stats/score…
                    ip = (rec.get("ip") or rec.get("indicator") or "").strip()
                    if not is_valid_ip(ip):
                        continue
                    if rec.get("indicator_type") and rec["indicator_type"] != "ip":
                        continue  
                    per_ip[ip].append(attach_provenance(rec, path, idx))
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[VT(UI)] Read failed: {path} | {e}")
    LOG.info(f"[VT(UI)] Loaded IPs: {len(per_ip)}")
    return per_ip

def load_otx_latest(otx_dir: str, since_days: int) -> Dict[str, List[Dict[str, Any]]]:
    per_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not otx_dir or not os.path.isdir(otx_dir):
        LOG.warning(f"OTX dir not found: {otx_dir}")
        return per_ip
    pattern = os.path.join(otx_dir, "otx_*.jsonl")
    files = files_within_days(pattern, since_days)
    LOG.info(f"[OTX] Scanning {len(files)} file(s)")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for idx, ln in enumerate(f, start=1):
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
                    per_ip[ip].append(attach_provenance(rec, path, idx))
        except FileNotFoundError:
            continue
        except Exception as e:
            LOG.warning(f"[OTX] Read failed: {path} | {e}")
    LOG.info(f"[OTX] Loaded IPs: {len(per_ip)}")
    return per_ip

# ---------------- tagging & confidence ----------------
def cat_to_tag(c: str) -> str:
    return f"AbuseCat:{ABUSE_CAT_MAP.get(str(c), str(c))}"

def build_tags_from_abuse(payload: Dict[str, Any], topn: int) -> Tuple[List[str], Dict[str,int], List[str]]:
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
    rb = recency_bucket(data.get("lastReportedAt")); tags.append(f"Recency:{rb}")
    cc = (data.get("countryCode") or "").strip().upper()
    if cc: tags.append(f"Country:{cc}")
    return sorted(set(t for t in tags if t and len(t) <= 128)), dict(counts), top_labels

def vt_tags_from_attributes(attrs: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    if not attrs: return tags
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(int(stats.get(k,0) or 0) for k in ("malicious","suspicious","harmless","undetected","timeout","failure","type-unsupported"))
    if total > 0: tags.append(f"VT:engines={total}")
    mal = int(stats.get("malicious",0) or 0)
    susp = int(stats.get("suspicious",0) or 0)
    harmless = int(stats.get("harmless",0) or 0)
    if mal > 0: tags.append("VT:malicious")
    elif susp > 0: tags.append("VT:suspicious")
    elif harmless > 0: tags.append("VT:harmless")
    last_ts = attrs.get("last_analysis_date")
    if isinstance(last_ts, int):
        try:
            dt_iso = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat().replace("+00:00","Z")
            tags.append(f"RecencyVT:{recency_bucket(dt_iso)}")
        except: pass
    if attrs.get("asn") is not None: tags.append(f"ASN:AS{attrs.get('asn')}")
    if isinstance(attrs.get("as_owner"), str) and attrs.get("as_owner").strip():
        tags.append(f"ASOwner:{attrs.get('as_owner').strip()[:64]}")
    country_raw = (attrs.get("country") or "").strip()
    if country_raw:
        if len(country_raw)<=3 and country_raw.upper().isalpha():
            tags.append(f"Country:{country_raw.upper()}")
        else:
            tags.append(f"CountryName:{country_raw}")
    if isinstance(attrs.get("continent"), str) and attrs.get("continent").strip():
        tags.append(f"Continent:{attrs.get('continent').strip().upper()}")
    return sorted(set(tags))

def otx_tags_only(otx_rec: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    if not otx_rec: return tags
    payload = otx_rec.get("otx") or {}
    pinfo = payload.get("pulse_info") or {}
    cnt = pinfo.get("count") or 0
    if cnt>0:
        tags.append("OTX:has_pulse"); tags.append(f"OTX:pulses={cnt}")
    pulses = pinfo.get("pulses") or []
    times = []
    for p in pulses:
        dt = p.get("modified") or p.get("created")
        if dt:
            t = parse_iso(dt)
            if t: times.append(t)
    if times:
        last = max(times)
        tags.append(f"RecencyOTX:{recency_bucket(to_iso_utc(last))}")
        now = datetime.now(timezone.utc)
        if any((now-t).days<=7 for t in times): tags.append("OTX:pulses_7d>0")
        if any((now-t).days<=30 for t in times): tags.append("OTX:pulses_30d>0")
    if isinstance(payload.get("reputation"), int):
        tags.append(f"OTX:reputation={payload['reputation']}")
    geo = payload.get("geo") or {}
    cc = (geo.get("country_code2") or geo.get("country") or "").strip()
    cn = (geo.get("country_name") or "").strip()
    if cc:
        if len(cc)<=3 and cc.upper().isalpha(): tags.append(f"Country:{cc.upper()}")
        else: tags.append(f"CountryName:{cc}")
    if cn: tags.append(f"CountryName:{cn}")
    if payload.get("hostname"): tags.append(f"Hostname:{payload.get('hostname')[:64]}")
    return sorted(set(tags))

def estimate_confidence_abuse(total_reports: Optional[int], distinct_users: Optional[int]) -> int:
    T=CONFIG["THRESHOLDS"]
    tr=int(total_reports or 0); du=int(distinct_users or 0)
    if du>=T["HIGH_DISTINCT_USERS"] or tr>=T["HIGH_TOTAL_REPORTS"]: return T["CONF_HIGH"]
    if du>=T["MED_DISTINCT_USERS"] or tr>=T["MED_TOTAL_REPORTS"]: return T["CONF_MED"]
    if tr>0: return T["CONF_LOW"]
    return T["CONF_MIN"]

def vt_estimate_confidence(stats: Dict[str, Any]) -> int:
    T=CONFIG["THRESHOLDS"]
    mal=int(stats.get("malicious",0) or 0); susp=int(stats.get("suspicious",0) or 0)
    total=sum(int(stats.get(k,0) or 0) for k in ("malicious","suspicious","harmless","undetected","timeout","failure","type-unsupported"))
    if mal>=T["VT_CONF_HIGH_MAL"] or total>=T["VT_CONF_HIGH_TOTAL"]: return T["CONF_HIGH"]
    if mal>=T["VT_CONF_MED_MAL"] or total>=T["VT_CONF_MED_TOTAL"]: return T["CONF_MED"]
    if mal>0 or susp>0: return T["CONF_LOW"]
    return T["CONF_MIN"]

def otx_estimate_confidence(otx_payload: Dict[str, Any]) -> int:
    T=CONFIG["THRESHOLDS"]
    pinfo=(otx_payload or {}).get("pulse_info") or {}
    cnt=int(pinfo.get("count") or 0); now=datetime.now(timezone.utc)
    p7=0
    for p in pinfo.get("pulses") or []:
        dt=p.get("modified") or p.get("created")
        t=parse_iso(dt)
        if t and (now-t).days<=7: p7+=1
    if cnt>=T["OTX_CONF_HIGH_PULSES"]: return T["CONF_HIGH"]
    if cnt>=T["OTX_CONF_MED_PULSES"] or p7>0: return T["CONF_MED"]
    if cnt>0: return T["CONF_LOW"]
    return T["CONF_MIN"]

# ---------------- comments & normalization ----------------
def summarize_comment_abuse(ip: str, score: Optional[int], distinct: Optional[int], total: Optional[int], last: Optional[str], top_labels: List[str]) -> str:
    tl=", ".join(top_labels) if top_labels else "N/A"
    return f"AbuseIPDB {ip} | score={score}, distinct={distinct}, total={total}, last={last or 'N/A'}, topCats=[{tl}]"

def summarize_comment_vt(ip: str, attrs: Dict[str, Any]) -> str:
    stats=(attrs or {}).get("last_analysis_stats") or {}
    return f"VirusTotal {ip} | stats={json.dumps(stats, ensure_ascii=False)}"

def summarize_comment_otx(ip: str, otx_payload: Dict[str, Any]) -> str:
    p=(otx_payload or {}).get("pulse_info") or {}
    return f"OTX {ip} | pulses={p.get('count',0)}"

def normalize_tags(raw_tags: List[str]) -> List[str]:
    tags=list(raw_tags) if raw_tags else []
    tags=[t.replace("VT:engines>=","VT:engines=") for t in tags]
    tags=[t for t in tags if not (t.startswith("Hostname:") and t.endswith(".example"))]
    return sorted(set(tags))

def severity_from_conf(c: int) -> str:
    T=CONFIG["THRESHOLDS"]
    if c>=T["CONF_HIGH"]: return "high"
    if c>=T["CONF_MED"]:  return "medium"
    if c>=T["CONF_LOW"]:  return "low"
    return "info"

# ---------------- main ----------------
def main():
    abuse_map = load_abuse_records(CONFIG["ABUSE_DIR"], CONFIG["SINCE_DAYS"])
    vt_api_map = load_vt_latest(CONFIG["VT_DIR"], CONFIG["SINCE_DAYS"])
    vt_ui_map  = load_vtui_latest(CONFIG["VTUI_DIR"], CONFIG["SINCE_DAYS"])
    otx_map    = load_otx_latest(CONFIG["OTX_DIR"], CONFIG["SINCE_DAYS"])

    all_ips = set().union(abuse_map.keys(), vt_api_map.keys(), vt_ui_map.keys(), otx_map.keys())
    LOG.info(f"Total unique IPs: {len(all_ips)}")

    # Input file list (for meta use)
    meta_inputs = {
        "abuse_files": files_within_days(os.path.join(CONFIG["ABUSE_DIR"], "abuse_*.jsonl"), CONFIG["SINCE_DAYS"]) if CONFIG["ABUSE_DIR"] and os.path.isdir(CONFIG["ABUSE_DIR"]) else [],
        "vt_api_files": files_within_days(os.path.join(CONFIG["VT_DIR"], "vt_*.jsonl"), CONFIG["SINCE_DAYS"]) if CONFIG["VT_DIR"] and os.path.isdir(CONFIG["VT_DIR"]) else [],
        "vt_ui_files": files_within_days(os.path.join(CONFIG["VTUI_DIR"], "vtui_*.jsonl"), CONFIG["SINCE_DAYS"]) if CONFIG["VTUI_DIR"] and os.path.isdir(CONFIG["VTUI_DIR"]) else [],
        "otx_files": files_within_days(os.path.join(CONFIG["OTX_DIR"], "otx_*.jsonl"), CONFIG["SINCE_DAYS"]) if CONFIG["OTX_DIR"] and os.path.isdir(CONFIG["OTX_DIR"]) else [],
    }

    results: List[Dict[str, Any]] = []
    T = CONFIG["THRESHOLDS"]
    default_conf = T["CONF_MIN"]

    for ip in sorted(all_ips, key=lambda x: (x.count(":"), x)):
        sources_present: List[str] = []
        tags_union: set = set()
        confidences: List[int] = []
        last_seens: List[datetime] = []
        first_seens: List[datetime] = []
        links = {"abuseipdb": None, "virustotal": None, "otx": None}
        details: Dict[str, Any] = {}
        provenance = {"abuse": [], "vt_api": [], "vt_ui": [], "otx": []}
        top_score: Optional[int] = None

        # ---------------- AbuseIPDB ----------------
        if ip in abuse_map:
            sources_present.append("AbuseIPDB")
            recs = abuse_map[ip]
            latest = pick_latest(recs, "checked_at")
            payload = latest.get("abuseipdb") or {}
            data = payload.get("data") or {}
            score = data.get("abuseConfidenceScore")
            total_reports = data.get("totalReports") or data.get("total_reports")
            distinct_users = data.get("numDistinctUsers") or data.get("distinctUsers")
            last = data.get("lastReportedAt") or latest.get("checked_at")
            tags_abuse, _, top_labels = build_tags_from_abuse(payload, CONFIG["TOPN_CATEGORIES"])
            conf_abuse = estimate_confidence_abuse(total_reports, distinct_users)
            tags_union.update(tags_abuse)
            confidences.append(conf_abuse)
            top_score = int(score) if (isinstance(score, int) or (isinstance(score, str) and str(score).isdigit())) else None
            links["abuseipdb"] = f"https://www.abuseipdb.com/check/{ip}"
            for r in recs:
                t = parse_iso(r.get("checked_at"))
                if t: first_seens.append(t); last_seens.append(t)
                if r.get("__file"): provenance["abuse"].append(r["__file"])
            details["abuse"] = {
                "score": top_score,
                "distinct_users": distinct_users,
                "total_reports": total_reports,
                "confidence": conf_abuse,
                "tags": sorted(tags_abuse),
                "last_seen": last,
                "comment": summarize_comment_abuse(ip, score, distinct_users, total_reports, last, top_labels),
                "source_name": "AbuseIPDB",
                "source_url": links["abuseipdb"],
            }

        # ---------------- VirusTotal API ----------------
        if ip in vt_api_map:
            sources_present.append("VirusTotal")
            recs = vt_api_map[ip]
            latest = pick_latest(recs, "checked_at")
            attrs = vt_ensure_attributes_from_api(latest)
            stats = attrs.get("last_analysis_stats") or {}
            conf_vt = vt_estimate_confidence(stats)
            tags_vt = vt_tags_from_attributes(attrs)
            tags_union.update(tags_vt)
            confidences.append(conf_vt)
            links["virustotal"] = f"https://www.virustotal.com/gui/ip-address/{ip}"
            for r in recs:
                t = parse_iso(vt_checked_at(r))
                if t: first_seens.append(t); last_seens.append(t)
                if r.get("__file"): provenance["vt_api"].append(r["__file"])
            details["vt_api"] = {
                "last_analysis_stats": stats,
                "last_analysis_date": attrs.get("last_analysis_date"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "continent": attrs.get("continent"),
                "confidence": conf_vt,
                "tags": sorted(tags_vt),
                "last_seen": vt_checked_at(latest),
                "comment": summarize_comment_vt(ip, attrs),
                "source_name": "VirusTotal",
                "source_url": links["virustotal"],
            }

        # ---------------- VirusTotal UI (keep original columns + normalized) ----------------
        if ip in vt_ui_map:
            sources_present.append("VirusTotal-UI")
            recs = vt_ui_map[ip]
            latest = pick_latest(recs, "fetched_at") if any(r.get("fetched_at") for r in recs) else pick_latest(recs, "checked_at")
            vtui_raw = dict(latest) 
            attrs_ui = vt_ensure_attributes_from_ui(latest)
            stats_ui = attrs_ui.get("last_analysis_stats") or {}
            conf_vtui = vt_estimate_confidence(stats_ui)
            vtui_raw["normalized"] = {
                "last_analysis_stats": stats_ui,
                "last_analysis_date": attrs_ui.get("last_analysis_date"),
                "asn": attrs_ui.get("asn"),
                "as_owner": attrs_ui.get("as_owner"),
                "country": attrs_ui.get("country"),
                "continent": attrs_ui.get("continent"),
                "confidence": conf_vtui,
            }
            details["vt_ui"] = vtui_raw
            confidences.append(conf_vtui)

            # tags / links / time range
            tags_vtui = vt_tags_from_attributes(attrs_ui)
            tags_union.update(tags_vtui)
            links["virustotal"] = links["virustotal"] or f"https://www.virustotal.com/gui/ip-address/{ip}"
            for r in recs:
                t = parse_iso(r.get("fetched_at")) or parse_iso(vt_checked_at(r))
                if t: first_seens.append(t); last_seens.append(t)
                if r.get("__file"): provenance["vt_ui"].append(r["__file"])

        # ---------------- OTX ----------------
        if ip in otx_map:
            sources_present.append("AlienVault-OTX")
            recs = otx_map[ip]
            latest = pick_latest(recs, "checked_at")
            payload = latest.get("otx") or {}
            conf_otx = otx_estimate_confidence(payload)
            tags_otx = otx_tags_only(latest)
            tags_union.update(tags_otx)
            confidences.append(conf_otx)
            links["otx"] = f"https://otx.alienvault.com/indicator/ip/{ip}"
            for r in recs:
                t = parse_iso(r.get("checked_at"))
                if t: first_seens.append(t); last_seens.append(t)
                if r.get("__file"): provenance["otx"].append(r["__file"])
            details["otx"] = {
                "pulse_info": payload.get("pulse_info"),
                "reputation": payload.get("reputation"),
                "geo": payload.get("geo"),
                "confidence": conf_otx,
                "tags": sorted(tags_otx),
                "last_seen": latest.get("checked_at"),
                "comment": summarize_comment_otx(ip, payload),
                "source_name": "AlienVault-OTX",
                "source_url": links["otx"],
            }

        combined_conf = max(confidences) if confidences else default_conf
        final_tags = normalize_tags(sorted(tags_union))

        engines_total = None
        engines_mal = None
        abuse_reports = None
        vt_stats_candidates = []
        if "vt_api" in details and isinstance(details["vt_api"].get("last_analysis_stats"), dict):
            vt_stats_candidates.append(details["vt_api"]["last_analysis_stats"])
        if "vt_ui" in details and isinstance(details["vt_ui"].get("normalized"), dict) and isinstance(details["vt_ui"]["normalized"].get("last_analysis_stats"), dict):
            vt_stats_candidates.append(details["vt_ui"]["normalized"]["last_analysis_stats"])
        if vt_stats_candidates:
            st = vt_stats_candidates[0]
            total = sum(int(st.get(k,0) or 0) for k in ("malicious","suspicious","harmless","undetected","timeout","failure","type-unsupported"))
            engines_total = total
            engines_mal = int(st.get("malicious", 0) or 0)
        if "abuse" in details:
            abuse_reports = int(details["abuse"].get("total_reports") or 0)

        verdict = "unknown"
        if engines_mal and engines_mal > 0:
            verdict = "malicious"
        elif any((isinstance(s.get("suspicious",0), int) and s.get("suspicious",0)>0) for s in vt_stats_candidates):
            verdict = "suspicious"
        elif vt_stats_candidates and all(int(s.get("malicious",0) or 0)==0 and int(s.get("suspicious",0) or 0)==0 for s in vt_stats_candidates):
            verdict = "harmless"

        # timeline
        first_seen_iso = to_iso_utc(min(first_seens)) if first_seens else None
        last_seen_iso  = to_iso_utc(max(last_seens)) if last_seens else None

        result_row = {
            "ip": ip,
            "score": details.get("abuse", {}).get("score"),    
            "confidence": int(combined_conf),
            "severity": severity_from_conf(int(combined_conf)),
            "tags": final_tags,
            "sources_present": sources_present,
            "summary": {
                "verdict": verdict,
                "engines_total": engines_total,
                "engines_malicious": engines_mal,
                "abuse_total_reports": abuse_reports,
            },
            "timeline": {
                "first_seen": first_seen_iso,
                "last_seen": last_seen_iso,
            },
            "links": links,
            "details": details,                          
            "provenance": {k: sorted(set(v)) for k, v in provenance.items()},
            "tlp": CONFIG["DEFAULT_TLP"],
        }

        results.append(result_row)

    # --- build dated output path ---
    out_path = CONFIG["OUTPUT_JSON"]
    if CONFIG.get("DATE_IN_FILENAME", True):
        out_path = with_dated_suffix(out_path, CONFIG.get("DATE_FORMAT", "%Y-%m-%d"))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    meta = {
        "schema_version": "2.1.0",
        "generated_at": to_iso_utc(datetime.now(timezone.utc)),
        "counts": {
            "total_rows": len(results),
            "has_abuse": sum(1 for r in results if "abuse" in r["details"]),
            "has_vt_api": sum(1 for r in results if "vt_api" in r["details"]),
            "has_vt_ui": sum(1 for r in results if "vt_ui" in r["details"]),
            "has_otx": sum(1 for r in results if "otx" in r["details"]),
        },
        "input_files": meta_inputs,
        "tlp_default": CONFIG["DEFAULT_TLP"],
    }

    out_obj = {"schema_version": meta["schema_version"], "meta": meta, "results": results}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, ensure_ascii=False, indent=2)

    LOG.info("==== Summary ====")
    LOG.info(f"Results               : {len(results)}  →  {out_path}")
    LOG.info(f"AbuseIPDB hits        : {meta['counts']['has_abuse']}")
    LOG.info(f"VT API hits           : {meta['counts']['has_vt_api']}")
    LOG.info(f"VT UI  hits           : {meta['counts']['has_vt_ui']}")
    LOG.info(f"OTX hits              : {meta['counts']['has_otx']}")
    LOG.info("Done.")

if __name__ == "__main__":
    main()
