import os, sys, time, json, sqlite3, ipaddress, random
import requests
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Tuple, Dict, Any

CONFIG = {
    "INPUT_FILE": "your_path",

    "VT_API_KEYS": [
        "api_key_1",
        "api_key_2",
    ],

    "PER_ACCOUNT_DAILY": 500,
    "PER_RUN_CAP": None,   
    "REQUEST_SLEEP_SEC": 0.4,

    "SQLITE_PATH": "your_path",
    "DAILY_JSONL_DIR": "your_path",

    "DRY_RUN": False,          
    "MAX_BACKOFF_SEC": 16,     
    "PROBE_KEYS_AND_EXIT": False,  
}

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
USER_AGENT = "vt-backlog/1.0"

def log(msg: str):
    ts = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"[{ts}] {msg}", flush=True)

def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False

def load_ips_from_file(path: str) -> List[str]:
    ips: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                x = line.split(",")[0].strip()
                if x and valid_ip(x):
                    ips.append(x)
    except FileNotFoundError:
        log(f"[WARN] input file not found: {path}")
    seen, res = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip); res.append(ip)
    return res

def append_daily_jsonl(ip: str, status: int, payload: dict, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    day = date.today().isoformat()
    path = os.path.join(out_dir, f"vt_{day}.jsonl")
    rec = {"ip": ip, "status": status, "checked_at": datetime.now().astimezone().isoformat(), "virustotal": payload}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def from_epoch(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).isoformat()
    except Exception:
        return None

class DB:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._init()

    def _init(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS pending_ips (
            ip TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'pending'  -- pending|done|error
        );
        CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_ips(status);

        CREATE TABLE IF NOT EXISTS query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            queried_at TEXT,
            account TEXT,
            status_code INTEGER,
            response_json TEXT
        );

        CREATE TABLE IF NOT EXISTS query_ledger (
            ip TEXT PRIMARY KEY,
            last_queried_at TEXT,
            last_account TEXT,
            last_status INTEGER,
            times_queried INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS query_flat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            queried_at TEXT,

            -- VT attributes (ip level)
            as_owner TEXT,
            asn INTEGER,
            continent TEXT,
            country TEXT,
            network TEXT,
            reputation INTEGER,
            whois_date TEXT,

            last_analysis_date TEXT,
            last_modification_date TEXT,

            harmless INTEGER,
            malicious INTEGER,
            suspicious INTEGER,
            undetected INTEGER,
            timeout INTEGER,

            votes_harmless INTEGER,
            votes_malicious INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_flat_ip ON query_flat(ip);
        CREATE INDEX IF NOT EXISTS idx_flat_queried_at ON query_flat(queried_at);

        CREATE TABLE IF NOT EXISTS intel_metrics (
            flat_id INTEGER PRIMARY KEY,
            engines_total INTEGER,
            engines_malicious INTEGER,
            engines_suspicious INTEGER,
            engines_harmless INTEGER,
            engines_undetected INTEGER,
            engines_timeout INTEGER,

            is_recent_7d INTEGER,
            is_recent_30d INTEGER,
            recency_bucket TEXT,

            top_malicious_engines TEXT,  -- JSON: [["EngineA","malicious","trojan.gen"], ...]
            FOREIGN KEY(flat_id) REFERENCES query_flat(id)
        );
        """)
        self.conn.commit()

    def enqueue_ips(self, ips: List[str]):
        if not ips:
            return
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        cur = self.conn.cursor()
        for ip in ips:
            cur.execute("SELECT ip FROM pending_ips WHERE ip=?", (ip,))
            if cur.fetchone():
                self.conn.execute("UPDATE pending_ips SET last_seen=? WHERE ip=?", (ts, ip))
            else:
                self.conn.execute(
                    "INSERT INTO pending_ips (ip, first_seen, last_seen, status) VALUES (?, ?, ?, 'pending')",
                    (ip, ts, ts)
                )
        self.conn.commit()

    def fetch_batch_pending(self, limit: int) -> List[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT ip FROM pending_ips WHERE status='pending' ORDER BY first_seen LIMIT ?", (limit,))
        return [r[0] for r in cur.fetchall()]

    def mark_done(self, ip: str):
        self.conn.execute("UPDATE pending_ips SET status='done' WHERE ip=?", (ip,))
        self.conn.commit()

    def mark_error(self, ip: str):
        self.conn.execute("UPDATE pending_ips SET status='error' WHERE ip=?", (ip,))
        self.conn.commit()

    def count_pending(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM pending_ips WHERE status='pending'")
        (n,) = cur.fetchone()
        return n or 0

    def count_used_today(self, account: str) -> int:
        today = date.today().isoformat()
        cur = self.conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM query_log
            WHERE account=? AND DATE(queried_at)=?
        """, (account, today))
        (n,) = cur.fetchone()
        return n or 0

    def record_query(self, ip: str, account: str, status_code: int, response_json: Optional[dict]):
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        self.conn.execute(
            "INSERT INTO query_log (ip, queried_at, account, status_code, response_json) VALUES (?, ?, ?, ?, ?)",
            (ip, ts, account, status_code, json.dumps(response_json, ensure_ascii=False) if response_json else None)
        )
        
        cur = self.conn.cursor()
        cur.execute("SELECT times_queried FROM query_ledger WHERE ip=?", (ip,))
        row = cur.fetchone()
        times = (row[0] if row else 0) + 1
        self.conn.execute("""
          INSERT INTO query_ledger (ip, last_queried_at, last_account, last_status, times_queried)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(ip) DO UPDATE SET
            last_queried_at=excluded.last_queried_at,
            last_account=excluded.last_account,
            last_status=excluded.last_status,
            times_queried=?
        """, (ts, account, status_code, status_code, times, times))
        self.conn.commit()

    def record_flat(self, ip: str, flat: Dict[str, Any]) -> int:
        cur = self.conn.cursor()
        cur.execute("""
          INSERT INTO query_flat (
            ip, queried_at, as_owner, asn, continent, country, network, reputation, whois_date,
            last_analysis_date, last_modification_date,
            harmless, malicious, suspicious, undetected, timeout,
            votes_harmless, votes_malicious
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip, flat.get("queried_at"),
            flat.get("as_owner"),
            flat.get("asn"),
            flat.get("continent"),
            flat.get("country"),
            flat.get("network"),
            flat.get("reputation"),
            flat.get("whois_date"),
            flat.get("last_analysis_date"),
            flat.get("last_modification_date"),
            flat.get("harmless"),
            flat.get("malicious"),
            flat.get("suspicious"),
            flat.get("undetected"),
            flat.get("timeout"),
            flat.get("votes_harmless"),
            flat.get("votes_malicious"),
        ))
        self.conn.commit()
        return cur.lastrowid

    def record_metrics(self, flat_id: int, metrics: Dict[str, Any]):
        self.conn.execute("""
          INSERT OR REPLACE INTO intel_metrics (
            flat_id,
            engines_total, engines_malicious, engines_suspicious,
            engines_harmless, engines_undetected, engines_timeout,
            is_recent_7d, is_recent_30d, recency_bucket, top_malicious_engines
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flat_id,
            metrics.get("engines_total"),
            metrics.get("engines_malicious"),
            metrics.get("engines_suspicious"),
            metrics.get("engines_harmless"),
            metrics.get("engines_undetected"),
            metrics.get("engines_timeout"),
            1 if metrics.get("is_recent_7d") else 0,
            1 if metrics.get("is_recent_30d") else 0,
            metrics.get("recency_bucket"),
            json.dumps(metrics.get("top_malicious_engines", []), ensure_ascii=False),
        ))
        self.conn.commit()

def flatten_payload(ip: str, payload: dict) -> Dict[str, Any]:
    data = (payload or {}).get("data") or {}
    attr = data.get("attributes") or {}
    las = attr.get("last_analysis_stats") or {}
    votes = attr.get("total_votes") or {}

    return {
        "ip": ip,
        "queried_at": datetime.now().astimezone().isoformat(timespec="seconds"),

        "as_owner": attr.get("as_owner"),
        "asn": attr.get("asn"),
        "continent": attr.get("continent"),
        "country": attr.get("country"),
        "network": attr.get("network"),
        "reputation": attr.get("reputation"),

        "whois_date": from_epoch(attr.get("whois_date")),
        "last_analysis_date": from_epoch(attr.get("last_analysis_date")),
        "last_modification_date": from_epoch(attr.get("last_modification_date")),

        "harmless": las.get("harmless"),
        "malicious": las.get("malicious"),
        "suspicious": las.get("suspicious"),
        "undetected": las.get("undetected"),
        "timeout": las.get("timeout"),

        "votes_harmless": votes.get("harmless"),
        "votes_malicious": votes.get("malicious"),
    }

def compute_metrics(payload: dict) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    data = (payload or {}).get("data") or {}
    attr = data.get("attributes") or {}

    results = attr.get("last_analysis_results") or {}
    last_analysis_date = attr.get("last_analysis_date")
    last_dt = datetime.fromtimestamp(last_analysis_date, timezone.utc) if isinstance(last_analysis_date, int) else None

    engines_total = 0
    engines_count = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0}
    top_mal = []  

    for eng, info in results.items():
        if not isinstance(info, dict):
            continue
        category = info.get("category")  
        result = info.get("result")
        engines_total += 1
        if category in engines_count:
            engines_count[category] += 1
        if category == "malicious":
            top_mal.append([eng, category, result])

    top_mal_sorted = sorted(top_mal, key=lambda x: (-len(x[2] or ""), x[0]))[:5]

    if last_dt:
        delta_days = (now - last_dt).days
        bucket = "7d" if delta_days <= 7 else "30d" if delta_days <= 30 else "90d" if delta_days <= 90 else "older"
        is7 = delta_days <= 7
        is30 = delta_days <= 30
    else:
        bucket = "none"
        is7 = False
        is30 = False

    return {
        "engines_total": engines_total,
        "engines_malicious": engines_count["malicious"],
        "engines_suspicious": engines_count["suspicious"],
        "engines_harmless": engines_count["harmless"],
        "engines_undetected": engines_count["undetected"],
        "engines_timeout": engines_count["timeout"],
        "is_recent_7d": is7,
        "is_recent_30d": is30,
        "recency_bucket": bucket,
        "top_malicious_engines": top_mal_sorted,
    }

def probe_key(key: str) -> Tuple[int, dict]:
    headers = {"x-apikey": key, "User-Agent": USER_AGENT}
    try:
        resp = requests.get(VT_URL.format("8.8.8.8"), headers=headers, timeout=10)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:200]}
        return resp.status_code, body
    except requests.RequestException as e:
        return 599, {"error": str(e)[:200]}

class VTClient:
    def __init__(self, keys: List[str], per_account_daily: int, dry_run: bool = False):
        self.keys = keys
        self.per_account_daily = per_account_daily
        self.idx = 0
        self.dry = dry_run

    def next_account(self, db: 'DB') -> Optional[str]:
        if self.dry:
            return "DRYRUN"
        if not self.keys:
            return None
        tried = 0
        while tried < len(self.keys):
            key = self.keys[self.idx]
            used = db.count_used_today(key)
            if used < self.per_account_daily:
                return key
            self.idx = (self.idx + 1) % len(self.keys)
            tried += 1
        return None

    def check(self, ip: str, key: str, max_backoff: int) -> Tuple[int, dict]:
        if self.dry:
            stats = random.choice([
                {"malicious": 0, "harmless": 25, "suspicious": 0, "undetected": 56, "timeout": 0},
                {"malicious": 2, "harmless": 20, "suspicious": 1, "undetected": 58, "timeout": 0},
                {"malicious": 5, "harmless": 12, "suspicious": 3, "undetected": 61, "timeout": 1},
            ])
            now_epoch = int(datetime.now(timezone.utc).timestamp())
            return 200, {
                "data": {
                    "id": ip,
                    "type": "ip_address",
                    "attributes": {
                        "as_owner": random.choice(["Example ISP", "Example DC", "Unknown"]),
                        "asn": random.randint(1000, 65000),
                        "continent": random.choice(["NA","EU","AS","SA","AF","OC"]),
                        "country": random.choice(["US","TW","CN","DE","BR","GB","JP"]),
                        "network": "1.2.3.0/24",
                        "reputation": random.randint(-50, 50),
                        "whois_date": now_epoch - 86400*random.randint(10, 2000),
                        "last_analysis_date": now_epoch - 86400*random.randint(0, 120),
                        "last_modification_date": now_epoch,
                        "total_votes": {"harmless": random.randint(0, 10), "malicious": random.randint(0, 10)},
                        "last_analysis_stats": stats,
                        "last_analysis_results": {
                            "EngineA": {"category": "malicious" if stats["malicious"] else "harmless", "result": "trojan.gen"},
                            "EngineB": {"category": "harmless", "result": None}
                        }
                    }
                }
            }

        headers = {"x-apikey": key, "User-Agent": USER_AGENT}
        backoff = 1.0
        last_status = None
        last_body = None

        for attempt in range(6):
            try:
                resp = requests.get(VT_URL.format(ip), headers=headers, timeout=20)
                last_status = resp.status_code
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text[:1000]}
                last_body = body
                if last_status == 200 or (400 <= last_status < 600 and last_status != 429):
                    if last_status != 200:
                        ra = resp.headers.get("Retry-After")
                        log(f"[WARN] HTTP {last_status} for {ip} | Retry-After={ra} | body={str(body)[:200]}")
                    return last_status, body

                if last_status == 429:
                    ra = resp.headers.get("Retry-After")
                    try:
                        sleep_s = max(1, int(float(ra))) if ra else backoff
                    except Exception:
                        sleep_s = backoff
                    sleep_s = min(sleep_s, max_backoff)
                    log(f"[INFO] 429 for {ip}; sleep {sleep_s}s (attempt {attempt+1}/6)")
                    time.sleep(sleep_s)
                    backoff = min(max_backoff, backoff * 2)
                    continue

                if 500 <= last_status < 600:
                    sleep_s = min(backoff, max_backoff)
                    log(f"[INFO] {last_status} for {ip}; backoff {sleep_s}s (attempt {attempt+1}/6)")
                    time.sleep(sleep_s)
                    backoff = min(max_backoff, backoff * 2)
                    continue

                return last_status, body

            except requests.RequestException as e:
                last_status = 599
                last_body = {"error": f"requests exception: {str(e)[:300]}"}
                sleep_s = min(backoff, max_backoff)
                log(f"[WARN] requests exception for {ip}; backoff {sleep_s}s (attempt {attempt+1}/6)")
                time.sleep(sleep_s)
                backoff = min(max_backoff, backoff * 2)

        return last_status if last_status is not None else 599, last_body or {"error": "unknown"}

def seed_from_file(db: DB, path: str):
    ips = load_ips_from_file(path)
    db.enqueue_ips(ips)
log(f"[INIT] Load {len(ips)} IPs from the file, total pending IPs = {db.count_pending()}")

def run_once(
    db: DB,
    client: VTClient,
    per_run_cap: int,
    sleep_sec: float,
    out_jsonl_dir: str,
    max_backoff_sec: int,
):
    out_dir = out_jsonl_dir
    theoretical_cap = per_run_cap if client.dry else min(per_run_cap, max(1, len(client.keys)) * client.per_account_daily)

    batch = db.fetch_batch_pending(theoretical_cap)
    if not batch:
        log("[RUN] There is currently no pending IP in the queue")
        return

    processed = 0
    ok = 0
    ng = 0

    for ip in batch:
        account = client.next_account(db)
        if not account:
            log("[RUN] All account quotas have been used up today, stop this round")
            break

        status, data = client.check(ip, account, max_backoff_sec)
        db.record_query(ip, account, status, data)
        append_daily_jsonl(ip, status, data, out_dir=out_dir)

        if status == 200:
            try:
                flat = flatten_payload(ip, data)
                flat_id = db.record_flat(ip, flat)
                metrics = compute_metrics(data)
                db.record_metrics(flat_id, metrics)
                ok += 1
                db.mark_done(ip)
            except Exception as e:
                log(f"[WARN] Flattening/metric writing failed {ip}: {e}")
                ng += 1
                db.mark_error(ip)
        else:
            ng += 1
            db.mark_error(ip)

        processed += 1
        if processed % 50 == 0:
            used = {k if client.dry else (k[:6] + "…"): db.count_used_today(k) for k in (["DRYRUN"] if client.dry else client.keys)}
            log(f"[RUN] processed={processed}/{len(batch)} | ok={ok} ng={ng} | used_today={used} | pending_left={db.count_pending()}")

        if not client.dry:
            time.sleep(sleep_sec)

    used = {k if client.dry else (k[:6] + "…"): db.count_used_today(k) for k in (["DRYRUN"] if client.dry else client.keys)}
    log(f"[DONE] processed={processed} ok={ok} ng={ng} | used_today={used} | pending_left={db.count_pending()}")

def main():
    INPUT_FILE         = CONFIG["INPUT_FILE"]
    VT_API_KEYS        = CONFIG["VT_API_KEYS"]
    PER_ACCOUNT_DAILY  = CONFIG["PER_ACCOUNT_DAILY"]
    PER_RUN_CAP        = CONFIG["PER_RUN_CAP"] if CONFIG["PER_RUN_CAP"] is not None else max(1, len(VT_API_KEYS)) * max(1, PER_ACCOUNT_DAILY)
    REQUEST_SLEEP_SEC  = CONFIG["REQUEST_SLEEP_SEC"]
    SQLITE_PATH        = CONFIG["SQLITE_PATH"]
    DAILY_JSONL_DIR    = CONFIG["DAILY_JSONL_DIR"]
    DRY_RUN            = CONFIG["DRY_RUN"]
    MAX_BACKOFF_SEC    = CONFIG["MAX_BACKOFF_SEC"]
    PROBE_ONLY         = CONFIG["PROBE_KEYS_AND_EXIT"]

    if PROBE_ONLY:
        if not VT_API_KEYS:
            log("No testable keys (VT_API_KEYS is empty)")
            sys.exit(2)
        ok = 0
        for i, k in enumerate(VT_API_KEYS, 1):
            status, _ = probe_key(k)
            if status == 200:
                log(f"API key #{i} verified")
                ok += 1
            else:
                log(f" API key #{i} verification failed: HTTP {status}")
        sys.exit(0 if ok == len(VT_API_KEYS) else 3)

    if not VT_API_KEYS and not DRY_RUN:
        log("Please fill in the key in CONFIG['VT_API_KEYS'], or set CONFIG['DRY_RUN']=True to do a dry run test first")
        sys.exit(2)

    db = DB(SQLITE_PATH)
    if INPUT_FILE:
        seed_from_file(db, INPUT_FILE)

    client = VTClient(VT_API_KEYS, PER_ACCOUNT_DAILY, dry_run=DRY_RUN)
    run_once(
        db=db,
        client=client,
        per_run_cap=PER_RUN_CAP,
        sleep_sec=REQUEST_SLEEP_SEC,
        out_jsonl_dir=DAILY_JSONL_DIR,
        max_backoff_sec=MAX_BACKOFF_SEC,
    )

if __name__ == "__main__":
    main()
