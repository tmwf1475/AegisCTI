import os, sys, time, json, sqlite3, ipaddress, random
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Tuple, Dict, Any
import requests

INPUT_FILE = "your_path"
ABUSE_API_KEYS: List[str] = [
    "api_key_1",
    "api_key_2"
]

PER_ACCOUNT_DAILY = 1000
PER_RUN_CAP = max(1, len(ABUSE_API_KEYS)) * max(1, PER_ACCOUNT_DAILY)

MAX_AGE_IN_DAYS = 365
REQUEST_SLEEP_SEC = 0.15
MAX_BACKOFF_SEC = 16

SQLITE_PATH = "your_path"
DAILY_JSONL_DIR = "your_path"

DRY_RUN = False

ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

def log(msg: str):
    ts = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"[{ts}] {msg}", flush=True)

def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False

def parse_iso8601(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

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
    path = os.path.join(out_dir, f"abuse_{day}.jsonl")
    rec = {"ip": ip, "status": status, "checked_at": datetime.now().astimezone().isoformat(), "abuseipdb": payload}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

class DB:
    def __init__(self, path: str = SQLITE_PATH):
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
            abuse_confidence_score INTEGER,
            total_reports INTEGER,
            num_distinct_users INTEGER,
            last_reported_at TEXT,
            country_code TEXT,
            country_name TEXT,
            is_tor INTEGER,
            usage_type TEXT,
            isp TEXT,
            domain TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_flat_ip ON query_flat(ip);
        CREATE INDEX IF NOT EXISTS idx_flat_queried_at ON query_flat(queried_at);

        CREATE TABLE IF NOT EXISTS intel_metrics (
            flat_id INTEGER PRIMARY KEY,
            first_reported_at TEXT,
            days_since_last INTEGER,
            days_since_first INTEGER,
            reports_7d INTEGER,
            reports_30d INTEGER,
            reports_90d INTEGER,
            reporter_cc_count INTEGER,
            reporter_id_count INTEGER,
            top_categories TEXT,     -- JSON: [["21", 12], ["18", 8], ["14", 4]]
            is_recent_7d INTEGER,
            is_recent_30d INTEGER,
            recency_bucket TEXT,
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
            ip, queried_at, abuse_confidence_score, total_reports, num_distinct_users,
            last_reported_at, country_code, country_name, is_tor, usage_type, isp, domain
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip, flat.get("queried_at"),
            flat.get("abuse_confidence_score"),
            flat.get("total_reports"),
            flat.get("num_distinct_users"),
            flat.get("last_reported_at"),
            flat.get("country_code"),
            flat.get("country_name"),
            1 if flat.get("is_tor") else 0,
            flat.get("usage_type"),
            flat.get("isp"),
            flat.get("domain"),
        ))
        self.conn.commit()
        return cur.lastrowid

    def record_metrics(self, flat_id: int, metrics: Dict[str, Any]):
        self.conn.execute("""
          INSERT OR REPLACE INTO intel_metrics (
            flat_id, first_reported_at, days_since_last, days_since_first,
            reports_7d, reports_30d, reports_90d,
            reporter_cc_count, reporter_id_count,
            top_categories, is_recent_7d, is_recent_30d, recency_bucket
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flat_id,
            metrics.get("first_reported_at"),
            metrics.get("days_since_last"),
            metrics.get("days_since_first"),
            metrics.get("reports_7d"),
            metrics.get("reports_30d"),
            metrics.get("reports_90d"),
            metrics.get("reporter_cc_count"),
            metrics.get("reporter_id_count"),
            json.dumps(metrics.get("top_categories", []), ensure_ascii=False),
            1 if metrics.get("is_recent_7d") else 0,
            1 if metrics.get("is_recent_30d") else 0,
            metrics.get("recency_bucket"),
        ))
        self.conn.commit()

def flatten_payload(ip: str, payload: dict) -> Dict[str, Any]:
    d = (payload or {}).get("data") or {}
    return {
        "ip": ip,
        "queried_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "num_distinct_users": d.get("numDistinctUsers"),
        "last_reported_at": d.get("lastReportedAt"),
        "country_code": d.get("countryCode"),
        "country_name": d.get("countryName"),
        "is_tor": d.get("isTor"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
    }

def compute_metrics(payload: dict) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    data = (payload or {}).get("data") or {}
    reports = data.get("reports") or []

    times: List[datetime] = []
    cats: Dict[str, int] = {}
    reporter_cc: set = set()
    reporter_ids: set = set()

    for r in reports:
        t = parse_iso8601(r.get("reportedAt"))
        if t:
            times.append(t.astimezone(timezone.utc))
        for c in (r.get("categories") or []):
            key = str(c)
            cats[key] = cats.get(key, 0) + 1
        cc = r.get("reporterCountryCode")
        if cc:
            reporter_cc.add(cc)
        rid = r.get("reporterId")
        if isinstance(rid, int):
            reporter_ids.add(rid)

    first_t = min(times) if times else None
    last_t = parse_iso8601(data.get("lastReportedAt"))
    if last_t:
        last_t = last_t.astimezone(timezone.utc)

    def days_since(t: Optional[datetime]) -> Optional[int]:
        return int((now - t).total_seconds() // 86400) if t else None

    def count_since(days: int) -> int:
        if not times:
            return 0
        threshold = now - timedelta(days=days)
        return sum(1 for t in times if t >= threshold)

    rep7 = count_since(7)
    rep30 = count_since(30)
    rep90 = count_since(90)
    top_cats = sorted(cats.items(), key=lambda kv: (-kv[1], kv[0]))[:3]

    if last_t:
        delta = (now - last_t).days
        bucket = "7d" if delta <= 7 else "30d" if delta <= 30 else "90d" if delta <= 90 else "older"
    else:
        bucket = "none"

    return {
        "first_reported_at": first_t.isoformat() if first_t else None,
        "days_since_last": days_since(last_t),
        "days_since_first": days_since(first_t),
        "reports_7d": rep7,
        "reports_30d": rep30,
        "reports_90d": rep90,
        "reporter_cc_count": len(reporter_cc),
        "reporter_id_count": len(reporter_ids),
        "top_categories": top_cats,
        "is_recent_7d": rep7 > 0,
        "is_recent_30d": rep30 > 0,
        "recency_bucket": bucket,
    }

def probe_key(key: str) -> Tuple[int, dict]:
    try:
        resp = requests.get(
            ABUSE_CHECK_URL,
            headers={"Key": key, "Accept": "application/json", "User-Agent": "abuse-backlog-probe"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": "1", "verbose": "false"},
            timeout=10,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:200]}
        return resp.status_code, body
    except requests.RequestException as e:
        return 599, {"error": str(e)[:200]}

class AbuseClient:
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

    def check(self, ip: str, key: str, max_age_days: int) -> Tuple[int, dict]:
        if self.dry:
            score = random.choice([0, 5, 15, 30, 50, 75, 100])
            total = random.randint(0, 120)
            now_iso = datetime.now().astimezone().isoformat(timespec="seconds")
            return 200, {
                "data": {
                    "ipAddress": ip, "isPublic": True,
                    "ipVersion": 4 if ":" not in ip else 6,
                    "isWhitelisted": False,
                    "abuseConfidenceScore": score,
                    "countryCode": random.choice(["US", "TW", "CN", "DE", "BR"]),
                    "countryName": random.choice(["United States", "Taiwan", "China", "Germany", "Brazil"]),
                    "usageType": random.choice(["Data Center/Web Hosting/Transit", "ISP", "Commercial", "Unknown"]),
                    "isp": random.choice(["ASXXXX Example ISP", "ASYYYY Example DC"]),
                    "domain": "example.test", "hostnames": [],
                    "isTor": random.choice([False, False, False, True]),
                    "totalReports": total,
                    "numDistinctUsers": random.randint(0, max(1, total)),
                    "lastReportedAt": now_iso,
                    "reports": [{
                        "reportedAt": now_iso, "comment": "dummy comment",
                        "categories": [18, 22], "reporterId": 1,
                        "reporterCountryCode": "US", "reporterCountryName": "United States"
                    }] if total > 0 else []
                }
            }

        headers = {"Key": key, "Accept": "application/json", "User-Agent": "abuse-backlog/1.3"}
        params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": "true"}

        backoff = 1.0
        last_status = None
        last_body = None

        for attempt in range(6):
            try:
                resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=20)
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
                    sleep_s = min(sleep_s, MAX_BACKOFF_SEC)
                    log(f"[INFO] 429 for {ip}; sleep {sleep_s}s (attempt {attempt+1}/6)")
                    time.sleep(sleep_s)
                    backoff = min(MAX_BACKOFF_SEC, backoff * 2)
                    continue

                if 500 <= last_status < 600:
                    sleep_s = min(backoff, MAX_BACKOFF_SEC)
                    log(f"[INFO] {last_status} for {ip}; backoff {sleep_s}s (attempt {attempt+1}/6)")
                    time.sleep(sleep_s)
                    backoff = min(MAX_BACKOFF_SEC, backoff * 2)
                    continue

                return last_status, body

            except requests.RequestException as e:
                last_status = 599
                last_body = {"error": f"requests exception: {str(e)[:300]}"}
                sleep_s = min(backoff, MAX_BACKOFF_SEC)
                log(f"[WARN] requests exception for {ip}; backoff {sleep_s}s (attempt {attempt+1}/6)")
                time.sleep(sleep_s)
                backoff = min(MAX_BACKOFF_SEC, backoff * 2)

        return last_status if last_status is not None else 599, last_body or {"error": "unknown"}

def seed_from_file(db: DB, path: str):
    ips = load_ips_from_file(path)
    db.enqueue_ips(ips)
    log(f"[INIT] Load {len(ips)} IPs from the file, total pending IPs = {db.count_pending()}")

def run_once(
    db: DB,
    client: AbuseClient,
    per_run_cap: int,
    max_age_days: int,
    sleep_sec: float,
    out_jsonl_dir: Optional[str] = None,
):
    out_dir = out_jsonl_dir or DAILY_JSONL_DIR
    theoretical_cap = per_run_cap if client.dry else min(per_run_cap, len(client.keys) * client.per_account_daily)

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

        status, data = client.check(ip, account, max_age_days)
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
               log(f"[WARN] Flattening/expiration write failed {ip}: {e}")
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

def _parse_args():
    import argparse
    ap = argparse.ArgumentParser(description="AbuseIPDB enrichment (run-once)")
    ap.add_argument("--input-file", default=INPUT_FILE, help="IP list file (txt, first column = IP)")
    ap.add_argument("--sqlite", default=SQLITE_PATH, help="SQLite path for backlog & results")
    ap.add_argument("--jsonl-dir", default=DAILY_JSONL_DIR, help="Output directory for abuse_YYYY-MM-DD.jsonl")
    ap.add_argument("--abuse-keys", default="", help='JSON array of keys, e.g., ["K1","K2"]')
    ap.add_argument("--per-account-daily", type=int, default=PER_ACCOUNT_DAILY)
    ap.add_argument("--max-run", type=int, default=PER_RUN_CAP, help="Max IPs to process in this run (upper bound)")
    ap.add_argument("--max-age-days", type=int, default=MAX_AGE_IN_DAYS)
    ap.add_argument("--sleep-sec", type=float, default=REQUEST_SLEEP_SEC)
    ap.add_argument("--dry-run", action="store_true", default=DRY_RUN)
    ap.add_argument("--probe-keys", action="store_true", help="Probe keys and exit")
    return ap.parse_args()

def _resolve_keys(arg_str: str) -> List[str]:
    if arg_str.strip():
        try:
            ks = json.loads(arg_str)
            if not isinstance(ks, list):
                raise ValueError
            return [str(k).strip() for k in ks if str(k).strip()]
        except Exception:
            raise SystemExit("--abuse-keys must be a JSON array, for example '[\"K1\",\"K2\"]'")
    if ABUSE_API_KEYS:
        return [k for k in ABUSE_API_KEYS if str(k).strip()]
    return []

if __name__ == "__main__":
    args = _parse_args()

    arg_keys = getattr(args, "abuse_keys", "")
    keys = _resolve_keys(arg_keys)
    if not keys and not args.dry_run and not args.probe_keys:
        log("No API key. Please set ABUSE_API_KEYS in the file, specify it with --abuse-keys, or test with --dry-run first.")
        sys.exit(2)

    if args.probe_keys:
        if not keys:
            log("No testable keys (please set ABUSE_API_KEYS in the file, or use --abuse-keys)")
            sys.exit(2)
        ok = 0
        for i, k in enumerate(keys, 1):
            status, body = probe_key(k)
            if status == 200:
                log(f"API key #{i} verified")
                ok += 1
            else:
                log(f" API key #{i} verification failed: HTTP {status} | {str(body)[:200]}")
        sys.exit(0 if ok == len(keys) else 3)

    db = DB(args.sqlite)
    if args.input_file:
        seed_from_file(db, args.input_file)

    client = AbuseClient(keys, args.per_account_daily, dry_run=args.dry_run)
    run_once(
        db=db,
        client=client,
        per_run_cap=args.max_run,
        max_age_days=args.max_age_days,
        sleep_sec=args.sleep_sec,
        out_jsonl_dir=args.jsonl_dir,
    )
