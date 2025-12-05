import os, sys, time, json, sqlite3, ipaddress, random
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Tuple, Dict, Any
import requests

INPUT_FILE = "your_path"

OTX_API_KEYS: List[str] = [
    "api_key_1",
    "api_key_2",
]



PER_ACCOUNT_DAILY = 1000
PER_RUN_CAP = max(1, len(OTX_API_KEYS)) * max(1, PER_ACCOUNT_DAILY)

REQUEST_SLEEP_SEC = 0.2
MAX_BACKOFF_SEC = 16

SQLITE_PATH = "your_path"
DAILY_JSONL_DIR = "your_path"

DRY_RUN = True

OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
USER_AGENT = "otx-backlog/1.0"

# ----------------- helpers -----------------
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
    path = os.path.join(out_dir, f"otx_{day}.jsonl")
    rec = {"ip": ip, "status": status, "checked_at": datetime.now().astimezone().isoformat(), "otx": payload}
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
            status TEXT DEFAULT 'pending'
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
            pulse_count INTEGER,
            reputation INTEGER,
            geo_country TEXT,
            hostname TEXT,
            malicious INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_flat_ip ON query_flat(ip);
        CREATE INDEX IF NOT EXISTS idx_flat_queried_at ON query_flat(queried_at);

        CREATE TABLE IF NOT EXISTS intel_metrics (
            flat_id INTEGER PRIMARY KEY,
            last_pulse_at TEXT,
            pulses_7d INTEGER,
            pulses_30d INTEGER,
            top_pulses TEXT,
            is_recent_7d INTEGER,
            is_recent_30d INTEGER,
            recency_bucket TEXT,
            FOREIGN KEY(flat_id) REFERENCES query_flat(id)
        );
        """)
        self.conn.commit()

    def enqueue_ips(self, ips: List[str]):
        if not ips: return
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        cur = self.conn.cursor()
        for ip in ips:
            cur.execute("SELECT ip FROM pending_ips WHERE ip=?", (ip,))
            if cur.fetchone():
                self.conn.execute("UPDATE pending_ips SET last_seen=? WHERE ip=?", (ts, ip))
            else:
                self.conn.execute("INSERT INTO pending_ips (ip, first_seen, last_seen, status) VALUES (?, ?, ?, 'pending')", (ip, ts, ts))
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
        cur.execute("SELECT COUNT(*) FROM query_log WHERE account=? AND DATE(queried_at)=?", (account, today))
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
          INSERT INTO query_flat (ip, queried_at, pulse_count, reputation, geo_country, hostname, malicious)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ip, flat.get("queried_at"),
            flat.get("pulse_count"),
            flat.get("reputation"),
            flat.get("geo_country"),
            flat.get("hostname"),
            1 if flat.get("malicious") else 0
        ))
        self.conn.commit()
        return cur.lastrowid

    def record_metrics(self, flat_id: int, metrics: Dict[str, Any]):
        self.conn.execute("""
          INSERT OR REPLACE INTO intel_metrics (
            flat_id, last_pulse_at, pulses_7d, pulses_30d, top_pulses,
            is_recent_7d, is_recent_30d, recency_bucket
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flat_id,
            metrics.get("last_pulse_at"),
            metrics.get("pulses_7d"),
            metrics.get("pulses_30d"),
            json.dumps(metrics.get("top_pulses", []), ensure_ascii=False),
            1 if metrics.get("is_recent_7d") else 0,
            1 if metrics.get("is_recent_30d") else 0,
            metrics.get("recency_bucket")
        ))
        self.conn.commit()

def flatten_payload(ip: str, payload: dict) -> Dict[str, Any]:
    d = (payload or {}).get("pulse_info") or {}
    pulse_count = d.get("count") or 0
    reputation = (payload.get("reputation") if isinstance(payload.get("reputation"), int) else None) or 0
    geo = payload.get("geo") or {}
    hostname = (payload.get("hostname") or "")
    malicious = bool(pulse_count > 0 or payload.get("malicious", False))
    return {
        "ip": ip,
        "queried_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "pulse_count": pulse_count,
        "reputation": reputation,
        "geo_country": geo.get("country_name") or geo.get("country") or None,
        "hostname": hostname,
        "malicious": malicious
    }

def compute_metrics(payload: dict) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    pulses = (payload or {}).get("pulse_info", {}).get("pulses", []) or []
    times = []
    top_pulses = []
    for p in pulses:
        dt = p.get("modified") or p.get("created")
        if dt:
            try:
                t = datetime.fromisoformat(str(dt).replace("Z", "+00:00")).astimezone(timezone.utc)
                times.append(t)
            except Exception:
                pass
        top_pulses.append({"name": p.get("name"), "id": p.get("id")})
    times_sorted = sorted(times)
    last_pulse = times_sorted[-1] if times_sorted else None

    def count_since(days: int) -> int:
        thr = now - timedelta(days=days)
        return sum(1 for t in times if t >= thr)

    p7 = count_since(7)
    p30 = count_since(30)

    if last_pulse:
        delta = (now - last_pulse).days
        bucket = "7d" if delta <= 7 else "30d" if delta <= 30 else "90d" if delta <= 90 else "older"
    else:
        bucket = "none"

    return {
        "last_pulse_at": last_pulse.isoformat() if last_pulse else None,
        "pulses_7d": p7,
        "pulses_30d": p30,
        "top_pulses": top_pulses[:5],
        "is_recent_7d": p7 > 0,
        "is_recent_30d": p30 > 0,
        "recency_bucket": bucket
    }

def probe_key(key: str) -> Tuple[int, dict]:
    headers = {"X-OTX-API-KEY": key, "User-Agent": USER_AGENT}
    try:
        resp = requests.get(OTX_IP_URL.format(ip="8.8.8.8"), headers=headers, timeout=10)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:200]}
        return resp.status_code, body
    except requests.RequestException as e:
        return 599, {"error": str(e)[:200]}

class OTXClient:
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

    def check(self, ip: str, key: str) -> Tuple[int, dict]:
        if self.dry:
            return 200, {
                "address": ip,
                "reputation": random.randint(-5, 50),
                "hostname": f"host-{ip.replace('.','-')}.example",
                "pulse_info": {"count": random.randint(0, 5), "pulses": []},
                "geo": {"country": "US", "country_name": "United States"}
            }

        headers = {"X-OTX-API-KEY": key, "User-Agent": USER_AGENT}
        backoff = 1.0
        last_status = None
        last_body = None
        for attempt in range(6):
            try:
                resp = requests.get(OTX_IP_URL.format(ip=ip), headers=headers, timeout=20)
                last_status = resp.status_code
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text[:1000]}
                last_body = body

                if last_status == 200 or (400 <= last_status < 600 and last_status != 429):
                    if last_status != 200:
                        log(f"[WARN] HTTP {last_status} for {ip} | body={str(body)[:200]}")
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
    log(f"[INIT] Load {len(ips)} IPs from the file, total pending = {db.count_pending()}")

def run_once(db: DB, client: OTXClient, per_run_cap: int, sleep_sec: float, out_jsonl_dir: Optional[str] = None):
    out_dir = out_jsonl_dir or DAILY_JSONL_DIR
    theoretical_cap = per_run_cap if client.dry else min(per_run_cap, len(client.keys) * client.per_account_daily)

    batch = db.fetch_batch_pending(theoretical_cap)
    if not batch:
        log("[RUN] queue currently has no pending IPs")
        return

    processed = 0
    ok = 0
    ng = 0

    for ip in batch:
        account = client.next_account(db)
        if not account:
            log("[RUN] All account quotas have been used up today, stopping this round")
            break

        status, data = client.check(ip, account)
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

def _parse_args():
    import argparse
    ap = argparse.ArgumentParser(description="AlienVault OTX enrichment (run-once)")
    ap.add_argument("--input-file", default=INPUT_FILE, help="IP list file (txt, first column = IP)")
    ap.add_argument("--sqlite", default=SQLITE_PATH, help="SQLite path for backlog & results")
    ap.add_argument("--jsonl-dir", default=DAILY_JSONL_DIR, help="Output directory for otx_YYYY-MM-DD.jsonl")
    ap.add_argument("--otx-keys", default="", help='JSON array of keys, e.g., ["K1","K2"]')
    ap.add_argument("--per-account-daily", type=int, default=PER_ACCOUNT_DAILY)
    ap.add_argument("--max-run", type=int, default=PER_RUN_CAP, help="Max IPs to process in this run (upper bound)")
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
            raise SystemExit("--otx-keys must be a JSON array, for example '[\"K1\",\"K2\"]'")
    if OTX_API_KEYS:
        return [k for k in OTX_API_KEYS if str(k).strip()]
    return []

if __name__ == "__main__":
    args = _parse_args()
    keys = _resolve_keys(getattr(args, "otx_keys", ""))

    if not keys and not args.dry_run and not args.probe_keys:
        log("No API key. Please set OTX_API_KEYS in the file, specify it with --otx-keys, or test with --dry-run first.")
        sys.exit(2)

    if args.probe_keys:
        if not keys:
            log("No testable keys (please set OTX_API_KEYS in the file, or specify with --otx-keys)")
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

    max_run = args.max_run if args.max_run else max(1, len(keys)) * max(1, args.per_account_daily)

    db = DB(args.sqlite)
    if args.input_file:
        seed_from_file(db, args.input_file)

    client = OTXClient(keys, args.per_account_daily, dry_run=args.dry_run)
    run_once(db=db, client=client, per_run_cap=max_run, sleep_sec=args.sleep_sec, out_jsonl_dir=args.jsonl_dir)
