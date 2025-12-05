import os, sys, json, time, logging
from collections import Counter, defaultdict
from datetime import datetime, date, timezone
from typing import Dict, Optional, Tuple, Any
import requests
from zoneinfo import ZoneInfo

OPENCTI_URL    = "change_me"
OPENCTI_TOKEN  = "change_me"

START_DATE     = "2025-01-XX"    # Including (GTM+8)
END_DATE       = "2025-12-XX"    # Excluding (GTM+8)

INCLUDE        = "both"          # "both" | "observables" | "indicators"
SKIP_REVOKED_INDICATORS = True   # The client ignores indicators with revoked==True

OUT_DIR        = "your_path"
BATCH_SIZE     = 500
REQUEST_TIMEOUT= 300
RETRY_TOTAL    = 5
RETRY_BACKOFF  = 1.2
LOG_LEVEL      = "INFO"

TZ = ZoneInfo("Asia/Taipei")

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format="%(asctime)s | %(levelname)s | %(message)s",
                    force=True)
log = logging.getLogger("ioc-daily-stats-simple")

def _to_utc(dt_local: datetime) -> datetime:
    return dt_local.astimezone(timezone.utc)

def _window_utc() -> Tuple[str, str]:
    d0 = date.fromisoformat(START_DATE)
    d1 = date.fromisoformat(END_DATE)
    start_local = datetime(d0.year, d0.month, d0.day, 0, 0, 0, tzinfo=TZ)
    end_local   = datetime(d1.year, d1.month, d1.day, 0, 0, 0, tzinfo=TZ)
    return _to_utc(start_local).replace(microsecond=0).isoformat().replace("+00:00","Z"), \
           _to_utc(end_local).replace(microsecond=0).isoformat().replace("+00:00","Z")

SINCE_ISO_Z, UNTIL_ISO_Z = _window_utc()
log.info(f"Query period (GTM+8): {START_DATE} ~ {END_DATE} → UTC: {SINCE_ISO_Z} ~ {UNTIL_ISO_Z}")

def _session() -> requests.Session:
    from requests.adapters import HTTPAdapter, Retry
    s = requests.Session()
    retries = Retry(total=RETRY_TOTAL, backoff_factor=RETRY_BACKOFF,
                    status_forcelist=[429,500,502,503,504],
                    allowed_methods=frozenset(["GET","POST"]))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

SESSION = _session()
HEADERS = {"Content-Type": "application/json", "Authorization": f"Bearer {OPENCTI_TOKEN}"}
GRAPHQL = f"{OPENCTI_URL.rstrip('/')}/graphql"

def gql(query: str, variables: dict) -> dict:
    r = SESSION.post(GRAPHQL, headers=HEADERS, json={"query": query, "variables": variables}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(json.dumps(data["errors"], ensure_ascii=False))
    return data["data"]

def paged(query: str, root_key: str):
    after = None
    fetched = 0
    while True:
        vars_ = {"first": BATCH_SIZE, "after": after}
        data = gql(query, vars_)
        conn = data[root_key]
        edges = conn.get("edges", [])
        for e in edges:
            node = e.get("node")
            if node:
                fetched += 1
                yield node
        if not conn["pageInfo"]["hasNextPage"]:
            break
        after = conn["pageInfo"]["endCursor"]

def q_obs_created() -> str:
    return f"""
query ObsCreated($first:Int!,$after:ID){{
  stixCyberObservables(
    first: $first, after: $after,
    filters: {{
      mode: and,
      filters: [
        {{ key: "created_at", values: ["{SINCE_ISO_Z}"], operator: gt }},
        {{ key: "created_at", values: ["{UNTIL_ISO_Z}"], operator: lt }}
      ], filterGroups: []
    }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{ id entity_type created_at }} }}
  }}
}}
"""

def q_obs_updated() -> str:
    return f"""
query ObsUpdated($first:Int!,$after:ID){{
  stixCyberObservables(
    first: $first, after: $after,
    filters: {{
      mode: and,
      filters: [
        {{ key: "updated_at", values: ["{SINCE_ISO_Z}"], operator: gt }},
        {{ key: "updated_at", values: ["{UNTIL_ISO_Z}"], operator: lt }}
      ], filterGroups: []
    }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{ id entity_type updated_at }} }}
  }}
}}
"""

def q_ind_created() -> str:
    return f"""
query IndCreated($first:Int!,$after:ID){{
  indicators(
    first: $first, after: $after,
    filters: {{
      mode: and,
      filters: [
        {{ key: "created_at", values: ["{SINCE_ISO_Z}"], operator: gt }},
        {{ key: "created_at", values: ["{UNTIL_ISO_Z}"], operator: lt }}
      ], filterGroups: []
    }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{ id revoked x_opencti_main_observable_type pattern_type created_at }} }}
  }}
}}
"""

def q_ind_updated() -> str:
    return f"""
query IndUpdated($first:Int!,$after:ID){{
  indicators(
    first: $first, after: $after,
    filters: {{
      mode: and,
      filters: [
        {{ key: "updated_at", values: ["{SINCE_ISO_Z}"], operator: gt }},
        {{ key: "updated_at", values: ["{UNTIL_ISO_Z}"], operator: lt }}
      ], filterGroups: []
    }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{ id revoked x_opencti_main_observable_type pattern_type updated_at }} }}
  }}
}}
"""

def _parse_iso(s: str):
    if not s: return None
    if s.endswith("Z"): s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)

def _local_day(iso_z: str) -> str:
    dt = _parse_iso(iso_z)
    return dt.astimezone(TZ).date().isoformat() if dt else "NA"

def _ind_type(node: dict) -> str:
    return node.get("x_opencti_main_observable_type") or node.get("pattern_type") or "Unknown"

def _summarize(cnt_by_day: Dict[str, Counter]) -> Dict[str, Any]:
    # 輸出：{"daily": {"YYYY-MM-DD": total}, "by_type": {"IPv4-Addr": N, ...}, "total": N}
    daily = {}
    by_type_total = Counter()
    for day, c in sorted(cnt_by_day.items()):
        daily[day] = sum(c.values())
        by_type_total.update(c)
    return {
        "daily": daily,
        "by_type": dict(sorted(by_type_total.items(), key=lambda kv: (-kv[1], kv[0]))),
        "total": sum(by_type_total.values())
    }

def collect_stats():
    obs_created_cnt, obs_updated_cnt = {}, {}
    ind_created_cnt, ind_updated_cnt = {}, {}

    if INCLUDE in ("both", "observables"):
        log.info("Observables.created Daily Statistics...")
        for nd in paged(q_obs_created(), "stixCyberObservables"):
            day = _local_day(nd.get("created_at"))
            typ = nd.get("entity_type") or "Unknown"
            obs_created_cnt.setdefault(day, Counter())[typ] += 1

        log.info("Observables.updated Daily Statistics...")
        for nd in paged(q_obs_updated(), "stixCyberObservables"):
            day = _local_day(nd.get("updated_at"))
            typ = nd.get("entity_type") or "Unknown"
            obs_updated_cnt.setdefault(day, Counter())[typ] += 1

    if INCLUDE in ("both", "indicators"):
        log.info("Indicators.created Daily Statistics...")
        for nd in paged(q_ind_created(), "indicators"):
            if SKIP_REVOKED_INDICATORS and nd.get("revoked") is True:
                continue
            day = _local_day(nd.get("created_at"))
            typ = _ind_type(nd)
            ind_created_cnt.setdefault(day, Counter())[typ] += 1

        log.info("Indicators.updated Daily Statistics...")
        for nd in paged(q_ind_updated(), "indicators"):
            if SKIP_REVOKED_INDICATORS and nd.get("revoked") is True:
                continue
            day = _local_day(nd.get("updated_at"))
            typ = _ind_type(nd)
            ind_updated_cnt.setdefault(day, Counter())[typ] += 1

    stats = {
        "observables": {
            "created": _summarize(obs_created_cnt),
            "updated": _summarize(obs_updated_cnt)
        },
        "indicators": {
            "created": _summarize(ind_created_cnt),
            "updated": _summarize(ind_updated_cnt)
        }
    }
    return stats

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    stats = collect_stats()
    ts = datetime.now(TZ).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(OUT_DIR, f"ioc_daily_count_{ts}.json")
    payload = {
        "window": {"since_local": START_DATE, "until_local": END_DATE, "tz": "Asia/Taipei",
                   "since_utc": SINCE_ISO_Z, "until_utc": UNTIL_ISO_Z},
        "stats": stats,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    log.info(f"JSON has output to : {out_path}")
    print(f"DONE → {out_path}")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
