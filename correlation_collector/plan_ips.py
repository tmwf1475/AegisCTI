import os, sys, re, json, time, datetime as dt, logging
from typing import Iterable, List, Dict, Set, Tuple, Optional
import requests
from requests.adapters import HTTPAdapter, Retry

OPENCTI_URL   = os.getenv("OPENCTI_URL", "").strip()
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "").strip()
EXPORT_DIR    = os.getenv("EXPORT_DIR", "opencti_output/ip_output").strip()
WINDOW_START  = os.getenv("WINDOW_START", "").strip()
WINDOW_END    = os.getenv("WINDOW_END", "").strip()   # " " = now(UTC)
BATCH_SIZE    = int(os.getenv("BATCH_SIZE", "500"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format="%(asctime)s | %(levelname)s | %(message)s",
                    force=True)
log = logging.getLogger("opencti-ip-export")

def make_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=1.2,
                    status_forcelist=[429, 500, 502, 503, 504],
                    allowed_methods=frozenset(["POST", "GET"]))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

SESSION = make_session()

def _require_env(name: str, value: str):
    if not value:
        raise SystemExit(f"Missing required env: {name}")

def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def compute_window() -> Tuple[str, str]:
    if WINDOW_START:
        since = WINDOW_START
    else:
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2))\
            .replace(hour=0, minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    until = WINDOW_END or iso_now()
    log.info("WINDOW = [%s, %s] (exclusive upper bound on updated_at)", since, until)
    return since, until

SINCE_ISO, UNTIL_ISO = compute_window()

def headers() -> Dict[str, str]:
    return {"Content-Type": "application/json", "Authorization": f"Bearer {OPENCTI_TOKEN}"}

def graphql_endpoint() -> str:
    return f"{OPENCTI_URL.rstrip('/')}/graphql"

def gql(query: str, variables: dict) -> dict:
    r = SESSION.post(graphql_endpoint(), headers=headers(), json={"query": query, "variables": variables}, timeout=300)
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]

def write_lines(path: str, lines: Iterable[str]):
    with open(path, "w", encoding="utf-8") as f:
        for s in lines:
            f.write(s + "\n")

def write_jsonl(path: str, rows: Iterable[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for obj in rows:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def paged_fetch(query: str, root_key: str, vars_extra: Optional[dict]=None):
    after = None
    fetched = 0
    while True:
        variables = {"first": BATCH_SIZE, "after": after}
        if vars_extra:
            variables.update(vars_extra)
        data = gql(query, variables)
        conn = data[root_key]
        edges = conn.get("edges") or []
        for e in edges:
            node = e.get("node")
            if node:
                yield node
                fetched += 1
                if fetched % 1000 == 0:
                    log.info("[%s] fetched: %d", root_key, fetched)
        page = conn["pageInfo"]
        if not page.get("hasNextPage"):
            break
        after = page.get("endCursor")
        time.sleep(0.05)

def _filters_time_between_updated() -> str:
    return f"""
      {{
        mode: and
        filters: [
          {{ key:"updated_at", values:["{SINCE_ISO}"], operator: gt }},
          {{ key:"updated_at", values:["{UNTIL_ISO}"], operator: lt }}
        ]
        filterGroups: []
      }}
    """

def q_observables_ipv4_in_window() -> str:
    return f"""
query ObsIPv4($first:Int!,$after:ID){{
  stixCyberObservables(
    first:$first, after:$after,
    orderBy: created_at, orderMode: desc,
    filters:{{
      mode: and
      filterGroups: []
      filters: [
        {{ key:"entity_type", values:["IPv4-Addr"] }}
      ]
    }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{
      __typename
      ... on StixCyberObservable {{
        entity_type
        created_at
        updated_at
        ... on IPv4Addr {{ value }}
      }}
    }} }}
  }}
}}
"""

def q_indicators_in_window_min() -> str:
    return f"""
query IndWin($first:Int!,$after:ID){{
  indicators(
    first:$first, after:$after,
    orderBy: created, orderMode: desc,
    filters: { _filters_time_between_updated() }
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{
      id name pattern_type pattern updated_at created revoked
      x_opencti_main_observable_type
    }} }}
  }}
}}
"""

PATTERN_IPV4_RE = re.compile(r"\[ipv4-addr:value\s*=\s*(['\"])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\1\]", re.I)

def extract_ipv4_from_pattern(stix_pattern: str) -> List[str]:
    if not stix_pattern:
        return []
    return [m.group("ip") for m in PATTERN_IPV4_RE.finditer(stix_pattern)]

def main():
    _require_env("OPENCTI_URL", OPENCTI_URL)
    _require_env("OPENCTI_TOKEN", OPENCTI_TOKEN)

    me = gql("query{ me{ id name user_email }}", {})
    log.info("Auth OK as %s <%s>", me.get("me",{}).get("name"), me.get("me",{}).get("user_email"))

    os.makedirs(EXPORT_DIR, exist_ok=True)
    path_txt   = os.path.join(EXPORT_DIR, "your_path.json")
    path_jsonl = os.path.join(EXPORT_DIR, "your_path.jsonl")

    uniq_ips: Set[str] = set()

    log.info("Fetching IPv4 observables ...")
    for nd in paged_fetch(q_observables_ipv4_in_window(), "stixCyberObservables"):
        if nd.get("entity_type") == "IPv4-Addr" and nd.get("value"):
            uniq_ips.add(nd["value"])

    log.info("Parsing indicator patterns (IPv4 only) within window ...")
    for ind in paged_fetch(q_indicators_in_window_min(), "indicators"):
        patt = ind.get("pattern") or ""
        for ip in extract_ipv4_from_pattern(patt):
            uniq_ips.add(ip)

    ips_sorted = sorted(uniq_ips)
    write_lines(path_txt, ips_sorted)
    write_jsonl(path_jsonl, ({"ip": ip} for ip in ips_sorted))

    log.info("[OK] unique IPv4: %d", len(ips_sorted))
    log.info("[OK] written: %s", path_txt)
    log.info("[OK] written: %s", path_jsonl)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
