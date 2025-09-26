import os, sys, json, requests
from typing import Optional, Dict, Any, List, Set, Tuple

OPENCTI_BASE_URL = os.getenv("OPENCTI_BASE_URL", "http://localhost:8080")
OPENCTI_TOKEN    = os.getenv("OPENCTI_TOKEN",    "replace_me")
GRAPHQL_CANDIDATES = ["/graphql", "/api/graphql"]
Q_PROBE = "{ __typename }"

Q_INDICATOR_COUNT = """
query IndicatorCount($filters: FilterGroup, $search: String, $first: Int) {
  indicators(filters: $filters, search: $search, first: $first) {
    pageInfo { globalCount }
  }
}
"""

Q_INDICATOR_PAGE = """
query IndicatorPage($first: Int, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, filters: $filters) {
    edges {
      node {
        x_opencti_main_observable_type
        indicator_types
        pattern_type
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
"""

def find_graphql_endpoint(base_url: str, token: str) -> Optional[str]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}
    for suf in GRAPHQL_CANDIDATES:
        url = base_url.rstrip("/") + suf
        try:
            r = requests.post(url, headers=headers, json={"query": Q_PROBE}, timeout=10)
            if r.status_code == 200 and "data" in r.json():
                return url
        except Exception:
            pass
    return None

def cond_eq(key: str, values: List[str]) -> Dict[str, Any]:
    return {"key": key, "values": values, "operator": "eq", "mode": "and"}

def group(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"mode": "and", "filters": conditions or [], "filterGroups": []}

def filters_root(conditions: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not conditions:
        return {"mode": "and", "filters": [], "filterGroups": []}
    return {"mode": "and", "filters": [], "filterGroups": [group(conditions)]}

def gql_indicator_count(session: requests.Session, gql_url: str,
                        filters: Optional[Dict[str, Any]] = None,
                        search: Optional[str] = None) -> Optional[int]:
    variables = {"first": 1}
    if filters is not None:
        variables["filters"] = filters
    if search:
        variables["search"] = search
    payload = {"query": Q_INDICATOR_COUNT, "variables": variables}
    r = session.post(gql_url, json=payload, timeout=30)
    try:
        js = r.json()
    except Exception:
        print(f"Not JSON Response（HTTP {r.status_code}）：{r.text[:200]}")
        return None
    if r.status_code != 200:
        print(f"HTTP {r.status_code}：{json.dumps(js, ensure_ascii=False)[:300]}")
        return None
    if "errors" in js:
        print(f"GraphQL errors：{json.dumps(js['errors'], ensure_ascii=False)}")
        return None
    node = js.get("data", {}).get("indicators")
    return node.get("pageInfo", {}).get("globalCount") if node else None

def sample_main_types(session: requests.Session, gql_url: str,
                      cap: int = 3000, batch: int = 200) -> Set[str]:
    vals: Set[str] = set()
    cursor = None
    fetched = 0
    while fetched < cap:
        variables = {"first": min(batch, cap - fetched), "after": cursor}
        r = session.post(gql_url, json={"query": Q_INDICATOR_PAGE, "variables": variables}, timeout=30)
        js = r.json()
        data = js.get("data", {}).get("indicators", {})
        edges = data.get("edges", [])
        if not edges:
            break
        for e in edges:
            n = e["node"]
            xm = (n.get("x_opencti_main_observable_type") or "").strip()
            if xm:
                vals.add(xm)
            fetched += 1
        page = data.get("pageInfo", {})
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
    return vals

def count_by_main_types(session: requests.Session, gql_url: str, main_types: List[str]) -> List[Tuple[str, int]]:
    out = []
    for mt in main_types:
        cnt = gql_indicator_count(session, gql_url, filters=filters_root([cond_eq("x_opencti_main_observable_type", [mt])]))
        out.append((mt, cnt if isinstance(cnt, int) else 0))
    return out

def print_table(title: str, rows: List[Tuple[str, int]], top: Optional[int] = None):
    print(title)
    if not rows:
        print("(no data)\n")
        return
    rows_sorted = sorted(rows, key=lambda x: (-x[1], x[0]))
    if top:
        rows_sorted = rows_sorted[:top]
    w = max(len(k) for k, _ in rows_sorted)
    for k, v in rows_sorted:
        print(f"{k:<{w}s} : {v}")
    print()

def main():
    if not OPENCTI_TOKEN or OPENCTI_TOKEN.startswith("REPLACE_"):
        print("Please set OPENCTI_TOKEN")
        sys.exit(1)

    gql_url = find_graphql_endpoint(OPENCTI_BASE_URL, OPENCTI_TOKEN)
    if not gql_url:
        print("Can't not find useful GraphQL endpoint（/graphql or /api/graphql）")
        sys.exit(2)

    sess = requests.Session()
    sess.headers.update({"Authorization": f"Bearer {OPENCTI_TOKEN}", "Accept": "application/json", "Content-Type": "application/json"})

    total = gql_indicator_count(sess, gql_url, filters=None)
    print("===== Total Indicator =====")
    print(f"All Indicators                : {total}")
    print()

    discovered = sample_main_types(sess, gql_url, cap=3000, batch=200)
    must_have = {"IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile", "File", "Hostname", "Unknown"}
    main_type_list = sorted(discovered.union(must_have))
    rows = count_by_main_types(sess, gql_url, main_type_list)
    print_table("===== x_opencti_main_observable_type（Top）=====", rows, top=15)

    print("---- Hash breakdown (global pattern search) ----")
    for algo, term in [("MD5", "hashes.'MD5'"),
                       ("SHA-1", "hashes.'SHA-1'"),
                       ("SHA-256", "hashes.'SHA-256'")]:
        cnt = gql_indicator_count(sess, gql_url, filters=None, search=term)
        print(f"[All Indicators] {algo:7s} : {cnt if isinstance(cnt, int) else 'Search Failed'}")
    print()

    if any(k == "StixFile" and v > 0 for k, v in rows):
        print("---- Hash breakdown (restricted to StixFile) ----")
        for algo, term in [("MD5", "hashes.'MD5'"),
                           ("SHA-1", "hashes.'SHA-1'"),
                           ("SHA-256", "hashes.'SHA-256'")]:
            fobj = filters_root([cond_eq("x_opencti_main_observable_type", ["StixFile"])])
            cnt = gql_indicator_count(sess, gql_url, filters=fobj, search=term)
            print(f"[StixFile only]  {algo:7s} : {cnt if isinstance(cnt, int) else 'Search Failed'}")
        print()

if __name__ == "__main__":
    main()
