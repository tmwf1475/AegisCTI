import os, sys, json, time, datetime as dt, logging
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple, Iterable, Set
import requests
from requests.adapters import HTTPAdapter, Retry

OPENCTI_URL   = "http://localhost:8080"
OPENCTI_TOKEN = "change_me"

EXPORT_DIR    = "your_path"
EXPORT_MODE   = "WINDOW"

WINDOW_START  = "2025-01-01T00:00:00Z"
WINDOW_END    = ""     # "" = now

INCLUDE_REPORTS          = True
INCLUDE_GLOBAL_OBJECTS   = True     
INCLUDE_OBSERVABLE_TYPES = ["IPv4-Addr", "IPv6-Addr"]  

BATCH_SIZE    = 400                 
PAGE_BATCH    = 500              
ID_CHUNK      = 200                

MAX_OBSERVABLES_PER_INDICATOR = 0

LOG_LEVEL = "INFO"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    force=True,
)
log = logging.getLogger("opencti-json-export")

# ========= HTTP / GraphQL =========
def make_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1.2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST", "GET"],
    )
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

SESSION = make_session()
HEADERS = {"Content-Type": "application/json", "Authorization": f"Bearer {OPENCTI_TOKEN}"}

def gql(query: str, variables: dict) -> dict:
    r = SESSION.post(
        f"{OPENCTI_URL.rstrip('/')}/graphql",
        headers=HEADERS,
        json={"query": query, "variables": variables},
        timeout=300,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]

# ========= Time =========
def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def normalize_iso(s: Optional[str]) -> Optional[str]:
    if not s: return s
    return s.replace("+00:00","Z")

def compute_window() -> Tuple[str, str]:
    since = (WINDOW_START or "").strip() or (dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=2))\
        .replace(hour=0,minute=0,second=0,microsecond=0).isoformat().replace("+00:00","Z")
    until = (WINDOW_END or "").strip() or iso_now()
    log.info("EXPORT_MODE=WINDOW → [%s, %s] (inclusive)", since, until)
    return since, until

SINCE_ISO, UNTIL_ISO = compute_window()
OBS_TYPES_FILTER = set(INCLUDE_OBSERVABLE_TYPES or [])

# ========= Path =========
os.makedirs(EXPORT_DIR, exist_ok=True)
def P(name: str) -> str: return os.path.join(EXPORT_DIR, name)

PATH_IOC_JSONL      = P("ioc_timelines.jsonl")
PATH_STIX_JSONL     = P("stix_objects.jsonl")
PATH_EVENTS_JSONL   = P("events_facts.jsonl")
PATH_IPS_JSONL      = P("enrichment_input_ips.jsonl")
PATH_SUMMARY_JSONL  = P("summary.jsonl")

def write_jsonl(path: str, obj: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def chunked(iterable: Iterable[str], n: int) -> Iterable[List[str]]:
    batch: List[str] = []
    for x in iterable:
        batch.append(x)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch

def safe_list(o, key):
    v = o.get(key)
    if isinstance(v, list):
        return v
    if isinstance(v, dict) and "edges" in v:
        return [ (e or {}).get("node") for e in (v.get("edges") or []) if (e or {}).get("node") ]
    return []

def labels_list(obj: dict) -> List[str]:
    return [ (nd or {}).get("value") for nd in safe_list(obj, "objectLabel") if (nd or {}).get("value") ]

def markings_list(obj: dict) -> List[str]:
    out = []
    for nd in safe_list(obj, "objectMarking"):
        t = (nd or {}).get("definition_type")
        d = (nd or {}).get("definition")
        if t or d: out.append(f"{t}:{d}")
    return out

def external_refs(obj: dict) -> List[dict]:
    out = []
    for nd in safe_list(obj, "externalReferences"):
        out.append({
            "source_name": nd.get("source_name"),
            "url": nd.get("url"),
            "external_id": nd.get("external_id"),
        })
    return out

def creator_name(obj: dict) -> Optional[str]:
    cb = obj.get("createdBy") or {}
    return cb.get("name")

def ioc_key_of(nd: dict) -> Optional[str]:
    et = nd.get("entity_type")
    if et == "IPv4-Addr" and nd.get("value"): return f"ipv4-addr|{nd['value']}"
    if et == "IPv6-Addr" and nd.get("value"): return f"ipv6-addr|{nd['value']}"
    if et == "Domain-Name" and nd.get("value"): return f"domain-name|{nd['value']}"
    if et == "Url" and nd.get("value"): return f"url|{nd['value']}"
    if et == "Email-Addr" and nd.get("value"): return f"email-addr|{nd['value']}"
    return None

# ========= GraphQL Queries =========
def _fg(filters: str) -> str:
    return f'{{ mode: or, filters: [ {filters} ], filterGroups: [] }}'

def _time_filters_reports() -> str:
    ors = (
        f'{{ key:"created",    values:["{SINCE_ISO}"], operator: gt }}',
        f'{{ key:"updated_at", values:["{SINCE_ISO}"], operator: gt }}',
        f'{{ key:"published",  values:["{SINCE_ISO}"], operator: gt }}',
    )
    return f'[ {_fg(", ".join(ors))} ]'

def _time_filters_created_or_updated() -> str:
    ors = (
        f'{{ key:"created",    values:["{SINCE_ISO}"], operator: gt }}',
        f'{{ key:"updated_at", values:["{SINCE_ISO}"], operator: gt }}',
    )
    return f'[ {_fg(", ".join(ors))} ]'

def _time_filters_obs_created_or_updated() -> str:
    ors = (
        f'{{ key:"created_at", values:["{SINCE_ISO}"], operator: gt }}',
        f'{{ key:"updated_at", values:["{SINCE_ISO}"], operator: gt }}',
    )
    return f'[ {_fg(", ".join(ors))} ]'

# 1) Reports
def q_reports_min_in_window() -> str:
    return f"""
query Rpt($first:Int!,$after:ID){{
  reports(
    first:$first, after:$after,
    orderBy: created, orderMode: desc,
    filters: {{ mode: and, filterGroups: { _time_filters_reports() }, filters:[] }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{
      id standard_id name description published created updated_at
      createdBy{{ id name }}
      objectLabel{{ id value color }}
      objectMarking{{ id definition_type definition }}
      externalReferences{{ edges{{ node{{ source_name url external_id }} }} }}
    }} }}
  }}
}}
"""

# 2) Report.objects 
def q_report_objects_page() -> str:
    return """
query RObjs($id:String!,$first:Int!,$after:ID){
  report(id:$id){
    id
    objects(first:$first, after:$after){
      pageInfo{ endCursor hasNextPage }
      edges{ node{
        __typename
        ... on BasicObject { id }
        ... on StixObject { standard_id }
        ... on StixCoreObject {
          entity_type
          createdBy{ id name }
          objectLabel{ id value color }
          objectMarking{ id definition_type definition }
          externalReferences{ edges{ node{ source_name url external_id } } }
        }
        ... on StixDomainObject { created updated_at }
        ... on StixCoreRelationship { relationship_type }

        # StixCyberObservable
        ... on StixCyberObservable {
          created_at updated_at
          ... on IPv4Addr { value }
          ... on IPv6Addr { value }
          ... on DomainName { value }
          ... on Url { value }
          ... on EmailAddr { value }
        }

        ... on Report { name description published created updated_at }
        ... on Note   { attribute_abstract content created updated_at }
        ... on Opinion{ explanation opinion created updated_at }
        ... on Case { name description created updated_at }
        ... on CaseIncident { name description created updated_at }
        ... on CaseRfi { name description created updated_at }
        ... on CaseRft { name description created updated_at }
        ... on Feedback { name description created updated_at }

        # Indicator
        ... on Indicator {
          name description pattern_type pattern confidence
          valid_from valid_until revoked
          x_opencti_main_observable_type
          created updated_at
        }

        ... on ObservedData {
          first_observed last_observed number_observed
          created updated_at
        }
      } }
    }
  }
}
"""

# 3) Indicator.observables
def q_indicator_observables_page() -> str:
    return """
query IndObs($id:String!,$first:Int!){
  indicator(id:$id){
    id standard_id name description pattern_type pattern confidence valid_from valid_until revoked
    created updated_at
    createdBy{ id name }
    objectLabel{ id value color }
    objectMarking{ id definition_type definition }
    externalReferences{ edges{ node{ source_name url external_id } } }
    observables(first:$first){
      edges{ node{
        __typename
        ... on BasicObject { id }
        ... on StixObject { standard_id }
        ... on StixCoreObject {
          entity_type
          createdBy{ id name }
          objectLabel{ id value color }
          objectMarking{ id definition_type definition }
          externalReferences{ edges{ node{ source_name url external_id } } }
        }
        ... on StixCyberObservable {
          created_at updated_at
          ... on IPv4Addr { value }
          ... on IPv6Addr { value }
          ... on DomainName { value }
          ... on Url { value }
          ... on EmailAddr { value }
        }
      } }
    }
  }
}
"""

# 4) ObservedData.objects 
def q_observed_data_objects_page() -> str:
    return """
query ODObjs($id:String!,$first:Int!,$after:ID){
  observedData(id:$id){
    id
    objects(first:$first, after:$after){
      pageInfo{ endCursor hasNextPage }
      edges{ node{
        __typename
        ... on BasicObject { id }
        ... on StixObject { standard_id }
        ... on StixCoreObject {
          entity_type
          createdBy{ id name }
          objectLabel{ id value color }
          objectMarking{ id definition_type definition }
          externalReferences{ edges{ node{ source_name url external_id } } }
        }
        ... on StixCyberObservable {
          created_at updated_at
          ... on IPv4Addr { value }
          ... on IPv6Addr { value }
          ... on DomainName { value }
          ... on Url { value }
          ... on EmailAddr { value }
        }
      } }
    }
  }
}
"""

# 5) by-ids
def q_indicators_by_ids() -> str:
    return """
query Inds($first:Int!,$after:ID,$ids:[Any!]!) {
  indicators(
    first:$first, after:$after,
    orderBy: created, orderMode: desc,
    filters:{ mode: and, filterGroups: [], filters:[ { key:"ids", values:$ids } ] }
  ){
    pageInfo{ endCursor hasNextPage }
    edges{ node{
      id standard_id name description pattern_type pattern confidence
      valid_from valid_until created updated_at revoked
      x_opencti_main_observable_type
      createdBy{ id name }
      objectLabel{ id value color }
      objectMarking{ id definition_type definition }
      externalReferences{ edges{ node{ source_name url external_id } } }
    } }
  }
}
"""

def q_observables_by_ids() -> str:
    return """
query ObsByIds($first:Int!,$after:ID,$ids:[Any!]!){
  stixCyberObservables(
    first:$first, after:$after,
    orderBy: created_at, orderMode: desc,
    filters:{ mode: and, filterGroups: [], filters:[ { key:"ids", values:$ids } ] }
  ){
    pageInfo{ endCursor hasNextPage }
    edges{ node{
      __typename
      ... on BasicObject { id }
      ... on StixObject { standard_id }
      ... on StixCoreObject {
        entity_type
        createdBy{ id name }
        objectLabel{ id value color }
        objectMarking{ id definition_type definition }
        externalReferences{ edges{ node{ source_name url external_id } } }
      }
      ... on StixCyberObservable {
        created_at updated_at
        ... on IPv4Addr { value }
        ... on IPv6Addr { value }
        ... on DomainName { value }
        ... on Url { value }
        ... on EmailAddr { value }
      }
    } }
  }
}
"""

# 6) Sightings
def q_sightings_by_object_ids() -> str:
    return """
query Sights($first:Int!,$after:ID,$ids:[Any!]!){
  stixSightingRelationships(
    first:$first, after:$after,
    orderBy: created_at, orderMode: desc,
    filters:{
      mode: or
      filterGroups: [
        { mode: and, filters: [ { key:"fromId", values:$ids } ], filterGroups: [] },
        { mode: and, filters: [ { key:"toId",   values:$ids } ], filterGroups: [] }
      ]
      filters:[]
    }
  ){
    pageInfo{ endCursor hasNextPage }
    edges{ node{
      id created_at updated_at description confidence
      first_seen last_seen attribute_count
      createdBy{ id name }
      objectLabel{ id value color }
      objectMarking{ id definition_type definition }
      externalReferences{ edges{ node{ source_name url external_id } } }
      from {
        __typename
        ... on BasicObject { id }
        ... on StixCoreObject { entity_type }
        ... on StixCyberObservable {
          entity_type
          ... on IPv4Addr { value }
          ... on IPv6Addr { value }
          ... on DomainName { value }
          ... on Url { value }
          ... on EmailAddr { value }
        }
        ... on Indicator { id entity_type pattern_type name }
      }
      to {
        __typename
        ... on BasicObject { id }
        ... on StixCoreObject { entity_type }
        ... on StixCyberObservable {
          entity_type
          ... on IPv4Addr { value }
          ... on IPv6Addr { value }
          ... on DomainName { value }
          ... on Url { value }
          ... on EmailAddr { value }
        }
        ... on Indicator { id entity_type pattern_type name }
      }
    } }
  }
}
"""

# 7) Global Replenishment: Indicators/Observables within the Time Window
def q_indicators_in_window() -> str:
    return f"""
query IndWin($first:Int!,$after:ID){{
  indicators(
    first:$first, after:$after,
    orderBy: created, orderMode: desc,
    filters: {{ mode: and, filterGroups: { _time_filters_created_or_updated() }, filters:[] }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{
      id standard_id name description pattern_type pattern confidence
      valid_from valid_until created updated_at revoked
      x_opencti_main_observable_type
      createdBy{{ id name }}
      objectLabel{{ id value color }}
      objectMarking{{ id definition_type definition }}
      externalReferences{{ edges{{ node{{ source_name url external_id }} }} }}
    }} }}
  }}
}}
"""

def q_observables_in_window(entity_types: List[str]) -> str:
    types_list = ",".join([f'"{t}"' for t in entity_types])
    return f"""
query ObsWin($first:Int!,$after:ID){{
  stixCyberObservables(
    first:$first, after:$after,
    orderBy: created_at, orderMode: desc,
    filters:{{
      mode: and
      filterGroups: { _time_filters_obs_created_or_updated() }
      filters: [ {{ key:"entity_type", values:[{types_list}] }} ]
    }}
  ){{
    pageInfo{{ endCursor hasNextPage }}
    edges{{ node{{
      __typename
      ... on BasicObject {{ id }}
      ... on StixObject {{ standard_id }}
      ... on StixCoreObject {{
        entity_type
        createdBy{{ id name }}
        objectLabel{{ id value color }}
        objectMarking{{ id definition_type definition }}
        externalReferences{{ edges{{ node{{ source_name url external_id }} }} }}
      }}
      ... on StixCyberObservable {{
        created_at updated_at
        ... on IPv4Addr {{ value }}
        ... on IPv6Addr {{ value }}
        ... on DomainName {{ value }}
        ... on Url {{ value }}
        ... on EmailAddr {{ value }}
      }}
    }} }}
  }}
}}
"""

#8) Capturing containers with Observable as the main body (Connection version)
def q_observable_containers_page() -> str:
    return """
query ObsContainers($id:String!,$first:Int!,$after:ID){
  stixCyberObservable(id:$id){
    id
    containers(first:$first, after:$after){
      pageInfo{ endCursor hasNextPage }
      edges{ node{
        __typename
        ... on BasicObject { id }
        ... on StixObject { standard_id }
        ... on StixCoreObject {
          entity_type
          createdBy{ id name }
          objectLabel{ id value color }
          objectMarking{ id definition_type definition }
          externalReferences{ edges{ node{ source_name url external_id } } }
        }
        ... on StixDomainObject { created updated_at }

        ... on Report { name description published created updated_at }
        ... on Note   { attribute_abstract content created updated_at }
        ... on Opinion{ explanation opinion created updated_at }
        ... on Case { name description created updated_at }
        ... on CaseIncident { name description created updated_at }
        ... on CaseRfi { name description created updated_at }
        ... on CaseRft { name description created updated_at }
        ... on Feedback { name description created updated_at }
      } }
    }
  }
}
"""

def fetch_observable_containers(oid: str):
    for node in paged_fetch_nested(
        q_observable_containers_page(),
        "stixCyberObservable",
        "containers",
        {"id": oid}
    ):
        yield node

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
        if not page["hasNextPage"]:
            break
        after = page["endCursor"]
        time.sleep(0.08)

def paged_fetch_nested(query: str, container_key: str, conn_key: str, vars_extra: dict):
    after = None
    fetched = 0
    while True:
        variables = {"first": PAGE_BATCH, "after": after}
        variables.update(vars_extra)
        data = gql(query, variables)
        cont = data.get(container_key)
        if not cont:
            break
        conn = cont.get(conn_key)

        #  A：Relay connection
        if isinstance(conn, dict):
            edges = conn.get("edges") or []
            for e in edges:
                node = (e or {}).get("node")
                if node:
                    yield node
                    fetched += 1
                    if fetched % 2000 == 0:
                        log.info("[%s.%s] fetched: %d", container_key, conn_key, fetched)
            page = conn.get("pageInfo") or {}
            if page.get("hasNextPage"):
                after = page.get("endCursor")
                time.sleep(0.05)
                continue
            break

        #  B: non-paged list
        if isinstance(conn, list):
            for node in conn:
                if node:
                    yield node
                    fetched += 1
                    if fetched % 2000 == 0:
                        log.info("[%s.%s] fetched: %d", container_key, conn_key, fetched)
            break

        break

# ========= STIX Normalizer =========
def stix_wrap(kind: str, nd: dict) -> dict:
    stix: Dict[str, Any] = {"spec_version": "2.1"}
    if kind == "report":
        stix.update({
            "type": "report",
            "id": nd.get("standard_id") or nd.get("id"),
            "name": nd.get("name"),
            "description": nd.get("description"),
            "published": normalize_iso(nd.get("published")),
            "created": normalize_iso(nd.get("created")),
            "modified": normalize_iso(nd.get("updated_at")),
            "labels": labels_list(nd),
        })
        stix["x_created_by_name"] = creator_name(nd)
        stix["x_object_marking"]  = markings_list(nd)
        stix["x_external_references"] = external_refs(nd)

    elif kind == "indicator":
        stix.update({
            "type": "indicator",
            "id": nd.get("standard_id") or nd.get("id"),
            "name": nd.get("name"),
            "description": nd.get("description"),
            "pattern_type": nd.get("pattern_type"),
            "pattern": nd.get("pattern"),
            "valid_from": normalize_iso(nd.get("valid_from")),
            "valid_until": normalize_iso(nd.get("valid_until")),
            "confidence": nd.get("confidence"),
            "revoked": nd.get("revoked"),
            "created": normalize_iso(nd.get("created")),
            "modified": normalize_iso(nd.get("updated_at")),
            "labels": labels_list(nd),
            "x_opencti_main_observable_type": nd.get("x_opencti_main_observable_type"),
        })
        stix["x_created_by_name"] = creator_name(nd)
        stix["x_object_marking"]  = markings_list(nd)
        stix["x_external_references"] = external_refs(nd)

    elif kind == "observable":
        et = nd.get("entity_type")
        if et == "IPv4-Addr":
            stix["type"] = "ipv4-addr"; stix["value"] = nd.get("value")
        elif et == "IPv6-Addr":
            stix["type"] = "ipv6-addr"; stix["value"] = nd.get("value")
        elif et == "Domain-Name":
            stix["type"] = "domain-name"; stix["value"] = nd.get("value")
        elif et == "Url":
            stix["type"] = "url"; stix["value"] = nd.get("value")
        elif et == "Email-Addr":
            stix["type"] = "email-addr"; stix["value"] = nd.get("value")
        else:
            stix["type"] = "x-opencti-observable"
        stix.update({
            "id": nd.get("standard_id") or nd.get("id"),
            "created": normalize_iso(nd.get("created_at") or nd.get("created")),
            "modified": normalize_iso(nd.get("updated_at")),
            "labels": labels_list(nd),
        })
        stix["x_created_by_name"] = creator_name(nd)
        stix["x_object_marking"]  = markings_list(nd)
        stix["x_external_references"] = external_refs(nd)

    elif kind == "observed-data":
        stix.update({
            "type": "observed-data",
            "id": nd.get("id"),
            "first_observed": normalize_iso(nd.get("first_observed")),
            "last_observed": normalize_iso(nd.get("last_observed")),
            "number_observed": nd.get("number_observed"),
            "created": normalize_iso(nd.get("created")),
            "modified": normalize_iso(nd.get("updated_at")),
            "labels": labels_list(nd),
            "x_object_marking": markings_list(nd),
            "x_created_by_name": creator_name(nd),
            "x_external_references": external_refs(nd),
        })

    elif kind == "sighting":
        fr = nd.get("from") or {}
        to = nd.get("to") or {}
        stix.update({
            "type": "sighting",
            "id": nd.get("id"),
            "created": normalize_iso(nd.get("created_at")),
            "modified": normalize_iso(nd.get("updated_at")),
            "first_seen": normalize_iso(nd.get("first_seen")),
            "last_seen": normalize_iso(nd.get("last_seen")),
            "count": nd.get("attribute_count"),
            "x_description": nd.get("description"),
            "x_confidence": nd.get("confidence"),
            "x_created_by_name": creator_name(nd),
            "x_object_marking": markings_list(nd),
            "x_external_references": external_refs(nd),
            "x_from": fr,
            "x_to": to,
        })
    else:
        stix["type"] = "x-unknown"

    return { "kind": kind, "stix": stix, "graph": nd }

# ========= Main_process =========
def main():
    me = gql("query{ me{ id name user_email }}", {})
    log.info("Auth OK as %s <%s>", me.get("me",{}).get("name"), me.get("me",{}).get("user_email"))

    for p in [PATH_IOC_JSONL, PATH_STIX_JSONL, PATH_EVENTS_JSONL, PATH_IPS_JSONL, PATH_SUMMARY_JSONL]:
        if os.path.exists(p):
            os.remove(p)

    ioc_docs:  Dict[str, dict] = {}  # ioc_key -> bundle
    indicator_ids: Set[str] = set()
    observable_ids: Set[str] = set()

    # ========== 1) Reports (within the time window) + objects paging ==========
    reports: List[dict] = []
    if INCLUDE_REPORTS:
        reports = list(paged_fetch(q_reports_min_in_window(), "reports"))
        log.info("Reports in window: %d", len(reports))

        for r in reports:
            write_jsonl(PATH_STIX_JSONL, stix_wrap("report", r))
            objs = list(paged_fetch_nested(q_report_objects_page(), "report", "objects", {"id": r["id"]}))
            r["_objects_expanded"] = objs

            # Assemble ids & write out STIX of observations/indicators/OD first
            for nd in objs:
                t  = (nd or {}).get("__typename")
                et = (nd or {}).get("entity_type")
                oid = (nd or {}).get("id")
                if t == "Indicator" or et == "Indicator":
                    if oid: indicator_ids.add(oid)
                    write_jsonl(PATH_STIX_JSONL, stix_wrap("indicator", nd))
                elif et in ("IPv4-Addr","IPv6-Addr","Domain-Name","Url","Email-Addr"):
                    if oid: observable_ids.add(oid)
                    write_jsonl(PATH_STIX_JSONL, stix_wrap("observable", nd))
                elif t == "ObservedData":
                    write_jsonl(PATH_STIX_JSONL, stix_wrap("observed-data", nd))

    # ========== 2) Global recovery ==========
    if INCLUDE_GLOBAL_OBJECTS:
        for nd in paged_fetch(q_indicators_in_window(), "indicators"):
            indicator_ids.add(nd.get("id"))
            write_jsonl(PATH_STIX_JSONL, stix_wrap("indicator", nd))
        for nd in paged_fetch(q_observables_in_window(INCLUDE_OBSERVABLE_TYPES), "stixCyberObservables"):
            if nd.get("id"):
                observable_ids.add(nd["id"])
            write_jsonl(PATH_STIX_JSONL, stix_wrap("observable", nd))
        log.info("After global add-ons → indicators: %d, observables: %d", len(indicator_ids), len(observable_ids))

    # ========== 3) by-ids: Complete Indicators/Observables ==========
    ind_full: Dict[str, dict] = {}
    obs_full: Dict[str, dict] = {}
    ind_id_to_obs: Dict[str, List[dict]] = defaultdict(list)

    # 3.1 Retrieve the complete indicator body field
    for batch in chunked(sorted(indicator_ids), ID_CHUNK):
        for nd in paged_fetch(q_indicators_by_ids(), "indicators", {"ids": list(batch)}):
            ind_full[nd["id"]] = nd
            write_jsonl(PATH_STIX_JSONL, stix_wrap("indicator", nd))

    # 3.2 Capture observables for each indicator (old Schema without after → single page)
    for iid in sorted(indicator_ids):
        count_added = 0
        for ob in paged_fetch_nested(q_indicator_observables_page(), "indicator", "observables", {"id": iid}):
            et = (ob or {}).get("entity_type")
            if OBS_TYPES_FILTER and et not in OBS_TYPES_FILTER:
                continue
            ind_id_to_obs[iid].append(ob)
            if ob.get("id"):
                observable_ids.add(ob["id"])
            write_jsonl(PATH_STIX_JSONL, stix_wrap("observable", ob))
            count_added += 1
            if MAX_OBSERVABLES_PER_INDICATOR and count_added >= MAX_OBSERVABLES_PER_INDICATOR:
                break

    # 3.3 by-ids fills in the complete observables field
    for batch in chunked(sorted(observable_ids), ID_CHUNK):
        for nd in paged_fetch(q_observables_by_ids(), "stixCyberObservables", {"ids": list(batch)}):
            obs_full[nd["id"]] = nd
            write_jsonl(PATH_STIX_JSONL, stix_wrap("observable", nd))

    # ========== 4) ObservedData.objects Paging Filling ==========
    if INCLUDE_REPORTS:
        for r in reports:
            for nd in (r.get("_objects_expanded") or []):
                if (nd or {}).get("__typename") == "ObservedData":
                    od_id = nd.get("id")
                    if not od_id:
                        continue
                    for ob in paged_fetch_nested(q_observed_data_objects_page(), "observedData", "objects", {"id": od_id}):
                        if OBS_TYPES_FILTER and (ob or {}).get("entity_type") not in OBS_TYPES_FILTER:
                            continue
                        if ob.get("id"):
                            observable_ids.add(ob["id"])
                        write_jsonl(PATH_STIX_JSONL, stix_wrap("observable", ob))

    # ========== 5) Sightings ==========
    object_ids_for_sight = list(sorted(indicator_ids.union(observable_ids)))
    sightings: List[dict] = []
    for batch in chunked(object_ids_for_sight, ID_CHUNK):
        for nd in paged_fetch(q_sightings_by_object_ids(), "stixSightingRelationships", {"ids": list(batch)}):
            sightings.append(nd)
            write_jsonl(PATH_STIX_JSONL, stix_wrap("sighting", nd))

    # ========== 6) Each observable takes containers (with Observable as the main body) ==========
    obs_id_to_containers: Dict[str, List[dict]] = defaultdict(list)
    for oid in sorted(observable_ids):
        try:
            for cont in fetch_observable_containers(oid):
                obs_id_to_containers[oid].append(cont)
        except Exception as e:
            log.warning("containers fetch failed for observable %s: %s", oid, e)
            continue

    # ========== 7) Group events_facts and IOC timelines ==========
    def ensure_ioc_bundle_from_observable(ob: dict) -> Optional[str]:
        key = ioc_key_of(ob)
        if not key:
            return None
        if key not in ioc_docs:
            ioc_docs[key] = {
                "ioc_key": key,
                "observable": { "stix": stix_wrap("observable", ob)["stix"], "graph": ob },
                "indicators": {},
                "events": [],
                "sightings": [],
                "containers": [],
                "sources_summary": defaultdict(lambda: defaultdict(int)),
            }
        return key

    def push_event(ioc_key: str, event: dict, when_iso: Optional[str], src_name: Optional[str]):
        ioc_docs[ioc_key]["events"].append(event)
        date_key = (when_iso or "")[:10] if when_iso else "unknown"
        who = src_name or "unknown"
        ioc_docs[ioc_key]["sources_summary"][date_key][who] += 1

    for oid, nd in obs_full.items():
        key = ensure_ioc_bundle_from_observable(nd)
        if not key:
            continue
        if obs_id_to_containers.get(oid):
            for cont in obs_id_to_containers[oid]:
                if cont.get("__typename") == "Report":
                    stix_cont = stix_wrap("report", cont)["stix"]
                else:
                    stix_cont = {
                        "type": cont.get("entity_type"),
                        "id": cont.get("standard_id") or cont.get("id"),
                        "name": cont.get("name"),
                        "description": cont.get("description") or cont.get("attribute_abstract") or cont.get("explanation") or cont.get("content"),
                        "created": normalize_iso(cont.get("created")),
                        "modified": normalize_iso(cont.get("updated_at")),
                        "labels": labels_list(cont),
                        "x_created_by_name": creator_name(cont),
                        "x_object_marking": markings_list(cont),
                        "x_external_references": external_refs(cont),
                        "x_published": normalize_iso(cont.get("published")) if "published" in cont else None,
                        "x_opinion": cont.get("opinion"),
                    }
                ioc_docs[key]["containers"].append({ "stix": stix_cont, "graph": cont })

    # 7.1 Report.objects → events
    if INCLUDE_REPORTS:
        for r in reports:
            rsrc  = creator_name(r)
            rtime = normalize_iso(r.get("published") or r.get("created") or r.get("updated_at"))
            objs  = r.get("_objects_expanded") or []

            for nd in objs:
                et = (nd or {}).get("entity_type")
                if et in ("IPv4-Addr","IPv6-Addr","Domain-Name","Url","Email-Addr"):
                    key = ensure_ioc_bundle_from_observable(nd)
                    if not key:
                        continue
                    ev = {
                        "evidence_type": "direct_observable",
                        "report": { "stix": stix_wrap("report", r)["stix"], "graph": r },
                        "indicator": None,
                        "observed_data": None,
                        "sighting": None,
                    }
                    write_jsonl(PATH_EVENTS_JSONL, { "evidence_type":"direct_observable", "ioc_key": key, "report": r })
                    push_event(key, ev, rtime, rsrc)

            for nd in objs:
                t  = (nd or {}).get("__typename")
                if t == "Indicator" or (nd or {}).get("entity_type") == "Indicator":
                    iid = nd.get("id")
                    ind_full_obj = ind_full.get(iid) or nd
                    for ob in ind_id_to_obs.get(iid, []):
                        key = ensure_ioc_bundle_from_observable(ob)
                        if not key:
                            continue
                        ioc_docs[key]["indicators"][iid] = { "stix": stix_wrap("indicator", ind_full_obj)["stix"], "graph": ind_full_obj }
                        ev = {
                            "evidence_type": "via_indicator",
                            "report": { "stix": stix_wrap("report", r)["stix"], "graph": r },
                            "indicator": { "stix": stix_wrap("indicator", ind_full_obj)["stix"], "graph": ind_full_obj },
                            "observed_data": None,
                            "sighting": None,
                        }
                        write_jsonl(PATH_EVENTS_JSONL, { "evidence_type":"via_indicator","ioc_key": key,"report": r,"indicator": ind_full_obj })
                        push_event(key, ev, rtime, rsrc)

            for nd in objs:
                if (nd or {}).get("__typename") == "ObservedData":
                    first_observed = normalize_iso(nd.get("first_observed"))
                    last_observed  = normalize_iso(nd.get("last_observed"))
                    for ob in paged_fetch_nested(q_observed_data_objects_page(), "observedData", "objects", {"id": nd.get("id")}):
                        if OBS_TYPES_FILTER and (ob or {}).get("entity_type") not in OBS_TYPES_FILTER:
                            continue
                        key = ensure_ioc_bundle_from_observable(ob)
                        if not key:
                            continue
                        ev = {
                            "evidence_type": "observed_data",
                            "report": { "stix": stix_wrap("report", r)["stix"], "graph": r },
                            "indicator": None,
                            "observed_data": { "stix": stix_wrap("observed-data", nd)["stix"], "graph": nd },
                            "sighting": None,
                        }
                        write_jsonl(PATH_EVENTS_JSONL, { "evidence_type":"observed_data","ioc_key": key,"report": r,"observed_data": nd })
                        push_event(key, ev, first_observed or last_observed or rtime, rsrc)

    # 7.2 Sightings → events
    for s in sightings:
        fr = s.get("from") or {}
        to = s.get("to") or {}
        candidate_obs: List[dict] = []

        for side in (fr, to):
            if side.get("entity_type") in ("IPv4-Addr","IPv6-Addr","Domain-Name","Url","Email-Addr") and side.get("value"):
                oid = side.get("id")
                ob = obs_full.get(oid, {"id": oid, "entity_type": side.get("entity_type"), "value": side.get("value")})
                candidate_obs.append(ob)

        if not candidate_obs:
            for side in (fr, to):
                if side.get("__typename") == "Indicator" and side.get("id"):
                    candidate_obs.extend(ind_id_to_obs.get(side["id"], []))

        when_iso = normalize_iso(s.get("first_seen") or s.get("created_at") or s.get("updated_at"))
        src_name = creator_name(s)

        for ob in candidate_obs:
            key = ensure_ioc_bundle_from_observable(ob)
            if not key:
                continue
            sight_payload = { "stix": stix_wrap("sighting", s)["stix"], "graph": s }
            ioc_docs[key]["sightings"].append(sight_payload)
            ev = { "evidence_type": "sighting", "report": None, "indicator": None, "observed_data": None, "sighting": sight_payload }
            write_jsonl(PATH_EVENTS_JSONL, { "evidence_type":"sighting","ioc_key": key,"sighting": s })
            push_event(key, ev, when_iso, src_name)

    # 7.3 Global observables/indicators also generate simple events
    if INCLUDE_GLOBAL_OBJECTS:
        for oid, nd in obs_full.items():
            key = ensure_ioc_bundle_from_observable(nd)
            if not key:
                continue
            ev = { "evidence_type": "observable_created", "report": None, "indicator": None, "observed_data": None, "sighting": None }
            push_event(key, ev, normalize_iso(nd.get("created_at") or nd.get("updated_at")), creator_name(nd))

        for iid, ind in ind_full.items():
            for ob in ind_id_to_obs.get(iid, []):
                key = ensure_ioc_bundle_from_observable(ob)
                if not key:
                    continue
                ioc_docs[key]["indicators"][iid] = { "stix": stix_wrap("indicator", ind)["stix"], "graph": ind }
                ev = {
                    "evidence_type": "via_indicator",
                    "report": None,
                    "indicator": { "stix": stix_wrap("indicator", ind)["stix"], "graph": ind },
                    "observed_data": None,
                    "sighting": None,
                }
                push_event(key, ev, normalize_iso(ind.get("created")), creator_name(ind))

    # ========== 8) Write IOC timelines ==========
    total_iocs = 0
    for key, bundle in ioc_docs.items():
        ss = { d: dict(m) for d, m in bundle["sources_summary"].items() }
        bundle["sources_summary"] = ss
        write_jsonl(PATH_IOC_JSONL, bundle)
        total_iocs += 1

    # ========== 9) enrichment_input_ips.jsonl ==========
    uniq_ips = sorted({
        b["observable"]["graph"]["value"]
        for b in ioc_docs.values()
        if b["observable"]["graph"].get("entity_type") in ("IPv4-Addr","IPv6-Addr")
        and b["observable"]["graph"].get("value")
    })
    for ip in uniq_ips:
        write_jsonl(PATH_IPS_JSONL, {"ip": ip})

    # ========== 10) Summary ==========
    summary = {
        "window": {"since": SINCE_ISO, "until": UNTIL_ISO},
        "reports_in_window": (len(reports) if INCLUDE_REPORTS else 0),
        "unique_iocs": total_iocs,
        "unique_ips": len(uniq_ips),
        "objects": {
            "indicators": len(indicator_ids),
            "observables": len(observable_ids),
            "sightings": len(sightings),
        },
        "files": {
            "ioc_timelines.jsonl": PATH_IOC_JSONL,
            "stix_objects.jsonl": PATH_STIX_JSONL,
            "events_facts.jsonl": PATH_EVENTS_JSONL,
            "enrichment_input_ips.jsonl": PATH_IPS_JSONL,
            "summary.jsonl": PATH_SUMMARY_JSONL,
        },
        "notes": [
            "Report is used as an event entry point, and objects/observables/observed-data/containers all support true paging. Indicator.observables only supports single-page fetching in the old schema (this program is already compatible).",
            "When INCLUDE_GLOBAL_OBJECTS=True, new/changed indicators/observables within the time window are also included (even if they are not attached to the report).",
            "ioc_timelines.jsonl focuses on IOCs, with complete report/indicator/observed_data/sighting and container history and properties.",
            "stix_objects.jsonl preserves both STIX and Graph original fields (complete).",
            "events_facts.jsonl is a flat fact table suitable for external enrichment or fast aggregation.",
        ],
    }
    write_jsonl(PATH_SUMMARY_JSONL, summary)

    log.info("DONE. Outputs:")
    for k,v in summary["files"].items():
        log.info(" - %s: %s", k, v)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
