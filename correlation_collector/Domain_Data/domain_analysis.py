"""
Functionality:
1. Reads multiple enriched JSONL files (domains_enriched_YYYYMMDD_HHMMSS.jsonl) at once,
and merges these files into groups based on the "most recent N days" (default 7 days).
2. Organize the merged data into a DataFrame, generating:
  - domain / verdict / dms_score / tld / age_days / entropy / url_count
  - VT: vt_malicious / vt_suspicious
  - AbuseIPDB: abuse_max_conf
  - OTX: otx_pulse_count
  - first_seen / last_seen / seen_count (across multiple files)
  - raw: raw record (containing features / sources / ns_records, etc.)
3. Perform analysis (primarily focusing on the latest records after "domain aggregation"):
  - TLD risk analysis (YYYYMMDD-YYYYMMDD.tld_stats.csv)
  - NS Provider analysis (YYYYMMDD-YYYYMMDD.ns_stats.csv)
  - Source feed performance analysis (YYYYMMDD-YYYYMMDD.source_stats.csv)
  - Ensemble Risk Score + Top High-Risk Domains (YYYYMMDD-YYYYMMDD.top_risk_domains.csv)
  - A Markdown Master Report (YYYYMMDD-YYYYMMDD.domain_report.md)
4. Added Time Series Analysis (based on "each crawl_timestamp"):
  - Daily Statistics (YYYYMMDD-YYYYMMDD.timeseries_daily.csv):
      date / total_records / unique_domains / malicious / suspicious /
      unknown / avg_dms / high_risk_records / active_domains / new_domains
  - Lifecycle of Each Domain (YYYYMMDD-YYYYMMDD.domain_lifecycle.csv):
      domain / first_seen / last_seen / seen_count / dms_score / verdict / tld / lifetime_days
"""

import json
import os
import glob
import re
import datetime
from typing import List, Dict, Any
from collections import Counter, defaultdict

import pandas as pd
DATE_RANGE_TAG: str = ""

class Config:
    INPUT_ENRICHED_FALLBACK = (
        "only for single file path"
    )

    BASE_INPUT_DIR = (
        "your_path"
    )
    BASE_OUTPUT_DIR = (
        "your_path"
    )

    ENRICHED_DIR = BASE_INPUT_DIR
    ENRICHED_GLOB = "domains_enriched_*.jsonl"  
    DAYS_BACK = 7
    HIGH_RISK_DMS = 70
    TOP_RISK_N = 100

    @staticmethod
    def _tag() -> str:
        global DATE_RANGE_TAG
        return DATE_RANGE_TAG or "all"
    @staticmethod
    def tld_stats_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.tld_stats.csv"
        )

    @staticmethod
    def ns_stats_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.ns_stats.csv"
        )

    @staticmethod
    def source_stats_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.source_stats.csv"
        )

    @staticmethod
    def top_risk_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.top_risk_domains.csv"
        )

    @staticmethod
    def report_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.domain_report.md"
        )

    @staticmethod
    def timeseries_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.timeseries_daily.csv"
        )

    @staticmethod
    def lifecycle_path() -> str:
        return os.path.join(
            Config.BASE_OUTPUT_DIR, f"{Config._tag()}.domain_lifecycle.csv"
        )

def list_enriched_files() -> List[Dict[str, Any]]:
    global DATE_RANGE_TAG
    os.makedirs(Config.BASE_INPUT_DIR, exist_ok=True)
    os.makedirs(Config.BASE_OUTPUT_DIR, exist_ok=True)

    pattern = os.path.join(Config.ENRICHED_DIR, Config.ENRICHED_GLOB)
    files = glob.glob(pattern)
    results: List[Dict[str, Any]] = []
    ts_pattern = re.compile(r"(\d{8})(?:_(\d{6}))?")

    for path in files:
        fname = os.path.basename(path)
        m = ts_pattern.search(fname)
        if not m:
            continue

        date_part = m.group(1)          
        time_part = m.group(2)         

        try:
            if time_part:
                ts_str = f"{date_part}_{time_part}"
                run_ts = datetime.datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
            else:
                run_ts = datetime.datetime.strptime(date_part, "%Y%m%d")
        except Exception:
            continue

        results.append({"path": path, "run_ts": run_ts})

    if not results:
        DATE_RANGE_TAG = "" 
        return []

    results.sort(key=lambda x: x["run_ts"])

    # If DAYS_BACK is set, only the most recent N days will be retained.
    if Config.DAYS_BACK and Config.DAYS_BACK > 0:
        latest_ts = results[-1]["run_ts"]
        cutoff = latest_ts - datetime.timedelta(days=Config.DAYS_BACK - 1)
        results = [r for r in results if r["run_ts"] >= cutoff]

    if results:
        start_date = results[0]["run_ts"].date()
        end_date = results[-1]["run_ts"].date()
        DATE_RANGE_TAG = f"{start_date:%Y%m%d}-{end_date:%Y%m%d}"
    else:
        DATE_RANGE_TAG = ""

    return results

def load_enriched_one(path: str) -> List[dict]:
    data: List[dict] = []
    if not os.path.exists(path):
        return data
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))
    return data


def load_enriched_multi() -> List[dict]:
    file_infos = list_enriched_files()
    if not file_infos:
        # If the directory does not contain segmented files, fallback will read older single files.
        if os.path.exists(Config.INPUT_ENRICHED_FALLBACK):
            print(
                "[WARN] No domains_enriched_*.jsonl found, "
                "fallback to INPUT_ENRICHED_FALLBACK."
            )
            return load_enriched_one(Config.INPUT_ENRICHED_FALLBACK)
        else:
            print("[ERROR] No enriched input files found.")
            return []

    print("Using enriched files:")
    for info in file_infos:
        print(f"- {info['path']} (run_ts={info['run_ts']})")

    records: List[dict] = []
    for info in file_infos:
        recs = load_enriched_one(info["path"])
        records.extend(recs)

    print(f"Total records loaded from {len(file_infos)} files: {len(records)}")
    print(f"Date range tag for outputs: {Config._tag()}")
    return records


def safe_int(x, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def extract_ns_provider(ns: str) -> str:
    """
    Retrieve provider names from NS hostname:
    ns1.cloudflare.com -> cloudflare.com
    dns1.registrar-servers.com -> registrar-servers.com
    """
    if not ns:
        return ""
    parts = ns.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return ns


def compute_abuse_max_conf(abuse: dict) -> int:
    """
    Retrieve the `max abuseConfidenceScore` from the `abuseipdb` field in the `enrich_domain` format.
    The structure is roughly as follows:：
      {
        "ips": {
          "1.2.3.4": {... "abuseConfidenceScore": 90, ...},
          "5.6.7.8": {...}
        },
        "last_checked": ...
      }
    """
    if not abuse:
        return 0
    ips = abuse.get("ips") or {}
    max_conf = 0
    for _ip, info in ips.items():
        score = safe_int(info.get("abuseConfidenceScore"), 0)
        if score > max_conf:
            max_conf = score
    return max_conf


def compute_otx_pulse_count(otx: dict) -> int:
    """
    OTX structure：
      {
        "pulse_info": {
          "count": N,
          "pulses": [...]
        },
        ...
      }
    """
    if not otx:
        return 0
    pulse_info = otx.get("pulse_info") or {}
    count = pulse_info.get("count")
    if count is not None:
        return safe_int(count, 0)
    pulses = pulse_info.get("pulses") or []
    return len(pulses)


def compute_risk_score(row: pd.Series) -> float:
    dms = safe_int(row.get("dms_score"), 0)
    vt_m = safe_int(row.get("vt_malicious"), 0)
    vt_s = safe_int(row.get("vt_suspicious"), 0)
    abuse = safe_int(row.get("abuse_max_conf"), 0)
    otx_p = safe_int(row.get("otx_pulse_count"), 0)

    score = (
        dms
        + 5 * vt_m
        + 2 * vt_s
        + 0.5 * abuse
        + 3 * (1 if otx_p > 0 else 0)
    )
    return score

def tld_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    TLD Risk Ranking：count / malicious% / avg_dms。
    """
    df_tld = df.copy()
    df_tld["tld"] = df_tld["tld"].fillna("")
    tld_groups = df_tld.groupby("tld")

    rows = []
    for tld, sub in tld_groups:
        total = len(sub)
        verdict_cnt = Counter(sub["verdict"].fillna("unknown"))
        malicious_cnt = verdict_cnt.get("malicious", 0)
        malicious_ratio = malicious_cnt / total if total > 0 else 0
        rows.append({
            "tld": tld or "(none)",
            "count": total,
            "malicious_count": malicious_cnt,
            "malicious_ratio": malicious_ratio,
            "dms_mean": sub["dms_score"].mean(),
        })

    out = pd.DataFrame(rows).sort_values(
        by=["malicious_ratio", "count"], ascending=[False, False]
    )
    out.to_csv(Config.tld_stats_path(), index=False)
    return out


def ns_provider_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    NS Provider risk analysis,based on domain-level raw["features"]["ns_records"].
    """
    provider_counts = defaultdict(int)
    provider_malicious = defaultdict(int)

    for _, row in df.iterrows():
        rec = row["raw"]
        verdict = row.get("verdict", "unknown")
        features = rec.get("features") or {}
        ns_records = features.get("ns_records") or []
        for ns in ns_records:
            provider = extract_ns_provider(ns)
            if not provider:
                continue
            provider_counts[provider] += 1
            if verdict == "malicious":
                provider_malicious[provider] += 1

    rows = []
    for provider, cnt in provider_counts.items():
        mal = provider_malicious.get(provider, 0)
        ratio = mal / cnt if cnt > 0 else 0
        rows.append({
            "ns_provider": provider,
            "count": cnt,
            "malicious_count": mal,
            "malicious_ratio": ratio,
        })

    out = pd.DataFrame(rows).sort_values(
        by=["malicious_ratio", "count"], ascending=[False, False]
    )
    out.to_csv(Config.ns_stats_path(), index=False)
    return out


def source_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    Source feed analysis: Performance of OpenPhish, URLhaus, etc. in samples. Requires raw["sources"] to be a list[str].
    """
    src_counts = Counter()
    src_malicious = Counter()

    for _, row in df.iterrows():
        rec = row["raw"]
        verdict = row.get("verdict", "unknown")
        sources = rec.get("sources") or []
        for s in sources:
            src_counts[s] += 1
            if verdict == "malicious":
                src_malicious[s] += 1

    rows = []
    for s, cnt in src_counts.items():
        mal = src_malicious.get(s, 0)
        ratio = mal / cnt if cnt > 0 else 0
        rows.append({
            "source": s,
            "count": cnt,
            "malicious_count": mal,
            "malicious_ratio": ratio,
        })

    out = pd.DataFrame(rows).sort_values(
        by=["malicious_ratio", "count"], ascending=[False, False]
    )
    out.to_csv(Config.source_stats_path(), index=False)
    return out


def add_risk_score_and_top(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate the ensemble risk score and output the top N.
    """
    df["risk_score"] = df.apply(compute_risk_score, axis=1)
    df_top = df.sort_values(by="risk_score", ascending=False).head(
        Config.TOP_RISK_N
    )
    df_top[[
        "domain",
        "risk_score",
        "dms_score",
        "verdict",
        "vt_malicious",
        "vt_suspicious",
        "abuse_max_conf",
        "otx_pulse_count",
        "tld",
        "first_seen",
        "last_seen",
        "seen_count",
    ]].to_csv(Config.top_risk_path(), index=False)
    return df_top

def timeseries_analysis(df_raw: pd.DataFrame, df_domain: pd.DataFrame) -> pd.DataFrame:
    """
    Daily statistics are calculated based on "each crawl_timestamp", and new/active domains are calculated using the domain-level first_seen / last_seen.
    """
    if df_raw.empty or "crawl_timestamp" not in df_raw.columns:
        print("No crawl_timestamp in raw dataframe, skip timeseries.")
        return pd.DataFrame()

    df_ts = df_raw.copy()
    df_ts["crawl_time"] = pd.to_datetime(
        df_ts["crawl_timestamp"], errors="coerce"
    )
    df_ts = df_ts.dropna(subset=["crawl_time"])
    if df_ts.empty:
        print("crawl_timestamp parsing failed, skip timeseries.")
        return pd.DataFrame()

    df_ts["date"] = df_ts["crawl_time"].dt.date

    df_daily = (
        df_ts.groupby("date")
        .agg(
            total_records=("domain", "count"),
            unique_domains=("domain", "nunique"),
            malicious=("verdict", lambda s: (s == "malicious").sum()),
            suspicious=("verdict", lambda s: (s == "suspicious").sum()),
            unknown=("verdict", lambda s: (s == "unknown").sum()),
            avg_dms=("dms_score", "mean"),
        )
        .reset_index()
        .sort_values("date")
    )

    # high risk（With DMS >= threshold）
    df_ts["is_high_risk"] = df_ts["dms_score"] >= Config.HIGH_RISK_DMS
    highrisk = (
        df_ts.groupby("date")["is_high_risk"]
        .sum()
        .reset_index()
        .rename(columns={"is_high_risk": "high_risk_records"})
    )
    df_daily = df_daily.merge(
        highrisk, on="date", how="left"
    )

    # new_domains / active_domains（Use domain-level lifecycle）
    if not df_domain.empty and "first_seen" in df_domain.columns:
        df_life = df_domain.copy()
        df_life["first_seen"] = pd.to_datetime(
            df_life["first_seen"], errors="coerce"
        )
        df_life["last_seen"] = pd.to_datetime(
            df_life["last_seen"], errors="coerce"
        )

        # The number of newly appearing domains each day (on the day first_seen).
        new_counts = (
            df_life.dropna(subset=["first_seen"])
            .groupby(df_life["first_seen"].dt.date)["domain"]
            .nunique()
            .reset_index()
            .rename(columns={"first_seen": "date", "domain": "new_domains"})
        )
        df_daily = df_daily.merge(
            new_counts, on="date", how="left"
        )
        df_daily["new_domains"] = (
            df_daily["new_domains"].fillna(0).astype(int)
        )

        # Daily active domains = first_seen <= date <= last_seen
        active_list = []
        first_dates = df_life["first_seen"].dt.date
        last_dates = df_life["last_seen"].dt.date

        for d in df_daily["date"]:
            mask = (first_dates <= d) & (last_dates >= d)
            active_list.append(mask.sum())
        df_daily["active_domains"] = active_list
    else:
        df_daily["new_domains"] = 0
        df_daily["active_domains"] = 0

    df_daily.to_csv(Config.timeseries_path(), index=False)
    return df_daily

def write_report(
    df_domain: pd.DataFrame,
    tld_df: pd.DataFrame,
    ns_df: pd.DataFrame,
    src_df: pd.DataFrame,
    top_risk_df: pd.DataFrame,
    ts_df: pd.DataFrame,
):
    total = len(df_domain)
    verdict_cnt = Counter(df_domain["verdict"].fillna("unknown"))

    tlds = df_domain["tld"].fillna("").tolist()
    tld_cnt = Counter(tlds)

    # intelligence coverage
    vt_covered = (
        df_domain["vt_malicious"] + df_domain["vt_suspicious"] > 0
    ).sum()
    abuse_covered = (df_domain["abuse_max_conf"] > 0).sum()
    otx_covered = (df_domain["otx_pulse_count"] > 0).sum()

    if "first_seen" in df_domain.columns and "last_seen" in df_domain.columns:
        first_seen_min = pd.to_datetime(
            df_domain["first_seen"], errors="coerce"
        ).min()
        last_seen_max = pd.to_datetime(
            df_domain["last_seen"], errors="coerce"
        ).max()
    else:
        first_seen_min = last_seen_max = None

    with open(Config.report_path(), "w", encoding="utf-8") as f:
        f.write("# Domain Risk Report (Weekly Merged + Time Series)\n\n")
        f.write(f"- Date range tag: `{Config._tag()}`\n")
        f.write(f"- Total domains (merged): **{total}**\n")
        f.write(f"- Verdict counts (from local DMS): `{dict(verdict_cnt)}`\n")

        if first_seen_min is not None and last_seen_max is not None:
            f.write(
                f"- Time window (first_seen ~ last_seen): "
                f"`{first_seen_min}` ~ `{last_seen_max}`\n"
            )
        f.write("\n")

        # TLD overview
        f.write("## Top 10 TLDs by Count\n\n")
        for tld, c in tld_cnt.most_common(10):
            if not tld:
                tld = "(none)"
            f.write(f"- `{tld}`: {c}\n")
        f.write("\n")
        f.write(
            f"- See `{os.path.basename(Config.tld_stats_path())}` "
            "for TLD risk ranking (malicious ratio, mean DMS).\n\n"
        )

        # External intelligence coverage
        f.write("## External Intelligence Coverage\n\n")
        f.write(f"- VirusTotal: {vt_covered} domains with non-zero stats\n")
        f.write(
            f"- AbuseIPDB: {abuse_covered} domains with "
            "abuse confidence > 0\n"
        )
        f.write(
            f"- AlienVault OTX: {otx_covered} domains with pulse_count > 0\n\n"
        )

        # NS provider
        f.write("## NS Provider Risk\n\n")
        if not ns_df.empty:
            top_ns = ns_df.head(10)
            for _, r in top_ns.iterrows():
                f.write(
                    f"- `{r['ns_provider']}`: count={r['count']}, "
                    f"malicious={r['malicious_count']}, "
                    f"ratio={r['malicious_ratio']:.2f}\n"
                )
            f.write(
                f"\n- See `{os.path.basename(Config.ns_stats_path())}` "
                "for full NS provider risk table.\n\n"
            )
        else:
            f.write("- No NS statistics available.\n\n")

        # Source stats
        f.write("## Source Feed Effectiveness\n\n")
        if not src_df.empty:
            top_src = src_df.head(10)
            for _, r in top_src.iterrows():
                f.write(
                    f"- `{r['source']}`: count={r['count']}, "
                    f"malicious={r['malicious_count']}, "
                    f"ratio={r['malicious_ratio']:.2f}\n"
                )
            f.write(
                f"\n- See `{os.path.basename(Config.source_stats_path())}` "
                "for full source stats.\n\n"
            )
        else:
            f.write("- No source information available.\n\n")

        # Risk score / top domains
        f.write("## Ensemble Risk Score / Top Domains\n\n")
        if not top_risk_df.empty:
            f.write(
                f"- Top {len(top_risk_df)} highest-risk domains exported to "
                f"`{os.path.basename(Config.top_risk_path())}`.\n"
            )
            f.write("\nSome examples:\n\n")
            for _, r in top_risk_df.head(10).iterrows():
                f.write(
                    f"- {r['domain']} (score={r['risk_score']:.1f}, "
                    f"dms={r['dms_score']}, verdict={r['verdict']}, "
                    f"VT(m={r['vt_malicious']}, s={r['vt_suspicious']}), "
                    f"Abuse={r['abuse_max_conf']}, "
                    f"OTX_pulses={r['otx_pulse_count']}, "
                    f"seen={r['seen_count']}, "
                    f"first_seen={r['first_seen']}, "
                    f"last_seen={r['last_seen']})\n"
                )
            f.write("\n")
        else:
            f.write("- No risk score computed.\n\n")

        # Time series summary
        f.write("## Time Series Overview\n\n")
        if ts_df is not None and not ts_df.empty:
            f.write(
                f"- Daily stats exported to "
                f"`{os.path.basename(Config.timeseries_path())}`.\n"
            )
            f.write(
                f"- Domain lifecycle exported to "
                f"`{os.path.basename(Config.lifecycle_path())}`.\n\n"
            )

            # Briefly show the trends of the past few days
            f.write("Recent daily stats (last 7 rows):\n\n")
            tail = ts_df.tail(7)
            for _, r in tail.iterrows():
                f.write(
                    f"- {r['date']}: "
                    f"records={r['total_records']}, "
                    f"unique_domains={r['unique_domains']}, "
                    f"malicious={r['malicious']}, "
                    f"suspicious={r['suspicious']}, "
                    f"unknown={r['unknown']}, "
                    f"high_risk={r['high_risk_records']}, "
                    f"new={r['new_domains']}, "
                    f"active={r['active_domains']}\n"
                )
            f.write("\n")
        else:
            f.write("- No time series stats available.\n\n")


def main():
    # 1. Read the enriched files from the last N days and merge them into records.
    records = load_enriched_multi()
    if not records:
        print("No enriched data found.")
        return

    # 2. Create a raw-level DataFrame (each record represents one crawl occurrence).
    raw_rows = []
    domain_hist: Dict[str, List[dict]] = defaultdict(list)

    for rec in records:
        domain = rec.get("domain")
        if not domain:
            continue

        feat = rec.get("features") or {}
        vt = rec.get("vt") or {}
        vt_stats = vt.get("last_analysis_stats") or {}
        abuse = rec.get("abuseipdb") or {}
        otx = rec.get("otx") or {}

        crawl_ts = rec.get("crawl_timestamp")

        raw_rows.append({
            "domain": domain,
            "verdict": rec.get("verdict", "unknown"),
            "dms_score": safe_int(rec.get("dms_score"), 0),
            "tld": feat.get("tld"),
            "age_days": feat.get("age_days"),
            "entropy": feat.get("entropy"),
            "url_count": safe_int(feat.get("url_count"), 0),
            "vt_malicious": safe_int(vt_stats.get("malicious", 0)),
            "vt_suspicious": safe_int(vt_stats.get("suspicious", 0)),
            "abuse_max_conf": compute_abuse_max_conf(abuse),
            "otx_pulse_count": compute_otx_pulse_count(otx),
            "crawl_timestamp": crawl_ts,
            "raw": rec,
        })

        domain_hist[domain].append(rec)

    df_raw = pd.DataFrame(raw_rows)
    if df_raw.empty:
        print("No rows constructed from enriched data.")
        return

    # 3. Domain-level aggregation (latest record + first_seen / last_seen / seen_count)
    domain_rows = []
    for domain, recs in domain_hist.items():
        # Sort by crawl_timestamp
        ts_list = []
        for r in recs:
            ts = r.get("crawl_timestamp")
            if not ts:
                continue
            ts_parsed = pd.to_datetime(ts, errors="coerce")
            if pd.notna(ts_parsed):
                ts_list.append((ts_parsed, r))

        if ts_list:
            ts_list.sort(key=lambda x: x[0])
            first_seen = ts_list[0][0]
            last_seen = ts_list[-1][0]
            last_rec = ts_list[-1][1]
        else:
            # Since crawl_timestamp is unavailable, use the last entry as a fallback.
            first_seen = None
            last_seen = None
            last_rec = recs[-1]

        feat = last_rec.get("features") or {}
        vt = last_rec.get("vt") or {}
        vt_stats = vt.get("last_analysis_stats") or {}
        abuse = last_rec.get("abuseipdb") or {}
        otx = last_rec.get("otx") or {}

        domain_rows.append({
            "domain": domain,
            "verdict": last_rec.get("verdict", "unknown"),
            "dms_score": safe_int(last_rec.get("dms_score"), 0),
            "tld": feat.get("tld"),
            "age_days": feat.get("age_days"),
            "entropy": feat.get("entropy"),
            "url_count": safe_int(feat.get("url_count"), 0),
            "vt_malicious": safe_int(vt_stats.get("malicious", 0)),
            "vt_suspicious": safe_int(vt_stats.get("suspicious", 0)),
            "abuse_max_conf": compute_abuse_max_conf(abuse),
            "otx_pulse_count": compute_otx_pulse_count(otx),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "seen_count": len(recs),
            "raw": last_rec,
        })

    df_domain = pd.DataFrame(domain_rows)
    if df_domain.empty:
        print("No domain-level rows constructed.")
        return

    df_domain["first_seen"] = pd.to_datetime(
        df_domain["first_seen"], errors="coerce"
    )
    df_domain["last_seen"] = pd.to_datetime(
        df_domain["last_seen"], errors="coerce"
    )
    df_domain["lifetime_days"] = (
        df_domain["last_seen"] - df_domain["first_seen"]
    ).dt.days

    df_domain[[
        "domain",
        "first_seen",
        "last_seen",
        "seen_count",
        "dms_score",
        "verdict",
        "tld",
        "lifetime_days",
    ]].to_csv(Config.lifecycle_path(), index=False)

    tld_df = tld_stats(df_domain)
    ns_df = ns_provider_stats(df_domain)
    src_df = source_stats(df_domain)

    top_risk_df = add_risk_score_and_top(df_domain)

    ts_df = timeseries_analysis(df_raw, df_domain)

    write_report(df_domain, tld_df, ns_df, src_df, top_risk_df, ts_df)

    print("Analysis & report done.")
    print(f"- Report: {Config.report_path()}")
    print(f"- TLD stats: {Config.tld_stats_path()}")
    print(f"- NS stats: {Config.ns_stats_path()}")
    print(f"- Source stats: {Config.source_stats_path()}")
    print(f"- Top risk domains: {Config.top_risk_path()}")
    print(f"- Time series: {Config.timeseries_path()}")
    print(f"- Domain lifecycle: {Config.lifecycle_path()}")


if __name__ == "__main__":
    main()
