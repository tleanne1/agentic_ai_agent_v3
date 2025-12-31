import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import csv
import io


DB_PATH = "baselines.db"

# Per-table preferred “baseline columns” (if present in CSV headers)
PREFERRED_COLUMNS = {
    "DeviceProcessEvents": ["FileName", "InitiatingProcessFileName", "ProcessCommandLine", "InitiatingProcessCommandLine"],
    "DeviceNetworkEvents": ["RemoteUrl", "RemoteIP", "InitiatingProcessFileName", "InitiatingProcessCommandLine"],
    "DeviceLogonEvents": ["AccountName", "RemoteIP", "RemoteDeviceName", "LogonType"],
    "DeviceFileEvents": ["FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
    "SigninLogs": ["UserPrincipalName", "IPAddress", "AppDisplayName", "LocationDetails"],
    "AzureActivity": ["Caller", "CallerIpAddress", "OperationNameValue", "ResourceGroup"],
    "AzureNetworkAnalytics_CL": ["DestIP_s", "DestPort_d", "SrcPublicIPs_s", "VM_s"],
}

# Defaults if table not mapped or columns missing
FALLBACK_COLUMNS = ["DeviceName", "AccountName", "RemoteIP", "RemoteUrl", "FileName"]


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    conn = _connect()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS baseline_counts (
        scope_key TEXT NOT NULL,
        table_name TEXT NOT NULL,
        column_name TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        value_text TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (scope_key, table_name, column_name, value_hash)
    );
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_baseline_scope_table
    ON baseline_counts(scope_key, table_name);
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS baseline_runs (
        run_id TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        scope_key TEXT NOT NULL,
        table_name TEXT NOT NULL,
        record_count INTEGER NOT NULL
    );
    """)

    conn.commit()
    conn.close()


def _hash_value(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8", errors="ignore")).hexdigest()


def _parse_csv_records(records_csv: str) -> Tuple[List[str], List[Dict[str, str]]]:
    """
    records_csv from EXECUTOR.query_log_analytics is CSV text.
    Returns (headers, rows_as_dicts).
    """
    if not records_csv or not isinstance(records_csv, str):
        return [], []

    buff = io.StringIO(records_csv)
    reader = csv.DictReader(buff)
    headers = reader.fieldnames or []
    rows = []
    for row in reader:
        # normalize None -> ""
        rows.append({k: ("" if v is None else str(v)) for k, v in row.items()})
    return headers, rows


def pick_baseline_columns(table_name: str, headers: List[str]) -> List[str]:
    preferred = PREFERRED_COLUMNS.get(table_name, [])
    chosen = [c for c in preferred if c in headers]
    if chosen:
        return chosen[:4]  # keep it small + fast

    # fallback: choose any of the fallback columns that exist
    chosen = [c for c in FALLBACK_COLUMNS if c in headers]
    if chosen:
        return chosen[:3]

    # last resort: pick first few columns
    return headers[:3]


def build_scope_key(query_context: dict) -> str:
    """
    Scope key controls baseline “identity”. We baseline per device if present, else per user, else global.
    """
    device = (query_context.get("device_name") or "").strip()
    upn = (query_context.get("user_principal_name") or "").strip()
    caller = (query_context.get("caller") or "").strip()

    if device:
        return f"device:{device.lower()}"
    if upn:
        return f"user:{upn.lower()}"
    if caller:
        return f"caller:{caller.lower()}"
    return "global"


def update_baseline_from_csv(
    *,
    table_name: str,
    query_context: dict,
    records_csv: str,
    record_count: int,
    max_unique_per_col: int = 2000
) -> Dict:
    """
    Updates baseline counts for a set of columns. Returns metadata.
    """
    init_db()
    scope_key = build_scope_key(query_context)
    headers, rows = _parse_csv_records(records_csv)

    if not headers or not rows:
        return {"ok": True, "scope_key": scope_key, "updated": 0, "columns": []}

    cols = pick_baseline_columns(table_name, headers)

    # Count frequencies in this run
    run_counts: Dict[Tuple[str, str], int] = {}  # (col, value_text) -> count
    for r in rows:
        for c in cols:
            v = (r.get(c) or "").strip()
            if not v:
                continue
            # reduce extremely long strings
            if len(v) > 350:
                v = v[:350]
            key = (c, v)
            run_counts[key] = run_counts.get(key, 0) + 1

    # cap unique values per col to protect DB growth
    per_col_seen = {}
    filtered = {}
    for (c, v), cnt in run_counts.items():
        per_col_seen.setdefault(c, 0)
        if per_col_seen[c] >= max_unique_per_col:
            continue
        per_col_seen[c] += 1
        filtered[(c, v)] = cnt

    conn = _connect()
    cur = conn.cursor()

    now = _utc_iso()
    updated = 0

    for (col, val), cnt in filtered.items():
        vh = _hash_value(val)
        # upsert
        cur.execute("""
        INSERT INTO baseline_counts(scope_key, table_name, column_name, value_hash, value_text, count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scope_key, table_name, column_name, value_hash)
        DO UPDATE SET
            count = count + excluded.count,
            last_seen = excluded.last_seen;
        """, (scope_key, table_name, col, vh, val, cnt, now, now))
        updated += 1

    run_id = _hash_value(f"{now}|{scope_key}|{table_name}|{record_count}")
    cur.execute("""
    INSERT OR REPLACE INTO baseline_runs(run_id, ts, scope_key, table_name, record_count)
    VALUES (?, ?, ?, ?, ?)
    """, (run_id, now, scope_key, table_name, int(record_count)))

    conn.commit()
    conn.close()

    return {"ok": True, "scope_key": scope_key, "updated": updated, "columns": cols, "headers": headers}


def fetch_baseline_counts(scope_key: str, table_name: str, column_name: str, limit: int = 5000) -> Dict[str, int]:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
    SELECT value_text, count
    FROM baseline_counts
    WHERE scope_key = ? AND table_name = ? AND column_name = ?
    ORDER BY count DESC
    LIMIT ?;
    """, (scope_key, table_name, column_name, int(limit)))
    rows = cur.fetchall()
    conn.close()
    return {v: int(c) for v, c in rows}


def anomaly_summary(
    *,
    table_name: str,
    query_context: dict,
    records_csv: str,
    record_count: int,
    min_run_count: int = 2,
    rarity_threshold: float = 0.003,
    max_items: int = 10
) -> str:
    """
    Produces a short text summary of rare values in the current run vs baseline.
    rarity_threshold ~ 0.003 means “~0.3% or less of historical occurrences”
    """
    init_db()
    scope_key = build_scope_key(query_context)
    headers, rows = _parse_csv_records(records_csv)
    if not headers or not rows:
        return ""

    cols = pick_baseline_columns(table_name, headers)

    # count values in current run
    run_counts: Dict[Tuple[str, str], int] = {}
    for r in rows:
        for c in cols:
            v = (r.get(c) or "").strip()
            if not v:
                continue
            if len(v) > 350:
                v = v[:350]
            run_counts[(c, v)] = run_counts.get((c, v), 0) + 1

    findings = []
    for c in cols:
        baseline = fetch_baseline_counts(scope_key, table_name, c)
        total_hist = sum(baseline.values()) or 0

        # if no baseline yet, skip "anomaly" (first run should just learn)
        if total_hist < 20:
            continue

        for (col, val), cnt in run_counts.items():
            if col != c:
                continue
            if cnt < min_run_count:
                continue

            hist_cnt = baseline.get(val, 0)
            p = (hist_cnt / total_hist) if total_hist else 0.0
            # rare if it barely ever happened historically
            if p <= rarity_threshold:
                findings.append((p, col, val, cnt, hist_cnt, total_hist))

    findings.sort(key=lambda x: x[0])  # smallest p first
    findings = findings[:max_items]

    if not findings:
        return ""

    lines = []
    lines.append(f"[Baseline Memory] Scope={scope_key}, Table={table_name}")
    lines.append("Rare / unusual values in current results compared to historical baseline:")

    for p, col, val, cnt, hist_cnt, total_hist in findings:
        lines.append(f"- {col}: '{val}' | run={cnt} | hist={hist_cnt}/{total_hist} (~{p*100:.3f}%)")

    return "\n".join(lines)
