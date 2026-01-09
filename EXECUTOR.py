# EXECUTOR.py
# -------------------------------------------------------------------
# Query execution utilities for Log Analytics + safe parsing helpers
#
# ✅ Backward compatible:
#   - accepts law_client or log_analytics_client
#   - accepts kql_query or kql
#   - accepts timespan_hours or timerange_hours
#   - accepts hours (alias)
#
# ✅ Robust column parsing:
#   Azure tables sometimes return columns as:
#     - objects with .name
#     - strings
#     - dict-like shapes
#
# ✅ Minimal-change "Demo Mode" (portfolio-safe):
#   - Set ENGINE_MODE=demo to bypass Azure and return deterministic mock telemetry
#   - Default is live (Azure)
# -------------------------------------------------------------------

from __future__ import annotations

from datetime import timedelta, datetime, timezone
from typing import Any, Dict, List, Optional

import os
import re
import csv
import io

from azure.monitor.query import LogsQueryClient
from azure.monitor.query import LogsQueryStatus


# -----------------------------
# Demo Mode Settings
# -----------------------------
ENGINE_MODE = (os.getenv("ENGINE_MODE") or "live").strip().lower()


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _col_name(c: Any) -> str:
    """
    Azure table columns may be:
      - object with .name
      - plain string
      - dict-like
    """
    if c is None:
        return ""
    if isinstance(c, str):
        return c
    # Column-like object
    if hasattr(c, "name"):
        try:
            return str(getattr(c, "name"))
        except Exception:
            pass
    # Dict-like fallback
    if isinstance(c, dict) and "name" in c:
        return str(c.get("name"))
    # Last resort
    return str(c)


def _table_to_records(table: Any) -> List[Dict[str, Any]]:
    """
    Convert Azure LogsQueryResult table -> list[dict]
    """
    if table is None:
        return []

    raw_cols = getattr(table, "columns", None) or []
    cols = [_col_name(c) for c in raw_cols]

    rows = getattr(table, "rows", None) or []

    out: List[Dict[str, Any]] = []
    for r in rows:
        d: Dict[str, Any] = {}
        for i, col in enumerate(cols):
            d[col] = r[i] if i < len(r) else None
        out.append(d)
    return out


def records_to_csv(records: List[Dict[str, Any]]) -> str:
    """
    list[dict] -> csv text (header + rows)
    """
    if not records:
        return ""

    # union of keys (stable order: keys from first row, then others)
    fieldnames = list(records[0].keys())
    seen = set(fieldnames)
    for r in records[1:]:
        for k in r.keys():
            if k not in seen:
                fieldnames.append(k)
                seen.add(k)

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames)
    w.writeheader()
    for r in records:
        w.writerow({k: r.get(k) for k in fieldnames})
    return buf.getvalue()


# -----------------------------
# Demo Mode Helpers (minimal)
# -----------------------------
_DEMO_NOW = datetime.now(timezone.utc)


def _demo_rows_for_table(table: str) -> List[Dict[str, Any]]:
    """
    Deterministic, portfolio-safe mock telemetry.
    Keep this small but realistic.
    """
    t = (table or "").strip()

    # Heartbeat (sanity check)
    if t.lower() == "heartbeat":
        return [
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=2)).isoformat(),
                "Computer": "windows-target-1",
                "Category": "Direct Agent",
                "OSName": "Windows",
                "SourceSystem": "OpsManager",
                "TenantId": "00000000-0000-0000-0000-000000000000",
            },
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=5)).isoformat(),
                "Computer": "linux-target-1",
                "Category": "Direct Agent",
                "OSName": "Linux",
                "SourceSystem": "OpsManager",
                "TenantId": "00000000-0000-0000-0000-000000000000",
            },
        ]

    # Defender for Endpoint-style table
    if t.lower() == "devicelogonevents":
        return [
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=12)).isoformat(),
                "DeviceName": "windows-target-1",
                "AccountName": "jsmith",
                "UserPrincipalName": "jsmith@contoso.local",
                "ActionType": "LogonSuccess",
                "RemoteIP": "198.51.100.24",
                "LogonType": "Interactive",
            },
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=11)).isoformat(),
                "DeviceName": "windows-target-1",
                "AccountName": "jsmith",
                "UserPrincipalName": "jsmith@contoso.local",
                "ActionType": "LogonFailed",
                "RemoteIP": "203.0.113.77",
                "LogonType": "RemoteInteractive",
            },
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=10)).isoformat(),
                "DeviceName": "linux-target-1",
                "AccountName": "root",
                "UserPrincipalName": "",
                "ActionType": "LogonFailed",
                "RemoteIP": "203.0.113.77",
                "LogonType": "SSH",
            },
        ]

    # Classic Windows Security Event
    if t.lower() == "securityevent":
        return [
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=15)).isoformat(),
                "Computer": "windows-target-1",
                "EventID": 4625,
                "Account": "jsmith",
                "Activity": "Logon Failure",
                "IpAddress": "203.0.113.77",
                "LogonType": 10,
            },
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=14)).isoformat(),
                "Computer": "windows-target-1",
                "EventID": 4624,
                "Account": "jsmith",
                "Activity": "Logon Success",
                "IpAddress": "198.51.100.24",
                "LogonType": 2,
            },
        ]

    # Azure AD Sign-in
    if t.lower() == "signinlogs":
        return [
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=25)).isoformat(),
                "UserPrincipalName": "jsmith@contoso.local",
                "AppDisplayName": "Microsoft Teams",
                "Status": "Success",
                "IPAddress": "198.51.100.24",
                "Location": "US",
            },
            {
                "TimeGenerated": (_DEMO_NOW - timedelta(minutes=23)).isoformat(),
                "UserPrincipalName": "jsmith@contoso.local",
                "AppDisplayName": "Azure Portal",
                "Status": "Failure",
                "IPAddress": "203.0.113.77",
                "Location": "RU",
            },
        ]

    # Unknown table -> empty
    return []


def _extract_table_name(kql: str) -> str:
    """
    Very small heuristic:
    - First non-empty line
    - First token is usually the table name
    """
    q = (kql or "").strip()
    if not q:
        return ""
    first_line = q.splitlines()[0].strip()
    # table could be like: DeviceLogonEvents | where ...
    token = first_line.split()[0].strip()
    # strip any leading pipes (just in case)
    token = token.lstrip("|").strip()
    return token


def _extract_take_limit(kql: str, default_limit: int = 2000) -> int:
    """
    Parse 'take N' or 'limit N' from KQL. If none, return default.
    """
    q = (kql or "").lower()
    m = re.search(r"\b(?:take|limit)\s+(\d+)\b", q)
    if m:
        return max(1, _safe_int(m.group(1), default_limit))
    return default_limit


def _run_demo_query(kql: str, hours: int, limit: Optional[int]) -> Dict[str, Any]:
    """
    Demo-mode response shaped EXACTLY like live mode.
    """
    q = (kql or "").strip()
    if not q:
        return {"ok": False, "query": q, "hours": hours, "error": "kql is empty", "rows": [], "csv": ""}

    table = _extract_table_name(q)
    rows = _demo_rows_for_table(table)

    # Apply limit (prefer explicit take/limit in query)
    eff_limit = _extract_take_limit(q, default_limit=(limit or 2000))
    rows = rows[: eff_limit]

    return {
        "ok": True if rows is not None else False,
        "query": q,
        "hours": hours,
        "rows": rows or [],
        "csv": records_to_csv(rows or []),
    }


def run_kql_query(
    *,
    law_client: Optional[LogsQueryClient] = None,
    log_analytics_client: Optional[LogsQueryClient] = None,
    workspace_id: str,
    kql: str,
    timerange_hours: int = 24,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute a raw KQL query against Log Analytics.
    """
    hours = max(1, _safe_int(timerange_hours, 24))
    q = (kql or "").strip()

    # ✅ Demo mode bypasses Azure completely
    if ENGINE_MODE == "demo":
        return _run_demo_query(q, hours=hours, limit=limit)

    client = log_analytics_client or law_client
    if client is None:
        raise ValueError("Missing LogsQueryClient: pass log_analytics_client (or law_client).")

    if not q:
        raise ValueError("kql is empty")

    # Optional safety cap (live mode only)
    if limit is not None:
        lim = max(1, _safe_int(limit, 2000))
        lower = q.lower()
        if " take " not in lower and "|take" not in lower and " limit " not in lower and "|limit" not in lower:
            q = f"{q}\n| take {lim}"

    resp = client.query_workspace(
        workspace_id=workspace_id,
        query=q,
        timespan=timedelta(hours=hours),
    )

    if resp.status != LogsQueryStatus.SUCCESS:
        partial_records: List[Dict[str, Any]] = []
        if getattr(resp, "partial_data", None):
            for t in resp.partial_data:
                partial_records.extend(_table_to_records(t))

        return {
            "ok": False,
            "query": q,
            "hours": hours,
            "error": str(resp.error) if getattr(resp, "error", None) else "Query failed",
            "rows": partial_records,
            "csv": records_to_csv(partial_records),
        }

    records: List[Dict[str, Any]] = []
    for t in resp.tables or []:
        records.extend(_table_to_records(t))

    return {
        "ok": True,
        "query": q,
        "hours": hours,
        "rows": records,
        "csv": records_to_csv(records),
    }


def query_log_analytics(
    *,
    # accept either name
    law_client: Optional[LogsQueryClient] = None,
    log_analytics_client: Optional[LogsQueryClient] = None,
    workspace_id: str,

    # allow either style: "kql_query" or "kql"
    kql_query: Optional[str] = None,
    kql: Optional[str] = None,

    # old/new time keyword aliases
    timespan_hours: Optional[int] = None,
    timerange_hours: int = 24,
    hours: Optional[int] = None,

    # optional
    limit: int = 2000,
) -> Dict[str, Any]:
    """
    Backward-compatible wrapper around run_kql_query.
    """
    resolved_hours = timerange_hours
    if hours is not None:
        resolved_hours = hours
    elif timespan_hours is not None:
        resolved_hours = timespan_hours

    resolved_hours = max(1, _safe_int(resolved_hours, 24))

    query = (kql_query if kql_query is not None else kql) or ""
    query = str(query)

    return run_kql_query(
        law_client=law_client,
        log_analytics_client=log_analytics_client,
        workspace_id=workspace_id,
        kql=query,
        timerange_hours=resolved_hours,
        limit=limit,
    )
