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
# -------------------------------------------------------------------

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

import csv
import io

from azure.monitor.query import LogsQueryClient
from azure.monitor.query import LogsQueryStatus


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
    client = log_analytics_client or law_client
    if client is None:
        raise ValueError("Missing LogsQueryClient: pass log_analytics_client (or law_client).")

    hours = max(1, _safe_int(timerange_hours, 24))
    q = (kql or "").strip()
    if not q:
        raise ValueError("kql is empty")

    # Optional safety cap
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
