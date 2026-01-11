# EXECUTOR.py
# -------------------------------------------------------------------
# Engine-compatible EXECUTOR for agentic_ai_agent_v3
#
# This file matches the function signatures expected by your current main.py:
#   ✅ get_query_context(openai_client, user_message, model=...)
#   ✅ query_log_analytics(... table_name, device_name, fields, user_principal_name ...)
#   ✅ prepare_log_data_for_llm(records_csv, number_of_records)
#   ✅ hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model)
#
# Also includes:
#   ✅ Live mode (Log Analytics) + Demo mode (ENGINE_MODE=demo)
#   ✅ Robust azure column parsing
#   ✅ Safe stubs for isolate/release (advisory-only)
# -------------------------------------------------------------------

from __future__ import annotations

import os
import re
import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from azure.monitor.query import LogsQueryClient
from azure.monitor.query import LogsQueryStatus

ENGINE_MODE = (os.getenv("ENGINE_MODE") or "live").strip().lower()

# Payload clamps used for prompt safety
MAX_EVIDENCE_ROWS = 400
MAX_EVIDENCE_CHARS = 80_000

_DEMO_NOW = datetime.now(timezone.utc)


# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _col_name(c: Any) -> str:
    if c is None:
        return ""
    if isinstance(c, str):
        return c
    if hasattr(c, "name"):
        try:
            return str(getattr(c, "name"))
        except Exception:
            pass
    if isinstance(c, dict) and "name" in c:
        return str(c.get("name"))
    return str(c)


def _table_to_records(table: Any) -> List[Dict[str, Any]]:
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


def _records_to_csv(records: List[Dict[str, Any]]) -> str:
    if not records:
        return ""

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


def _extract_hours_from_text(text: str, default_hours: int = 24) -> int:
    t = (text or "").lower()

    # "last 24 hours"
    m = re.search(r"last\s+(\d+)\s*h", t)
    if m:
        return max(1, _safe_int(m.group(1), default_hours))

    m = re.search(r"(\d+)\s*hours", t)
    if m:
        return max(1, _safe_int(m.group(1), default_hours))

    # "last 7 days"
    m = re.search(r"last\s+(\d+)\s*days", t)
    if m:
        return max(1, _safe_int(m.group(1), 1) * 24)

    # "last day"
    if "last day" in t or "past day" in t:
        return 24

    return default_hours


def _extract_device_from_text(text: str) -> str:
    """
    Simple heuristic to capture your lab device naming style:
    - windows-target-1
    - linux-target-1
    - etc.
    """
    t = (text or "")
    m = re.search(r"\b([a-zA-Z]+-target-\d+)\b", t)
    if m:
        return m.group(1).strip()
    return ""


def _choose_table_and_fields(user_text: str) -> Dict[str, Any]:
    """
    Lightweight tool-selection fallback (keeps engine working for recording).
    """
    t = (user_text or "").lower()

    # Defaults: logons
    table = "DeviceLogonEvents"
    fields = [
        "TimeGenerated",
        "DeviceName",
        "AccountName",
        "UserPrincipalName",
        "ActionType",
        "RemoteIP",
        "LogonType",
    ]

    if "signin" in t or "azure ad" in t or "entra" in t:
        table = "SigninLogs"
        fields = [
            "TimeGenerated",
            "UserPrincipalName",
            "AppDisplayName",
            "Status",
            "IPAddress",
            "Location",
        ]
    elif "securityevent" in t or "event id" in t or "4624" in t or "4625" in t:
        table = "SecurityEvent"
        fields = [
            "TimeGenerated",
            "Computer",
            "EventID",
            "Account",
            "Activity",
            "IpAddress",
            "LogonType",
        ]

    return {"table_name": table, "fields": fields}


def _build_kql(
    *,
    table_name: str,
    hours: int,
    fields: List[str],
    device_name: str = "",
    user_principal_name: str = "",
) -> str:
    table = (table_name or "").strip()
    f = [x for x in (fields or []) if str(x).strip()] or ["TimeGenerated"]

    where_parts = [f"TimeGenerated >= ago({hours}h)"]

    if device_name:
        where_parts.append(
            f'(DeviceName has "{device_name}" or Computer has "{device_name}" or HostName has "{device_name}")'
        )

    if user_principal_name:
        where_parts.append(
            f'(UserPrincipalName has "{user_principal_name}" or AccountName has "{user_principal_name}" or Account has "{user_principal_name}")'
        )

    return (
        f"{table}\n"
        f"| where {' and '.join(where_parts)}\n"
        f"| project {', '.join(f)}\n"
        f"| take 2000"
    )


# -------------------------------------------------------------------
# ✅ REQUIRED BY main.py: get_query_context
# -------------------------------------------------------------------

def get_query_context(openai_client: Any, user_message: Dict[str, Any], model: str = "") -> Dict[str, Any]:
    """
    Engine-compatible tool selection:
    - Keeps the same interface your main.py calls
    - Uses deterministic heuristics (safe for recording)
    """
    _ = openai_client
    _ = model

    user_text = (user_message.get("content") or "").strip()
    hours = _extract_hours_from_text(user_text, default_hours=24)
    device = _extract_device_from_text(user_text)

    pick = _choose_table_and_fields(user_text)

    return {
        "table_name": pick["table_name"],
        "time_range_hours": hours,
        "device_name": device,                 # empty => global hunt
        "caller": "security_team",
        "user_principal_name": "",
        "fields": pick["fields"],
        "rationale": "Heuristic tool selection (recording-safe fallback).",
    }


# -------------------------------------------------------------------
# ✅ REQUIRED BY main.py: query_log_analytics
# -------------------------------------------------------------------

def query_log_analytics(
    *,
    law_client: Optional[LogsQueryClient] = None,
    log_analytics_client: Optional[LogsQueryClient] = None,
    workspace_id: str,
    timerange_hours: int = 24,
    table_name: str,
    device_name: str = "",
    fields: Optional[List[str]] = None,
    caller: str = "",
    user_principal_name: str = "",
    limit: int = 2000,
) -> Dict[str, Any]:
    """
    Runs a KQL query shaped the way main.py expects.

    Returns:
      {
        "ok": bool,
        "kql": str,
        "count": int,
        "records": csv_text
      }
    """
    _ = caller

    hours = max(1, _safe_int(timerange_hours, 24))
    resolved_fields = [str(x) for x in _as_list(fields)] if fields else ["TimeGenerated"]

    kql = _build_kql(
        table_name=table_name,
        hours=hours,
        fields=resolved_fields,
        device_name=(device_name or "").strip(),
        user_principal_name=(user_principal_name or "").strip(),
    )

    # Demo mode: deterministic mock telemetry
    if ENGINE_MODE == "demo":
        rows = _demo_rows_for_table(table_name)[: max(1, _safe_int(limit, 2000))]
        csv_text = _records_to_csv(rows)
        return {"ok": True, "kql": kql, "count": len(rows), "records": csv_text}

    client = log_analytics_client or law_client
    if client is None:
        raise ValueError("Missing LogsQueryClient: pass log_analytics_client (or law_client).")

    resp = client.query_workspace(
        workspace_id=workspace_id,
        query=kql,
        timespan=timedelta(hours=hours),
    )

    if resp.status != LogsQueryStatus.SUCCESS:
        partial_records: List[Dict[str, Any]] = []
        if getattr(resp, "partial_data", None):
            for t in resp.partial_data:
                partial_records.extend(_table_to_records(t))

        csv_text = _records_to_csv(partial_records)
        return {"ok": False, "kql": kql, "count": len(partial_records), "records": csv_text, "error": str(getattr(resp, "error", ""))}

    records: List[Dict[str, Any]] = []
    for t in resp.tables or []:
        records.extend(_table_to_records(t))

    # Apply hard limit if caller didn't specify take/limit
    records = records[: max(1, _safe_int(limit, 2000))]
    csv_text = _records_to_csv(records)
    return {"ok": True, "kql": kql, "count": len(records), "records": csv_text}


# -------------------------------------------------------------------
# ✅ REQUIRED BY main.py: prepare_log_data_for_llm
# -------------------------------------------------------------------

def prepare_log_data_for_llm(records_csv: str, number_of_records: int) -> str:
    """
    main.py calls: EXECUTOR.prepare_log_data_for_llm(records_csv, number_of_records)

    We keep header + first MAX_EVIDENCE_ROWS rows, and clamp chars.
    """
    _ = number_of_records

    if not records_csv:
        return ""

    lines = records_csv.splitlines()
    if not lines:
        return ""

    header = lines[:1]
    body = lines[1 : MAX_EVIDENCE_ROWS + 1]
    payload = "\n".join(header + body)

    if len(lines) > (MAX_EVIDENCE_ROWS + 1):
        payload += f"\n...TRUNCATED ROWS... ({len(lines) - (MAX_EVIDENCE_ROWS + 1)} more)"

    if len(payload) > MAX_EVIDENCE_CHARS:
        payload = payload[:MAX_EVIDENCE_CHARS] + "\n...TRUNCATED CHARS..."

    return payload


# -------------------------------------------------------------------
# ✅ REQUIRED BY main.py: hunt
# -------------------------------------------------------------------

def hunt(
    *,
    openai_client: Any,
    threat_hunt_system_message: Dict[str, Any],
    threat_hunt_user_message: Dict[str, Any],
    openai_model: str,
) -> Dict[str, Any]:
    """
    Runs the LLM step and returns {"findings": [...]}.

    Designed to be resilient across OpenAI SDK minor differences.
    """
    try:
        # Newer SDKs support response_format directly
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[threat_hunt_system_message, threat_hunt_user_message],
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or "{}"
    except TypeError:
        # Fallback: no response_format
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[threat_hunt_system_message, threat_hunt_user_message],
        )
        content = resp.choices[0].message.content or "{}"
    except Exception as e:
        return {"ok": False, "error": str(e), "findings": []}

    # Parse JSON safely
    import json
    try:
        data = json.loads(content)
        findings = data.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        return {"ok": True, "findings": findings, "raw": data}
    except Exception:
        return {"ok": True, "findings": [], "raw_text": content}


# -------------------------------------------------------------------
# Demo data (used when ENGINE_MODE=demo)
# -------------------------------------------------------------------

def _demo_rows_for_table(table: str) -> List[Dict[str, Any]]:
    t = (table or "").strip().lower()

    if t == "devicelogonevents":
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

    if t == "securityevent":
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

    if t == "signinlogs":
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

    return []


# -------------------------------------------------------------------
# Advisory-only stubs (keep engine stable)
# -------------------------------------------------------------------

def isolate_vm_by_name(*args, **kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "isolate_vm_by_name not configured in this build (advisory-only)."}


def release_vm_by_name(*args, **kwargs) -> Dict[str, Any]:
    return {"ok": False, "error": "release_vm_by_name not configured in this build (advisory-only)."}