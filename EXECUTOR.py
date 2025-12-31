# EXECUTOR.py
# -------------------------------------------------------------------
# Executor:
# - Tool selection: get_query_context() via OpenAI function calling
# - Query Log Analytics: query_log_analytics() builds SAFE KQL
# - Token-safe payload for LLM
# - Hunt: calls model with response_format json_object safely
# - MDE Isolation helpers:
#     ✅ get_bearer_token()
#     ✅ get_mde_workstation_id_from_name() using computerDnsName (fixes HTTP 400 deviceName error)
#     ✅ isolate_vm_by_name()
#     ✅ release_vm_by_name()
# -------------------------------------------------------------------

import csv
import io
import json
from datetime import timedelta
from typing import Dict, Any, List, Optional

import requests
from colorama import Fore, Style
from azure.identity import DefaultAzureCredential

import PROMPT_MANAGEMENT
import GUARDRAILS

MAX_QUERY_ROWS = 2000          # cap rows returned from Log Analytics
SUMMARY_TRIGGER_ROWS = 800     # if >=, we summarize for LLM
MAX_LLM_ROWS = 200             # if raw CSV is used, clamp to this
MAX_LLM_CHARS = 120_000        # last-resort clamp
MAX_LLM_LINES = 1200           # last-resort clamp


# ----------------------------
# MDE Isolation Helpers
# ----------------------------
MDE_BASE_URL = "https://api.securitycenter.microsoft.com/api"


def get_bearer_token():
    """
    Get an Azure AD token scoped for Microsoft Defender for Endpoint API.
    """
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.securitycenter.microsoft.com/.default")
    return token


def get_mde_workstation_id_from_name(token, device_name: str) -> str:
    """
    Look up Defender for Endpoint machine ID by device name.
    Uses computerDnsName (supported) and avoids unsupported 'deviceName' filter.
    """
    dn = (device_name or "").strip()
    if not dn:
        raise ValueError("device_name is empty")

    headers = {"Authorization": f"Bearer {token.token}"}
    base = f"{MDE_BASE_URL}/machines"

    # Attempt 1: startswith computerDnsName (works for short hostname + FQDN)
    params = {"$filter": f"startswith(computerDnsName,'{dn}')"}
    r = requests.get(base, headers=headers, params=params, timeout=30)

    if r.status_code != 200:
        raise RuntimeError(f"MDE machine lookup failed: HTTP {r.status_code} {r.text}")

    data = r.json() or {}
    values = data.get("value") or []

    # Attempt 2: contains computerDnsName (looser fallback)
    if not values:
        params2 = {"$filter": f"contains(computerDnsName,'{dn}')"}
        r2 = requests.get(base, headers=headers, params=params2, timeout=30)

        if r2.status_code != 200:
            raise RuntimeError(f"MDE machine lookup failed: HTTP {r2.status_code} {r2.text}")

        data2 = r2.json() or {}
        values = data2.get("value") or []

    if not values:
        raise RuntimeError(f"No MDE machine matches found for '{dn}'")

    machine_id = values[0].get("id")
    if not machine_id:
        raise RuntimeError("MDE machine match returned no 'id' field")

    return machine_id


def isolate_vm_by_name(device_name: str, *, comment: str = "Isolation requested by Agentic SOC Analyst") -> Dict[str, Any]:
    """
    Isolate a machine in Microsoft Defender for Endpoint by device name.
    """
    token = get_bearer_token()
    machine_id = get_mde_workstation_id_from_name(token, device_name)

    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }

    url = f"{MDE_BASE_URL}/machines/{machine_id}/isolate"
    payload = {"Comment": comment, "IsolationType": "Full"}  # "Full" is standard

    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code not in (200, 201, 202):
        raise RuntimeError(f"MDE isolate failed: HTTP {r.status_code} {r.text}")

    return r.json() if r.text else {"status": "submitted", "machine_id": machine_id}


def release_vm_by_name(device_name: str, *, comment: str = "Release requested by Agentic SOC Analyst") -> Dict[str, Any]:
    """
    Release (unisolate) a machine in Microsoft Defender for Endpoint by device name.
    """
    token = get_bearer_token()
    machine_id = get_mde_workstation_id_from_name(token, device_name)

    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }

    url = f"{MDE_BASE_URL}/machines/{machine_id}/unisolate"
    payload = {"Comment": comment}

    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code not in (200, 201, 202):
        raise RuntimeError(f"MDE unisolate failed: HTTP {r.status_code} {r.text}")

    return r.json() if r.text else {"status": "submitted", "machine_id": machine_id}


# ----------------------------
# Tool selection
# ----------------------------
def get_query_context(openai_client, user_message: dict, model: str) -> Dict[str, Any]:
    """
    Uses function calling to decide table/fields/time range. Returns dict of tool args.
    """
    print(Fore.LIGHTGREEN_EX + "Deciding log search parameters based on user request...\n" + Style.RESET_ALL)

    resp = openai_client.chat.completions.create(
        model=model,
        messages=[PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION, user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice="auto",
    )

    choice = resp.choices[0].message
    tool_calls = getattr(choice, "tool_calls", None) or []
    if not tool_calls:
        raise RuntimeError("Tool selection returned no tool call.")

    call = tool_calls[0]
    args = json.loads(call.function.arguments)

    cleaned_fields = GUARDRAILS.validate_tables_and_fields(
        args["table_name"],
        args.get("fields", []),
        strict=False,
    )
    args["fields"] = cleaned_fields  # keep as list
    return args


# ----------------------------
# KQL builder
# ----------------------------
def _kql_time_filter(hours: int) -> str:
    return f"TimeGenerated >= ago({int(hours)}h)"


def _escape_kql_string(s: str) -> str:
    return (s or "").replace('"', '\\"')


def _has_device_field(table_name: str) -> bool:
    allowed = GUARDRAILS.ALLOWED_TABLES.get(table_name)
    if allowed is None:
        return False
    return "DeviceName" in allowed


def _build_filters(*, table_name: str, device_name: str, caller: str, user_principal_name: str, time_range_hours: int) -> str:
    parts = [_kql_time_filter(time_range_hours)]

    dn = (device_name or "").strip()
    if dn:
        if table_name.startswith("Device") or _has_device_field(table_name):
            parts.append(f'DeviceName startswith "{_escape_kql_string(dn)}"')

    if (caller or "").strip() and table_name == "AzureActivity":
        parts.append(f'Caller has "{_escape_kql_string(caller.strip())}"')

    if (user_principal_name or "").strip() and table_name == "SigninLogs":
        parts.append(f'UserPrincipalName has "{_escape_kql_string(user_principal_name.strip())}"')

    return " and ".join(parts)


def _build_kql(*, table_name: str, fields: List[str], device_name: str, caller: str, user_principal_name: str, time_range_hours: int) -> str:
    filters = _build_filters(
        table_name=table_name,
        device_name=device_name,
        caller=caller,
        user_principal_name=user_principal_name,
        time_range_hours=int(time_range_hours),
    )

    project = ", ".join(fields) if fields else "*"

    return (
        f"{table_name}\n"
        f"| where {filters}\n"
        f"| project {project}\n"
        f"| take {MAX_QUERY_ROWS}\n"
    )


# ----------------------------
# Log Analytics query
# ----------------------------
def query_log_analytics(
    *,
    log_analytics_client,
    workspace_id: str,
    timerange_hours: int,
    table_name: str,
    device_name: str,
    fields,
    caller: str,
    user_principal_name: str,
) -> Dict[str, Any]:
    """
    Executes safe, capped KQL and returns:
      { "count": int, "records": "csv text" }
    """
    cleaned_fields = GUARDRAILS.validate_tables_and_fields(
        table_name,
        fields,
        strict=False,
    )

    kql = _build_kql(
        table_name=table_name,
        fields=cleaned_fields,
        device_name=device_name,
        caller=caller,
        user_principal_name=user_principal_name,
        time_range_hours=int(timerange_hours),
    )

    print(Fore.LIGHTGREEN_EX + "Constructed KQL Query:" + Style.RESET_ALL)
    print(kql)
    print(Fore.LIGHTGREEN_EX + f"Querying Log Analytics Workspace ID: '{workspace_id}'..." + Style.RESET_ALL)

    timespan = timedelta(hours=int(timerange_hours))
    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=kql,
        timespan=timespan,
    )

    if not response or not getattr(response, "tables", None):
        return {"count": 0, "records": ""}

    table = response.tables[0]
    columns = [getattr(c, "name", c) for c in (table.columns or [])]
    rows = table.rows or []
    return {"count": len(rows), "records": _rows_to_csv(columns, rows)}


def _rows_to_csv(columns: List[str], rows: List[list]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    for r in rows:
        writer.writerow(r)
    return out.getvalue()


# ----------------------------
# Token-safe payload for LLM
# ----------------------------
def _hard_clamp_text(text: str, *, max_chars: int = MAX_LLM_CHARS, max_lines: int = MAX_LLM_LINES) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... (clamped: {len(lines)-max_lines} lines omitted)"]
    clamped = "\n".join(lines)
    if len(clamped) > max_chars:
        clamped = clamped[:max_chars] + "\n... (clamped by char limit)"
    return clamped


def summarize_csv_for_llm(records_csv: str, *, top_n: int = 12, sample_rows: int = 200) -> str:
    if not records_csv:
        return ""

    lines = records_csv.splitlines()
    if len(lines) <= 1:
        return records_csv

    header = lines[0].split(",")
    body = lines[1:]

    interesting = [c for c in ["AccountName", "ActionType", "RemoteIP", "RemotePort", "FileName", "ProcessCommandLine", "DeviceName"] if c in header]
    if not interesting:
        interesting = header[:5]

    idx = {name: header.index(name) for name in interesting}
    counts = {name: {} for name in interesting}

    for row in body[:5000]:
        parts = row.split(",")
        for k, i in idx.items():
            val = parts[i] if i < len(parts) else ""
            if val == "":
                val = "<blank>"
            counts[k][val] = counts[k].get(val, 0) + 1

    summary = [
        "[SAFE_LOG_SUMMARY json]",
        f"- rows_total: {len(body)}",
        f"- sample_rows_used: {min(len(body), 5000)}",
        "",
        "Top values by field:"
    ]
    for field in interesting:
        summary.append(f"\n- {field}:")
        top = sorted(counts[field].items(), key=lambda x: x[1], reverse=True)[:top_n]
        for v, c in top:
            summary.append(f"  - {v}: {c}")

    summary.append("\nRaw sample rows (first few):")
    summary.append(lines[0])
    summary.extend(body[:sample_rows])
    return _hard_clamp_text("\n".join(summary))


def build_token_safe_log_payload(*, records_csv: str, record_count: int) -> str:
    if not records_csv:
        return ""
    if record_count >= SUMMARY_TRIGGER_ROWS:
        return summarize_csv_for_llm(records_csv)

    lines = records_csv.splitlines()
    if len(lines) <= 1:
        return records_csv

    header = lines[0]
    body = lines[1:][:MAX_LLM_ROWS]
    trimmed = "\n".join([header] + body)
    return _hard_clamp_text(trimmed)


def prepare_log_data_for_llm(records_csv: str, record_count: int) -> str:
    """
    Compatibility wrapper: supports positional calls from older code.
    """
    return build_token_safe_log_payload(records_csv=records_csv, record_count=record_count)


# ----------------------------
# LLM Hunt
# ----------------------------
def hunt(
    *,
    openai_client,
    threat_hunt_system_message: dict,
    threat_hunt_user_message: dict,
    openai_model: str,
) -> Dict[str, Any]:
    sys_c = (threat_hunt_system_message.get("content") or "")
    usr_c = (threat_hunt_user_message.get("content") or "")
    if "json" not in sys_c.lower() and "json" not in usr_c.lower():
        threat_hunt_system_message = {
            **threat_hunt_system_message,
            "content": sys_c + "\n\nYou MUST output valid json.",
        }

    resp = openai_client.chat.completions.create(
        model=openai_model,
        messages=[threat_hunt_system_message, threat_hunt_user_message],
        response_format={"type": "json_object"},
    )

    raw = resp.choices[0].message.content
    if not raw:
        return {}

    try:
        return json.loads(raw)
    except Exception:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw[start:end + 1])
        raise
