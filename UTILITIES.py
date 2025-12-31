# UTILITIES.py
# -------------------------------------------------------------------
# Utilities for:
# - Logging
# - Pretty printing
# - Query context sanitization
# - CSV reduction for LLM context safety
#
# Key fix:
# ✅ reduce_csv_for_llm(): keep header + sample rows + enforce max chars
# -------------------------------------------------------------------

import json
import os
import time
from typing import Dict, Any, List
from colorama import Fore, Style

LOG_RAW_RECORDS = False


def print_banner():
    print(Fore.CYAN + "Agentic SOC Analyst at your service!" + Style.RESET_ALL)


def print_help():
    print(Fore.WHITE + "Commands: help | clear | quit | release" + Style.RESET_ALL)


def log_event(event_name: str, payload: Dict[str, Any]):
    """
    Lightweight JSONL logger. Writes to agent_events.jsonl
    """
    try:
        record = {
            "ts": time.time(),
            "event": event_name,
            "payload": payload,
        }
        with open("agent_events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


def sanitize_query_context(qc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal sanitizer; your main.py already guards most things.
    """
    out = dict(qc or {})
    out["table_name"] = str(out.get("table_name", "")).strip()
    out["device_name"] = str(out.get("device_name", "")).strip()
    out["caller"] = str(out.get("caller", "")).strip()
    out["user_principal_name"] = str(out.get("user_principal_name", "")).strip()
    try:
        out["time_range_hours"] = int(out.get("time_range_hours") or 24)
    except Exception:
        out["time_range_hours"] = 24
    return out


def display_query_context(qc: Dict[str, Any]):
    print(Fore.LIGHTGREEN_EX + "\nSearch context decided by tool selection:\n" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Table: {qc.get('table_name')}" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Time range (hours): {qc.get('time_range_hours')}" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Device filter: {qc.get('device_name')}" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Caller filter: {qc.get('caller')}" + Style.RESET_ALL)
    print(Fore.WHITE + f"- UserPrincipalName filter: {qc.get('user_principal_name')}" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Fields: {qc.get('fields')}" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Rationale: {qc.get('rationale')}" + Style.RESET_ALL)
    print("")


def display_threats(threat_list: List[dict]):
    if not threat_list:
        print(Fore.YELLOW + "No findings." + Style.RESET_ALL)
        return

    for i, t in enumerate(threat_list, 1):
        title = t.get("title", "Untitled")
        confidence = t.get("confidence", "Unknown")
        mitre = t.get("mitre", {})
        print(Fore.LIGHTRED_EX + f"\n[{i}] {title}" + Style.RESET_ALL)
        print(Fore.WHITE + f"    Confidence: {confidence}" + Style.RESET_ALL)
        if mitre:
            print(Fore.WHITE + f"    MITRE: {mitre}" + Style.RESET_ALL)


# ----------------------------
# CSV reduction for LLM safety
# ----------------------------
def reduce_csv_for_llm(
    records_csv: str,
    *,
    max_chars: int = 90_000,
    sample_rows: int = 600,
) -> str:
    """
    Keep header + evenly sample rows and enforce max_chars.
    This prevents context_length_exceeded even on very large tables.
    """
    if not records_csv:
        return ""

    lines = records_csv.splitlines()
    if not lines:
        return ""

    header = lines[0]
    rows = lines[1:]

    if len(records_csv) <= max_chars:
        return records_csv

    # If too many rows, sample evenly across the set
    if len(rows) > sample_rows:
        step = max(1, len(rows) // sample_rows)
        sampled = rows[::step][:sample_rows]
    else:
        sampled = rows

    # Rebuild
    out_lines = [header] + sampled
    out = "\n".join(out_lines)

    # Hard char clamp (keep header + top chunk)
    if len(out) > max_chars:
        out = out[:max_chars]

        # try not to cut mid-line
        last_nl = out.rfind("\n")
        if last_nl > 0:
            out = out[:last_nl]

    out += "\n... (trimmed for LLM context safety)"
    return out
