# Standard library
import json
import os
import re
from datetime import datetime, timezone

# Third-party libraries
from colorama import Fore, Style

# ----------------------------
# Logging
# ----------------------------

# Writes JSONL (one JSON object per line). Easy to parse later.
LOG_FILE = os.getenv("AGENT_LOG_FILE", "agent_events.jsonl")

# Toggle: log raw Log Analytics CSV payloads (can be large and sensitive)
LOG_RAW_RECORDS = os.getenv("AGENT_LOG_RAW_RECORDS", "0").strip().lower() in {"1", "true", "yes", "y"}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(event_type: str, payload: dict):
    """
    Append a structured event to a local JSONL file.
    Never crash the agent due to logging errors.
    """
    rec = {"ts": _utc_iso(), "event": event_type, "payload": payload or {}}
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ----------------------------
# Sanitization helpers
# ----------------------------

_SUSPICIOUS_CHARS = re.compile(r"[|;`$<>]")


def sanitize_literal(value: str, *, max_len: int = 128) -> str:
    """
    Defang values that get interpolated into KQL string literals.

    - Strips newlines
    - Removes characters commonly used for KQL injection / command chaining
    - Removes quotes
    - Truncates to max_len
    """
    if value is None:
        return ""

    v = str(value).replace("\r", " ").replace("\n", " ").strip()
    v = _SUSPICIOUS_CHARS.sub("", v)
    v = v.replace('"', "").replace("'", "")
    if len(v) > max_len:
        v = v[:max_len]
    return v


def sanitize_query_context(query_context: dict) -> dict:
    """
    Normalizes tool-selection output and makes it safer for KQL templating.
    This matches your EXECUTOR.query_log_analytics signature.
    """
    qc = dict(query_context or {})

    # Defaults expected by your pipeline
    qc.setdefault("table_name", "")
    qc.setdefault("device_name", "")
    qc.setdefault("caller", "")
    qc.setdefault("user_principal_name", "")
    qc.setdefault("time_range_hours", 96)
    qc.setdefault("fields", [])
    qc.setdefault("about_individual_user", False)
    qc.setdefault("about_individual_host", False)
    qc.setdefault("about_network_security_group", False)
    qc.setdefault("rationale", "")

    # Sanitize interpolated values
    qc["device_name"] = sanitize_literal(qc.get("device_name", ""))
    qc["caller"] = sanitize_literal(qc.get("caller", ""))
    qc["user_principal_name"] = sanitize_literal(qc.get("user_principal_name", ""))

    # Normalize fields -> ensure string "a, b, c" because your EXECUTOR joins it into `project ...`
    fields = qc.get("fields", [])
    if isinstance(fields, list):
        fields = [str(f).strip() for f in fields if str(f).strip()]
        qc["fields"] = ", ".join(fields)
    else:
        qc["fields"] = ", ".join([f.strip() for f in str(fields).split(",") if f.strip()])

    # Normalize time_range_hours
    try:
        qc["time_range_hours"] = int(qc.get("time_range_hours", 96))
    except Exception:
        qc["time_range_hours"] = 96

    return qc


# ----------------------------
# Output formatting
# ----------------------------

def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "\nAgentic SOC Threat Hunting Assistant (continuous mode)\n" + Style.RESET_ALL)


def print_help():
    print(
        Fore.WHITE
        + """
Commands:
  help          Show this help menu
  clear / cls   Clear the screen
  quit / exit   Exit the agent

Tips:
  - Be specific about time range + target (device/user/IP).
  - Example: "Hunt for suspicious PowerShell downloads on HOST123 in the last 24 hours"
"""
        + Style.RESET_ALL
    )


def display_query_context(query_context: dict):
    print(f"{Fore.LIGHTGREEN_EX}Search context decided by tool selection:\n{Style.RESET_ALL}")
    print(f"{Fore.WHITE}- Table: {Fore.CYAN}{query_context.get('table_name','')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}- Time range (hours): {Fore.CYAN}{query_context.get('time_range_hours','')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}- Device filter: {Fore.CYAN}{query_context.get('device_name','')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}- Caller filter: {Fore.CYAN}{query_context.get('caller','')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}- UserPrincipalName filter: {Fore.CYAN}{query_context.get('user_principal_name','')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}- Fields: {Fore.CYAN}{query_context.get('fields','')}{Style.RESET_ALL}")
    rat = query_context.get("rationale", "")
    if rat:
        print(f"{Fore.WHITE}- Rationale: {Fore.WHITE}{rat}{Style.RESET_ALL}")
    print("")


def display_threats(threat_list):
    if not threat_list:
        print(Fore.LIGHTGREEN_EX + "No threats returned." + Style.RESET_ALL)
        return

    for i, threat in enumerate(threat_list, 1):
        title = threat.get("title", "Untitled")
        confidence = threat.get("confidence", "Unknown")
        recommendation = threat.get("recommendation", "")
        mitre = threat.get("mitre", "")

        print(Fore.WHITE + f"\n[{i}] " + Fore.LIGHTRED_EX + title + Style.RESET_ALL)
        print(Fore.WHITE + "    Confidence: " + Fore.CYAN + str(confidence) + Style.RESET_ALL)
        if mitre:
            print(Fore.WHITE + "    MITRE: " + Fore.CYAN + str(mitre) + Style.RESET_ALL)
        if recommendation:
            print(Fore.WHITE + "    Recommendation: " + Fore.CYAN + str(recommendation) + Style.RESET_ALL)

        iocs = threat.get("iocs") or threat.get("IOCs") or []
        if iocs:
            print(Fore.WHITE + "    IOCs: " + Fore.CYAN + ", ".join([str(x) for x in iocs]) + Style.RESET_ALL)

        evidence = threat.get("evidence") or ""
        if evidence:
            ev = str(evidence)
            if len(ev) > 700:
                ev = ev[:700] + "..."
            print(Fore.WHITE + "    Evidence: " + Fore.WHITE + ev + Style.RESET_ALL)
