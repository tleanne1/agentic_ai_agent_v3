# GUARDRAILS.py
# -------------------------------------------------------------------
# Guardrails for:
# - Allowed tables + allowed fields (allowlist)
# - Field normalization (aliases)
# - Safe validation:
#     strict=True  -> raise SystemExit on invalid
#     strict=False -> auto-prune invalid + continue (recommended for LLM output)
# - Prompt injection / raw KQL detection
# - Model allowlist
#
# NOTE (minimal fix you wanted):
# - Keep your “signature uses normalized fields” idea
# - BUT avoid printing "[i] Normalized fields..." during signature computation
#   by using a silent normalizer for the signature only.
# -------------------------------------------------------------------

import re
from typing import Optional, Set, Union, List, Dict, Tuple
from colorama import Fore, Style


# ----------------------------
# Lightweight console de-dupe
# ----------------------------
_LAST_VALIDATION_SIGNATURE: Optional[Tuple[str, Tuple[str, ...], bool]] = None
_PRINTED_MODELS: Set[str] = set()


# ----------------------------
# Allowed tables and fields
# ----------------------------
# If fields are None => broad schema allowed (skip field validation)
ALLOWED_TABLES: Dict[str, Optional[Set[str]]] = {
    "DeviceLogonEvents": {
        "TimeGenerated", "Timestamp",
        "AccountName", "AccountDomain", "AccountSid",
        "DeviceName",
        "ActionType", "LogonType", "FailureReason",
        "RemoteIP", "RemotePort",
        "RemoteDeviceName",
    },

    "DeviceProcessEvents": {
        "TimeGenerated", "Timestamp",
        "DeviceName", "ActionType",
        "FileName", "FolderPath",
        "ProcessCommandLine",
        "ProcessId", "ParentProcessId",
        "InitiatingProcessId",
        "InitiatingProcessFileName",
        "InitiatingProcessFolderPath",
        "InitiatingProcessCommandLine",
        "AccountName",
        "InitiatingProcessAccountName",
        # Keep these allowed (some tenants may have them), but we will normalize away from them by default:
        "InitiatingAccountName",
        "InitiatingUserName",
        "InitiatingProcessAccountDomain",
        "InitiatingProcessAccountSid",
        "SHA256", "MD5",
    },

    "DeviceNetworkEvents": {
        "TimeGenerated", "Timestamp",
        "DeviceName", "ActionType",
        "RemoteIP", "RemotePort",
        "LocalIP", "LocalPort",
        "Protocol",
        "RemoteUrl",
        "RemoteDeviceName",
        "RemoteIPType",
        "InitiatingProcessId",
        "InitiatingProcessFileName",
        "InitiatingProcessFolderPath",
        "InitiatingProcessCommandLine",
        "InitiatingProcessAccountName",
        # Keep allowed but normalize away by default:
        "InitiatingAccountName",
        "InitiatingUserName",
        "ProcessId",
    },

    "DeviceFileEvents": {
        "TimeGenerated", "Timestamp",
        "DeviceName", "ActionType",
        "FileName", "FolderPath",
        "InitiatingProcessAccountName",
        # Keep allowed but normalize away by default:
        "InitiatingAccountName",
        "InitiatingUserName",
        "InitiatingProcessFileName",
        "InitiatingProcessFolderPath",
        "InitiatingProcessCommandLine",
        "SHA256", "MD5",
    },

    "DeviceRegistryEvents": None,
    "DeviceImageLoadEvents": None,

    "AlertInfo": None,
    "AlertEvidence": None,

    "AzureNetworkAnalytics_CL": {
        "TimeGenerated", "FlowType_s",
        "SrcPublicIPs_s", "DestIP_s", "DestPort_d",
        "VM_s",
        "AllowedInFlows_d", "AllowedOutFlows_d",
        "DeniedInFlows_d", "DeniedOutFlows_d",
    },

    "AzureActivity": {
        "TimeGenerated",
        "OperationNameValue", "ActivityStatusValue",
        "ResourceGroup",
        "Caller", "CallerIpAddress",
        "Category",
    },

    "SigninLogs": {
        "TimeGenerated",
        "UserPrincipalName",
        "OperationName",
        "Category",
        "ResultSignature", "ResultDescription",
        "AppDisplayName",
        "IPAddress",
        "LocationDetails",
    },

    "AuditLogs": None,
}


# ----------------------------
# Field aliases (fix common LLM mistakes)
# ----------------------------
FIELD_ALIASES_BY_TABLE: Dict[str, Dict[str, str]] = {
    "DeviceLogonEvents": {
        # Common confusions:
        "ActivityStatusValue": "ActionType",
        "UserPrincipalName": "AccountName",
        "Username": "AccountName",
        "UserName": "AccountName",

        # Logon time & IP aliasing:
        "LogonTime": "TimeGenerated",
        "IPAddress": "RemoteIP",
        "IpAddress": "RemoteIP",
        "DestinationIp": "RemoteIP",
        "DestinationIP": "RemoteIP",
    },

    "DeviceProcessEvents": {
        "InitiatingUser": "InitiatingUserName",
        "InitiatingUsername": "InitiatingUserName",

        # ✅ Minimal compatibility fix (workspace schema variance):
        # Prefer InitiatingProcessAccountName when InitiatingUserName isn't present.
        "InitiatingUserName": "InitiatingProcessAccountName",

        # ✅ Prefer InitiatingProcessAccountName over InitiatingAccountName (often missing)
        "InitiatingAccount": "InitiatingProcessAccountName",
        "InitiatingAccountName": "InitiatingProcessAccountName",

        "UserPrincipalName": "AccountName",
        "Username": "AccountName",
        "UserName": "AccountName",

        "ProcessName": "FileName",
        "Process": "FileName",
        "CommandLine": "ProcessCommandLine",

        "InitiatingProcessID": "InitiatingProcessId",
        "InitiatingProcessId": "InitiatingProcessId",
    },

    "DeviceNetworkEvents": {
        "InitiatingUser": "InitiatingUserName",
        "InitiatingUsername": "InitiatingUserName",

        # ✅ Minimal compatibility fix:
        # If RemoteDeviceName isn't present in your workspace, map to RemoteIP to avoid pivot crashes.
        "RemoteDeviceName": "RemoteIP",

        # ✅ Prefer InitiatingProcessAccountName over InitiatingAccountName
        "InitiatingAccount": "InitiatingProcessAccountName",
        "InitiatingAccountName": "InitiatingProcessAccountName",

        "DestinationDeviceName": "RemoteDeviceName",
        "DestPort": "RemotePort",
        "DestinationPort": "RemotePort",
        "DestIP": "RemoteIP",
        "DestinationIP": "RemoteIP",
        "DestinationIp": "RemoteIP",
        "Url": "RemoteUrl",
        "SourceIp": "LocalIP",
        "SourceIP": "LocalIP",
    },

    "DeviceFileEvents": {
        "InitiatingUser": "InitiatingUserName",
        "InitiatingUsername": "InitiatingUserName",
        "UserName": "InitiatingUserName",
        "Username": "InitiatingUserName",

        # ✅ Prefer InitiatingProcessAccountName over InitiatingAccountName
        "InitiatingAccount": "InitiatingProcessAccountName",
        "InitiatingAccountName": "InitiatingProcessAccountName",

        "FilePath": "FolderPath",
        "Hash": "SHA256",
    },
}


# ----------------------------
# Model allowlist (simple)
# ----------------------------
ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576},
    "gpt-4.1":      {"max_input_tokens": 1_047_576},
    "gpt-5-mini":   {"max_input_tokens": 272_000},
    "gpt-5":        {"max_input_tokens": 272_000},
}


# ----------------------------
# Field list helpers
# ----------------------------
def _normalize_field_list(fields: Union[str, list]) -> List[str]:
    if isinstance(fields, list):
        return [str(f).strip() for f in fields if str(f).strip()]
    return [f.strip() for f in str(fields).split(",") if f.strip()]


def normalize_fields(table: str, fields: Union[str, list]) -> List[str]:
    """
    Canonicalize field list:
    - apply aliases (DestinationPort -> RemotePort, ProcessName -> FileName, etc.)
    - de-dupe while preserving order
    """
    raw = _normalize_field_list(fields)
    alias_map = FIELD_ALIASES_BY_TABLE.get(table, {})

    out: List[str] = []
    seen = set()

    for f in raw:
        canonical = alias_map.get(f, f)
        if canonical not in seen:
            out.append(canonical)
            seen.add(canonical)

    if raw != out:
        print(
            f"{Fore.YELLOW}[i] Normalized fields for {table}: "
            f"{Fore.WHITE}{', '.join(raw)} {Fore.YELLOW}→ {Fore.WHITE}{', '.join(out)}{Style.RESET_ALL}"
        )

    return out


def normalize_fields_silent(table: str, fields: Union[str, list]) -> List[str]:
    """
    Same normalization as normalize_fields(), but does NOT print.
    Used for signature/dedupe computation so we don't emit noise.
    """
    raw = _normalize_field_list(fields)
    alias_map = FIELD_ALIASES_BY_TABLE.get(table, {})

    out: List[str] = []
    seen = set()

    for f in raw:
        canonical = alias_map.get(f, f)
        if canonical not in seen:
            out.append(canonical)
            seen.add(canonical)

    return out


def coerce_fields_to_allowed(table: str, fields: Union[str, list]) -> Tuple[List[str], List[str]]:
    """
    Normalize + prune invalid fields (non-fatal).
    Returns: (clean_fields, dropped_fields)
    """
    allowed = ALLOWED_TABLES.get(table)
    normalized = normalize_fields(table, fields)

    if allowed is None:
        return normalized, []

    clean: List[str] = []
    dropped: List[str] = []
    for f in normalized:
        if f in allowed:
            clean.append(f)
        else:
            dropped.append(f)

    # If everything got dropped, fall back to safe defaults
    if not clean:
        fallback_defaults = {
            "DeviceLogonEvents": ["TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName"],
            "DeviceProcessEvents": ["TimeGenerated", "DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
            "DeviceNetworkEvents": ["TimeGenerated", "DeviceName", "LocalIP", "RemoteIP", "RemotePort", "Protocol"],
            "DeviceFileEvents": ["TimeGenerated", "DeviceName", "ActionType", "FileName", "FolderPath", "SHA256"],
        }
        clean = fallback_defaults.get(table, normalized[:6] or [])

    return clean, dropped


def validate_tables_and_fields(table: str, fields: Union[str, list], *, strict: bool = True) -> List[str]:
    """
    strict=True  -> raise SystemExit for invalid fields/tables
    strict=False -> prune invalid fields and continue
    """
    global _LAST_VALIDATION_SIGNATURE

    # ✅ Use normalized fields for signature so aliases (LogonTime vs TimeGenerated)
    # dedupe to the same signature and reduce repeated console banners.
    # ✅ IMPORTANT: compute signature SILENTLY so we don't print "[i] Normalized..." early.
    normalized_for_sig = tuple(normalize_fields_silent(table, fields))
    signature = (table, normalized_for_sig, strict)

    verbose = signature != _LAST_VALIDATION_SIGNATURE
    _LAST_VALIDATION_SIGNATURE = signature

    if verbose:
        print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...{Style.RESET_ALL}")

    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Table '{table}' is not allowed.{Style.RESET_ALL}")
        raise SystemExit(1)

    allowed_fields = ALLOWED_TABLES.get(table)

    # Broad schema: just normalize (with prints only if needed)
    if allowed_fields is None:
        cleaned = normalize_fields(table, list(normalized_for_sig))
        if verbose:
            print(f"{Fore.WHITE}Table '{table}' allowed. Field validation skipped (broad schema).\n{Style.RESET_ALL}")
        return cleaned

    # For strict schemas, run full normalize+prune (this will print normalization if it changed)
    cleaned, dropped = coerce_fields_to_allowed(table, list(normalized_for_sig))

    if dropped:
        if verbose:
            print(
                f"{Fore.YELLOW}[i] Dropped invalid field(s) for {table}: "
                f"{Fore.WHITE}{', '.join(dropped)}{Style.RESET_ALL}"
            )
        if strict:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Invalid fields for '{table}' (strict mode).{Style.RESET_ALL}")
            raise SystemExit(1)

    if verbose:
        print(f"{Fore.WHITE}Fields and tables validated.\n{Style.RESET_ALL}")
    return cleaned


def validate_model(model: str) -> None:
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed.{Style.RESET_ALL}")
        raise SystemExit(1)

    # Avoid repeating "Selected model is valid" if multiple layers validate the same model.
    if model not in _PRINTED_MODELS:
        _PRINTED_MODELS.add(model)
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}{Style.RESET_ALL}")


# ----------------------------
# Prompt/KQL injection detection
# ----------------------------
_KQL_MARKERS = [
    "|", "project", "where", "summarize", "extend", "join", "union",
    "datatable", "externaldata", "invoke", "let", "print", "take", "top",
    "parse", "mv-expand", "evaluate", "range"
]

_INJECTION_MARKERS = [
    "ignore previous", "system prompt", "developer message", "tool_choice", "jailbreak",
    "you are not", "act as", "simulate", "reveal", "exfiltrate", "bypass guardrails"
]


def detect_prompt_injection(user_prompt: str) -> list:
    """
    Return a list of reasons the prompt looks like raw KQL / injection.
    Keep this lightweight: it is just a guardrail, not a parser.
    """
    if not user_prompt:
        return []

    p = user_prompt.lower()
    reasons = []

    # Pipe operator almost always indicates raw KQL
    if "|" in user_prompt:
        reasons.append("|")

    # KQL keywords
    for kw in _KQL_MARKERS:
        if re.search(rf"\b{re.escape(kw)}\b", p):
            reasons.append(f"contains KQL keyword '{kw}'")
            break

    # Obvious injection patterns
    for kw in _INJECTION_MARKERS:
        if kw in p:
            reasons.append(f"contains injection phrase '{kw}'")
            break

    # Tool JSON leakage
    if '"table_name"' in p or '"fields"' in p or '"time_range_hours"' in p:
        reasons.append("contains tool-parameter JSON-like content")

    return reasons
