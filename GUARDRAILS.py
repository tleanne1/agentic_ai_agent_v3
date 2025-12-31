from colorama import Fore, Style
import re

# Allowed tables and fields returned by tool-selection step.
# Keep this in sync with PROMPT_MANAGEMENT.TOOLS (and expand over time).
# If fields are None => allow any fields (broad schema)
ALLOWED_TABLES = {
    # MDE Advanced Hunting
    "DeviceProcessEvents": {"TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine"},
    "DeviceNetworkEvents": {"TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort"},
    "DeviceLogonEvents": {"TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName"},
    "DeviceFileEvents": {"TimeGenerated", "ActionType", "DeviceName", "FileName", "FolderPath", "InitiatingProcessAccountName", "SHA256"},

    # Alert tables (broad schemas differ by tenant)
    "AlertInfo": None,
    "AlertEvidence": None,

    # Optional / future MDE tables you may add to TOOLS
    "DeviceRegistryEvents": None,
    "DeviceImageLoadEvents": None,

    # Sentinel / Azure tables
    "AzureNetworkAnalytics_CL": {"TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d"},
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category"},
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails"},

    # Entra ID tables (broad schemas)
    "AuditLogs": None,
}

# Model allowlist
ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}},
}

def validate_tables_and_fields(table, fields):
    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...{Style.RESET_ALL}")

    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Table '{table}' is not in allowed list — exiting.{Style.RESET_ALL}")
        raise SystemExit(1)

    allowed_fields = ALLOWED_TABLES.get(table)

    # If None, allow any fields (broad schema)
    if allowed_fields is None:
        print(f"{Fore.WHITE}Table '{table}' is allowed. Field validation skipped (broad schema).\n{Style.RESET_ALL}")
        return

    # Normalize fields -> list[str]
    if isinstance(fields, list):
        field_list = [str(f).strip() for f in fields if str(f).strip()]
    else:
        field_list = [f.strip() for f in str(fields).replace(" ", "").split(",") if f.strip()]

    for field in field_list:
        if field not in allowed_fields:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not allowed for table '{table}' — exiting.{Style.RESET_ALL}")
            raise SystemExit(1)

    print(f"{Fore.WHITE}Fields and tables validated.\n{Style.RESET_ALL}")

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — exiting.{Style.RESET_ALL}")
        raise SystemExit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")

# ----------------------------
# Prompt-injection / KQL-injection detection
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

def detect_prompt_injection(user_prompt: str):
    """
    Returns list[str] reasons if suspicious, else [].
    Conservative by design: blocks raw KQL pipes + common injection strings.
    """
    if not user_prompt:
        return []

    p = user_prompt.lower()
    reasons = []

    # KQL pipe operator
    if "|" in user_prompt:
        reasons.append("contains pipe operator '|'")

    # KQL keywords
    for kw in _KQL_MARKERS:
        if re.search(rf"\b{re.escape(kw)}\b", p):
            reasons.append(f"contains KQL keyword '{kw}'")
            break

    # Prompt-injection patterns
    for kw in _INJECTION_MARKERS:
        if kw in p:
            reasons.append(f"contains injection phrase '{kw}'")
            break

    # Attempts to smuggle tool params as JSON
    if '"table_name"' in p or '"fields"' in p or '"time_range_hours"' in p:
        reasons.append("contains tool-parameter JSON-like content")

    return reasons
