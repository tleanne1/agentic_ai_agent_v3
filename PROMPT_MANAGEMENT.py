# PROMPT_MANAGEMENT.py
# -------------------------------------------------------------------
# Prompt Management:
# - User input
# - Threat hunt prompt builder
# - Tool selection system prompt
# - IMPORTANT FIXES:
#   ✅ log payload clamp (rows + chars) to prevent token explosions
#   ✅ include the literal word "json" to satisfy response_format=json_object rules
# -------------------------------------------------------------------

from colorama import Fore

MAX_EVIDENCE_CHARS = 80_000     # safety: prevent huge prompts
MAX_EVIDENCE_ROWS = 400         # safety: prevent huge prompts


def clamp_log_payload(csv_text: str) -> str:
    """
    Keep only header + first N rows, then clamp characters.
    """
    if not csv_text:
        return ""

    lines = csv_text.splitlines()
    if not lines:
        return ""

    header = lines[:1]
    body = lines[1: MAX_EVIDENCE_ROWS + 1]
    payload = "\n".join(header + body)

    if len(lines) > (MAX_EVIDENCE_ROWS + 1):
        payload += f"\n...TRUNCATED ROWS... (kept {MAX_EVIDENCE_ROWS} rows)"

    if len(payload) > MAX_EVIDENCE_CHARS:
        payload = payload[:MAX_EVIDENCE_CHARS] + "\n...TRUNCATED CHARS..."

    return payload


FORMATTING_INSTRUCTIONS = """
Return your findings as valid JSON.

Return your findings in the following JSON format:
{
  "findings": [
    <finding 1>,
    <finding 2>
  ]
}

If there are no findings, return:
{
  "findings": []
}

Schema example (one finding):
{
  "findings": [
    {
      "title": "Brief title describing the suspicious activity",
      "description": "Detailed explanation grounded in the logs",
      "mitre": {
        "tactic": "Execution",
        "technique": "T1059",
        "sub_technique": "T1059.001",
        "id": "T1059.001",
        "description": "MITRE mapping"
      },
      "confirmations": ["pivot", "create incident", "monitor", "ignore"],
      "log_lines": ["Relevant log line(s)"],
      "confidence": "Low | Medium | High",
      "recommendations": ["pivot", "create incident", "monitor", "ignore"],
      "indicators_of_compromise": ["IP/domain/hash/etc"],
      "tags": ["credential access", "suspicious login"],
      "notes": "Optional analyst notes"
    }
  ]
}

Logs below:
"""


THREAT_HUNT_PROMPTS = {
    "GeneralThreatHunter": """
You are a top-tier Threat Hunting Analyst AI focused on Microsoft Defender for Endpoint (MDE) host data.

Output MUST be valid json.
""",

    "DeviceProcessEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceProcessEvents.
Output MUST be valid json.
""",

    "DeviceNetworkEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceNetworkEvents.
Output MUST be valid json.
""",

    "DeviceLogonEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceLogonEvents.
Output MUST be valid json.
""",

    "DeviceRegistryEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceRegistryEvents.
Output MUST be valid json.
""",

    "AlertEvidence": """
You are an expert Threat Hunting AI analyzing MDE AlertEvidence.
Output MUST be valid json.
""",

    "DeviceFileEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceFileEvents.
Output MUST be valid json.
""",
}


SYSTEM_PROMPT_THREAT_HUNT = {
    "role": "system",
    "content": (
        "You are a cybersecurity threat hunting AI.\n\n"
        "You MUST output valid json.\n"
        "Do not invent evidence; ground findings in provided logs.\n"
    )
}


SYSTEM_PROMPT_TOOL_SELECTION = {
    "role": "system",
    "content": (
        "You are part of a tools/function call.\n"
        "You MUST return valid json.\n"
        "If no timeframe specified, choose 96 hours.\n"
        "Only choose allowed fields for the selected table.\n"
        "Never output raw KQL.\n"
    )
}


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_log_analytics",
            "description": (
                "Query a Log Analytics table using KQL.\n"
                "You must return json.\n"
                "Allowed tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, "
                "DeviceFileEvents, DeviceRegistryEvents, AlertInfo, AlertEvidence, AzureNetworkAnalytics_CL, "
                "AzureActivity, SigninLogs.\n"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name": {"type": "string"},
                    "device_name": {"type": "string"},
                    "caller": {"type": "string"},
                    "user_principal_name": {"type": "string"},
                    "time_range_hours": {"type": "integer"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                    "about_individual_user": {"type": "boolean"},
                    "about_individual_host": {"type": "boolean"},
                    "about_network_security_group": {"type": "boolean"},
                    "rationale": {"type": "string"},
                },
                "required": [
                    "table_name",
                    "device_name",
                    "time_range_hours",
                    "fields",
                    "caller",
                    "user_principal_name",
                    "about_individual_user",
                    "about_individual_host",
                    "about_network_security_group",
                    "rationale"
                ]
            }
        }
    }
]


def get_user_message():
    prompt = ""
    # Removed excessive startup spacing (was: print("\n" * 20))

    user_input = input(
        f"{Fore.LIGHTBLUE_EX}Agentic SOC Analyst at your service! What would you like to do?\n\n{Fore.RESET}"
    ).strip()

    if user_input:
        prompt = user_input

    return {"role": "user", "content": prompt}


def build_threat_hunt_prompt(user_prompt: str, table_name: str, log_data: str) -> dict:
    # NOTE: Printing this here caused duplicate console output because _main.py
    # also prints the same status line. Keep logging centralized in _main.py.

    instructions = THREAT_HUNT_PROMPTS.get(table_name, THREAT_HUNT_PROMPTS["GeneralThreatHunter"])

    safe_log_data = clamp_log_payload(log_data)

    full_prompt = (
        f"User request:\n{user_prompt}\n\n"
        f"Threat Hunt Instructions:\n{instructions}\n\n"
        f"Formatting Instructions:\n{FORMATTING_INSTRUCTIONS}\n\n"
        f"Log Data:\n{safe_log_data}\n"
    )

    return {"role": "user", "content": full_prompt}
