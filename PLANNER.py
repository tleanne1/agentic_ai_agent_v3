"""
Agentic SOC Engine

Copyright (c) 2026 Tracey Buentello

All Rights Reserved.

This source code is provided for portfolio,
educational, and evaluation purposes only.

Unauthorized copying, redistribution,
modification, commercial use, or reproduction
of substantial portions of this software
is prohibited without written permission.
"""

# PLANNER.py
# ------------------------------------------------------------
# Planner:
# - Ask LLM for 1-3 pivot steps (JSON only)
# - Sanitize each step (table/fields/time range)
# - Execute pivots via your query runner (EXECUTOR.query_log_analytics)
#
# ✅ Also includes a lightweight UI/API helper:
#   cluster_campaigns(device_logons, device_net)
#   (non-destructive: does not affect agent behavior)
# ------------------------------------------------------------

import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict

import UTILITIES
import GUARDRAILS


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_json_mention(messages: List[dict]) -> List[dict]:
    out = []
    for m in messages:
        if m.get("role") == "system" and "json" not in (m.get("content") or "").lower():
            m = dict(m)
            m["content"] = (m.get("content") or "") + "\n\nOutput must be valid json."
        out.append(m)
    return out


def _int_clamp(v: Any, min_v: int, max_v: int, default: int) -> int:
    try:
        n = int(v)
    except Exception:
        return default
    return max(min_v, min(max_v, n))


def _sanitize_planned_step(step: dict, initial_query_context: dict) -> dict:
    table_name = (step.get("table_name") or "").strip()
    if not table_name:
        raise ValueError("missing table_name")

    device_name = (step.get("device_name") or initial_query_context.get("device_name") or "").strip()
    user_principal_name = (step.get("user_principal_name") or initial_query_context.get("user_principal_name") or "").strip()
    caller = (step.get("caller") or initial_query_context.get("caller") or "").strip()

    time_range_hours = _int_clamp(step.get("time_range_hours"), 1, 168, int(initial_query_context.get("time_range_hours") or 96))

    fields_raw = step.get("fields") or ""
    if isinstance(fields_raw, str):
        fields = [f.strip() for f in fields_raw.split(",") if f.strip()]
    elif isinstance(fields_raw, list):
        fields = [str(f).strip() for f in fields_raw if str(f).strip()]
    else:
        fields = []

    cleaned_fields = GUARDRAILS.validate_tables_and_fields(table_name, fields, strict=False)

    # 🔹 SOC VISIBILITY UPGRADE (still minimal)
    if table_name == "DeviceNetworkEvents":
        allowed = GUARDRAILS.ALLOWED_TABLES.get("DeviceNetworkEvents") or set()
        if "RemoteIP" in allowed and "RemoteIP" not in cleaned_fields:
            cleaned_fields.append("RemoteIP")
        if "LocalIP" in allowed and "LocalIP" not in cleaned_fields:
            cleaned_fields.append("LocalIP")

    return {
        "goal": (step.get("goal") or "").strip(),
        "table_name": table_name,
        "time_range_hours": time_range_hours,
        "device_name": device_name,
        "user_principal_name": user_principal_name,
        "caller": caller,
        "fields": cleaned_fields,
    }


def _summarize_csv(csv_text: str, max_lines: int = 18) -> str:
    if not csv_text:
        return ""
    lines = csv_text.splitlines()
    if not lines:
        return ""
    head = lines[: max_lines + 1]
    out = "\n".join(head)
    if len(lines) > len(head):
        out += f"\n... ({len(lines) - len(head)} more lines omitted)"
    return out


def _format_pivot_block(idx: int, step: dict, count: int, preview: str) -> str:
    return (
        f"\n[Planner Pivot #{idx}] {step.get('goal')}\n"
        f"- table: {step.get('table_name')}\n"
        f"- time_range_hours: {step.get('time_range_hours')}\n"
        f"- device={step.get('device_name')}, caller={step.get('caller')}\n"
        f"- record_count: {count}\n"
        f"- preview:\n{preview}\n"
    )


def build_plan(
    openai_client,
    *,
    model: str,
    user_prompt: str,
    initial_query_context: dict,
    baseline_note: str = ""
) -> List[dict]:
    system = {
        "role": "system",
        "content": (
            "You are a SOC investigation planner. "
            "You do NOT write KQL and you do NOT use pipe operators. "
            "You must output JSON only.\n\n"
            "Goal: propose 1 to 3 pivot queries that help confirm or refute suspicious activity.\n"
            "Constraints:\n"
            "- Only select from allowed tables: "
            + ", ".join(list(GUARDRAILS.ALLOWED_TABLES.keys()))
            + "\n"
            "- Provide fields as a comma-separated list (no KQL, no pipes).\n"
            "- Keep pivots anchored to the same device/user/caller scope.\n"
            "- time_range_hours must be between 1 and 168.\n\n"
            "Return JSON in this exact format:\n"
            "{\n"
            '  "steps": [\n'
            "    {\n"
            '      "goal": "short objective",\n'
            '      "table_name": "OneAllowedTable",\n'
            '      "time_range_hours": 24,\n'
            '      "device_name": "",\n'
            '      "user_principal_name": "",\n'
            '      "caller": "",\n'
            '      "fields": "Field1, Field2, Field3"\n'
            "    }\n"
            "  ]\n"
            "}\n"
        ),
    }

    initial_context_str = json.dumps(
        {
            "table_name": initial_query_context.get("table_name"),
            "time_range_hours": initial_query_context.get("time_range_hours"),
            "device_name": initial_query_context.get("device_name"),
            "user_principal_name": initial_query_context.get("user_principal_name"),
            "caller": initial_query_context.get("caller"),
            "fields": initial_query_context.get("fields"),
        },
        indent=2,
    )

    user = {
        "role": "user",
        "content": (
            f"Analyst request:\n{user_prompt}\n\n"
            f"Initial query context:\n{initial_context_str}\n\n"
            + (f"Baseline anomaly note (if any):\n{baseline_note}\n\n" if baseline_note else "")
            + "Propose pivot steps now."
        ),
    }

    messages = _ensure_json_mention([system, user])

    resp = openai_client.chat.completions.create(
        model=model,
        messages=messages,
        response_format={"type": "json_object"},
    )

    raw = resp.choices[0].message.content
    data = json.loads(raw)
    steps = (data.get("steps") or [])[:3]

    cleaned = []
    for s in steps:
        try:
            cleaned.append(_sanitize_planned_step(s, initial_query_context))
        except Exception as e:
            UTILITIES.log_event("planner_step_rejected", {"error": str(e), "step": s})

    return cleaned


def _dedupe_planner_steps(steps: List[dict]) -> List[dict]:
    seen = set()
    out: List[dict] = []
    for s in steps or []:
        sig = (
            str(s.get("table_name") or ""),
            int(s.get("time_range_hours") or 0),
            str(s.get("device_name") or ""),
            str(s.get("user_principal_name") or ""),
            str(s.get("caller") or ""),
            ",".join(list(s.get("fields") or [])) if isinstance(s.get("fields"), list) else str(s.get("fields") or ""),
        )
        if sig in seen:
            continue
        seen.add(sig)
        out.append(s)
    return out


def run_planner_pivots(
    *,
    openai_client,
    planner_model: str,
    user_prompt: str,
    initial_query_context: dict,
    baseline_note: str,
    query_runner_fn,
    log_workspace_id: str,
    log_client,
) -> Dict[str, Any]:
    UTILITIES.log_event("planner_start", {"ts": _utc_iso()})

    steps = build_plan(
        openai_client,
        model=planner_model,
        user_prompt=user_prompt,
        initial_query_context=initial_query_context,
        baseline_note=baseline_note,
    )

    steps = _dedupe_planner_steps(steps)
    UTILITIES.log_event("planner_plan", {"steps": steps})

    pivot_blocks = ""
    pivot_counts = []

    for idx, step_qc in enumerate(steps, start=1):
        try:
            res = query_runner_fn(
                log_analytics_client=log_client,
                workspace_id=log_workspace_id,
                timerange_hours=step_qc["time_range_hours"],
                table_name=step_qc["table_name"],
                device_name=step_qc["device_name"],
                fields=step_qc["fields"],
                caller=step_qc["caller"],
                user_principal_name=step_qc["user_principal_name"],
            )

            count = int(res.get("count") or 0)
            pivot_counts.append(count)

            preview = _summarize_csv(res.get("records", ""), max_lines=18)
            pivot_blocks += _format_pivot_block(idx, step_qc, count, preview)

            UTILITIES.log_event("planner_pivot_result", {"idx": idx, "step": step_qc, "count": count})

        except Exception as e:
            UTILITIES.log_event("planner_pivot_error", {"idx": idx, "error": str(e), "step": step_qc})
            pivot_blocks += f"\n[Planner Pivot #{idx}] ERROR running pivot: {e}\n"

    UTILITIES.log_event("planner_done", {"pivot_counts": pivot_counts})
    return {"steps": steps, "pivot_blocks": pivot_blocks.strip(), "pivot_counts": pivot_counts}


# -------------------------------------------------------------------
# UI/API helper (non-destructive)
# -------------------------------------------------------------------

def cluster_campaigns(
    device_logons: Optional[List[Dict[str, Any]]] = None,
    device_net: Optional[List[Dict[str, Any]]] = None,
    max_clusters: int = 6,
) -> List[Dict[str, Any]]:
    """
    Lightweight "campaign clustering" for the UI layer.

    This is NOT the LLM pivot planner. It doesn't call OpenAI.
    It simply groups events into small clusters using a basic heuristic:
      - device name (DeviceName/Computer/HostName)
      - remote IP (RemoteIP/RemoteUrl/IpAddress)
      - account/user (Account/User/UPN)

    Returns a UI-friendly list:
    [
      {
        "id": "CMP-1",
        "key": "device:mm-final-lab",
        "risk": 0-100,
        "cases": int,
        "entities": int,
        "top_entities": [...],
      },
      ...
    ]
    """
    device_logons = device_logons or []
    device_net = device_net or []

    def pick(row: Dict[str, Any], *keys: str) -> Any:
        for k in keys:
            if k in row and row.get(k) not in (None, ""):
                return row.get(k)
        return None

    buckets = defaultdict(list)

    # Bucket logons
    for r in device_logons:
        dev = pick(r, "DeviceName", "Computer", "HostName", "Device") or "unknown-device"
        user = pick(r, "Account", "User", "UserPrincipalName", "TargetUserName") or ""
        key = f"device:{dev}"
        if user:
            key = f"{key}|user:{user}"
        buckets[key].append(r)

    # Bucket network events
    for r in device_net:
        dev = pick(r, "DeviceName", "Computer", "HostName", "Device") or "unknown-device"
        rip = pick(r, "RemoteIP", "RemoteUrl", "RemoteIPCountry", "IpAddress") or ""
        key = f"device:{dev}"
        if rip:
            key = f"{key}|remote:{rip}"
        buckets[key].append(r)

    clusters = []
    for idx, (k, rows) in enumerate(sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True)[:max_clusters], start=1):
        # crude "risk": scaled by volume
        volume = len(rows)
        risk = min(100, max(5, int(volume ** 0.6 * 10)))

        # entity extraction
        entities = set()
        for rr in rows:
            dev = pick(rr, "DeviceName", "Computer", "HostName", "Device")
            user = pick(rr, "Account", "User", "UserPrincipalName", "TargetUserName")
            rip = pick(rr, "RemoteIP", "RemoteUrl", "IpAddress")
            if dev:
                entities.add(f"device:{dev}")
            if user:
                entities.add(f"user:{user}")
            if rip:
                entities.add(f"remote:{rip}")

        ent_counts = Counter()
        for e in entities:
            ent_counts[e] += 1

        clusters.append(
            {
                "id": f"CMP-{idx}",
                "key": k,
                "risk": risk,
                "cases": 1,  # UI placeholder (can map to cases later)
                "entities": len(entities),
                "top_entities": [e for e, _ in ent_counts.most_common(6)],
            }
        )

    return clusters
