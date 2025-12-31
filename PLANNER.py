# Standard library
import json
from datetime import datetime, timezone
from typing import Dict, List, Any

# Local modules
import UTILITIES
import GUARDRAILS


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clamp_int(v, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
    except Exception:
        return default
    return max(lo, min(hi, n))


def _normalize_fields(fields) -> str:
    """
    Return fields as a project-able comma string.
    """
    if isinstance(fields, list):
        fields = [str(x).strip() for x in fields if str(x).strip()]
        return ", ".join(fields[:20])  # hard cap
    parts = [p.strip() for p in str(fields).split(",") if p.strip()]
    return ", ".join(parts[:20])


def _same_scope_guard(initial_qc: dict, qc: dict) -> bool:
    init_device = (initial_qc.get("device_name") or "").strip().lower()
    init_upn = (initial_qc.get("user_principal_name") or "").strip().lower()
    init_caller = (initial_qc.get("caller") or "").strip().lower()

    device = (qc.get("device_name") or "").strip().lower()
    upn = (qc.get("user_principal_name") or "").strip().lower()
    caller = (qc.get("caller") or "").strip().lower()

    anchors_present = any([init_device, init_upn, init_caller])
    if not anchors_present:
        return True

    if init_device and device and device.startswith(init_device):
        return True
    if init_upn and upn and upn.startswith(init_upn):
        return True
    if init_caller and caller and caller.startswith(init_caller):
        return True

    return False


def _sanitize_planned_step(step: dict, initial_qc: dict) -> dict:
    qc = dict(step or {})

    qc.setdefault("table_name", initial_qc.get("table_name", ""))
    qc.setdefault("time_range_hours", initial_qc.get("time_range_hours", 24))
    qc.setdefault("device_name", initial_qc.get("device_name", ""))
    qc.setdefault("caller", initial_qc.get("caller", ""))
    qc.setdefault("user_principal_name", initial_qc.get("user_principal_name", ""))
    qc.setdefault("fields", initial_qc.get("fields", ""))

    qc["time_range_hours"] = _clamp_int(
        qc.get("time_range_hours"),
        1,
        168,
        int(initial_qc.get("time_range_hours") or 24),
    )

    qc["fields"] = _normalize_fields(qc.get("fields"))

    # ✅ Apply aliases BEFORE validation (ProcessName -> FileName, etc.)
    qc["fields"] = UTILITIES.normalize_fields_for_table(qc.get("table_name", ""), qc.get("fields", ""))

    # enforce allowlist tables/fields (now raises ValueError, does not kill program)
    GUARDRAILS.validate_tables_and_fields(qc.get("table_name", ""), qc.get("fields", ""))

    if not _same_scope_guard(initial_qc, qc):
        qc["device_name"] = initial_qc.get("device_name", "")
        qc["caller"] = initial_qc.get("caller", "")
        qc["user_principal_name"] = initial_qc.get("user_principal_name", "")

    qc["goal"] = (qc.get("goal") or "").strip()[:220]

    return qc


def _summarize_csv(records_csv: str, max_lines: int = 20) -> str:
    if not records_csv:
        return ""

    lines = records_csv.splitlines()
    if not lines:
        return ""

    head = lines[: max_lines]
    snippet = "\n".join(head)
    if len(lines) > max_lines:
        snippet += f"\n... ({len(lines)-max_lines} more lines omitted)"
    return snippet


def _format_pivot_block(step_idx: int, qc: dict, record_count: int, preview: str) -> str:
    goal = qc.get("goal") or f"Pivot step {step_idx}"
    table_name = qc.get("table_name")
    tr = qc.get("time_range_hours")
    device = qc.get("device_name")
    upn = qc.get("user_principal_name")
    caller = qc.get("caller")

    scope_parts = []
    if device:
        scope_parts.append(f"device={device}")
    if upn:
        scope_parts.append(f"user={upn}")
    if caller:
        scope_parts.append(f"caller={caller}")
    scope = ", ".join(scope_parts) if scope_parts else "scope=global"

    return (
        f"\n[Planner Pivot #{step_idx}] {goal}\n"
        f"- table: {table_name}\n"
        f"- time_range_hours: {tr}\n"
        f"- {scope}\n"
        f"- record_count: {record_count}\n"
        f"- preview:\n{preview}\n"
    )


def build_plan(openai_client, *, model: str, user_prompt: str, initial_query_context: dict, baseline_note: str = "") -> List[dict]:
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

    resp = openai_client.chat.completions.create(
        model=model,
        messages=[system, user],
        response_format={"type": "json_object"},
    )

    raw = resp.choices[0].message.content
    data = json.loads(raw)
    steps = data.get("steps") or []
    steps = steps[:3]

    cleaned = []
    for s in steps:
        # If one step is invalid, log + skip instead of killing the plan
        try:
            cleaned.append(_sanitize_planned_step(s, initial_query_context))
        except Exception as e:
            UTILITIES.log_event("planner_step_rejected", {"error": str(e), "step": s})

    return cleaned


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
                device_name=step_qc.get("device_name", ""),
                fields=step_qc.get("fields", ""),
                caller=step_qc.get("caller", ""),
                user_principal_name=step_qc.get("user_principal_name", ""),
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
