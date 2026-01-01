# main.py
# -------------------------------------------------------------------
# Agentic SOC Analyst (Beginner-friendly main loop)
#
# Flow:
# 1) Ask user what to hunt
# 2) Tool selection chooses table + fields + time window
# 3) Run KQL query in Log Analytics
# 4) Update baseline + print anomalies
# 5) Planner pivots (extra evidence)
# 6) Kill Chain Step 1 + Step 2 (escalation)
# 7) Cognitive threat hunt (LLM) w/ token-safe payload
# 8) If HIGH finding: prompt user to isolate (NEVER automatic)
#    ✅ Works even if initial query was global (no device filter)
#    ✅ Ensures DeviceName is included for global Device* hunts so we can attribute a device
# 9) If isolated in this session: allow release via command
#
# NEW IN THIS VERSION
# ✅ Adds an "Executive Summary" block after every hunt (portfolio / screenshot-ready)
#   - Targets, time window, tables queried
#   - Top anomalies (baseline + pivots)
#   - Killchain + escalation
#   - Top findings + confidence
#   - Isolation status (NOW prints AFTER isolation decision)
# -------------------------------------------------------------------

# Standard library
import os
import time
import csv
import io
import re
from collections import Counter
from typing import Dict, Any, List, Optional

# Third-party libraries
from colorama import Fore, init, Style
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from dotenv import load_dotenv

# Local modules
import UTILITIES
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS
import BASELINES
import PLANNER
import KILLCHAIN
import KILLCHAIN_ESCALATION

# Local config (non-secret)
from _config import LOG_ANALYTICS_WORKSPACE_ID


# ----------------------------
# Setup
# ----------------------------
init(autoreset=True)
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError(
        "OPENAI_API_KEY is missing. Add it to your .env file like:\n"
        "OPENAI_API_KEY=sk-xxxxx (no quotes, no spaces)"
    )

law_client = LogsQueryClient(credential=DefaultAzureCredential())
openai_client = OpenAI(api_key=OPENAI_API_KEY)


# ----------------------------
# Kill-chain helpers
# ----------------------------
def _run_killchain_assessment(*, query_context: dict, baseline_note: str, pivot_blocks: str) -> Dict[str, Any]:
    return KILLCHAIN.run_killchain(
        query_context=query_context,
        baseline_note=baseline_note,
        pivot_blocks=pivot_blocks,
    )


def _print_killchain_report(report: Dict[str, Any]) -> None:
    if not report:
        return

    stages = report.get("observed_stages") or []
    score = report.get("score")
    signals = report.get("signals") or []
    suggested = report.get("next_pivots") or []

    print(Fore.CYAN + "\n🧭 Kill-Chain Assessment (heuristic)" + Style.RESET_ALL)
    if stages:
        print(Fore.WHITE + f"- Observed stages: {', '.join(stages)}" + Style.RESET_ALL)
    if score is not None:
        print(Fore.WHITE + f"- Compromise progression score: {score}/100" + Style.RESET_ALL)

    if signals:
        print(Fore.WHITE + "\nStage signals:" + Style.RESET_ALL)
        for s in signals[:12]:
            print(Fore.WHITE + f"  - {s}" + Style.RESET_ALL)

    if suggested:
        print(Fore.WHITE + "\nSuggested next pivots (not executed):" + Style.RESET_ALL)
        for i, p in enumerate(suggested[:5], 1):
            print(Fore.WHITE + f"  {i}. {p}" + Style.RESET_ALL)

    print("")


def _print_escalation(escalation: Dict[str, Any]) -> None:
    if not escalation:
        return

    action = escalation.get("action") or "monitor"
    score = escalation.get("score")

    label = {
        "monitor": "🟢 Escalation Level: Monitor",
        "elevated_hunt": "🟡 Escalation Level: Elevated Hunt",
        "prepare_containment": "🟠 Escalation Level: Prepare Containment",
        "containment_recommended": "🔴 Escalation Level: Containment Recommended",
        "auto_isolate": "🚨 Escalation Level: Isolation Suggested",
    }.get(action, f"🟢 Escalation Level: {action}")

    if score is not None:
        print(Fore.LIGHTCYAN_EX + f"{label} (score={score})" + Style.RESET_ALL)
    else:
        print(Fore.LIGHTCYAN_EX + f"{label}" + Style.RESET_ALL)
    print("")


# ----------------------------
# CSV device inference (for global hunts)
# ----------------------------
def _top_devices_from_csv(records_csv: str, *, top_n: int = 5) -> List[str]:
    """
    If DeviceName exists in returned CSV, infer the most frequent devices.
    """
    if not records_csv:
        return []

    try:
        f = io.StringIO(records_csv)
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []
        if "DeviceName" not in reader.fieldnames:
            return []

        counts = Counter()
        for row in reader:
            dn = (row.get("DeviceName") or "").strip()
            if dn:
                counts[dn] += 1

        return [d for d, _ in counts.most_common(top_n)]
    except Exception:
        return []


# ----------------------------
# Ask-first isolation
# ----------------------------
def _ask_to_isolate(*, device_name: str, reason: str) -> bool:
    device_name = (device_name or "").strip()

    print(Fore.YELLOW + "\n⚠️ Isolation option" + Style.RESET_ALL)
    print(Fore.WHITE + f"- Device: {Fore.CYAN}{device_name or '[unknown]'}{Style.RESET_ALL}")
    print(Fore.WHITE + f"- Why: {reason}{Style.RESET_ALL}\n")

    print(Fore.WHITE + "Nothing will be isolated unless you approve." + Style.RESET_ALL)

    confirm = input(
        f"{Fore.LIGHTGREEN_EX}Would you like to isolate this VM now? (yes/no): {Style.RESET_ALL}"
    ).strip().lower()
    return confirm.startswith("y")


def _choose_device_from_list(devices: List[str]) -> Optional[str]:
    if not devices:
        return None
    if len(devices) == 1:
        return devices[0]

    print(Fore.YELLOW + "\nMultiple devices appear in the results." + Style.RESET_ALL)
    for i, d in enumerate(devices, 1):
        print(Fore.WHITE + f"  {i}. {d}" + Style.RESET_ALL)

    choice = input(
        f"{Fore.LIGHTGREEN_EX}Enter the number of the device you want to isolate (or press Enter to skip): {Style.RESET_ALL}"
    ).strip()

    if not choice:
        return None

    try:
        idx = int(choice)
        if 1 <= idx <= len(devices):
            return devices[idx - 1]
    except Exception:
        pass

    print(Fore.CYAN + "[i] Invalid selection. Skipping isolation." + Style.RESET_ALL)
    return None


# ----------------------------
# Token/model safety helpers
# ----------------------------
def _get_model_max_input(model_name: str) -> int:
    meta = GUARDRAILS.ALLOWED_MODELS.get(model_name) or {}
    return int(meta.get("max_input_tokens") or 0)


def _shrink_log_payload(log_payload: str, *, max_lines: int, max_chars: int) -> str:
    if not log_payload:
        return ""

    lines = log_payload.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"...TRUNCATED LINES... (kept {max_lines})"]

    out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[:max_chars] + "\n...TRUNCATED CHARS..."
    return out


def _select_model_safely(*, messages: List[dict], record_count: int, model_default: str) -> str:
    est = MODEL_MANAGEMENT.count_tokens(messages, model_default)

    candidate = MODEL_MANAGEMENT.auto_select_model(
        input_tokens=est,
        tier=getattr(MODEL_MANAGEMENT, "CURRENT_TIER", "4"),
        prefer_quality=(record_count >= 5000),
    )
    candidate = MODEL_MANAGEMENT.ensure_model_ok(candidate)

    max_in = _get_model_max_input(candidate)
    if max_in and est > max_in:
        fallback = "gpt-4.1"
        fallback = MODEL_MANAGEMENT.ensure_model_ok(fallback)
        return fallback

    return candidate


# ----------------------------
# Executive Summary (analyst-grade output)
# ----------------------------
def _extract_top_baseline_anomalies(baseline_note: str, *, max_items: int = 3) -> List[str]:
    """
    baseline_note is your BASELINES.anomaly_summary text.
    We pull the first N bullet-like anomaly lines if present.
    """
    if not baseline_note:
        return []

    lines = [ln.strip() for ln in baseline_note.splitlines() if ln.strip()]
    hits = [ln for ln in lines if ln.startswith("- ")]
    if not hits:
        hits = [ln for ln in lines if (" | run=" in ln) or ("Rare / unusual" in ln)]

    out = []
    for h in hits:
        out.append(h[2:] if h.startswith("- ") else h)
        if len(out) >= max_items:
            break
    return out


def _summarize_pivots(steps: List[dict]) -> str:
    if not steps:
        return ""
    parts = []
    for s in steps[:3]:
        t = (s.get("table_name") or "").strip()
        g = (s.get("goal") or "").strip()
        if t and g:
            parts.append(f"{t} — {g}")
        elif t:
            parts.append(t)
    return "; ".join(parts)


def _print_executive_summary(
    *,
    query_context: dict,
    record_count_initial: int,
    baseline_note: str,
    planner_steps: List[dict],
    killchain_report: Dict[str, Any],
    escalation: Dict[str, Any],
    findings: List[dict],
    isolation_performed: bool,
    isolated_device_name: Optional[str],
) -> None:
    target = (query_context.get("device_name") or "").strip() or "[global]"
    hours = int(query_context.get("time_range_hours") or 0)
    primary_table = (query_context.get("table_name") or "").strip()

    tables = [primary_table] if primary_table else []
    for s in planner_steps or []:
        t = (s.get("table_name") or "").strip()
        if t and t not in tables:
            tables.append(t)

    top_anoms = _extract_top_baseline_anomalies(baseline_note, max_items=3)

    def _conf_rank(c: str) -> int:
        c = (c or "").strip().lower()
        return {"high": 0, "medium": 1, "low": 2}.get(c, 3)

    top_findings = sorted(findings or [], key=lambda x: _conf_rank(x.get("confidence")))[:3]

    observed = ", ".join(killchain_report.get("observed_stages") or []) if killchain_report else ""
    kscore = killchain_report.get("score") if killchain_report else None

    esc_action = escalation.get("action") if escalation else None
    esc_score = escalation.get("score") if escalation else None

    iso_line = "Not performed"
    if isolation_performed and isolated_device_name:
        iso_line = f"Performed (device={isolated_device_name})"

    print(Fore.LIGHTWHITE_EX + "\n" + "─" * 52 + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + "EXECUTIVE SUMMARY" + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + "─" * 52 + Style.RESET_ALL)

    print(Fore.WHITE + f"Target(s):            {Fore.CYAN}{target}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Time Window:          Last {hours} hours" + Style.RESET_ALL)
    print(Fore.WHITE + f"Tables Queried:       {', '.join(tables) if tables else '[unknown]'}" + Style.RESET_ALL)
    print(Fore.WHITE + f"Records (initial):    {record_count_initial}" + Style.RESET_ALL)

    if planner_steps:
        piv = _summarize_pivots(planner_steps)
        if piv:
            print(Fore.WHITE + f"Pivot Summary:        {piv}" + Style.RESET_ALL)

    if top_anoms:
        print(Fore.WHITE + "\nTop Anomalies:" + Style.RESET_ALL)
        for i, a in enumerate(top_anoms, 1):
            print(Fore.WHITE + f"  {i}) {a}" + Style.RESET_ALL)

    if top_findings:
        print(Fore.WHITE + "\nTop Findings:" + Style.RESET_ALL)
        for i, f in enumerate(top_findings, 1):
            title = (f.get("title") or "Finding").strip()
            conf = (f.get("confidence") or "Unknown").strip()
            print(Fore.WHITE + f"  {i}) {title}  [{conf.upper()}]" + Style.RESET_ALL)

    if observed or (kscore is not None):
        print(Fore.WHITE + "\nKill Chain:" + Style.RESET_ALL)
        if observed:
            print(Fore.WHITE + f"  Observed Stages:    {observed}" + Style.RESET_ALL)
        if kscore is not None:
            print(Fore.WHITE + f"  Progression Score:  {kscore}/100" + Style.RESET_ALL)

    if esc_action or (esc_score is not None):
        print(Fore.WHITE + "\nEscalation:" + Style.RESET_ALL)
        if esc_action:
            print(Fore.WHITE + f"  Action:             {esc_action}" + Style.RESET_ALL)
        if esc_score is not None:
            print(Fore.WHITE + f"  Score:              {esc_score}" + Style.RESET_ALL)

    print(Fore.WHITE + "\nIsolation Status:     " + Fore.YELLOW + iso_line + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + "─" * 52 + Style.RESET_ALL + "\n")


# ----------------------------
# One full run iteration
# ----------------------------
def _run_single_iteration(*, model_default: str, machine_state: dict) -> str:
    user_message = PROMPT_MANAGEMENT.get_user_message()
    user_prompt = (user_message.get("content") or "").strip()

    if not user_prompt:
        print(Fore.YELLOW + "No input provided. Type a request or 'quit' to exit." + Style.RESET_ALL)
        return "continue"

    if user_prompt.lower() in {"q", "quit", "exit"}:
        return "quit"

    if user_prompt.lower() in {"help", "h", "?"}:
        UTILITIES.print_help()
        return "continue"

    if user_prompt.lower() in {"clear", "cls"}:
        os.system("cls" if os.name == "nt" else "clear")
        UTILITIES.print_banner()
        return "continue"

    suspicious = GUARDRAILS.detect_prompt_injection(user_prompt)
    if suspicious:
        print(Fore.LIGHTRED_EX + Style.BRIGHT + "🚫 Suspicious request blocked.\n" + Style.RESET_ALL)
        print(Fore.WHITE + "Reason(s): " + Fore.LIGHTRED_EX + ", ".join(suspicious) + Style.RESET_ALL)
        print(
            Fore.WHITE
            + "\nRephrase as analyst intent (no raw KQL). Example:\n"
            + "  'Hunt suspicious logons on windows-target-1 in last 24h'\n"
            + Style.RESET_ALL
        )
        UTILITIES.log_event("blocked_prompt", {"prompt": user_prompt, "reasons": suspicious})
        return "continue"

    UTILITIES.log_event("user_prompt", {"prompt": user_prompt})

    # Tool selection
    try:
        query_context = EXECUTOR.get_query_context(openai_client, user_message, model=model_default)
    except Exception as e:
        UTILITIES.log_event("tool_selection_error", {"error": str(e)})
        print(Fore.LIGHTRED_EX + f"Tool-selection error: {e}" + Style.RESET_ALL)
        return "continue"

    query_context = UTILITIES.sanitize_query_context(query_context)
    UTILITIES.display_query_context(query_context)

    # Validate fields (non-strict) + keep as list
    cleaned_fields = GUARDRAILS.validate_tables_and_fields(
        query_context["table_name"],
        query_context.get("fields", []),
        strict=False,
    )
    query_context["fields"] = cleaned_fields

    # If global Device* hunt, ensure DeviceName is included
    device_filter = (query_context.get("device_name") or "").strip()
    if not device_filter and str(query_context.get("table_name", "")).startswith("Device"):
        if "DeviceName" not in query_context["fields"]:
            query_context["fields"] = GUARDRAILS.validate_tables_and_fields(
                query_context["table_name"],
                query_context["fields"] + ["DeviceName"],
                strict=False,
            )

    # Query LA
    try:
        law_query_results = EXECUTOR.query_log_analytics(
            log_analytics_client=law_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            timerange_hours=query_context["time_range_hours"],
            table_name=query_context["table_name"],
            device_name=query_context.get("device_name", ""),
            fields=query_context.get("fields", []),
            caller=query_context.get("caller", ""),
            user_principal_name=query_context.get("user_principal_name", ""),
        )
    except Exception as e:
        UTILITIES.log_event("law_query_error", {"error": str(e), "query_context": query_context})
        print(Fore.LIGHTRED_EX + f"Log Analytics query error: {e}" + Style.RESET_ALL)
        return "continue"

    records_csv = law_query_results.get("records", "") or ""
    number_of_records = int(law_query_results.get("count") or 0)

    print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

    UTILITIES.log_event(
        "law_query_result",
        {"query_context": query_context, "record_count": number_of_records, "records_logged": UTILITIES.LOG_RAW_RECORDS},
    )

    if number_of_records == 0:
        print(Fore.YELLOW + "No records returned. Try a wider time range or different target." + Style.RESET_ALL)
        return "continue"

    # Baseline
    baseline_note = ""
    pivot_blocks = ""

    try:
        meta = BASELINES.update_baseline_from_csv(
            table_name=query_context["table_name"],
            query_context=query_context,
            records_csv=records_csv,
            record_count=number_of_records,
        )

        baseline_note = BASELINES.anomaly_summary(
            table_name=query_context["table_name"],
            query_context=query_context,
            records_csv=records_csv,
            record_count=number_of_records,
            min_run_count=1,
            rarity_threshold=0.02,
        )

        if baseline_note:
            print(Fore.LIGHTYELLOW_EX + "\n⚡ Baseline Anomaly Summary:" + Style.RESET_ALL)
            print(Fore.WHITE + baseline_note + Style.RESET_ALL + "\n")

        UTILITIES.log_event(
            "baseline_update",
            {"scope": meta.get("scope_key"), "table": query_context["table_name"], "updated": meta.get("updated")},
        )
    except Exception as e:
        UTILITIES.log_event("baseline_error", {"error": str(e)})

    # Planner pivots
    planner_steps: List[dict] = []
    try:
        plan_out = PLANNER.run_planner_pivots(
            openai_client=openai_client,
            planner_model="gpt-4.1-nano",
            user_prompt=user_prompt,
            initial_query_context={**query_context, "fields": ", ".join(query_context.get("fields", []))},
            baseline_note=baseline_note,
            query_runner_fn=EXECUTOR.query_log_analytics,
            log_workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            log_client=law_client,
        )

        planner_steps = plan_out.get("steps") or []
        pivot_blocks = plan_out.get("pivot_blocks") or ""
        if pivot_blocks:
            print(Fore.LIGHTMAGENTA_EX + "\n🧠 Planner Pivot Evidence:" + Style.RESET_ALL)
            print(Fore.WHITE + pivot_blocks + Style.RESET_ALL + "\n")
    except Exception as e:
        UTILITIES.log_event("planner_fatal", {"error": str(e)})
        pivot_blocks = ""
        planner_steps = []

    # Killchain
    killchain_report: Dict[str, Any] = {}
    try:
        killchain_report = _run_killchain_assessment(
            query_context=query_context,
            baseline_note=baseline_note,
            pivot_blocks=pivot_blocks,
        )
        _print_killchain_report(killchain_report)
        if killchain_report:
            UTILITIES.log_event("killchain_report", killchain_report)
    except Exception as e:
        UTILITIES.log_event("killchain_error", {"error": str(e)})
        killchain_report = {}

    escalation: Dict[str, Any] = {}
    try:
        if killchain_report:
            escalation = KILLCHAIN_ESCALATION.compute_escalation(killchain_report)
            _print_escalation(escalation)
    except Exception as e:
        UTILITIES.log_event("killchain_escalation_error", {"error": str(e)})
        escalation = {}

    # Threat hunt prompt
    final_user_prompt = user_prompt
    if baseline_note:
        final_user_prompt += "\n\n" + baseline_note
    if pivot_blocks:
        final_user_prompt += "\n\n" + pivot_blocks
    if escalation:
        final_user_prompt += "\n\n" + f"[KillChain Escalation] score={escalation.get('score')} action={escalation.get('action')}"

    print(Fore.LIGHTGREEN_EX + "Building threat hunt prompt/instructions...\n" + Style.RESET_ALL)

    # First-pass token-safe payload
    safe_log_payload = EXECUTOR.prepare_log_data_for_llm(records_csv, number_of_records)

    threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
        user_prompt=final_user_prompt,
        table_name=query_context["table_name"],
        log_data=safe_log_payload,
    )

    threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT
    threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

    # Model selection with hard max-input safety
    model = _select_model_safely(
        messages=threat_hunt_messages,
        record_count=number_of_records,
        model_default=model_default,
    )

    # If still too big, shrink further
    for attempt in range(4):
        est_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model_default)
        max_in = _get_model_max_input(model)

        if max_in and est_tokens > max_in:
            shrink_profiles = [
                (800, 120_000),
                (400, 80_000),
                (200, 50_000),
                (120, 30_000),
            ]
            max_lines, max_chars = shrink_profiles[min(attempt, len(shrink_profiles) - 1)]
            shrunk = _shrink_log_payload(safe_log_payload, max_lines=max_lines, max_chars=max_chars)

            threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
                user_prompt=final_user_prompt,
                table_name=query_context["table_name"],
                log_data=shrunk,
            )
            threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

            model = _select_model_safely(
                messages=threat_hunt_messages,
                record_count=number_of_records,
                model_default=model_default,
            )
            continue

        break

    model = MODEL_MANAGEMENT.ensure_model_ok(model)

    UTILITIES.log_event(
        "model_selection",
        {
            "input_tokens_estimate": MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model_default),
            "record_count": number_of_records,
            "selected_model": model,
        },
    )

    print(
        f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against target logs...\n"
        f"{Fore.WHITE}Model: {Fore.CYAN}{model}{Fore.WHITE}\n"
    )

    start_time = time.time()

    hunt_results = EXECUTOR.hunt(
        openai_client=openai_client,
        threat_hunt_system_message=threat_hunt_system_message,
        threat_hunt_user_message=threat_hunt_user_message,
        openai_model=model,
    )

    if not hunt_results:
        UTILITIES.log_event("hunt_failed", {"query_context": query_context})
        return "continue"

    elapsed = time.time() - start_time
    findings = hunt_results.get("findings") or []

    print(
        f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found "
        f"{Fore.LIGHTRED_EX}{len(findings)} {Fore.WHITE}potential threat(s)!\n"
    )

    UTILITIES.log_event(
        "hunt_results",
        {"elapsed_seconds": round(elapsed, 2), "query_context": query_context, "finding_count": len(findings)},
    )

    input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} to see results.")
    UTILITIES.display_threats(threat_list=findings)

    # ----------------------------
    # Ask-first isolation
    # ----------------------------
    high_findings = [t for t in findings if (t.get("confidence") or "").strip().lower() == "high"]
    if high_findings and (not machine_state.get("machine_is_isolated")):
        top = high_findings[0]
        title = top.get("title") or "High confidence threat"
        reason = f"{title} (confidence=high)"

        device_name = (query_context.get("device_name") or "").strip()

        if not device_name:
            candidates = _top_devices_from_csv(records_csv, top_n=5)
            device_name = _choose_device_from_list(candidates) or ""

        if device_name:
            if _ask_to_isolate(device_name=device_name, reason=reason):
                try:
                    result = EXECUTOR.isolate_vm_by_name(
                        device_name,
                        comment="Isolation via Agentic SOC Analyst (user-approved)",
                    )

                    UTILITIES.log_event(
                        "remediation_isolate_attempt",
                        {"device_name": device_name, "result": result},
                    )

                    machine_state["machine_is_isolated"] = True
                    machine_state["isolated_device_name"] = device_name
                    print(Fore.GREEN + "[+] VM isolation submitted successfully." + Style.RESET_ALL)

                except Exception as e:
                    UTILITIES.log_event("remediation_isolate_error", {"error": str(e)})
                    print(Fore.LIGHTRED_EX + f"[-] Isolation workflow error: {e}" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + "[i] Isolation skipped by analyst." + Style.RESET_ALL)
        else:
            print(
                Fore.CYAN
                + "[i] High finding detected, but no device could be attributed from the results. Skipping isolation prompt."
                + Style.RESET_ALL
            )

    # ✅ Executive Summary NOW prints AFTER isolation decision
    _print_executive_summary(
        query_context=query_context,
        record_count_initial=number_of_records,
        baseline_note=baseline_note,
        planner_steps=planner_steps,
        killchain_report=killchain_report,
        escalation=escalation,
        findings=findings,
        isolation_performed=bool(machine_state.get("machine_is_isolated")),
        isolated_device_name=machine_state.get("isolated_device_name"),
    )

    return "continue"


# ----------------------------
# Entrypoint
# ----------------------------
def main():
    UTILITIES.print_banner()
    print(Fore.WHITE + "Type 'help' for commands. Type 'quit' any time to exit.\n" + Style.RESET_ALL)

    machine_state = {
        "machine_is_isolated": False,
        "isolated_device_name": None,
    }
    model_default = MODEL_MANAGEMENT.DEFAULT_MODEL

    while True:
        try:
            action = _run_single_iteration(model_default=model_default, machine_state=machine_state)
            if action == "quit":
                break

            nxt = input(
                f"{Fore.LIGHTBLUE_EX}\nWhat next? {Fore.WHITE}(Enter=another hunt / 'release'=release isolated VM / 'quit'):{Fore.RESET} "
            ).strip().lower()

            if nxt in {"q", "quit", "exit"}:
                break

            if nxt == "release":
                if machine_state.get("machine_is_isolated") and machine_state.get("isolated_device_name"):
                    try:
                        device_name = machine_state["isolated_device_name"]
                        result = EXECUTOR.release_vm_by_name(
                            device_name,
                            comment="Unisolation via Agentic SOC Analyst (manual release command)",
                        )

                        UTILITIES.log_event("remediation_unisolate_attempt", {"device_name": device_name, "result": result})

                        machine_state["machine_is_isolated"] = False
                        machine_state["isolated_device_name"] = None
                        print(Fore.GREEN + "[+] VM release submitted successfully." + Style.RESET_ALL)

                    except Exception as e:
                        UTILITIES.log_event("remediation_unisolate_error", {"error": str(e)})
                        print(Fore.LIGHTRED_EX + f"[-] Release failed: {e}" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "No VM is currently isolated in this session." + Style.RESET_ALL)

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nInterrupted. Exiting." + Style.RESET_ALL)
            break
        except Exception as e:
            UTILITIES.log_event("fatal_error", {"error": str(e)})
            print(Fore.LIGHTRED_EX + f"\nUnexpected error: {e}\n" + Style.RESET_ALL)

    print(Fore.CYAN + "\nGoodbye.\n" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
