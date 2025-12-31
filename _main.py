# Standard library
import time
import os

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
import BASELINES  # ✅ NEW

# Local config (non-secret)
from _config import LOG_ANALYTICS_WORKSPACE_ID  # <- if you rename to config.py, change this import


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

# Build Log Analytics client (requires `az login`)
law_client = LogsQueryClient(credential=DefaultAzureCredential())

# Build OpenAI client
openai_client = OpenAI(api_key=OPENAI_API_KEY)


def _run_single_iteration(*, model_default: str, machine_state: dict) -> str:
    """
    One full iteration:
      user -> tool-selection -> query -> threat hunt -> display -> (optional remediation)
    Returns: "continue" | "quit"
    """

    # ----------------------------
    # Get user request
    # ----------------------------
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

    # Guardrail: block KQL injection / prompt injection patterns early
    suspicious = GUARDRAILS.detect_prompt_injection(user_prompt)
    if suspicious:
        print(
            Fore.LIGHTRED_EX
            + Style.BRIGHT
            + "🚫 Potential KQL/prompt-injection detected in your request.\n"
            + Style.RESET_ALL
        )
        print(Fore.WHITE + "Reason(s): " + Fore.LIGHTRED_EX + ", ".join(suspicious) + Style.RESET_ALL)
        print(
            Fore.WHITE
            + "\nPlease rephrase as an analyst intent (example: 'Hunt for suspicious PowerShell downloads on HOSTNAME in last 24h'). "
            + "Do not include raw KQL, pipe operators, or tool JSON.\n"
        )
        UTILITIES.log_event("blocked_prompt", {"prompt": user_prompt, "reasons": suspicious})
        return "continue"

    UTILITIES.log_event("user_prompt", {"prompt": user_prompt})

    # ----------------------------
    # Decide query context (tool selection)
    # ----------------------------
    try:
        unformatted_query_context = EXECUTOR.get_query_context(openai_client, user_message, model=model_default)
    except Exception as e:
        UTILITIES.log_event("tool_selection_error", {"error": str(e)})
        print(Fore.LIGHTRED_EX + f"Tool-selection error: {e}" + Style.RESET_ALL)
        return "continue"

    # Normalize + sanitize values returned by tool selection
    query_context = UTILITIES.sanitize_query_context(unformatted_query_context)

    # Show the user what we decided
    UTILITIES.display_query_context(query_context)

    # Guardrails: enforce table/field allowlist
    GUARDRAILS.validate_tables_and_fields(query_context.get("table_name", ""), query_context.get("fields", ""))

    # ----------------------------
    # Query Log Analytics
    # ----------------------------
    try:
        law_query_results = EXECUTOR.query_log_analytics(
            log_analytics_client=law_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            timerange_hours=query_context["time_range_hours"],
            table_name=query_context["table_name"],
            device_name=query_context["device_name"],
            fields=query_context["fields"],
            caller=query_context["caller"],
            user_principal_name=query_context["user_principal_name"],
        )
    except Exception as e:
        UTILITIES.log_event("law_query_error", {"error": str(e), "query_context": query_context})
        print(Fore.LIGHTRED_EX + f"Log Analytics query error: {e}" + Style.RESET_ALL)
        return "continue"

    number_of_records = int(law_query_results.get("count") or 0)
    print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

    UTILITIES.log_event(
        "law_query_result",
        {
            "query_context": query_context,
            "record_count": number_of_records,
            "records_logged": UTILITIES.LOG_RAW_RECORDS,
        },
    )

    if number_of_records == 0:
        print(Fore.YELLOW + "No records returned. Try a wider time range or different target." + Style.RESET_ALL)
        return "continue"

    # ----------------------------
    # Baseline memory update + anomaly summary ✅ NEW
    # ----------------------------
    baseline_note = ""
    try:
        meta = BASELINES.update_baseline_from_csv(
            table_name=query_context["table_name"],
            query_context=query_context,
            records_csv=law_query_results.get("records", ""),
            record_count=number_of_records
        )

        # Higher sensitivity during early learning
        baseline_note = BASELINES.anomaly_summary(
            table_name=query_context["table_name"],
            query_context=query_context,
            records_csv=law_query_results.get("records", ""),
            record_count=number_of_records,
            min_run_count=1,
            rarity_threshold=0.02
        )

        if baseline_note:
            print(Fore.LIGHTYELLOW_EX + "\n⚡ Baseline Anomaly Summary:" + Style.RESET_ALL)
            print(Fore.WHITE + baseline_note + Style.RESET_ALL + "\n")

        UTILITIES.log_event(
            "baseline_update",
            {
                "scope": meta.get("scope_key"),
                "table": query_context["table_name"],
                "updated": meta.get("updated"),
                "columns": meta.get("columns"),
            }
        )

    except Exception as e:
        UTILITIES.log_event("baseline_error", {"error": str(e)})

    # ----------------------------
    # Build threat hunt prompt + run model
    # ----------------------------
    # If we have baseline context, append it to the analyst prompt so the LLM prioritizes anomalies.
    final_user_prompt = user_prompt
    if baseline_note:
        final_user_prompt = user_prompt + "\n\n" + baseline_note

    threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
        user_prompt=final_user_prompt,
        table_name=query_context["table_name"],
        log_data=law_query_results["records"],
    )

    threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT
    threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

    # Estimate tokens (cheap)
    number_of_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model_default)

    # Auto-select model based on size + cost + tier (no user prompt)
    model = MODEL_MANAGEMENT.auto_select_model(
        input_tokens=number_of_tokens,
        tier=MODEL_MANAGEMENT.CURRENT_TIER,
        prefer_quality=(number_of_records >= 5000),
    )

    GUARDRAILS.validate_model(model)

    UTILITIES.log_event(
        "model_selection",
        {
            "input_tokens_estimate": number_of_tokens,
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
        {
            "elapsed_seconds": round(elapsed, 2),
            "query_context": query_context,
            "finding_count": len(findings),
            "findings": findings,
        },
    )

    input(
        f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} or {Fore.LIGHTGREEN_EX}[Return]{Fore.WHITE} to see results."
    )
    UTILITIES.display_threats(threat_list=findings)

    # ----------------------------
    # Response actions (MDE isolate / unisolate workflow)
    # ----------------------------
    token = EXECUTOR.get_bearer_token()

    query_is_about_individual_host = bool(query_context.get("about_individual_host"))
    query_is_about_individual_user = bool(query_context.get("about_individual_user"))
    query_is_about_network_security_group = bool(query_context.get("about_network_security_group"))

    # Host isolation rule: only ask once per run if a High confidence threat is present.
    if query_is_about_individual_host:
        for threat in findings:
            threat_confidence_is_high = (threat.get("confidence") or "").lower() == "high"

            if threat_confidence_is_high and (not machine_state.get("machine_is_isolated")):
                print(
                    Fore.YELLOW
                    + "[!] High confidence threat detected on host: "
                    + Style.RESET_ALL
                    + (query_context.get("device_name") or "")
                )
                print(Fore.LIGHTRED_EX + (threat.get("title") or "Untitled threat") + Style.RESET_ALL)

                confirm = input(
                    f"{Fore.RED}{Style.BRIGHT}Would you like to isolate this VM? (yes/no): {Style.RESET_ALL}"
                ).strip().lower()

                if confirm.startswith("y"):
                    try:
                        isolated_machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                            token=token,
                            device_name=query_context["device_name"],
                        )

                        isolate_result = EXECUTOR.isolate_virtual_machine(
                            token=token,
                            machine_id=isolated_machine_id,
                            comment="Isolation via Python Agentic AI using DefaultAzureCredential",
                            isolation_type="Full",
                        )

                        UTILITIES.log_event(
                            "remediation_isolate_attempt",
                            {
                                "device_name": query_context["device_name"],
                                "machine_id": isolated_machine_id,
                                "result": isolate_result,
                            },
                        )

                        if isolate_result.get("ok"):
                            machine_state["machine_is_isolated"] = True
                            machine_state["isolated_machine_id"] = isolated_machine_id
                            machine_state["last_isolation_action_id"] = isolate_result.get("action_id")

                            print(Fore.GREEN + "[+] VM successfully isolated." + Style.RESET_ALL)

                            action_id = machine_state.get("last_isolation_action_id")
                            if action_id:
                                final = EXECUTOR.poll_machine_action(
                                    token=token,
                                    action_id=action_id,
                                    timeout_seconds=90,
                                    interval_seconds=5,
                                )
                                status = (final.get("body") or {}).get("status") or (final.get("body") or {}).get("Status")
                                if status:
                                    print(Fore.CYAN + f"[i] Isolation final status: {status}" + Style.RESET_ALL)

                        else:
                            print(
                                Fore.LIGHTRED_EX
                                + f"[-] Isolation failed (HTTP {isolate_result.get('status_code')})."
                                + Style.RESET_ALL
                            )

                    except Exception as e:
                        UTILITIES.log_event("remediation_isolate_error", {"error": str(e)})
                        print(Fore.LIGHTRED_EX + f"[-] Error during isolation workflow: {e}" + Style.RESET_ALL)
                else:
                    print(Fore.CYAN + "[i] Isolation skipped by user." + Style.RESET_ALL)

                # Only ask once per iteration
                break

    elif query_is_about_individual_user:
        # Stub for future: disable user, reset password, revoke sessions, etc.
        pass

    elif query_is_about_network_security_group:
        # Stub for future: create NSG deny rule for malicious flow, etc.
        pass

    # Offer end-of-iteration unisolate if still isolated
    if machine_state.get("machine_is_isolated") and machine_state.get("isolated_machine_id"):
        release_end = input(
            f"{Fore.YELLOW}VM is currently isolated. Release it now? (yes/no): {Style.RESET_ALL}"
        ).strip().lower()
        if release_end.startswith("y"):
            un_result = EXECUTOR.unisolate_virtual_machine(
                token=token,
                machine_id=machine_state["isolated_machine_id"],
                comment="Unisolation via Python Agentic AI (user approved)",
            )

            UTILITIES.log_event(
                "remediation_unisolate_attempt",
                {
                    "device_name": query_context.get("device_name"),
                    "machine_id": machine_state["isolated_machine_id"],
                    "result": un_result,
                },
            )

            if un_result.get("ok"):
                machine_state["machine_is_isolated"] = False
                print(Fore.GREEN + "[+] VM successfully released from isolation." + Style.RESET_ALL)
            else:
                print(
                    Fore.LIGHTRED_EX
                    + f"[-] Failed to release from isolation (HTTP {un_result.get('status_code')})."
                    + Style.RESET_ALL
                )

    return "continue"


def main():
    UTILITIES.print_banner()
    print(Fore.WHITE + "Type 'help' for commands. Type 'quit' any time to exit.\n" + Style.RESET_ALL)

    # Keep remediation state across iterations
    machine_state = {"machine_is_isolated": False, "isolated_machine_id": None, "last_isolation_action_id": None}

    model_default = MODEL_MANAGEMENT.DEFAULT_MODEL

    while True:
        try:
            action = _run_single_iteration(model_default=model_default, machine_state=machine_state)
            if action == "quit":
                break

            # After each iteration: ask what next
            nxt = input(
                f"{Fore.LIGHTBLUE_EX}\nWhat next? "
                f"{Fore.WHITE}(Enter=another hunt / 'release'=release isolated VM / 'quit'):{Fore.RESET} "
            ).strip().lower()

            if nxt in {"q", "quit", "exit"}:
                break

            if nxt == "release":
                if machine_state.get("machine_is_isolated") and machine_state.get("isolated_machine_id"):
                    try:
                        token = EXECUTOR.get_bearer_token()
                        un_result = EXECUTOR.unisolate_virtual_machine(
                            token=token,
                            machine_id=machine_state["isolated_machine_id"],
                            comment="Unisolation via Python Agentic AI (manual release command)",
                        )
                        UTILITIES.log_event("remediation_unisolate_attempt", {"result": un_result})
                        if un_result.get("ok"):
                            machine_state["machine_is_isolated"] = False
                            print(Fore.GREEN + "[+] VM successfully released from isolation." + Style.RESET_ALL)
                        else:
                            print(
                                Fore.LIGHTRED_EX
                                + f"[-] Failed to release from isolation (HTTP {un_result.get('status_code')})."
                                + Style.RESET_ALL
                            )
                    except Exception as e:
                        UTILITIES.log_event("remediation_unisolate_error", {"error": str(e)})
                        print(Fore.LIGHTRED_EX + f"[-] Release failed: {e}" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "No VM is currently isolated in this session." + Style.RESET_ALL)

            # else: Enter -> continue loop

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nInterrupted. Exiting." + Style.RESET_ALL)
            break
        except Exception as e:
            UTILITIES.log_event("fatal_error", {"error": str(e)})
            print(Fore.LIGHTRED_EX + f"\nUnexpected error: {e}\n" + Style.RESET_ALL)

    print(Fore.CYAN + "\nGoodbye.\n" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
