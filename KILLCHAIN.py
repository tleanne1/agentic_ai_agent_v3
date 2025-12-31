# Standard library
from typing import Dict, Any

# Local modules (these should exist as separate files)
# If you haven't created some yet, comment them out for now.
import KILLCHAIN_INITIAL_ACCESS
import KILLCHAIN_EXECUTION
# import KILLCHAIN_PRIV_ESCALATION  # optional / later

# ----------------------------
# KillChain Step Registry
# ----------------------------
# Each module MUST expose:
#   def run(query_context: dict, baseline_note: str, pivot_blocks: str) -> dict
#
# The dict should look like:
# {
#   "score": int,
#   "signals": [str, ...],
#   "next_pivots": [str, ...]
# }
KILLCHAIN_STEPS = {
    "Initial Access": KILLCHAIN_INITIAL_ACCESS,
    "Execution": KILLCHAIN_EXECUTION,
    # "Privilege Escalation": KILLCHAIN_PRIV_ESCALATION,  # later
}


def run_killchain(
    *,
    query_context: dict,
    baseline_note: str,
    pivot_blocks: str,
) -> Dict[str, Any]:
    """
    Run kill-chain heuristic steps in order. Each step is a lightweight, deterministic heuristic.
    Returns a normalized report dict.
    """

    report = {
        "observed_stages": [],
        "signals": [],
        "score": 0,
        "next_pivots": [],
    }

    for stage_name, module in KILLCHAIN_STEPS.items():
        try:
            if not hasattr(module, "run"):
                continue

            result = module.run(
                query_context=query_context,
                baseline_note=baseline_note,
                pivot_blocks=pivot_blocks,
            )

            if not isinstance(result, dict):
                continue

            stage_score = int(result.get("score") or 0)
            if stage_score > 0:
                report["observed_stages"].append(stage_name)

            report["score"] += stage_score
            report["signals"].extend(result.get("signals") or [])
            report["next_pivots"].extend(result.get("next_pivots") or [])

        except Exception:
            # KillChain should never crash your agent; it is advisory
            continue

    # De-duplicate pivots while preserving order
    seen = set()
    deduped = []
    for p in report["next_pivots"]:
        if p and p not in seen:
            seen.add(p)
            deduped.append(p)
    report["next_pivots"] = deduped

    return report
