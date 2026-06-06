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


# KILLCHAIN.py
# -------------------------------------------------------------------
# Kill chain utilities
#
# This module powers two different use-cases:
# 1) Agent pipeline (heuristic step runner): run_killchain(...)
# 2) API/UI summaries (lightweight aggregation): summarize_kill_chain(...)
#
# ✅ Adding summarize_kill_chain is NON-DESTRUCTIVE:
# - Does not change run_killchain behavior
# - Simply provides a stable function for the UI API layer to call
# -------------------------------------------------------------------

# Standard library
from typing import Dict, Any, List, Optional
from collections import Counter

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


# -------------------------------------------------------------------
# UI/API helper (non-destructive)
# -------------------------------------------------------------------

def summarize_kill_chain(
    device_logons: Optional[List[Dict[str, Any]]] = None,
    device_net: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Lightweight kill-chain-ish summary for the UI layer.

    This does NOT run the full heuristic step pipeline.
    It simply summarizes common indicators from the provided rows, so the
    UI can display a stable, fast "overview" without heavy analysis.

    Args:
        device_logons: List of logon-like rows (dicts)
        device_net: List of network-like rows (dicts)

    Returns:
        dict suitable for the UI to render:
        {
          "observed_stages": [...],
          "signals": [...],
          "score": int,
          "top_users": [...],
          "top_devices": [...],
          "notes": str
        }
    """
    device_logons = device_logons or []
    device_net = device_net or []

    signals: List[str] = []
    observed: List[str] = []
    score = 0

    # Helper: pull a field if it exists under several common names
    def pick(row: Dict[str, Any], *keys: str) -> Any:
        for k in keys:
            if k in row and row.get(k) not in (None, ""):
                return row.get(k)
        return None

    # Count top users/devices from whatever fields we have
    user_counter = Counter()
    device_counter = Counter()

    for r in device_logons:
        user = pick(r, "Account", "User", "UserPrincipalName", "TargetUserName", "InitiatingProcessAccountName")
        dev = pick(r, "DeviceName", "Computer", "Device", "HostName")
        if user:
            user_counter[str(user)] += 1
        if dev:
            device_counter[str(dev)] += 1

    for r in device_net:
        dev = pick(r, "DeviceName", "Computer", "Device", "HostName")
        if dev:
            device_counter[str(dev)] += 1

    # Very lightweight “stage” inference based on presence of data
    if len(device_logons) > 0:
        observed.append("Initial Access")
        signals.append(f"Observed {len(device_logons)} authentication-related events (last window).")
        score += 1

    if len(device_net) > 0:
        observed.append("Command & Control")
        signals.append(f"Observed {len(device_net)} network-related events (last window).")
        score += 1

    # Add “hot” entities if any
    top_users = [{"name": u, "events": c} for u, c in user_counter.most_common(8)]
    top_devices = [{"name": d, "events": c} for d, c in device_counter.most_common(8)]

    if top_users:
        signals.append(f"Top user by event volume: {top_users[0]['name']} ({top_users[0]['events']}).")
    if top_devices:
        signals.append(f"Top device by event volume: {top_devices[0]['name']} ({top_devices[0]['events']}).")

    notes = (
        "UI summary only (lightweight). For full heuristics, the agent uses run_killchain()."
    )

    return {
        "observed_stages": observed,
        "signals": signals,
        "score": score,
        "top_users": top_users,
        "top_devices": top_devices,
        "notes": notes,
    }
