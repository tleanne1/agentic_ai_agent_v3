# Standard library
import re
from typing import Dict, Any, List


def _contains_any(text: str, needles: List[str]) -> bool:
    t = (text or "").lower()
    return any(n.lower() in t for n in needles)


def run(*, query_context: dict, baseline_note: str, pivot_blocks: str) -> Dict[str, Any]:
    """
    KillChain Step 1: Initial Access (heuristic)
    Signals: brute-force patterns, lots of failed logons, unusual accounts.
    """

    signals = []
    score = 0

    blob = f"{baseline_note}\n{pivot_blocks}".lower()

    # Strong hints of brute force
    brute_markers = ["logonfailed", "failed logon", "brute force", "password spray", "spray"]
    if _contains_any(blob, brute_markers):
        signals.append("failed logons / brute force indicators")
        score += 2

    # If baseline is calling out lots of rare AccountName values, treat as mild signal
    if "rare / unusual values" in blob and "accountname" in blob:
        signals.append("unusual account names compared to baseline")
        score += 1

    # Remote IP present with failures is a common pattern
    if "remoteip" in blob and "logonfailed" in blob:
        signals.append("remote IPs associated with failed logons")
        score += 1

    next_pivots = [
        "DeviceLogonEvents — summarize failures by RemoteIP and AccountName (confirm spray/brute-force sources)",
        "DeviceLogonEvents — check for any successful logons from the same RemoteIP(s) after failures",
    ]

    return {"score": score, "signals": signals, "next_pivots": next_pivots}
