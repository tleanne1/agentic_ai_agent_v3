# Standard library
from typing import Dict, Any, List


def _contains_any(text: str, needles: List[str]) -> bool:
    t = (text or "").lower()
    return any(n.lower() in t for n in needles)


def run(*, query_context: dict, baseline_note: str, pivot_blocks: str) -> Dict[str, Any]:
    """
    KillChain Step 2: Execution (heuristic)
    Signals: script engines, LOLBins, suspicious command interpreters.
    """

    signals = []
    score = 0

    blob = f"{baseline_note}\n{pivot_blocks}".lower()

    execution_bins = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "conhost.exe",
    ]

    if _contains_any(blob, execution_bins):
        signals.append("command/script execution indicators (PowerShell/cmd/LOLBins)")
        score += 2

    # If pivot shows ProcessCommandLine, that's more evidence
    if "processcommandline" in blob or "initiatingprocesscommandline" in blob:
        signals.append("process command lines present near suspicious window")
        score += 1

    next_pivots = [
        "DeviceProcessEvents — filter around the suspicious time window; look for encoded PowerShell, LOLBins, downloads",
        "DeviceNetworkEvents — check outbound connections right after suspicious processes (RemoteIP/RemotePort)",
        "DeviceFileEvents — check file drops (scripts/tools) near suspicious processes",
    ]

    return {"score": score, "signals": signals, "next_pivots": next_pivots}
