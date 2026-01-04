# KILLCHAIN_ESCALATION.py
# ------------------------------------------------------------
# Escalation logic:
# - Compute an escalation score based on observed kill-chain stages
# - Provide a simple action recommendation
#
# ✅ Backward compatible for UI/API imports:
#   - decide_actions(...) -> calls compute_escalation(...)
# ✅ Supports killchain reports using either:
#   - "stages" (older)
#   - "observed_stages" (newer)
# ------------------------------------------------------------

# Standard library
from typing import Dict, Any, List

# Local modules
import UTILITIES


# Stage severity weights
STAGE_WEIGHTS = {
    "Initial Access": 10,
    "Execution": 12,
    "Persistence": 15,
    "Privilege Escalation": 15,
    "Defense Evasion": 15,
    "Command and Control": 20,
    "Lateral Movement": 25,
    "Impact": 40,
}


def _get_stages(killchain_report: Dict[str, Any]) -> List[str]:
    """
    Normalize stages from different killchain report shapes.
    """
    if not isinstance(killchain_report, dict):
        return []

    # Newer killchain.py uses observed_stages; older used stages
    stages = killchain_report.get("observed_stages")
    if stages is None:
        stages = killchain_report.get("stages", [])

    if not isinstance(stages, list):
        return []
    return [str(s) for s in stages if s]


def compute_escalation(killchain_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a weighted score + action recommendation from killchain stages.
    """
    stages = _get_stages(killchain_report)

    score = 0
    for s in stages:
        score += STAGE_WEIGHTS.get(s, 0)

    decision = {
        "score": score,
        "action": "monitor",
    }

    if score >= 30:
        decision["action"] = "elevated_hunt"

    if score >= 55:
        decision["action"] = "prepare_containment"

    if score >= 75:
        decision["action"] = "containment_recommended"

    # NOTE: "auto_isolate" is a label only. Your agent/UI should NEVER isolate automatically.
    if score >= 90:
        decision["action"] = "auto_isolate"

    UTILITIES.log_event("killchain_escalation", {"stages": stages, **decision})
    return decision


# -------------------------------------------------------------------
# ✅ Backward-compatible alias for UI/API layer
# -------------------------------------------------------------------

def decide_actions(killchain_report: Dict[str, Any], campaigns: Any = None) -> Dict[str, Any]:
    """
    Compatibility wrapper expected by intel_api.py.

    campaigns is accepted (ignored for now) so intel_api can call:
      decide_actions(killchain, campaigns)

    Returns the same structure as compute_escalation().
    """
    return compute_escalation(killchain_report)
