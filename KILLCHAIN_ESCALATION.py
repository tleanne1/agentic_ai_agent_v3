# Standard library
from typing import Dict, Any

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


def compute_escalation(killchain_report: Dict[str, Any]) -> Dict[str, Any]:
    stages = killchain_report.get("stages", [])
    score = 0

    for s in stages:
        score += STAGE_WEIGHTS.get(s, 0)

    decision = {
        "score": score,
        "action": "monitor"
    }

    if score >= 30:
        decision["action"] = "elevated_hunt"

    if score >= 55:
        decision["action"] = "prepare_containment"

    if score >= 75:
        decision["action"] = "containment_recommended"

    if score >= 90:
        decision["action"] = "auto_isolate"

    UTILITIES.log_event("killchain_escalation", decision)
    return decision
 