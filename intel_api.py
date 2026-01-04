# intel_api.py
from fastapi import APIRouter, Query
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

from _config import LOG_ANALYTICS_WORKSPACE_ID
from EXECUTOR import query_log_analytics

# These are your existing engines
from KILLCHAIN import summarize_kill_chain
from PLANNER import cluster_campaigns
from KILLCHAIN_ESCALATION import decide_actions

router = APIRouter()

# Create a Log Analytics client for this API module
law_client = LogsQueryClient(credential=DefaultAzureCredential())

@router.get("/intel/overview")
def intel_overview(hours: int = Query(24, ge=1, le=168)):
    """
    Pull live telemetry from Log Analytics and produce:
      - killchain summary
      - campaign clustering
      - decisions / recs
    """
    try:
        # NOTE: These tables may not exist depending on workspace type.
        # If they fail, we'll still return ok:false with a helpful error.
        device_logons = query_log_analytics(
            law_client=law_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            kql="DeviceLogonEvents | where TimeGenerated > ago(24h) | take 200",
            hours=hours,
        )

        device_net = query_log_analytics(
            law_client=law_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            kql="DeviceNetworkEvents | where TimeGenerated > ago(24h) | take 200",
            hours=hours,
        )

        # If either query failed, return details
        if not device_logons.get("ok") or not device_net.get("ok"):
            return {
                "ok": False,
                "hours": hours,
                "device_logons_ok": bool(device_logons.get("ok")),
                "device_net_ok": bool(device_net.get("ok")),
                "device_logons_error": device_logons.get("error"),
                "device_net_error": device_net.get("error"),
                "hint": "Your workspace may not have DeviceLogonEvents/DeviceNetworkEvents. Try /api/hunt with 'Heartbeat | take 5' to confirm connectivity.",
            }

        # Use the rows (list[dict]) as inputs to your engines
        killchain = summarize_kill_chain(device_logons.get("rows", []), device_net.get("rows", []))
        campaigns = cluster_campaigns(device_logons.get("rows", []), device_net.get("rows", []))
        decisions = decide_actions(killchain, campaigns)

        return {
            "ok": True,
            "hours": hours,
            "killchain": killchain,
            "campaigns": campaigns,
            "decisions": decisions,
        }

    except Exception as e:
        return {
            "ok": False,
            "hours": hours,
            "error": f"{type(e).__name__}: {str(e)}",
            "hint": "Try /api/hunt with a known-good table like: Heartbeat | take 5",
        }
