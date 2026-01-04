
# api_server.py
# -------------------------------------------------------------------
# Agentic SOC Engine API (FastAPI)
#
# Phase 2 goal:
# - Expose live telemetry endpoints your UI can call
# - Provide an /api/intel/overview endpoint (your browser is hitting this)
#
# Uses your existing executor:
#   EXECUTOR.query_log_analytics(law_client, kql_query, workspace_id, timespan_hours)
# -------------------------------------------------------------------

from __future__ import annotations

from typing import Any, Dict, List, Optional
import traceback

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

import EXECUTOR
from _config import LOG_ANALYTICS_WORKSPACE_ID


# -----------------------------
# App + Clients
# -----------------------------
app = FastAPI(title="Agentic SOC Engine API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Next.js dev
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

credential = DefaultAzureCredential()
law_client = LogsQueryClient(credential=credential)


# -----------------------------
# Models
# -----------------------------
class HuntRequest(BaseModel):
    kql: str
    hours: int = 24


# -----------------------------
# Helpers
# -----------------------------
def _require_workspace_id() -> str:
    ws = (LOG_ANALYTICS_WORKSPACE_ID or "").strip()
    if not ws:
        raise HTTPException(
            status_code=500,
            detail="LOG_ANALYTICS_WORKSPACE_ID is missing. Set it in .env and load it in _config.py.",
        )
    return ws


def run_kql(kql: str, hours: int = 24) -> Dict[str, Any]:
    """
    Runs KQL through your existing EXECUTOR.query_log_analytics so we keep
    one consistent query path across CLI engine + API.
    """
    ws = _require_workspace_id()

    try:
        result = EXECUTOR.query_log_analytics(
            law_client=law_client,
            kql_query=kql,
            workspace_id=ws,
            timespan_hours=hours,
        )

        # Normalize: always return a dict with ok + rows
        ok = bool(result.get("ok", False))
        rows = result.get("rows", []) or []
        error = result.get("error") if not ok else None

        return {
            "ok": ok,
            "rows": rows,
            "count": len(rows),
            "error": error,
        }

    except Exception as e:
        # Don’t hide the real reason — return it safely to the caller
        tb = traceback.format_exc()
        return {
            "ok": False,
            "rows": [],
            "count": 0,
            "error": f"{type(e).__name__}: {e}",
            "trace": tb,
        }


def pick_first_ok(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Try multiple queries; return the first successful one.
    If all fail, return the *most informative* failure.
    """
    first_fail = None
    for r in results:
        if r.get("ok"):
            return r
        if first_fail is None:
            first_fail = r
    return first_fail or {"ok": False, "rows": [], "count": 0, "error": "No results"}


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    ws = (LOG_ANALYTICS_WORKSPACE_ID or "").strip()
    return {"ok": True, "workspace_id_set": bool(ws)}


@app.post("/api/hunt")
def api_hunt(req: HuntRequest):
    """
    Generic KQL endpoint (useful for debugging from browser/Postman/UI).
    """
    resp = run_kql(req.kql, hours=req.hours)
    if not resp.get("ok"):
        # Return a helpful 500 with the actual KQL failure details
        raise HTTPException(status_code=500, detail=resp.get("error", "KQL query failed"))
    return resp


@app.get("/api/intel/overview")
def intel_overview(hours: int = 24):
    """
    Returns a small "Command Center" style summary from live telemetry.

    IMPORTANT:
    Workspace schemas vary wildly. To avoid constant breakage,
    we try a few common tables and pick the first one that works.
    """

    # 1) Candidate queries for "logon-style" telemetry
    logon_candidates = [
        # Microsoft Defender for Endpoint (if piped into LA)
        f"""
DeviceLogonEvents
| where TimeGenerated >= ago({hours}h)
| summarize
    total=count(),
    devices=dcount(DeviceName),
    users=dcount(AccountName)
""",
        # Windows SecurityEvent (classic)
        f"""
SecurityEvent
| where TimeGenerated >= ago({hours}h)
| where EventID in (4624,4625)
| summarize
    total=count(),
    devices=dcount(Computer),
    users=dcount(Account)
""",
        # Azure AD sign-in logs (if connected)
        f"""
SigninLogs
| where TimeGenerated >= ago({hours}h)
| summarize
    total=count(),
    users=dcount(UserPrincipalName),
    apps=dcount(AppDisplayName)
""",
    ]

    summary_attempts = [run_kql(kql, hours=hours) for kql in logon_candidates]
    summary = pick_first_ok(summary_attempts)

    if not summary.get("ok"):
        # Don’t 500 with a blank page — return a structured error payload.
        return {
            "ok": False,
            "hours": hours,
            "error": summary.get("error", "Failed to query workspace"),
            "hint": "Your workspace may not have DeviceLogonEvents/SecurityEvent/SigninLogs. Try /api/hunt with a known-good table.",
        }

    row0 = (summary.get("rows") or [{}])[0]

    # 2) Top entities/devices (best-effort)
    top_devices_candidates = [
        f"""
DeviceLogonEvents
| where TimeGenerated >= ago({hours}h)
| summarize events=count() by DeviceName
| top 8 by events desc
""",
        f"""
SecurityEvent
| where TimeGenerated >= ago({hours}h)
| summarize events=count() by Computer
| top 8 by events desc
""",
    ]
    top_devices = pick_first_ok([run_kql(kql, hours=hours) for kql in top_devices_candidates])
    devices_list = []
    if top_devices.get("ok"):
        for r in top_devices.get("rows", []):
            # normalize either DeviceName or Computer
            name = r.get("DeviceName") or r.get("Computer") or ""
            devices_list.append({"name": str(name), "events": int(r.get("events", 0) or 0)})

    # 3) Return overview payload
    return {
        "ok": True,
        "hours": hours,
        "source_table_hint": "auto",
        "summary": row0,
        "top_devices": devices_list,
        # placeholders your UI can later expand:
        "campaigns": [],
        "mitre": [],
        "lateral": [],
        "cases_open": None,
    }