# api_server.py
# -------------------------------------------------------------------
# Agentic SOC Engine API (FastAPI)
#
# ✅ Minimal-change upgrade:
# - Keeps /api/hunt (raw KQL) exactly as-is
# - Adds /api/hunt/smart which accepts either:
#     • raw KQL  (runs directly)
#     • natural-language prompt (LLM translates -> KQL -> runs)
#
# ✅ Mode badge support (minimal):
# - /health now returns {"mode": "live" | "demo"} in addition to existing fields
# - Set ENGINE_MODE=demo in your engine .env (or export in shell) to switch
# -------------------------------------------------------------------

from __future__ import annotations

from typing import Any, Dict, List
import os
import re
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
app = FastAPI(title="Agentic SOC Engine API", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
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


class SmartHuntRequest(BaseModel):
    prompt: str
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
    ws = _require_workspace_id()

    try:
        result = EXECUTOR.query_log_analytics(
            law_client=law_client,
            kql_query=kql,
            workspace_id=ws,
            timespan_hours=hours,
        )

        ok = bool(result.get("ok", False))
        rows = result.get("rows", []) or []
        error = result.get("error") if not ok else None

        return {"ok": ok, "rows": rows, "count": len(rows), "error": error}

    except Exception as e:
        tb = traceback.format_exc()
        return {
            "ok": False,
            "rows": [],
            "count": 0,
            "error": f"{type(e).__name__}: {e}",
            "trace": tb,
        }


def pick_first_ok(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    first_fail = None
    for r in results:
        if r.get("ok"):
            return r
        if first_fail is None:
            first_fail = r
    return first_fail or {"ok": False, "rows": [], "count": 0, "error": "No results"}


def looks_like_kql(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False

    if "|" in t:
        return True

    # single token like "Heartbeat"
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", t):
        return True

    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*\|", t):
        return True

    return False


def _get_openai_client():
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="openai package not installed. Run: python3 -m pip install openai",
        ) from e

    api_key = (os.getenv("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="OPENAI_API_KEY not set (.env). Needed for natural-language prompts.",
        )

    return OpenAI(api_key=api_key)


def translate_prompt_to_kql(prompt: str, hours: int) -> str:
    client = _get_openai_client()
    model = (os.getenv("OPENAI_MODEL") or "gpt-4o-mini").strip()

    system = (
        "You translate analyst natural-language requests into KQL for Azure Log Analytics.\n"
        "Return ONLY valid KQL. No markdown. No explanations.\n"
        f"If time filtering is needed, use: TimeGenerated >= ago({hours}h).\n"
        "Prefer common tables if appropriate: Heartbeat, SecurityEvent, SigninLogs, DeviceLogonEvents.\n"
        "If the request is ambiguous, choose a reasonable common table and keep output simple.\n"
    )

    try:
        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        kql = (resp.output_text or "").strip()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to translate prompt: {type(e).__name__}: {e}",
        )

    if not kql:
        raise HTTPException(status_code=500, detail="Failed to translate prompt to KQL (empty result).")

    return kql.replace("```kql", "").replace("```", "").strip()


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    ws = (LOG_ANALYTICS_WORKSPACE_ID or "").strip()

    # ✅ Minimal addition for the UI "Mode" badge (default: live)
    # Set ENGINE_MODE=demo later when you add demo-mode endpoints/data.
    mode = (os.getenv("ENGINE_MODE") or "live").strip().lower()
    if mode not in ("live", "demo"):
        mode = "live"

    return {"ok": True, "workspace_id_set": bool(ws), "mode": mode}


@app.post("/api/hunt")
def api_hunt(req: HuntRequest):
    resp = run_kql(req.kql, hours=req.hours)
    if not resp.get("ok"):
        raise HTTPException(status_code=500, detail=resp.get("error", "KQL query failed"))
    return resp


@app.post("/api/hunt/smart")
def api_hunt_smart(req: SmartHuntRequest):
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")

    if looks_like_kql(prompt):
        kql_used = prompt
        input_type = "kql"
    else:
        kql_used = translate_prompt_to_kql(prompt, hours=req.hours)
        input_type = "natural_language"

    resp = run_kql(kql_used, hours=req.hours)
    if not resp.get("ok"):
        raise HTTPException(status_code=500, detail=resp.get("error", "KQL query failed"))

    return {**resp, "kql_used": kql_used, "input_type": input_type, "hours": req.hours}


@app.get("/api/intel/overview")
def intel_overview(hours: int = 24):
    logon_candidates = [
        f"""
DeviceLogonEvents
| where TimeGenerated >= ago({hours}h)
| summarize total=count(), devices=dcount(DeviceName), users=dcount(AccountName)
""",
        f"""
SecurityEvent
| where TimeGenerated >= ago({hours}h)
| where EventID in (4624,4625)
| summarize total=count(), devices=dcount(Computer), users=dcount(Account)
""",
        f"""
SigninLogs
| where TimeGenerated >= ago({hours}h)
| summarize total=count(), users=dcount(UserPrincipalName), apps=dcount(AppDisplayName)
""",
    ]

    summary = pick_first_ok([run_kql(kql, hours=hours) for kql in logon_candidates])

    if not summary.get("ok"):
        return {
            "ok": False,
            "hours": hours,
            "error": summary.get("error", "Failed to query workspace"),
            "hint": "Workspace may not have DeviceLogonEvents/SecurityEvent/SigninLogs. Try /api/hunt with Heartbeat | take 10.",
        }

    row0 = (summary.get("rows") or [{}])[0]

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
            name = r.get("DeviceName") or r.get("Computer") or ""
            devices_list.append({"name": str(name), "events": int(r.get("events", 0) or 0)})

    return {
        "ok": True,
        "hours": hours,
        "source_table_hint": "auto",
        "summary": row0,
        "top_devices": devices_list,
        "campaigns": [],
        "mitre": [],
        "lateral": [],
        "cases_open": None,
    }
