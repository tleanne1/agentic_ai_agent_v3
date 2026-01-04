# api_server.py
# -------------------------------------------------------------------
# FastAPI adapter for the Agentic SOC Engine
# - Exposes endpoints to query Log Analytics and return structured JSON
# - Intended to be consumed by the Next.js "SOC UI" frontend
# -------------------------------------------------------------------

import os
from _config import LOG_ANALYTICS_WORKSPACE_ID

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

app = FastAPI(title="Agentic SOC Engine API")

# CORS (dev-friendly). Tighten for prod.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

credential = DefaultAzureCredential()
law_client = LogsQueryClient(credential=credential)


@app.get("/health")
def health():
    return {
        "ok": True,
        "workspace_id_set": bool(LOG_ANALYTICS_WORKSPACE_ID),
    }


@app.post("/query")
async def query(payload: dict):
    """
    Expected payload:
      {
        "kql": "DeviceLogonEvents | take 10",
        "timespan": "PT24H"   # optional ISO-8601 duration
      }
    """
    kql = payload.get("kql", "")
    timespan = payload.get("timespan", "PT24H")

    if not kql or not isinstance(kql, str):
        return {"ok": False, "error": "Missing 'kql' string in payload"}

    try:
        result = law_client.query_workspace(
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            query=kql,
            timespan=timespan,
        )

        tables = []
        for t in (result.tables or []):
            tables.append(
                {
                    "name": t.name,
                    "columns": [c.name for c in t.columns],
                    "rows": t.rows,
                }
            )

        return {
            "ok": True,
            "tables": tables,
            "statistics": getattr(result, "statistics", None),
            "visualization": getattr(result, "visualization", None),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}
