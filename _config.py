# _config.py
# -------------------------------------------------------------------
# Central config for the Agentic SOC Engine
# Keep secrets in .env (never commit)
# -------------------------------------------------------------------

import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError(
        "OPENAI_API_KEY is missing. Add it to your .env file like:\n"
        "OPENAI_API_KEY=sk-xxxxx (no quotes, no spaces)"
    )

LOG_ANALYTICS_WORKSPACE_ID = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
if not LOG_ANALYTICS_WORKSPACE_ID:
    raise RuntimeError(
        "LOG_ANALYTICS_WORKSPACE_ID is missing. Add it to your .env file like:\n"
        'LOG_ANALYTICS_WORKSPACE_ID="60c7f53e-249a-4077-b68e-55a4ae877d7c"'
    )
