# MODEL_MANAGEMENT.py
# -------------------------------------------------------------------
# Model management:
# - Token estimation (safe + lightweight)
# - Default model selection
# - Auto model selection by size
# - Chooses a model that can actually fit the prompt (token-safe)
# -------------------------------------------------------------------

from typing import List, Dict, Any
import GUARDRAILS

DEFAULT_MODEL = "gpt-4.1-nano"
CURRENT_TIER = "4"


def count_tokens(messages: List[Dict[str, str]], model: str = DEFAULT_MODEL) -> int:
    """
    Approx token estimate.
    Safe rule: ~4 chars per token for English-ish content.
    """
    total_chars = 0
    for m in messages:
        total_chars += len(m.get("role", ""))
        total_chars += len(m.get("content", "") or "")
    return max(1, total_chars // 4)


def _model_can_fit(model: str, input_tokens: int, buffer_tokens: int = 2000) -> bool:
    """
    Check if a model can fit the estimated input tokens.
    buffer_tokens accounts for formatting overhead + response JSON.
    """
    meta = GUARDRAILS.ALLOWED_MODELS.get(model, {})
    max_in = int(meta.get("max_input_tokens", 0) or 0)
    return (input_tokens + buffer_tokens) <= max_in


def auto_select_model(*, input_tokens: int, tier: str = "4", prefer_quality: bool = False) -> str:
    """
    Token-safe routing:
    - Pick the best model that can fit the prompt.
    - Prefer smaller/cheaper when safe, but avoid overflow.
    - Important: gpt-4.1 / gpt-4.1-nano have very large context windows.
    """

    # Candidate order (cheap -> better quality)
    # NOTE: gpt-5 has smaller max input tokens than gpt-4.1 in your allowlist.
    candidates = [
        "gpt-4.1-nano",
        "gpt-4.1",
        "gpt-5-mini",
        "gpt-5",
    ]

    # If prefer_quality, bias upward (but still must fit)
    if prefer_quality:
        candidates = [
            "gpt-4.1",
            "gpt-5-mini",
            "gpt-5",
            "gpt-4.1-nano",
        ]

    # First pass: choose first that fits
    for m in candidates:
        if m in GUARDRAILS.ALLOWED_MODELS and _model_can_fit(m, input_tokens):
            return m

    # Fallback: if nothing fits, choose the biggest-context model available
    # (In your allowlist that's gpt-4.1 / gpt-4.1-nano)
    if "gpt-4.1" in GUARDRAILS.ALLOWED_MODELS:
        return "gpt-4.1"
    return "gpt-4.1-nano"


def ensure_model_ok(model: str) -> str:
    GUARDRAILS.validate_model(model)
    return model