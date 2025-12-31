from colorama import Fore, Style
import tiktoken
import GUARDRAILS

# ---- Settings ---------------------------------------------------------------

# If you want, set your actual org tier here. It’s only used for TPM “soft checks.”
CURRENT_TIER = "4"
DEFAULT_MODEL = "gpt-5-mini"
WARNING_RATIO = 0.80  # 80%


def money(usd):
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"


def estimate_cost(input_tokens, output_tokens, model_info):
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout


def count_tokens(messages, model):
    """
    Cheap estimate for chat messages.
    """
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")

    text = ""
    for m in messages:
        text += m.get("role", "") + " " + (m.get("content", "") or "") + "\n"
    return len(enc.encode(text))


def _model_limits_ok(model_name: str, input_tokens: int, tier: str) -> bool:
    info = GUARDRAILS.ALLOWED_MODELS[model_name]
    tpm_limit = info["tier"].get(tier)

    if input_tokens > info["max_input_tokens"]:
        return False

    # This is a “soft” check; TPM varies by org settings and time. Still useful.
    if tpm_limit is not None and input_tokens > tpm_limit:
        return False

    return True


def auto_select_model(
    input_tokens: int,
    tier: str = CURRENT_TIER,
    assumed_output_tokens: int = 1200,
    prefer_quality: bool = False,
) -> str:
    """
    Automatically choose an allowed model given token constraints.

    Heuristics:
      - Must fit input cap and (when known) TPM tier cap
      - If prefer_quality=True, bias toward higher models (gpt-5 > gpt-5-mini > gpt-4.1 > nano)
      - Otherwise choose lowest estimated cost that fits
    """
    allowed = list(GUARDRAILS.ALLOWED_MODELS.keys())

    candidates = []
    for name in allowed:
        if not _model_limits_ok(name, input_tokens, tier):
            continue

        info = GUARDRAILS.ALLOWED_MODELS[name]
        est = estimate_cost(input_tokens, assumed_output_tokens, info)

        # crude quality tier for tie-breaking
        quality_rank = 0
        if name == "gpt-5":
            quality_rank = 3
        elif name == "gpt-5-mini":
            quality_rank = 2
        elif name.startswith("gpt-4.1"):
            quality_rank = 1

        candidates.append((name, est, quality_rank))

    if not candidates:
        return DEFAULT_MODEL

    if prefer_quality:
        candidates.sort(key=lambda x: (-x[2], x[1]))
        return candidates[0][0]

    candidates.sort(key=lambda x: (x[1], -x[2]))
    return candidates[0][0]
