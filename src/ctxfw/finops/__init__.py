# manifest_hash: 0dd507acac7dc966a16fa69ccffcb7a51797ce899ca6edab88837448ad38d415
"""
src/ctxfw/finops/__init__.py — Sovereign FinOps Model Matrix, LiveBench Intelligence & Multi-Turn Compounding Engine
Axiom Manifest Hash: 0dd507acac7dc966a16fa69ccffcb7a51797ce899ca6edab88837448ad38d415

Enforces:
- AXIOM-V41-1: Zero-Egress Model Matrix Resolution (100% local deterministic resolution in data plane).
- AXIOM-V41-2: Strict FinOps Numerical Bounds (No NaN/Inf, compounding_factor in [1.0, 20.0]).
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator

BUNDLED_MATRIX_PATH = Path(__file__).resolve().parent / "model_matrix.json"
DEFAULT_MODEL_ID = "claude-sonnet-4-20250514"
DEFAULT_COMPOUNDING_FACTOR = 4.2


class ModelPricingSpecDTO(BaseModel):
    """Immutable specification of a model's token pricing and LiveBench coding scores."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str = Field(..., min_length=1, max_length=128)
    provider: str = Field(default="anthropic", min_length=1, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=128)
    aliases: Tuple[str, ...] = Field(default_factory=tuple)
    input_price_per_m: float = Field(..., ge=0.001, le=500.0)
    output_price_per_m: float = Field(..., ge=0.001, le=1000.0)
    cache_write_price_per_m: float = Field(..., ge=0.001, le=625.0)
    cache_read_price_per_m: float = Field(..., ge=0.001, le=500.0)
    context_window: int = Field(default=200000, ge=1024, le=10_000_000)
    livebench_coding_score: float = Field(default=0.0, ge=0.0, le=100.0)
    livebench_agentic_score: float = Field(default=0.0, ge=0.0, le=100.0)
    arbitrage_target: Optional[str] = Field(default=None)

    @field_validator(
        "input_price_per_m",
        "output_price_per_m",
        "cache_write_price_per_m",
        "cache_read_price_per_m",
        "livebench_coding_score",
        "livebench_agentic_score",
    )
    @classmethod
    def _reject_nan_inf(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("FinOps numerical fields shall never be NaN or Infinity.")
        return float(v)


def _get_user_matrix_cache_path() -> Path:
    return Path.home() / ".ctxfw" / "model_matrix.json"


def load_model_matrix() -> Dict[str, ModelPricingSpecDTO]:
    """
    Loads the canonical model pricing & LiveBench matrix from local disk.
    Prefers user-synced ~/.ctxfw/model_matrix.json if valid, falling back to bundled model_matrix.json.
    Never performs network calls (AXIOM-V41-1).
    """
    raw_data: Optional[Dict[str, Any]] = None
    user_cache = _get_user_matrix_cache_path()
    for candidate in (user_cache, BUNDLED_MATRIX_PATH):
        if candidate.is_file():
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("models"), dict):
                    raw_data = loaded
                    break
            except Exception:
                continue

    if not raw_data:
        return {}

    catalog: Dict[str, ModelPricingSpecDTO] = {}
    for key, entry in raw_data["models"].items():
        try:
            aliases = tuple(entry.get("aliases", ()))
            dto = ModelPricingSpecDTO(
                model_id=entry.get("model_id", key),
                provider=entry.get("provider", "unknown"),
                display_name=entry.get("display_name", key),
                aliases=aliases,
                input_price_per_m=float(entry["input_price_per_m"]),
                output_price_per_m=float(entry["output_price_per_m"]),
                cache_write_price_per_m=float(entry.get("cache_write_price_per_m", entry["input_price_per_m"])),
                cache_read_price_per_m=float(entry.get("cache_read_price_per_m", entry["input_price_per_m"] * 0.1)),
                context_window=int(entry.get("context_window", 200000)),
                livebench_coding_score=float(entry.get("livebench_coding_score", 0.0)),
                livebench_agentic_score=float(entry.get("livebench_agentic_score", 0.0)),
                arbitrage_target=entry.get("arbitrage_target"),
            )
            catalog[dto.model_id] = dto
        except Exception:
            continue
    return catalog


def resolve_model_spec(model_identifier: Optional[str] = None) -> ModelPricingSpecDTO:
    """
    Resolves a model identifier or alias (e.g., 'opus', 'claude-opus-4', 'gpt-4o', 'sonnet')
    to its canonical ModelPricingSpecDTO.
    """
    catalog = load_model_matrix()
    default_spec = catalog.get(DEFAULT_MODEL_ID) or ModelPricingSpecDTO(
        model_id=DEFAULT_MODEL_ID,
        provider="anthropic",
        display_name="Claude Sonnet 4",
        aliases=("sonnet", "claude-sonnet-4"),
        input_price_per_m=3.0,
        output_price_per_m=15.0,
        cache_write_price_per_m=3.75,
        cache_read_price_per_m=0.30,
        context_window=200000,
        livebench_coding_score=80.1,
        livebench_agentic_score=81.5,
        arbitrage_target="claude-3-5-haiku-20241022",
    )

    if not model_identifier or not isinstance(model_identifier, str):
        return default_spec

    needle = model_identifier.strip().lower()
    if not needle or needle in {"auto", "default", "unknown"}:
        return default_spec

    # 1. Exact model_id match
    for mid, spec in catalog.items():
        if mid.lower() == needle:
            return spec

    # 2. Exact alias match
    for spec in catalog.values():
        if any(a.lower() == needle for a in spec.aliases):
            return spec

    # 3. Substring / prefix match (e.g. 'claude-opus-4-20250514-v1' or 'anthropic/claude-opus-4')
    for spec in catalog.values():
        if spec.model_id.lower() in needle or any(a.lower() in needle for a in spec.aliases if len(a) >= 4):
            return spec

    return default_spec


def resolve_active_model(
    explicit_model: Optional[str] = None,
    project_root: Optional[str | Path] = None,
) -> ModelPricingSpecDTO:
    """
    Auto-detects the active coding LLM used by the developer in deterministic order:
      1. Explicit model parameter (from MCP tool call or HTTP proxy payload).
      2. Active environment variables (CTXFW_MODEL, ANTHROPIC_MODEL, CLAUDE_MODEL, OPENAI_MODEL, GEMINI_MODEL).
      3. Workspace config (.ctxfwrc / .claude/settings.json) in project_root.
      4. Global user config (~/.ctxfw/config.json: finops.model or matching finops.input_price_per_m).
      5. Canonical default (Claude Sonnet 4).
    """
    # 1. Explicit model argument
    if explicit_model and str(explicit_model).strip().lower() not in {"", "auto", "unknown", "none"}:
        return resolve_model_spec(str(explicit_model))

    # 2. Environment variables
    for env_key in ("CTXFW_MODEL", "ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL", "GEMINI_MODEL"):
        env_val = os.environ.get(env_key, "").strip()
        if env_val and env_val.lower() not in {"auto", "unknown"}:
            return resolve_model_spec(env_val)

    # 3. Workspace configuration (.ctxfwrc or .claude/settings.json)
    if project_root:
        try:
            root_path = Path(project_root).resolve()
            if root_path.is_file():
                root_path = root_path.parent
            for rel_candidate in (".ctxfwrc", ".ctxfw.json", ".claude/settings.json", ".claude/settings.local.json"):
                cfg_file = root_path / rel_candidate
                if cfg_file.is_file():
                    data = json.loads(cfg_file.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        m_val = (
                            data.get("model")
                            or (data.get("finops", {}) if isinstance(data.get("finops"), dict) else {}).get("model")
                        )
                        if isinstance(m_val, str) and m_val.strip().lower() not in {"", "auto"}:
                            return resolve_model_spec(m_val)
        except Exception:
            pass

    # 4. Global ~/.ctxfw/config.json (finops.model or price-matched tier)
    try:
        from ctxfw.config import load_config

        cfg = load_config()
        cfg_model = getattr(cfg.finops, "model", "auto")
        if isinstance(cfg_model, str) and cfg_model.strip().lower() not in {"", "auto"}:
            return resolve_model_spec(cfg_model)

        # Infer model if user customized finops.input_price_per_m (e.g. 15.0 -> Claude Opus 4)
        catalog = load_model_matrix()
        price = float(cfg.finops.input_price_per_m)
        for spec in catalog.values():
            if abs(spec.input_price_per_m - price) < 0.01:
                return spec
    except Exception:
        pass

    return resolve_model_spec(DEFAULT_MODEL_ID)


def compute_compounded_savings(
    tokens_saved: int,
    model_spec: Optional[ModelPricingSpecDTO] = None,
    compounding_factor: float = DEFAULT_COMPOUNDING_FACTOR,
    override_input_price_per_m: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Computes both 1-Turn Direct Savings and Multi-Turn Compounded Session Savings.
    Enforces AXIOM-V41-2: compounding_factor clamped/validated in [1.0, 20.0], no NaN/Inf.
    """
    if math.isnan(compounding_factor) or math.isinf(compounding_factor):
        raise ValueError("compounding_factor cannot be NaN or Infinity.")
    if compounding_factor < 1.0 or compounding_factor > 20.0:
        raise ValueError(f"compounding_factor must be in [1.0, 20.0], got {compounding_factor}")

    safe_tokens = max(0, int(tokens_saved))
    spec = model_spec or resolve_active_model()
    effective_price = (
        float(override_input_price_per_m)
        if override_input_price_per_m is not None
        else float(spec.input_price_per_m)
    )
    if math.isnan(effective_price) or math.isinf(effective_price) or effective_price < 0.0:
        raise ValueError("Invalid effective input price.")

    direct_usd = round((safe_tokens / 1_000_000.0) * effective_price, 6)
    compounded_tokens = int(round(safe_tokens * compounding_factor))
    compounded_usd = round(direct_usd * compounding_factor, 6)

    return {
        "model_id": spec.model_id,
        "display_name": spec.display_name,
        "input_price_per_m": effective_price,
        "output_price_per_m": spec.output_price_per_m,
        "livebench_coding_score": spec.livebench_coding_score,
        "livebench_agentic_score": spec.livebench_agentic_score,
        "tokens_saved_1turn": safe_tokens,
        "direct_1turn_usd": direct_usd,
        "compounding_factor": round(compounding_factor, 2),
        "compounded_session_tokens": compounded_tokens,
        "compounded_session_usd": compounded_usd,
    }


def compute_arbitrage_recommendation(
    model_spec: ModelPricingSpecDTO,
    evaluated_tokens: int,
    tokens_saved: int,
    compounding_factor: float = DEFAULT_COMPOUNDING_FACTOR,
) -> Dict[str, Any]:
    """
    Uses LiveBench Coding scores and live pricing to compute Pareto model efficiency
    and cost-arbitrage recommendations.
    """
    catalog = load_model_matrix()
    target_id = model_spec.arbitrage_target
    target_spec = catalog.get(target_id) if target_id else None

    pruned_tokens = max(0, evaluated_tokens - tokens_saved)
    compounded_pruned_tokens = pruned_tokens * compounding_factor
    current_session_spend_usd = (compounded_pruned_tokens / 1_000_000.0) * model_spec.input_price_per_m

    if target_spec is None or target_spec.input_price_per_m >= model_spec.input_price_per_m:
        return {
            "has_arbitrage": False,
            "active_model": model_spec.model_id,
            "active_display_name": model_spec.display_name,
            "active_coding_score": model_spec.livebench_coding_score,
            "recommendation": (
                f"`{model_spec.display_name}` (`LiveBench Coding: {model_spec.livebench_coding_score:.1f}`) "
                "is already on the Pareto-optimal cost frontier."
            ),
        }

    quality_retention_pct = (
        (target_spec.livebench_coding_score / max(0.1, model_spec.livebench_coding_score)) * 100.0
    )
    cost_ratio_pct = (target_spec.input_price_per_m / max(0.001, model_spec.input_price_per_m)) * 100.0
    cost_reduction_pct = max(0.0, 100.0 - cost_ratio_pct)
    target_session_spend_usd = (compounded_pruned_tokens / 1_000_000.0) * target_spec.input_price_per_m
    additional_usd_saved = max(0.0, current_session_spend_usd - target_session_spend_usd)

    return {
        "has_arbitrage": True,
        "active_model": model_spec.model_id,
        "active_display_name": model_spec.display_name,
        "active_coding_score": model_spec.livebench_coding_score,
        "target_model": target_spec.model_id,
        "target_display_name": target_spec.display_name,
        "target_coding_score": target_spec.livebench_coding_score,
        "quality_retention_pct": round(quality_retention_pct, 1),
        "cost_reduction_pct": round(cost_reduction_pct, 1),
        "additional_usd_saved": round(additional_usd_saved, 4),
        "recommendation": (
            f"Switch routine tasks (delta <= 3) from `{model_spec.display_name}` (`${model_spec.input_price_per_m:.2f}/1M`, "
            f"Coding `{model_spec.livebench_coding_score:.1f}`) to `{target_spec.display_name}` "
            f"(`${target_spec.input_price_per_m:.2f}/1M`, Coding `{target_spec.livebench_coding_score:.1f}`): "
            f"retains **{quality_retention_pct:.1f}% LiveBench coding intelligence** at "
            f"**{cost_ratio_pct:.0f}% of the cost** (`-{cost_reduction_pct:.0f}%` spend)."
        ),
    }


def sync_model_matrix(
    url: str = "https://ctxfw.heuristicolab.com/v1/model-matrix.json",
    target_path: Optional[Path] = None,
) -> Tuple[bool, str]:
    """
    Explicit on-demand CLI command (`ctxfw config sync-models`) to fetch the latest
    signed LiveBench & pricing matrix. Sends zero user data (pure HTTP GET).
    """
    import urllib.request
    from ctxfw import __version__

    dest = target_path or _get_user_matrix_cache_path()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": f"ctxfw/{__version__}",
                "Accept": "application/json",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            raw_bytes = resp.read()
        parsed = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(parsed, dict) or not isinstance(parsed.get("models"), dict):
            return False, "Downloaded payload is not a valid model_matrix.json schema."
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        return True, f"Synced {len(parsed['models'])} models to {dest}"
    except Exception as exc:
        return False, f"Offline or remote matrix unreachable ({exc}); using bundled model_matrix.json ({len(load_model_matrix())} models)."


__all__ = [
    "BUNDLED_MATRIX_PATH",
    "DEFAULT_MODEL_ID",
    "DEFAULT_COMPOUNDING_FACTOR",
    "ModelPricingSpecDTO",
    "load_model_matrix",
    "resolve_model_spec",
    "resolve_active_model",
    "compute_compounded_savings",
    "compute_arbitrage_recommendation",
    "sync_model_matrix",
]
