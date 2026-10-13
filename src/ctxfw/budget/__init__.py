"""ctxfw.budget -- TokenCast Budgeter vendored blueprint (milestone 4.0-M2).

CTXFW Axiomatic Gateway (milestone M2): status VERIFIED | ACI 1.0000
manifest_hash: 66f8c88b0407bc071195d430d5f467a35d4de570bc5e8c9069dc51e96d11d1f5
Sealed blueprint manifest_hash (TokenCast SIG-947678205487bc66, VERIFIED, ACI 1.0000):
    7b7ef06dfc91c02c73bf8117efd362ffecd01cffdb9d0e5a8700be01c874bdae

Vendored, byte-for-byte, from the sealed blueprint (never edited here):
    contracts.py             <- specs/2_pydantic_contracts.py
    schema.sql               <- specs/3_schema_ddl.sql
    blueprint_manifest.json  <- blueprint_manifest.json
``.gitattributes`` pins them as ``-text`` and ``tests/test_tokencast_vendor.py`` re-checks their SHA-256
against the sealed manifest (gate G9). Any contract change requires a new sealed blueprint.

Exported contracts and types:
    SessionTokenBudgetDTO (aliased as TokenBudget)
    TokenTrajectoryForecastDTO (aliased as CostProjection)
    BreakerState (aliased as CircuitBreakerState)
    BreakerEvent (aliased as CircuitBreakerEvent)
    TurnObservationTelemetryDTO
    BudgetEnforcementDecisionDTO
    DecisionKind, FailureClass, transition, estimate_cost_usd, etc.

This package imports nothing heavy at import time (lazy): pydantic models and helper functions
in ``contracts`` load only upon attribute access or direct submodule import.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

__all__ = [
    "CONTRACTS_PATH",
    "MANIFEST_PATH",
    "PACKAGE_DIR",
    "SCHEMA_PATH",
    "load_manifest",
    "load_schema_sql",
    # Architecture directive aliases:
    "TokenBudget",
    "CostProjection",
    "CircuitBreakerState",
    "CircuitBreakerEvent",
    # Canonical vendored contracts and types:
    "SessionTokenBudgetDTO",
    "TurnObservationTelemetryDTO",
    "TokenTrajectoryForecastDTO",
    "BudgetEnforcementDecisionDTO",
    "DecisionKind",
    "FailureClass",
    "BreakerState",
    "BreakerEvent",
    "TokenCastBaseDTO",
    "TERMINAL_STATES",
    "TRANSITION_TABLE",
    "FAILURE_ROUTING",
    "FAILURE_DISPOSITION",
    "transition",
    "ceil_div",
    "ceil_isqrt",
    "estimate_cost_usd",
    "derive_ledger_id",
]

PACKAGE_DIR = Path(__file__).resolve().parent
CONTRACTS_PATH = PACKAGE_DIR / "contracts.py"
SCHEMA_PATH = PACKAGE_DIR / "schema.sql"
MANIFEST_PATH = PACKAGE_DIR / "blueprint_manifest.json"

_ALIASES: dict[str, str] = {
    "TokenBudget": "SessionTokenBudgetDTO",
    "CostProjection": "TokenTrajectoryForecastDTO",
    "CircuitBreakerState": "BreakerState",
    "CircuitBreakerEvent": "BreakerEvent",
}


def load_schema_sql() -> str:
    """Return the sealed DDL text exactly as vendored (UTF-8)."""
    return SCHEMA_PATH.read_text(encoding="utf-8")


def load_manifest() -> dict[str, Any]:
    """Return the sealed blueprint manifest as a dictionary."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def __getattr__(name: str) -> Any:
    if name in _ALIASES:
        from . import contracts

        return getattr(contracts, _ALIASES[name])
    if name in __all__:
        from . import contracts

        return getattr(contracts, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(__all__))


if TYPE_CHECKING:
    from .contracts import (
        FAILURE_DISPOSITION,
        FAILURE_ROUTING,
        TERMINAL_STATES,
        TRANSITION_TABLE,
        BreakerEvent,
        BreakerState,
        BudgetEnforcementDecisionDTO,
        DecisionKind,
        FailureClass,
        SessionTokenBudgetDTO,
        TokenCastBaseDTO,
        TokenTrajectoryForecastDTO,
        TurnObservationTelemetryDTO,
        ceil_div,
        ceil_isqrt,
        derive_ledger_id,
        estimate_cost_usd,
        transition,
    )

    TokenBudget = SessionTokenBudgetDTO
    CostProjection = TokenTrajectoryForecastDTO
    CircuitBreakerState = BreakerState
    CircuitBreakerEvent = BreakerEvent
