# manifest_hash: 46c18f0959a0f31e56e83b719078e1331678c6ed972bdbc93ef075205f583f98
"""ctxfw.sara -- SARA Action Induction Runtime Authorization vendored blueprint (milestone 4.0-M3).

CTXFW Axiomatic Gateway (milestone M3): status VERIFIED | ACI 1.0000
manifest_hash: 46c18f0959a0f31e56e83b719078e1331678c6ed972bdbc93ef075205f583f98
Sealed blueprint manifest_hash (SARA SIG-0d2acf53b92882b0, VERIFIED, ACI 1.0000):
    51d819312f8dd802981a7b7d97b9d6397316738ded76c94161a9f147411c94ea

Vendored, byte-for-byte, from the sealed blueprint (never edited here):
    contracts.py             <- specs/2_pydantic_contracts.py
    schema.sql               <- specs/3_schema_ddl.sql
    blueprint_manifest.json  <- blueprint_manifest.json
``.gitattributes`` pins them as ``-text`` and ``tests/test_sara_vendor.py`` re-checks their SHA-256
against the sealed manifest (gate G9). Any contract change requires a new sealed blueprint.

Exported contracts and types:
    UntrustedObservationDTO (aliased to RawToolObservationDTO)
    AuthorizedPolicyDTO (aliased to AuthorizationPolicyRuleDTO)
    ToolExecutionSourceDTO
    RawToolObservationDTO
    InductionDirectiveDTO
    AuthorizationPolicyRuleDTO
    AuthorizationVerdictDTO
    SourceType
    VerdictKind
    DirectiveKind
    FailureClass
    SaraState
    SaraEvent
    TERMINAL_STATES
    SARA_TRANSITIONS
    FAILURE_ROUTING
    SaraBaseDTO
    transition
    verdict_for_risk
    observation_digest
    load_schema_sql
    load_manifest

This package imports nothing heavy at import time (lazy): pydantic models and helper functions
load only upon attribute access or direct submodule import.
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
    "UntrustedObservationDTO",
    "AuthorizedPolicyDTO",
    # Canonical vendored contracts and types:
    "ToolExecutionSourceDTO",
    "RawToolObservationDTO",
    "InductionDirectiveDTO",
    "AuthorizationPolicyRuleDTO",
    "AuthorizationVerdictDTO",
    "SourceType",
    "VerdictKind",
    "DirectiveKind",
    "FailureClass",
    "SaraState",
    "SaraEvent",
    "SaraBaseDTO",
    "TERMINAL_STATES",
    "SARA_TRANSITIONS",
    "FAILURE_ROUTING",
    "transition",
    "verdict_for_risk",
    "observation_digest",
    # Constants:
    "MAX_RAW_OUTPUT_CHARS",
    "MAX_DIRECTIVES_PER_OBSERVATION",
    "MAX_DIRECTIVE_TEXT_CHARS",
    "MAX_POLICY_ITEMS",
    "MAX_POLICY_ITEM_CHARS",
    "MAX_POLICY_MASK",
    "RISK_QUARANTINE_THRESHOLD",
    "RISK_STRIP_THRESHOLD",
    "GATE_LATENCY_BUDGET_MS",
    "TOOL_NAME_PATTERN",
    "EXECUTION_ID_PATTERN",
    "POLICY_ID_PATTERN",
    "SHA256_PATTERN",
]

PACKAGE_DIR = Path(__file__).resolve().parent
CONTRACTS_PATH = PACKAGE_DIR / "contracts.py"
SCHEMA_PATH = PACKAGE_DIR / "schema.sql"
MANIFEST_PATH = PACKAGE_DIR / "blueprint_manifest.json"

_ALIASES: dict[str, str] = {
    "UntrustedObservationDTO": "RawToolObservationDTO",
    "AuthorizedPolicyDTO": "AuthorizationPolicyRuleDTO",
}


def load_schema_sql() -> str:
    """Return the sealed DDL text exactly as vendored (UTF-8)."""
    return SCHEMA_PATH.read_text(encoding="utf-8")


def load_manifest() -> dict[str, Any]:
    """Return the sealed blueprint manifest as a dictionary."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def __getattr__(name: str) -> Any:
    if name == "contracts":
        import importlib

        mod = importlib.import_module(f"{__name__}.contracts")
        globals()["contracts"] = mod
        return mod
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
        EXECUTION_ID_PATTERN,
        GATE_LATENCY_BUDGET_MS,
        MAX_DIRECTIVE_TEXT_CHARS,
        MAX_DIRECTIVES_PER_OBSERVATION,
        MAX_POLICY_ITEM_CHARS,
        MAX_POLICY_ITEMS,
        MAX_POLICY_MASK,
        MAX_RAW_OUTPUT_CHARS,
        POLICY_ID_PATTERN,
        RISK_QUARANTINE_THRESHOLD,
        RISK_STRIP_THRESHOLD,
        SARA_TRANSITIONS,
        SHA256_PATTERN,
        TERMINAL_STATES,
        TOOL_NAME_PATTERN,
        AuthorizationPolicyRuleDTO,
        AuthorizationVerdictDTO,
        DirectiveKind,
        FailureClass,
        InductionDirectiveDTO,
        RawToolObservationDTO,
        SaraBaseDTO,
        SaraEvent,
        SaraState,
        SourceType,
        ToolExecutionSourceDTO,
        VerdictKind,
        observation_digest,
        transition,
        verdict_for_risk,
    )

    UntrustedObservationDTO = RawToolObservationDTO
    AuthorizedPolicyDTO = AuthorizationPolicyRuleDTO
