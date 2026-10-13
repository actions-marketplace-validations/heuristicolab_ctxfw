# manifest_hash: f65c9e8fcc9152df8275d94641f7e9d4c8bd8e88072359102e32b1e849187710
"""ctxfw.swegate -- SWE-Gate CI Verifier vendored blueprint contracts and schema (milestone 4.0-M4).

CTXFW Axiomatic Gateway (milestone M4-P1): status VERIFIED | ACI 1.0000
manifest_hash: f65c9e8fcc9152df8275d94641f7e9d4c8bd8e88072359102e32b1e849187710
Sealed blueprint manifest_hash (SWE-Gate SIG-673052a2a791ec2b, VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f

Vendored, byte-for-byte, from the sealed blueprint (never edited here):
    contracts.py             <- specs/2_pydantic_contracts.py
    schema.sql               <- specs/3_schema_ddl.sql
    blueprint_manifest.json  <- blueprint_manifest.json
``.gitattributes`` pins them as ``-text`` and ``tests/test_swegate_vendor.py`` re-checks their SHA-256
against the sealed manifest (gate G9). Any contract change requires a new sealed blueprint.

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
    # DTOs:
    "SweGateBaseDTO",
    "PatchMetadataDTO",
    "FunctionalTestResultDTO",
    "ArchitecturalConstraintRuleDTO",
    "PatchInspectionAuditDTO",
    # Enums:
    "AuthorKind",
    "FunctionalVerdict",
    "GateVerdict",
    "ViolationType",
    "FailureClass",
    "GateState",
    "GateEvent",
    # FSM tables, failure routing and helpers:
    "TERMINAL_STATES",
    "TRANSITION_TABLE",
    "GATE_VERDICT_TO_TERMINAL",
    "FAILURE_ROUTING",
    "FAILURE_DISPOSITION",
    "transition",
    "classify_failure",
    "sha256_hex",
    "derive_gate_id",
    "format_violation",
    "split_violation",
    "decide_gate_verdict",
    # Annotated types:
    "CommitSha",
    "PrId",
    "DiffSizeBytes",
    "TestsCount",
    "MaxCyclomaticDelta",
    "CyclomaticDelta",
    "ModuleName",
    "ViolationEntry",
    # Constants and pattern bounds:
    "COMMIT_SHA_LEN",
    "COMMIT_SHA_PATTERN",
    "PR_ID_MIN",
    "PR_ID_MAX",
    "DIFF_SIZE_MIN",
    "DIFF_SIZE_MAX",
    "DIFF_LINES_MAX",
    "TESTS_COUNT_MIN",
    "TESTS_COUNT_MAX",
    "MAX_CYCLOMATIC_DELTA_MIN",
    "MAX_CYCLOMATIC_DELTA_MAX",
    "CYCLOMATIC_DELTA_MIN",
    "CYCLOMATIC_DELTA_MAX",
    "DISALLOWED_MODULES_MAX",
    "MODULE_NAME_MAX",
    "VIOLATIONS_MAX",
    "VIOLATION_ENTRY_MAX",
    "VIOLATION_LOCATION_MAX",
    "WAL_RETRY_ATTEMPTS_MAX",
    "INSPECTION_LATENCY_BUDGET_MS",
    "REPO_ID_PATTERN",
    "EVALUATION_ID_PATTERN",
    "VIOLATION_ID_PATTERN",
    "RULE_ID_PATTERN",
    "MODULE_NAME_PATTERN",
    "VIOLATION_ENTRY_PATTERN",
]

PACKAGE_DIR = Path(__file__).resolve().parent
CONTRACTS_PATH = PACKAGE_DIR / "contracts.py"
SCHEMA_PATH = PACKAGE_DIR / "schema.sql"
MANIFEST_PATH = PACKAGE_DIR / "blueprint_manifest.json"

_SUBMODULES = frozenset({"contracts"})


def load_schema_sql() -> str:
    """Return the sealed DDL text exactly as vendored (UTF-8)."""
    return SCHEMA_PATH.read_text(encoding="utf-8")


def load_manifest() -> dict[str, Any]:
    """Return the sealed blueprint manifest as a dictionary."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def __getattr__(name: str) -> Any:
    if name in _SUBMODULES:
        import importlib

        mod = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = mod
        return mod
    if name in __all__:
        from . import contracts

        return getattr(contracts, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(__all__) | set(_SUBMODULES))


if TYPE_CHECKING:
    from .contracts import (
        COMMIT_SHA_LEN,
        COMMIT_SHA_PATTERN,
        CYCLOMATIC_DELTA_MAX,
        CYCLOMATIC_DELTA_MIN,
        DIFF_LINES_MAX,
        DIFF_SIZE_MAX,
        DIFF_SIZE_MIN,
        DISALLOWED_MODULES_MAX,
        EVALUATION_ID_PATTERN,
        FAILURE_DISPOSITION,
        FAILURE_ROUTING,
        GATE_VERDICT_TO_TERMINAL,
        INSPECTION_LATENCY_BUDGET_MS,
        MAX_CYCLOMATIC_DELTA_MAX,
        MAX_CYCLOMATIC_DELTA_MIN,
        MODULE_NAME_MAX,
        MODULE_NAME_PATTERN,
        PR_ID_MAX,
        PR_ID_MIN,
        REPO_ID_PATTERN,
        RULE_ID_PATTERN,
        TERMINAL_STATES,
        TESTS_COUNT_MAX,
        TESTS_COUNT_MIN,
        TRANSITION_TABLE,
        VIOLATION_ENTRY_MAX,
        VIOLATION_ENTRY_PATTERN,
        VIOLATION_ID_PATTERN,
        VIOLATION_LOCATION_MAX,
        VIOLATIONS_MAX,
        WAL_RETRY_ATTEMPTS_MAX,
        ArchitecturalConstraintRuleDTO,
        AuthorKind,
        CommitSha,
        CyclomaticDelta,
        DiffSizeBytes,
        FailureClass,
        FunctionalTestResultDTO,
        FunctionalVerdict,
        GateEvent,
        GateState,
        GateVerdict,
        MaxCyclomaticDelta,
        ModuleName,
        PatchInspectionAuditDTO,
        PatchMetadataDTO,
        PrId,
        SweGateBaseDTO,
        TestsCount,
        ViolationEntry,
        ViolationType,
        classify_failure,
        decide_gate_verdict,
        derive_gate_id,
        format_violation,
        sha256_hex,
        split_violation,
        transition,
    )
