"""ctxfw.kernel -- Kernel K of the v4.0 Sovereign Pentad (milestone 4.0-M1).

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000 | 11 negative invariants
manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3

Lazy by design: importing this package imports **nothing** heavy. Submodules (and the
pydantic models inside ``contracts``/``audit_port``) load only when a public name is first
accessed, so ``ctxfw mcp`` pays zero resident-memory cost until a module is actually wired.
"""
from importlib import import_module
from typing import Any, Dict

__all__ = [
    "AuditEventDTO",
    "AuditPort",
    "AuditReceiptDTO",
    "AuditUnavailableError",
    "Clock",
    "FailureClass",
    "FixedClock",
    "ModeGatedAuditPort",
    "ModeState",
    "RetryExhausted",
    "RuntimeMode",
    "SystemUtcClock",
    "classify_failure_class",
    "derive_session_id",
    "make_audit_event",
    "mode_transition",
    "new_session_id",
    "parse_mode",
    "require_utc",
    "resolve_mode",
    "run_with_wal_retry",
]

_LAZY: Dict[str, str] = {
    "AuditEventDTO": "contracts",
    "AuditReceiptDTO": "contracts",
    "ModeState": "contracts",
    "RuntimeMode": "contracts",
    "derive_session_id": "contracts",
    "make_audit_event": "contracts",
    "mode_transition": "contracts",
    "new_session_id": "contracts",
    "parse_mode": "contracts",
    "resolve_mode": "contracts",
    "FailureClass": "failure",
    "classify_failure_class": "failure",
    "Clock": "clock",
    "FixedClock": "clock",
    "SystemUtcClock": "clock",
    "require_utc": "clock",
    "AuditPort": "audit_port",
    "AuditUnavailableError": "audit_port",
    "ModeGatedAuditPort": "audit_port",
    "RetryExhausted": "retry",
    "run_with_wal_retry": "retry",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module 'ctxfw.kernel' has no attribute {name!r}")
    value = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = value
    return value


def __dir__() -> list:
    return sorted(set(globals()) | set(__all__))
