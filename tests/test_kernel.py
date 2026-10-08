"""Tests for the v4.0-M1 kernel (ctxfw.kernel).

manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3
"""
from __future__ import annotations

import ast
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from ctxfw.kernel.audit_port import AuditUnavailableError, ModeGatedAuditPort
from ctxfw.kernel.clock import FixedClock, SystemUtcClock, require_utc
from ctxfw.kernel.contracts import (
    AuditEventDTO,
    AuditReceiptDTO,
    ModeEvent,
    ModeState,
    RuntimeMode,
    derive_session_id,
    make_audit_event,
    mode_transition,
    new_session_id,
    parse_mode,
    resolve_mode,
)
from ctxfw.kernel.failure import FailureClass, classify_failure_class
from ctxfw.kernel.retry import (
    MAX_RETRIES,
    RETRY_BACKOFF_SECONDS,
    RetryExhausted,
    is_transient_sqlite_error,
    run_with_wal_retry,
)

KERNEL_DIR = Path(__file__).resolve().parents[1] / "src" / "ctxfw" / "kernel"
T0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- failure taxonomy
def test_failure_class_canonical_and_exact_names():
    for name in ("TRANSIENT", "DETERMINISTIC", "BUSINESS", "SECURITY"):
        assert classify_failure_class(name).value == name
    assert classify_failure_class(FailureClass.BUSINESS) is FailureClass.BUSINESS


@pytest.mark.parametrize("bad", ["transient", " TRANSIENT", "Business", "", None, 3, True, b"SECURITY", object()])
def test_unknown_failure_class_never_maps_to_benign(bad):
    assert classify_failure_class(bad) is FailureClass.SECURITY


def test_blueprint_failure_class_maps_by_value():
    from ctxfw.audit.contracts import FailureClass as TraceKitFailureClass

    for member in TraceKitFailureClass:
        assert classify_failure_class(member).value == member.value


# ---------------------------------------------------------------- clock
def test_require_utc_rejects_naive_and_offsets():
    assert require_utc(T0) is T0
    with pytest.raises(ValueError):
        require_utc(datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        require_utc(datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2))))
    with pytest.raises(ValueError):
        require_utc("2026-01-01T00:00:00Z")


def test_fixed_clock_never_moves_backwards():
    clock = FixedClock(T0)
    assert clock.now() == T0
    assert clock.advance(timedelta(seconds=5)) == T0 + timedelta(seconds=5)
    with pytest.raises(ValueError):
        clock.advance(timedelta(seconds=-1))
    with pytest.raises(ValueError):
        FixedClock(datetime(2026, 1, 1))


def test_system_clock_is_utc_aware():
    assert require_utc(SystemUtcClock().now())


# ---------------------------------------------------------------- retry
def test_retry_policy_constants_match_blueprints():
    assert MAX_RETRIES == 3
    assert RETRY_BACKOFF_SECONDS == (0.02, 0.04, 0.08)


def test_retry_succeeds_after_transient_errors_with_exact_backoff():
    calls, sleeps = [], []

    def op():
        calls.append(1)
        if len(calls) < 3:
            raise sqlite3.OperationalError("database is locked")
        return "ok"

    assert run_with_wal_retry(op, sleep=sleeps.append) == "ok"
    assert len(calls) == 3
    assert sleeps == [0.02, 0.04]


def test_retry_exhaustion_after_three_retries():
    calls, sleeps = [], []

    def op():
        calls.append(1)
        raise sqlite3.OperationalError("database is locked")

    with pytest.raises(RetryExhausted) as info:
        run_with_wal_retry(op, sleep=sleeps.append)
    assert len(calls) == 4  # 1 attempt + 3 retries, never more
    assert sleeps == [0.02, 0.04, 0.08]
    assert info.value.attempts == 4


def test_retry_never_retries_non_transient():
    calls, sleeps = [], []

    def op():
        calls.append(1)
        raise sqlite3.OperationalError("no such table: x")

    with pytest.raises(sqlite3.OperationalError):
        run_with_wal_retry(op, sleep=sleeps.append)
    assert len(calls) == 1 and sleeps == []

    def op2():
        calls.append(1)
        raise ValueError("bad")

    with pytest.raises(ValueError):
        run_with_wal_retry(op2, sleep=sleeps.append)
    assert sleeps == []


def test_is_transient_sqlite_error():
    assert is_transient_sqlite_error(sqlite3.OperationalError("database is locked"))
    assert not is_transient_sqlite_error(sqlite3.OperationalError("disk I/O error"))
    assert not is_transient_sqlite_error(RuntimeError("database is locked"))


# ---------------------------------------------------------------- runtime mode FSM
def test_mode_default_is_shadow_when_unset():
    assert resolve_mode("CTXFW_TEST_MODE_UNSET", environ={}) is RuntimeMode.SHADOW


@pytest.mark.parametrize("value,expected", [("off", RuntimeMode.OFF), ("shadow", RuntimeMode.SHADOW), ("enforce", RuntimeMode.ENFORCE)])
def test_mode_parse_exact(value, expected):
    assert parse_mode(value) is expected
    assert resolve_mode("X", environ={"X": value}) is expected


@pytest.mark.parametrize("bad", ["", "OFF", "Shadow", " shadow", "shadow ", "on", "true", None, 1, b"off"])
def test_invalid_mode_is_never_silently_accepted(bad):
    with pytest.raises(ValueError):
        parse_mode(bad)
    if isinstance(bad, str):
        with pytest.raises(ValueError):
            resolve_mode("X", environ={"X": bad})


def test_mode_transition_is_total_and_rejected_absorbs():
    assert mode_transition(ModeState.OFF, ModeEvent.SET_ENFORCE) is ModeState.ENFORCE
    assert mode_transition(ModeState.ENFORCE, ModeEvent.SET_OFF) is ModeState.OFF
    assert mode_transition(ModeState.SHADOW, ModeEvent.INVALID_VALUE) is ModeState.REJECTED
    for event in ModeEvent:
        assert mode_transition(ModeState.REJECTED, event) is ModeState.REJECTED
    assert mode_transition("OFF", ModeEvent.SET_OFF) is ModeState.REJECTED
    assert mode_transition(ModeState.OFF, "SET_OFF") is ModeState.REJECTED
    assert mode_transition(None, None) is ModeState.REJECTED


# ---------------------------------------------------------------- audit envelope
def test_session_ids_match_pattern():
    assert derive_session_id("a", "b") == derive_session_id("a", "b")
    assert derive_session_id("a", "b") != derive_session_id("ab")
    sid = new_session_id()
    assert sid.startswith("SES-") and len(sid) == 36
    with pytest.raises(ValueError):
        derive_session_id()
    with pytest.raises(ValueError):
        derive_session_id(1)  # type: ignore[arg-type]


def test_make_audit_event_hashes_at_boundary_and_uses_injected_clock():
    clock = FixedClock(T0)
    sid = derive_session_id("t")
    event = make_audit_event(sid, "do the thing", "plan: A then B", "prune_file", "payload", clock)
    assert event.timestamp_utc == T0
    assert event.intent_sha256 != event.reasoning_sha256
    assert "do the thing" not in event.model_dump_json()  # raw text never retained
    with pytest.raises(ValidationError):
        event.session_id = "SES-other"  # frozen


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(user_prompt=""),
        dict(user_prompt="x" * 65_537),
        dict(plan_summary="x" * 16_385),
        dict(tool_or_file="bad\x00name"),
        dict(tool_or_file="x" * 513),
        dict(payload=""),
    ],
)
def test_make_audit_event_rejects_out_of_bounds(kwargs):
    base = dict(session_id=derive_session_id("t"), user_prompt="p", plan_summary="s", tool_or_file="t", payload="x", clock=FixedClock(T0))
    base.update(kwargs)
    with pytest.raises((ValueError, ValidationError)):
        make_audit_event(**base)


def test_audit_dtos_reject_naive_timestamp_extras_and_bad_digests():
    good = dict(
        session_id=derive_session_id("t"),
        intent_sha256="a" * 64,
        reasoning_sha256="b" * 64,
        tool_or_file="tool",
        payload_sha256="c" * 64,
        timestamp_utc=T0,
    )
    AuditEventDTO(**good)
    with pytest.raises(ValidationError):
        AuditEventDTO(**{**good, "timestamp_utc": datetime(2026, 1, 1)})
    with pytest.raises(ValidationError):
        AuditEventDTO(**{**good, "intent_sha256": "A" * 64})
    with pytest.raises(ValidationError):
        AuditEventDTO(**{**good, "extra_field": 1})
    with pytest.raises(ValidationError):
        AuditReceiptDTO(session_id=good["session_id"], block_seq=1_000_001, block_hash="d" * 64)
    AuditReceiptDTO(session_id=good["session_id"], block_seq=0, block_hash="d" * 64)


# ---------------------------------------------------------------- mode-gated port
class _Recorder:
    def __init__(self, fail: bool = False):
        self.fail, self.events = fail, []

    def append(self, event):
        if self.fail:
            raise RuntimeError("boom")
        self.events.append(event)
        return AuditReceiptDTO(session_id=event.session_id, block_seq=len(self.events) - 1, block_hash="e" * 64)


def _event():
    return make_audit_event(derive_session_id("t"), "p", "s", "tool", "x", FixedClock(T0))


def test_off_mode_never_calls_inner():
    inner = _Recorder()
    port = ModeGatedAuditPort(inner, RuntimeMode.OFF)
    assert port.append(_event()) is None
    assert inner.events == []


def test_shadow_mode_swallows_failures_and_reports():
    seen = []
    port = ModeGatedAuditPort(_Recorder(fail=True), RuntimeMode.SHADOW, on_error=seen.append)
    assert port.append(_event()) is None
    assert len(seen) == 1 and isinstance(seen[0], RuntimeError)

    def bad_hook(_):
        raise RuntimeError("hook")

    assert ModeGatedAuditPort(_Recorder(fail=True), RuntimeMode.SHADOW, on_error=bad_hook).append(_event()) is None
    assert ModeGatedAuditPort(None, RuntimeMode.SHADOW).append(_event()) is None
    ok = ModeGatedAuditPort(_Recorder(), RuntimeMode.SHADOW).append(_event())
    assert ok is not None and ok.block_seq == 0


def test_enforce_mode_is_fail_closed():
    with pytest.raises(RuntimeError):
        ModeGatedAuditPort(_Recorder(fail=True), RuntimeMode.ENFORCE).append(_event())
    with pytest.raises(AuditUnavailableError):
        ModeGatedAuditPort(None, RuntimeMode.ENFORCE).append(_event())
    assert ModeGatedAuditPort(_Recorder(), RuntimeMode.ENFORCE).append(_event()) is not None


def test_gated_port_requires_runtime_mode():
    with pytest.raises(ValueError):
        ModeGatedAuditPort(None, "shadow")  # type: ignore[arg-type]


# ---------------------------------------------------------------- structural invariants
FORBIDDEN_MODULES = {
    "ctxfw.mcp", "ctxfw.mcp_server", "ctxfw.proxy", "ctxfw.cli", "ctxfw.service",
    "httpx", "requests", "urllib", "urllib3", "aiohttp", "socket", "http", "fastapi", "uvicorn", "websockets",
}


def _imported_modules(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_kernel_never_imports_host_entrypoints_or_network_libs():
    for path in sorted(KERNEL_DIR.glob("*.py")):
        for module in _imported_modules(path):
            root = module.split(".")[0]
            assert module not in FORBIDDEN_MODULES and root not in FORBIDDEN_MODULES, f"{path.name} imports {module}"
            if root == "ctxfw":
                assert module.startswith("ctxfw.kernel"), f"{path.name} imports non-kernel {module}"


def test_kernel_never_writes_to_stdout(capsys):
    port = ModeGatedAuditPort(_Recorder(fail=True), RuntimeMode.SHADOW, on_error=lambda e: None)
    port.append(_event())
    classify_failure_class("nope")
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    for path in KERNEL_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "print", f"{path.name} calls print()"
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
                assert not (node.value.attr == "stdout" and node.attr in {"write", "flush"}), f"{path.name} writes stdout"


def test_importing_host_modules_does_not_load_kernel_or_audit():
    code = (
        "import sys, ctxfw, ctxfw.mcp, ctxfw.core.contracts, ctxfw.storage.cache;"
        "bad=[m for m in sys.modules if m=='ctxfw.kernel' or m.startswith('ctxfw.kernel.')"
        " or m=='ctxfw.audit' or m.startswith('ctxfw.audit.')];"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_kernel_package_import_is_lazy():
    code = (
        "import sys, ctxfw.kernel;"
        "loaded=[m for m in sys.modules if m.startswith('ctxfw.kernel.')];"
        "print(loaded);"
        "ctxfw.kernel.FailureClass;"
        "print(sorted(m for m in sys.modules if m.startswith('ctxfw.kernel.')))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    first, second = out.stdout.strip().splitlines()
    assert first == "[]"
    assert second == "['ctxfw.kernel.failure']"
