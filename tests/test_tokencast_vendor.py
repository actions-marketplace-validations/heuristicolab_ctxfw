"""Gate G9 for ctxfw.budget: vendored TokenCast blueprint files must stay byte-for-byte sealed.

manifest_hash: 66f8c88b0407bc071195d430d5f467a35d4de570bc5e8c9069dc51e96d11d1f5
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from decimal import Decimal

import pytest
from pydantic import ValidationError

from ctxfw.budget import (
    CONTRACTS_PATH,
    MANIFEST_PATH,
    SCHEMA_PATH,
    CircuitBreakerEvent,
    CircuitBreakerState,
    CostProjection,
    TokenBudget,
    load_manifest,
    load_schema_sql,
)

BLUEPRINT_MANIFEST_HASH = "7b7ef06dfc91c02c73bf8117efd362ffecd01cffdb9d0e5a8700be01c874bdae"
EXPECTED_CONTRACTS_SHA256 = "4ac36c42e0173f9f6d58e31dd857128dec452a9b37ce8f826bfbc42e4b597fac"
EXPECTED_SCHEMA_SHA256 = "eaf5befdc878c5b834b041f4297293c1a3a090cd18847692e5d8beaac2083fb8"


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_manifest_is_the_sealed_tokencast_manifest():
    manifest = load_manifest()
    assert manifest["signal_id"] == "SIG-947678205487bc66"
    assert manifest["blueprint_id"] == "BP-SIG-947678205487bc66-TOKENCAST-BUDGETER"
    assert manifest["proposal_id"] == "PROP-947678205487bc66-H1"
    assert manifest["horizon"] == "HORIZON_1"
    assert manifest["ctxfw"]["status"] == "VERIFIED"
    assert manifest["ctxfw"]["aci_score"] == 1.0
    assert manifest["ctxfw"]["manifest_hash"] == BLUEPRINT_MANIFEST_HASH
    assert manifest["hermetic_compiler"]["passed_tests"] == 46


def test_vendored_contracts_and_schema_match_sealed_sha256():
    deliverables = load_manifest()["deliverables"]
    assert deliverables["specs/2_pydantic_contracts.py"]["sha256"] == EXPECTED_CONTRACTS_SHA256
    assert deliverables["specs/3_schema_ddl.sql"]["sha256"] == EXPECTED_SCHEMA_SHA256
    assert _sha256(CONTRACTS_PATH) == EXPECTED_CONTRACTS_SHA256
    assert _sha256(SCHEMA_PATH) == EXPECTED_SCHEMA_SHA256


def test_vendored_files_carry_the_blueprint_hash_header():
    assert BLUEPRINT_MANIFEST_HASH in CONTRACTS_PATH.read_text(encoding="utf-8")
    assert BLUEPRINT_MANIFEST_HASH in load_schema_sql()


def test_vendored_files_have_no_crlf():
    for path in (CONTRACTS_PATH, SCHEMA_PATH, MANIFEST_PATH):
        assert b"\r" not in path.read_bytes(), f"{path.name} was rewritten with CR (line-ending drift)"


def test_budget_package_import_is_lazy():
    code = (
        "import sys, ctxfw.budget;"
        "print([m for m in sys.modules if m=='ctxfw.budget.contracts'])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_pydantic_v2_schemas_instantiate_without_side_effects():
    from ctxfw.budget import (
        BudgetEnforcementDecisionDTO,
        DecisionKind,
        SessionTokenBudgetDTO,
        TokenTrajectoryForecastDTO,
        TurnObservationTelemetryDTO,
    )

    # Validate aliases
    assert TokenBudget is SessionTokenBudgetDTO
    assert CostProjection is TokenTrajectoryForecastDTO

    # SessionTokenBudgetDTO
    budget = TokenBudget(
        session_id="SES-0001-test",
        soft_limit_tokens=80_000,
        hard_limit_tokens=100_000,
        max_turns=30,
    )
    assert budget.session_id == "SES-0001-test"
    assert budget.soft_limit_tokens == 80_000
    assert budget.hard_limit_tokens == 100_000
    assert budget.max_turns == 30

    # TurnObservationTelemetryDTO
    telem = TurnObservationTelemetryDTO(
        turn_index=0,
        prompt_tokens=1500,
        completion_tokens=500,
        tool_count=2,
        elapsed_ms=1200,
    )
    assert telem.turn_index == 0
    assert telem.total_tokens == 2000

    # TokenTrajectoryForecastDTO
    forecast = CostProjection(
        forecast_turns=(0, 1, 2, 3),
        predicted_cumulative_tokens=8500,
        confidence_interval=(8000, 9500),
    )
    assert forecast.predicted_cumulative_tokens == 8500
    assert forecast.confidence_interval == (8000, 9500)

    # BudgetEnforcementDecisionDTO
    decision = BudgetEnforcementDecisionDTO(
        session_id="SES-0001-test",
        decision=DecisionKind.CONTINUE,
        predicted_overrun=False,
        estimated_cost_usd=Decimal("0.0255"),
    )
    assert decision.decision is DecisionKind.CONTINUE
    assert decision.predicted_overrun is False
    assert decision.estimated_cost_usd == Decimal("0.0255")


def test_pydantic_v2_strict_validation_and_negative_invariants():
    from ctxfw.budget import (
        BudgetEnforcementDecisionDTO,
        DecisionKind,
        SessionTokenBudgetDTO,
        TokenTrajectoryForecastDTO,
        TurnObservationTelemetryDTO,
    )

    # INV-1: soft_limit > hard_limit must raise
    with pytest.raises(ValidationError, match="soft_limit_tokens must be <= hard_limit_tokens"):
        SessionTokenBudgetDTO(
            session_id="SES-invalid-bounds",
            soft_limit_tokens=100_000,
            hard_limit_tokens=50_000,
            max_turns=10,
        )

    # INV-2: Negative token counts must be rejected
    with pytest.raises(ValidationError):
        SessionTokenBudgetDTO(
            session_id="SES-negative-tokens",
            soft_limit_tokens=-1,
            hard_limit_tokens=100_000,
            max_turns=10,
        )

    # Closed bounds: max_turns in [1, 1024]
    with pytest.raises(ValidationError):
        SessionTokenBudgetDTO(
            session_id="SES-valid-0001",
            soft_limit_tokens=1000,
            hard_limit_tokens=2000,
            max_turns=0,
        )
    with pytest.raises(ValidationError):
        SessionTokenBudgetDTO(
            session_id="SES-valid-0001",
            soft_limit_tokens=1000,
            hard_limit_tokens=2000,
            max_turns=1025,
        )

    # Session ID pattern: ^SES-[A-Za-z0-9_-]{4,64}$
    with pytest.raises(ValidationError):
        SessionTokenBudgetDTO(
            session_id="BAD-PREFIX-001",
            soft_limit_tokens=1000,
            hard_limit_tokens=2000,
            max_turns=10,
        )

    # INV-3: Strict typing (no str/float coercion)
    with pytest.raises(ValidationError):
        TurnObservationTelemetryDTO(
            turn_index="0",  # type: ignore[arg-type]
            prompt_tokens=100,
            completion_tokens=50,
            tool_count=1,
            elapsed_ms=10,
        )

    # INV-4: Immutability (frozen=True) and no extra fields (extra="forbid")
    budget = SessionTokenBudgetDTO(
        session_id="SES-frozen-0001",
        soft_limit_tokens=1000,
        hard_limit_tokens=2000,
        max_turns=10,
    )
    with pytest.raises(ValidationError):
        budget.hard_limit_tokens = 3000  # type: ignore[misc]

    with pytest.raises(ValidationError):
        SessionTokenBudgetDTO(
            session_id="SES-extra-0001",
            soft_limit_tokens=1000,
            hard_limit_tokens=2000,
            max_turns=10,
            undeclared_field="illegal",  # type: ignore[call-arg]
        )

    # INV-6: Cost scale must be exactly 4 decimal places
    with pytest.raises(ValidationError, match="estimated_cost_usd must have exactly 4 decimal places"):
        BudgetEnforcementDecisionDTO(
            session_id="SES-bad-cost-001",
            decision=DecisionKind.CONTINUE,
            predicted_overrun=False,
            estimated_cost_usd=Decimal("1.50"),
        )

    # INV-7: Decision consistency with predicted_overrun
    with pytest.raises(ValidationError, match="predicted_overrun is inconsistent with decision"):
        BudgetEnforcementDecisionDTO(
            session_id="SES-inconsistent-01",
            decision=DecisionKind.CONTINUE,
            predicted_overrun=True,  # CONTINUE cannot have predicted_overrun=True
            estimated_cost_usd=Decimal("0.0100"),
        )

    with pytest.raises(ValidationError, match="predicted_overrun is inconsistent with decision"):
        BudgetEnforcementDecisionDTO(
            session_id="SES-inconsistent-02",
            decision=DecisionKind.EMERGENCY_HALT,
            predicted_overrun=False,  # HALT must have predicted_overrun=True
            estimated_cost_usd=Decimal("0.0100"),
        )

    # INV-8: Confidence interval must contain point forecast
    with pytest.raises(ValidationError, match="confidence_interval must satisfy low <= predicted <= high"):
        TokenTrajectoryForecastDTO(
            forecast_turns=(0, 1),
            predicted_cumulative_tokens=5000,
            confidence_interval=(6000, 7000),  # 5000 is outside
        )

    # Forecast turns must be contiguous and ascending
    with pytest.raises(ValidationError, match="forecast_turns must be contiguous and ascending"):
        TokenTrajectoryForecastDTO(
            forecast_turns=(0, 2),  # non-contiguous
            predicted_cumulative_tokens=5000,
            confidence_interval=(4000, 6000),
        )


def test_tokencast_fsm_total_and_fail_closed():
    from ctxfw.budget import (
        FAILURE_DISPOSITION,
        FAILURE_ROUTING,
        TERMINAL_STATES,
        BreakerEvent,
        BreakerState,
        FailureClass,
        ceil_div,
        ceil_isqrt,
        derive_ledger_id,
        estimate_cost_usd,
        transition,
    )

    # Aliases
    assert CircuitBreakerState is BreakerState
    assert CircuitBreakerEvent is BreakerEvent

    # Terminal states
    assert BreakerState.RECORDED in TERMINAL_STATES
    assert BreakerState.REJECTED_INVALID in TERMINAL_STATES

    # Standard transitions
    assert transition(BreakerState.RECEIVED, BreakerEvent.TELEMETRY_OK) is BreakerState.INGESTED
    assert transition(BreakerState.RECEIVED, BreakerEvent.VALIDATION_FAIL) is BreakerState.REJECTED_INVALID
    assert transition(BreakerState.INGESTED, BreakerEvent.FORECAST_OK) is BreakerState.FORECASTED
    assert transition(BreakerState.FORECASTED, BreakerEvent.WITHIN_SOFT) is BreakerState.DECIDED_CONTINUE
    assert transition(BreakerState.FORECASTED, BreakerEvent.SOFT_CROSSED) is BreakerState.DECIDED_PRUNE
    assert transition(BreakerState.FORECASTED, BreakerEvent.HARD_CROSSED) is BreakerState.DECIDED_HALT
    assert transition(BreakerState.DECIDED_CONTINUE, BreakerEvent.WAL_COMMIT) is BreakerState.RECORDED

    # Total: unknown state or event collapses to REJECTED_INVALID (fail-closed)
    assert transition("invalid_state", BreakerEvent.TELEMETRY_OK) is BreakerState.REJECTED_INVALID
    assert transition(BreakerState.RECEIVED, "invalid_event") is BreakerState.REJECTED_INVALID
    assert transition("garbage", "garbage") is BreakerState.REJECTED_INVALID

    # Once terminal, remains in terminal state
    assert transition(BreakerState.RECORDED, BreakerEvent.TELEMETRY_OK) is BreakerState.RECORDED
    assert transition(BreakerState.REJECTED_INVALID, BreakerEvent.TELEMETRY_OK) is BreakerState.REJECTED_INVALID

    # Pure deterministic cost calculation
    cost = estimate_cost_usd(1000, Decimal("2.5000"))
    assert cost == Decimal("2.5000")
    cost_fractional = estimate_cost_usd(100, Decimal("2.5000"))
    assert cost_fractional == Decimal("0.2500")

    with pytest.raises(TypeError, match="usd_per_1k_tokens must be Decimal"):
        estimate_cost_usd(1000, 2.5)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="predicted_tokens must be int"):
        estimate_cost_usd(100.5, Decimal("2.5000"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="predicted_tokens out of range"):
        estimate_cost_usd(-1, Decimal("2.5000"))
    with pytest.raises(ValueError, match="usd_per_1k_tokens out of range"):
        estimate_cost_usd(1000, Decimal("-0.0001"))

    # Pure deterministic helpers: ceil_div, ceil_isqrt, derive_ledger_id
    assert ceil_div(10, 3) == 4
    assert ceil_div(9, 3) == 3
    assert ceil_div(0, 5) == 0
    with pytest.raises(ValueError, match="denominator must be > 0"):
        ceil_div(10, 0)
    with pytest.raises(ValueError, match="denominator must be > 0"):
        ceil_div(10, -1)

    assert ceil_isqrt(10) == 4
    assert ceil_isqrt(9) == 3
    assert ceil_isqrt(0) == 0
    with pytest.raises(ValueError, match="value must be >= 0"):
        ceil_isqrt(-1)

    tel_id = derive_ledger_id("TEL-", "SES-001", 0)
    assert tel_id.startswith("TEL-") and len(tel_id) == 20
    evt_id = derive_ledger_id("EVT-", "SES-001", "CONTINUE")
    assert evt_id.startswith("EVT-") and len(evt_id) == 20
    with pytest.raises(ValueError, match="prefix must be 'TEL-' or 'EVT-'"):
        derive_ledger_id("BAD-", 1)

    # Failure taxonomy: complete coverage
    for code, f_class in FAILURE_ROUTING.items():
        assert isinstance(f_class, FailureClass)
        assert f_class in FAILURE_DISPOSITION
        assert "HALT" in FAILURE_DISPOSITION[f_class] or "REJECT" in FAILURE_DISPOSITION[f_class]


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 37, 0), reason="sealed DDL requires SQLite >= 3.37")
def test_sealed_schema_loads_and_has_append_only_triggers(tmp_path):
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(load_schema_sql())
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"tokencast_session_budgets", "tokencast_turn_telemetry", "tokencast_enforcement_events"} <= tables

        triggers = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert len(triggers) == 9
        assert "trg_tokencast_budgets_no_update" in triggers
        assert "trg_tokencast_telemetry_no_update" in triggers
        assert "trg_tokencast_events_no_update" in triggers
        assert "trg_tokencast_telemetry_sequential" in triggers
        assert "trg_tokencast_telemetry_max_turns" in triggers
        assert "trg_tokencast_telemetry_halt_latch" in triggers
        assert "trg_tokencast_events_halt_latch" in triggers
        assert "trg_tokencast_telemetry_no_direct_delete" in triggers
        assert "trg_tokencast_events_no_direct_delete" in triggers

        # 1. Parent budget insert
        conn.execute(
            "INSERT INTO tokencast_session_budgets (session_id, soft_limit_tokens, hard_limit_tokens, max_turns) "
            "VALUES ('SES-test-append-only', 1000, 2000, 3)"
        )
        with pytest.raises(sqlite3.IntegrityError, match="tokencast_session_budgets is immutable: UPDATE forbidden"):
            conn.execute("UPDATE tokencast_session_budgets SET max_turns = 20 WHERE session_id = 'SES-test-append-only'")

        # 2. Sequential turns trigger
        with pytest.raises(sqlite3.IntegrityError, match="turn_index must be contiguous starting at 0"):
            conn.execute(
                "INSERT INTO tokencast_turn_telemetry (telemetry_id, session_id, turn_index, tokens_used) "
                "VALUES ('TEL-test-0001', 'SES-test-append-only', 1, 100)"
            )

        conn.execute(
            "INSERT INTO tokencast_turn_telemetry (telemetry_id, session_id, turn_index, tokens_used) "
            "VALUES ('TEL-test-0000', 'SES-test-append-only', 0, 100)"
        )
        conn.execute(
            "INSERT INTO tokencast_turn_telemetry (telemetry_id, session_id, turn_index, tokens_used) "
            "VALUES ('TEL-test-0001', 'SES-test-append-only', 1, 150)"
        )

        # UPDATE on telemetry forbidden
        with pytest.raises(sqlite3.IntegrityError, match="tokencast_turn_telemetry is immutable: UPDATE forbidden"):
            conn.execute("UPDATE tokencast_turn_telemetry SET tokens_used = 999 WHERE telemetry_id = 'TEL-test-0000'")

        # Direct DELETE on telemetry forbidden
        with pytest.raises(sqlite3.IntegrityError, match="tokencast_turn_telemetry is append-only: direct DELETE forbidden"):
            conn.execute("DELETE FROM tokencast_turn_telemetry WHERE telemetry_id = 'TEL-test-0000'")

        # Turn exceeds max_turns (3)
        conn.execute(
            "INSERT INTO tokencast_turn_telemetry (telemetry_id, session_id, turn_index, tokens_used) "
            "VALUES ('TEL-test-0002', 'SES-test-append-only', 2, 200)"
        )
        with pytest.raises(sqlite3.IntegrityError, match="turn_index exceeds session max_turns"):
            conn.execute(
                "INSERT INTO tokencast_turn_telemetry (telemetry_id, session_id, turn_index, tokens_used) "
                "VALUES ('TEL-test-0003', 'SES-test-append-only', 3, 200)"
            )

        # 3. Enforcement events & halt latch
        conn.execute(
            "INSERT INTO tokencast_enforcement_events (event_id, session_id, decision, forecast_tokens) "
            "VALUES ('EVT-test-0001', 'SES-test-append-only', 'EMERGENCY_HALT', 5000)"
        )
        with pytest.raises(sqlite3.IntegrityError, match="tokencast_enforcement_events is immutable: UPDATE forbidden"):
            conn.execute("UPDATE tokencast_enforcement_events SET forecast_tokens = 999 WHERE event_id = 'EVT-test-0001'")

        with pytest.raises(sqlite3.IntegrityError, match="tokencast_enforcement_events is append-only: direct DELETE forbidden"):
            conn.execute("DELETE FROM tokencast_enforcement_events WHERE event_id = 'EVT-test-0001'")

        # Non-EMERGENCY_HALT event after EMERGENCY_HALT is rejected by latch
        with pytest.raises(sqlite3.IntegrityError, match="session halted: only EMERGENCY_HALT may follow EMERGENCY_HALT"):
            conn.execute(
                "INSERT INTO tokencast_enforcement_events (event_id, session_id, decision, forecast_tokens) "
                "VALUES ('EVT-test-0002', 'SES-test-append-only', 'CONTINUE', 100)"
            )
    finally:
        conn.close()

    # 4. On-disk SQLite WAL concurrency & multi-threaded contention
    import threading
    db_file = tmp_path / "tokencast_concurrency.db"
    init_conn = sqlite3.connect(db_file)
    init_conn.execute("PRAGMA foreign_keys=ON")
    init_conn.executescript(load_schema_sql())
    init_conn.execute(
        "INSERT INTO tokencast_session_budgets (session_id, soft_limit_tokens, hard_limit_tokens, max_turns) "
        "VALUES ('SES-thread-concurrency', 100000, 200000, 100)"
    )
    init_conn.commit()
    init_conn.close()

    worker_errors = []
    def thread_worker(worker_id: int):
        try:
            w_conn = sqlite3.connect(db_file, timeout=5.0)
            w_conn.execute("PRAGMA busy_timeout=5000")
            w_conn.execute("PRAGMA foreign_keys=ON")
            w_conn.execute(
                "INSERT INTO tokencast_enforcement_events (event_id, session_id, decision, forecast_tokens) "
                f"VALUES ('EVT-th-{worker_id:04d}', 'SES-thread-concurrency', 'CONTINUE', {1000 + worker_id})"
            )
            w_conn.commit()
            w_conn.close()
        except Exception as exc:
            worker_errors.append(exc)

    threads = [threading.Thread(target=thread_worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not worker_errors, f"Thread errors: {worker_errors}"
    check_conn = sqlite3.connect(db_file)
    count = check_conn.execute(
        "SELECT COUNT(*) FROM tokencast_enforcement_events WHERE session_id='SES-thread-concurrency'"
    ).fetchone()[0]
    check_conn.close()
    assert count == 10

