# manifest_hash: 862e0dc20133fe81f2ce12812b86d74068db80cce8566a3b71d2d406db72c549
"""
TokenCast Engine Test Suite
===========================
Verifies:
  1. TokenCastForecaster exact oracle math and bounds.
  2. Pure integer arithmetic stress (zero floats, large numbers, robust bounds).
  3. Latency micro-benchmark (50 iterations, 64 turns, horizon 64, median < 5.0 ms).
  4. CircuitBreaker decisions (CONTINUE, FORCE_D3_PRUNING, EMERGENCY_HALT, fail-closed).
  5. TokenCastStore SQLite WAL persistence, sequential turn triggers, halt latch, and concurrency.
"""
from __future__ import annotations

import sqlite3
import statistics
import threading
import time
from decimal import Decimal

import pytest
from pydantic import ValidationError

from ctxfw.budget import (
    BreakerState,
    CircuitBreaker,
    DecisionKind,
    SessionTokenBudgetDTO,
    TokenCastForecaster,
    TokenCastStore,
    TurnObservationTelemetryDTO,
    predict_token_trajectory,
)


def _make_turn(idx: int, prompt: int, completion: int) -> TurnObservationTelemetryDTO:
    return TurnObservationTelemetryDTO(
        turn_index=idx,
        prompt_tokens=prompt,
        completion_tokens=completion,
        tool_count=1,
        elapsed_ms=100,
    )


def test_forecaster_oracle_single_turn():
    history = [_make_turn(0, 1000, 200)]
    forecast = predict_token_trajectory(history, max_turns=10, horizon_turns=4)

    # total = 1200
    # mean_c = ceil_div(200, 1) = 200
    # p_last = 1000
    # growth = history[0].completion_tokens = 200
    # horizon = min(4, 9) = 4
    # additional = 4 * (1000 + 200) + 200 * 4 * 5 // 2 = 4800 + 2000 = 6800
    # predicted = 1200 + 6800 = 8000
    # width = ceil_div(6800, 2) = 3400
    # low = max(1200, 8000 - 3400) = 4600
    # high = 8000 + 3400 = 11400
    assert forecast.predicted_cumulative_tokens == 8000
    assert forecast.confidence_interval == (4600, 11400)
    assert forecast.forecast_turns == (1, 2, 3, 4)


def test_forecaster_oracle_multi_turns():
    history = [
        _make_turn(0, 1000, 200),
        _make_turn(1, 1200, 300),
    ]
    forecast = TokenCastForecaster.predict(history, max_turns=5, horizon_turns=3)

    # total = 1200 + 1500 = 2700
    # mean_c = ceil_div(500, 2) = 250
    # growth = ceil_div(1200 - 1000, 1) = 200
    # horizon = min(3, 3) = 3
    # additional = 3 * (1200 + 250) + 200 * 3 * 4 // 2 = 4350 + 1200 = 5550
    # predicted = 2700 + 5550 = 8250
    # t_series = [1200, 1500]
    # sum_sq = 1200^2 + 1500^2 = 3690000
    # total^2 = 7290000
    # 2 * 3690000 - 7290000 = 90000
    # variance = ceil_div(90000, 4) = 22500
    # sigma = ceil_isqrt(22500) = 150
    # ceil_isqrt(3) = 2
    # width = (196 * 150 * 2 + 99) // 100 = 588
    # low = max(2700, 8250 - 588) = 7662
    # high = 8250 + 588 = 8838
    assert forecast.predicted_cumulative_tokens == 8250
    assert forecast.confidence_interval == (7662, 8838)
    assert forecast.forecast_turns == (2, 3, 4)


def test_forecaster_zero_remaining_horizon():
    history = [_make_turn(0, 500, 100), _make_turn(1, 600, 100)]
    forecast = predict_token_trajectory(history, max_turns=2, horizon_turns=4)

    total = 600 + 700
    assert forecast.predicted_cumulative_tokens == total
    assert forecast.confidence_interval == (total, total)
    assert forecast.forecast_turns == ()


def test_forecaster_input_validations():
    # Empty history
    with pytest.raises(ValueError, match="history cannot be empty"):
        predict_token_trajectory([], max_turns=10, horizon_turns=4)

    # Non-contiguous turn index
    with pytest.raises(ValueError, match="turn_index must be contiguous"):
        predict_token_trajectory([_make_turn(1, 100, 50)], max_turns=10, horizon_turns=4)

    # Gap in turn indices
    with pytest.raises(ValueError, match="turn_index must be contiguous"):
        predict_token_trajectory([_make_turn(0, 100, 50), _make_turn(2, 100, 50)], max_turns=10, horizon_turns=4)

    # History exceeds max_turns
    with pytest.raises(ValueError, match="history length 2 exceeds max_turns 1"):
        predict_token_trajectory([_make_turn(0, 100, 50), _make_turn(1, 100, 50)], max_turns=1, horizon_turns=4)

    # Bounds on max_turns
    with pytest.raises(ValueError, match="max_turns must be in"):
        predict_token_trajectory([_make_turn(0, 100, 50)], max_turns=0, horizon_turns=4)
    with pytest.raises(ValueError, match="max_turns must be in"):
        predict_token_trajectory([_make_turn(0, 100, 50)], max_turns=1025, horizon_turns=4)

    # Bounds on horizon_turns
    with pytest.raises(ValueError, match="horizon_turns must be in"):
        predict_token_trajectory([_make_turn(0, 100, 50)], max_turns=10, horizon_turns=0)
    with pytest.raises(ValueError, match="horizon_turns must be in"):
        predict_token_trajectory([_make_turn(0, 100, 50)], max_turns=10, horizon_turns=65)

    # Strict typing on bounds
    with pytest.raises(TypeError, match="max_turns must be an integer"):
        predict_token_trajectory([_make_turn(0, 100, 50)], max_turns=True, horizon_turns=4)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="horizon_turns must be an integer"):
        predict_token_trajectory([_make_turn(0, 100, 50)], max_turns=10, horizon_turns=4.5)  # type: ignore[arg-type]


def test_forecaster_integer_stress_and_large_numbers():
    history = [
        _make_turn(0, 9_000_000, 100_000),
        _make_turn(1, 9_500_000, 150_000),
        _make_turn(2, 9_800_000, 200_000),
    ]
    forecast = predict_token_trajectory(history, max_turns=100, horizon_turns=10)

    # Check that all returned numbers are strictly ints
    assert isinstance(forecast.predicted_cumulative_tokens, int)
    assert isinstance(forecast.confidence_interval[0], int)
    assert isinstance(forecast.confidence_interval[1], int)
    assert forecast.confidence_interval[0] <= forecast.predicted_cumulative_tokens <= forecast.confidence_interval[1]


def test_forecaster_micro_benchmark_latency():
    # 64 turns of history
    history = [_make_turn(i, 1000 + i * 50, 200 + i * 5) for i in range(64)]

    durations: list[float] = []
    for _ in range(50):
        t0 = time.perf_counter()
        res = predict_token_trajectory(history, max_turns=128, horizon_turns=64)
        t1 = time.perf_counter()
        durations.append(t1 - t0)
        assert res.predicted_cumulative_tokens > 0

    median_sec = statistics.median(durations)
    median_ms = median_sec * 1000.0
    # Must certify median < 5.0 ms
    assert median_ms < 5.0, f"TokenCast latency exceeded SLA: {median_ms:.3f} ms >= 5.0 ms"


def test_circuit_breaker_decisions():
    budget = SessionTokenBudgetDTO(
        session_id="SES-breaker-001",
        soft_limit_tokens=5_000,
        hard_limit_tokens=15_000,
        max_turns=10,
    )

    # Case 1: CONTINUE (within soft limit)
    history_ok = [_make_turn(0, 500, 100)]
    dec_ok, fc_ok, trace_ok = CircuitBreaker.decide(budget, history_ok, horizon_turns=2, usd_per_1k=Decimal("2.5000"))
    assert dec_ok.decision is DecisionKind.CONTINUE
    assert dec_ok.predicted_overrun is False
    assert dec_ok.estimated_cost_usd > Decimal("0.0000")
    assert trace_ok[-1] is BreakerState.DECIDED_CONTINUE

    # Case 2: FORCE_D3_PRUNING (predicted > soft_limit_tokens)
    history_prune = [_make_turn(0, 1000, 200), _make_turn(1, 1200, 300)]
    dec_prune, fc_prune, trace_prune = CircuitBreaker.decide(budget, history_prune, horizon_turns=3)
    # Predicted is 8250, soft is 5000, hard is 15000 -> FORCE_D3_PRUNING
    assert dec_prune.decision is DecisionKind.FORCE_D3_PRUNING
    assert dec_prune.predicted_overrun is True
    assert trace_prune[-1] is BreakerState.DECIDED_PRUNE

    # Case 3: EMERGENCY_HALT (predicted > hard_limit_tokens)
    tight_budget = SessionTokenBudgetDTO(
        session_id="SES-breaker-002",
        soft_limit_tokens=5_000,
        hard_limit_tokens=7_000,
        max_turns=10,
    )
    dec_halt, fc_halt, trace_halt = CircuitBreaker.decide(tight_budget, history_prune, horizon_turns=3)
    assert dec_halt.decision is DecisionKind.EMERGENCY_HALT
    assert dec_halt.predicted_overrun is True
    assert trace_halt[-1] is BreakerState.DECIDED_HALT

    # Case 4: EMERGENCY_HALT (turns exhausted: len(history) >= max_turns)
    small_turns_budget = SessionTokenBudgetDTO(
        session_id="SES-breaker-003",
        soft_limit_tokens=50_000,
        hard_limit_tokens=100_000,
        max_turns=2,
    )
    dec_turns, _, trace_turns = CircuitBreaker.decide(small_turns_budget, history_prune)
    assert dec_turns.decision is DecisionKind.EMERGENCY_HALT
    assert trace_turns[-1] is BreakerState.DECIDED_HALT


def test_circuit_breaker_fail_closed_mode():
    # Pass invalid history (empty)
    budget = SessionTokenBudgetDTO(
        session_id="SES-failclosed-01",
        soft_limit_tokens=1000,
        hard_limit_tokens=2000,
        max_turns=5,
    )
    dec, fc, trace = CircuitBreaker.decide_fail_closed(budget, [])
    assert dec.decision is DecisionKind.EMERGENCY_HALT
    assert dec.predicted_overrun is True
    assert dec.estimated_cost_usd == Decimal("0.0000")
    assert fc is None
    assert trace == (BreakerState.RECEIVED, BreakerState.REJECTED_INVALID)

    # Pass invalid budget type
    dec2, fc2, trace2 = CircuitBreaker.decide_fail_closed("not_a_budget", [_make_turn(0, 100, 50)])
    assert dec2.decision is DecisionKind.EMERGENCY_HALT
    assert dec2.session_id.startswith("SES-")
    assert fc2 is None
    assert trace2 == (BreakerState.RECEIVED, BreakerState.REJECTED_INVALID)


def test_tokencast_store_operations_and_triggers(tmp_path):
    db_file = tmp_path / "tokencast_engine.db"
    store = TokenCastStore(db_file)

    budget = SessionTokenBudgetDTO(
        session_id="SES-store-001",
        soft_limit_tokens=5000,
        hard_limit_tokens=10000,
        max_turns=5,
    )
    store.create_session_budget(budget)

    fetched = store.get_session_budget("SES-store-001")
    assert fetched is not None
    assert fetched["session_id"] == "SES-store-001"
    assert fetched["soft_limit_tokens"] == 5000

    # Sequential telemetry
    t0 = store.record_turn_telemetry("SES-store-001", turn_index=0, prompt_tokens=100, completion_tokens=50)
    assert t0.startswith("TEL-")
    t1 = store.record_turn_telemetry("SES-store-001", turn_index=1, prompt_tokens=150, completion_tokens=60)
    assert t1.startswith("TEL-")

    # Non-sequential turn must raise IntegrityError via trigger
    with pytest.raises(sqlite3.IntegrityError, match="turn_index must be contiguous starting at 0"):
        store.record_turn_telemetry("SES-store-001", turn_index=3, prompt_tokens=200, completion_tokens=50)

    # Contiguous turns up to max_turns
    store.record_turn_telemetry("SES-store-001", turn_index=2, prompt_tokens=200, completion_tokens=50)
    store.record_turn_telemetry("SES-store-001", turn_index=3, prompt_tokens=200, completion_tokens=50)
    store.record_turn_telemetry("SES-store-001", turn_index=4, prompt_tokens=200, completion_tokens=50)
    with pytest.raises(sqlite3.IntegrityError, match="turn_index exceeds session max_turns"):
        store.record_turn_telemetry("SES-store-001", turn_index=5, prompt_tokens=200, completion_tokens=50)

    # Enforcement decisions & halt latch
    e0 = store.record_enforcement_decision("SES-store-001", DecisionKind.CONTINUE, forecast_tokens=1000)
    assert e0.startswith("EVT-")

    # HALT latch
    e1 = store.record_enforcement_decision("SES-store-001", DecisionKind.EMERGENCY_HALT, forecast_tokens=12000)
    assert e1.startswith("EVT-")

    # After EMERGENCY_HALT, telemetry is rejected by trigger
    # Note: turn 3 would also violate max_turns, but let's test a second session to isolate halt latch
    budget2 = SessionTokenBudgetDTO(
        session_id="SES-store-002",
        soft_limit_tokens=5000,
        hard_limit_tokens=10000,
        max_turns=10,
    )
    store.create_session_budget(budget2)
    store.record_turn_telemetry("SES-store-002", 0, 100, 50)
    store.record_enforcement_decision("SES-store-002", DecisionKind.EMERGENCY_HALT, 15000)

    with pytest.raises(sqlite3.IntegrityError, match="session halted: telemetry rejected after EMERGENCY_HALT"):
        store.record_turn_telemetry("SES-store-002", 1, 100, 50)

    # After EMERGENCY_HALT, non-halt decision is rejected
    with pytest.raises(sqlite3.IntegrityError, match="session halted: only EMERGENCY_HALT may follow EMERGENCY_HALT"):
        store.record_enforcement_decision("SES-store-002", DecisionKind.CONTINUE, 500)

    store.close()


def test_tokencast_store_concurrency(tmp_path):
    db_file = tmp_path / "tokencast_threads.db"
    store = TokenCastStore(db_file)
    budget = SessionTokenBudgetDTO(
        session_id="SES-thread-001",
        soft_limit_tokens=50000,
        hard_limit_tokens=100000,
        max_turns=100,
    )
    store.create_session_budget(budget)

    errors: list[Exception] = []

    def worker(worker_id: int):
        try:
            # Each worker records an enforcement decision through store
            store.record_enforcement_decision(
                "SES-thread-001",
                DecisionKind.CONTINUE,
                forecast_tokens=1000 + worker_id,
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not errors, f"Concurrency errors encountered: {errors}"
    events = store.get_enforcement_events("SES-thread-001")
    assert len(events) == 10
    store.close()


def test_forecaster_oracle_zero_growth_and_equal_tokens():
    # When tokens across turns are identical, variance should be 0 and confidence interval collapsed
    history = [
        _make_turn(0, 500, 100),
        _make_turn(1, 500, 100),
    ]
    forecast = predict_token_trajectory(history, max_turns=5, horizon_turns=2)
    assert forecast.predicted_cumulative_tokens == 2400
    assert forecast.confidence_interval == (2400, 2400)
    assert forecast.forecast_turns == (2, 3)

