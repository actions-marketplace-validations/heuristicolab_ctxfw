# manifest_hash: 862e0dc20133fe81f2ce12812b86d74068db80cce8566a3b71d2d406db72c549
"""
TokenCast Breaker :: Circuit Breaker Decision Engine
===================================================
Enforces budget limits across LLM agent execution turns via deterministic FSM transitions.
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, Sequence

from pydantic import ValidationError

from ctxfw.budget.contracts import (
    SESSION_ID_PATTERN,
    BreakerEvent,
    BreakerState,
    BudgetEnforcementDecisionDTO,
    DecisionKind,
    SessionTokenBudgetDTO,
    TokenTrajectoryForecastDTO,
    TurnObservationTelemetryDTO,
    estimate_cost_usd,
    transition,
)
from ctxfw.budget.forecaster import predict_token_trajectory

__all__ = ["CircuitBreaker"]


class CircuitBreaker:
    """Deterministic token-budget circuit breaker with total FSM transitions."""

    @classmethod
    def decide(
        cls,
        budget: SessionTokenBudgetDTO,
        history: Sequence[TurnObservationTelemetryDTO],
        horizon_turns: int = 4,
        usd_per_1k: Decimal = Decimal("0.0000"),
    ) -> tuple[BudgetEnforcementDecisionDTO, TokenTrajectoryForecastDTO, tuple[BreakerState, ...]]:
        """Evaluate session budget against history, returning decision, forecast, and FSM trace.

        Precedence hierarchy:
          1. observed > budget.hard_limit_tokens OR predicted > budget.hard_limit_tokens OR len(history) >= budget.max_turns:
             EMERGENCY_HALT (HARD_CROSSED)
          2. predicted > budget.soft_limit_tokens:
             FORCE_D3_PRUNING (SOFT_CROSSED)
          3. Otherwise:
             CONTINUE (WITHIN_SOFT)
        """
        if not isinstance(budget, SessionTokenBudgetDTO):
            raise TypeError(f"budget must be SessionTokenBudgetDTO, got {type(budget).__name__}")

        state = BreakerState.RECEIVED
        trace: list[BreakerState] = [state]

        # 1. Telemetry ingestion
        state = transition(state, BreakerEvent.TELEMETRY_OK)
        trace.append(state)

        # 2. Trajectory forecast
        forecast = predict_token_trajectory(history, max_turns=budget.max_turns, horizon_turns=horizon_turns)
        state = transition(state, BreakerEvent.FORECAST_OK)
        trace.append(state)

        # 3. Decision evaluation
        observed = sum(t.prompt_tokens + t.completion_tokens for t in history)
        predicted = forecast.predicted_cumulative_tokens
        n = len(history)

        if (
            observed > budget.hard_limit_tokens
            or predicted > budget.hard_limit_tokens
            or n >= budget.max_turns
        ):
            kind = DecisionKind.EMERGENCY_HALT
            event = BreakerEvent.HARD_CROSSED
            overrun = True
        elif predicted > budget.soft_limit_tokens:
            kind = DecisionKind.FORCE_D3_PRUNING
            event = BreakerEvent.SOFT_CROSSED
            overrun = True
        else:
            kind = DecisionKind.CONTINUE
            event = BreakerEvent.WITHIN_SOFT
            overrun = False

        state = transition(state, event)
        trace.append(state)

        cost = estimate_cost_usd(predicted, usd_per_1k)
        decision = BudgetEnforcementDecisionDTO(
            session_id=budget.session_id,
            decision=kind,
            predicted_overrun=overrun,
            estimated_cost_usd=cost,
        )

        return decision, forecast, tuple(trace)

    @classmethod
    def decide_fail_closed(
        cls,
        budget: Any,
        history: Any,
        horizon_turns: int = 4,
        usd_per_1k: Any = Decimal("0.0000"),
    ) -> tuple[BudgetEnforcementDecisionDTO, TokenTrajectoryForecastDTO | None, tuple[BreakerState, ...]]:
        """Fail-closed wrapper catching ValueError, TypeError, ValidationError and halting."""
        try:
            return cls.decide(budget, history, horizon_turns=horizon_turns, usd_per_1k=usd_per_1k)
        except (ValueError, TypeError, ValidationError):
            session_id = "SES-0000-failclosed"
            if isinstance(budget, SessionTokenBudgetDTO):
                session_id = budget.session_id
            elif hasattr(budget, "session_id") and isinstance(getattr(budget, "session_id"), str):
                sid = getattr(budget, "session_id")
                if re.match(SESSION_ID_PATTERN, sid):
                    session_id = sid

            fallback_decision = BudgetEnforcementDecisionDTO(
                session_id=session_id,
                decision=DecisionKind.EMERGENCY_HALT,
                predicted_overrun=True,
                estimated_cost_usd=Decimal("0.0000"),
            )
            return fallback_decision, None, (BreakerState.RECEIVED, BreakerState.REJECTED_INVALID)
