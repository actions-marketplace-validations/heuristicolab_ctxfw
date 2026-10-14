# manifest_hash: 862e0dc20133fe81f2ce12812b86d74068db80cce8566a3b71d2d406db72c549
"""
TokenCast Forecaster :: Deterministic Integer Token Trajectory Projection
========================================================================
Implements closed-form integer math for projecting token trajectories across LLM agent execution.
Strict invariants:
- 100% integer arithmetic: zero floats, zero math.sqrt, zero '/' divisions.
- Uses ceil_div and ceil_isqrt from ctxfw.budget.contracts.
- Enforces strict telemetry history validation and horizon bounds.
- Guaranteed execution latency < 5.0 ms.
"""
from __future__ import annotations

from typing import Sequence

from ctxfw.budget.contracts import (
    HORIZON_TURNS_MAX,
    HORIZON_TURNS_MIN,
    MAX_TURNS_MAX,
    MAX_TURNS_MIN,
    TokenTrajectoryForecastDTO,
    TurnObservationTelemetryDTO,
    ceil_div,
    ceil_isqrt,
)

__all__ = ["TokenCastForecaster", "predict_token_trajectory"]


def predict_token_trajectory(
    history: Sequence[TurnObservationTelemetryDTO],
    max_turns: int,
    horizon_turns: int = 4,
) -> TokenTrajectoryForecastDTO:
    """Deterministic token trajectory projection using exact integer arithmetic.

    Formulation:
      total = sum(prompt + completion)
      mean_c = ceil_div(sum(completion), n)
      growth = ceil_div(max(0, p_last - p_first), n - 1) if n >= 2 else history[0].completion_tokens
      horizon = min(horizon_turns, max_turns - n)
      additional = horizon * (p_last + mean_c) + growth * horizon * (horizon + 1) // 2
      predicted = total + additional
      variance = ceil_div(n * sum(x*x for x in t) - sum(t)**2, n * n) if n >= 2
      sigma = ceil_isqrt(variance)
      width = (196 * sigma * ceil_isqrt(horizon) + 99) // 100 if n >= 2 else ceil_div(additional, 2)
      low = max(total, predicted - width)
      high = predicted + width
    """
    if isinstance(max_turns, bool) or not isinstance(max_turns, int):
        raise TypeError("max_turns must be an integer")
    if not (MAX_TURNS_MIN <= max_turns <= MAX_TURNS_MAX):
        raise ValueError(f"max_turns must be in [{MAX_TURNS_MIN}, {MAX_TURNS_MAX}], got {max_turns}")

    if isinstance(horizon_turns, bool) or not isinstance(horizon_turns, int):
        raise TypeError("horizon_turns must be an integer")
    if not (HORIZON_TURNS_MIN <= horizon_turns <= HORIZON_TURNS_MAX):
        raise ValueError(
            f"horizon_turns must be in [{HORIZON_TURNS_MIN}, {HORIZON_TURNS_MAX}], got {horizon_turns}"
        )

    if not history:
        raise ValueError("history cannot be empty")

    n = len(history)
    if n > max_turns:
        raise ValueError(f"history length {n} exceeds max_turns {max_turns}")

    for idx, turn in enumerate(history):
        if not isinstance(turn, TurnObservationTelemetryDTO):
            raise TypeError(f"history element at index {idx} must be TurnObservationTelemetryDTO")
        if turn.turn_index != idx:
            raise ValueError(
                f"turn_index must be contiguous starting at 0: expected {idx}, got {turn.turn_index}"
            )

    # Historical aggregations
    t_series = [t.prompt_tokens + t.completion_tokens for t in history]
    total = sum(t_series)
    sum_completion = sum(t.completion_tokens for t in history)
    mean_c = ceil_div(sum_completion, n)

    p_last = history[-1].prompt_tokens
    p_first = history[0].prompt_tokens

    if n >= 2:
        growth = ceil_div(max(0, p_last - p_first), n - 1)
    else:
        growth = history[0].completion_tokens

    horizon = min(horizon_turns, max_turns - n)
    if horizon > 0:
        additional = horizon * (p_last + mean_c) + growth * horizon * (horizon + 1) // 2
        forecast_turns = tuple(range(n, n + horizon))
    else:
        additional = 0
        forecast_turns = ()

    predicted = total + additional

    if n >= 2:
        sum_sq = sum(x * x for x in t_series)
        var_num = max(0, n * sum_sq - total * total)
        variance = ceil_div(var_num, n * n)
        sigma = ceil_isqrt(variance)
        width = (196 * sigma * ceil_isqrt(horizon) + 99) // 100
    else:
        width = ceil_div(additional, 2)

    low = max(total, predicted - width)
    high = predicted + width

    return TokenTrajectoryForecastDTO(
        forecast_turns=forecast_turns,
        predicted_cumulative_tokens=predicted,
        confidence_interval=(low, high),
    )


class TokenCastForecaster:
    """Forecaster engine wrapping deterministic token trajectory projection."""

    @staticmethod
    def predict(
        history: Sequence[TurnObservationTelemetryDTO],
        max_turns: int,
        horizon_turns: int = 4,
    ) -> TokenTrajectoryForecastDTO:
        return predict_token_trajectory(history, max_turns=max_turns, horizon_turns=horizon_turns)

    def forecast(
        self,
        history: Sequence[TurnObservationTelemetryDTO],
        max_turns: int,
        horizon_turns: int = 4,
    ) -> TokenTrajectoryForecastDTO:
        return predict_token_trajectory(history, max_turns=max_turns, horizon_turns=horizon_turns)
