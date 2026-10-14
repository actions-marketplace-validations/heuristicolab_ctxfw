"""
TOKENCAST BUDGETER :: 2_pydantic_contracts.py
=============================================
Signal   : SIG-947678205487bc66
Proposal : PROP-947678205487bc66-H1
Horizon  : HORIZON_1
Source   : arXiv 2609.35760v1 -- "TokenCast: Forecasting Token Consumption During LLM Agent Execution"
manifest_hash (CTXFW evaluate_spec_axioms, status VERIFIED, ACI 1.0000):
    7b7ef06dfc91c02c73bf8117efd362ffecd01cffdb9d0e5a8700be01c874bdae

Immutable Pydantic v2 contracts, total FSM and numeric bound validators for the
token-budget circuit breaker.

Negative invariants enforced by this module
-------------------------------------------
1. A budget with soft_limit_tokens > hard_limit_tokens shall never be constructed.
2. A negative token count (or any value outside its closed interval) shall never be accepted.
3. A float, bool or str shall never be coerced into an integer token field (strict typing).
4. A DTO shall never be mutated after construction (frozen=True) and shall never
   accept an undeclared field (extra="forbid").
5. transition(S, E) shall never raise: every (state, event) pair maps to a state and
   every unknown pair maps to REJECTED_INVALID (fail-closed).
6. A cost shall never be represented with a float or with a scale other than exactly 4 decimals.
7. A decision CONTINUE shall never carry predicted_overrun=True and a decision
   FORCE_D3_PRUNING / EMERGENCY_HALT shall never carry predicted_overrun=False.
8. A confidence interval shall never exclude its own point forecast.
"""

import hashlib
import math
from decimal import ROUND_CEILING, Decimal, localcontext
from enum import Enum
from types import MappingProxyType
from typing import Annotated, Mapping, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ----------------------------------------------------------------------------
# Closed numeric bounds (single source of truth shared with 3_schema_ddl.sql)
# ----------------------------------------------------------------------------
LIMIT_TOKENS_MIN: int = 1
LIMIT_TOKENS_MAX: int = 100_000_000_000
MAX_TURNS_MIN: int = 1
MAX_TURNS_MAX: int = 1024
TURN_INDEX_MIN: int = 0
TURN_INDEX_MAX: int = 1023
TURN_TOKENS_MIN: int = 0
TURN_TOKENS_MAX: int = 10_000_000
TOOL_COUNT_MIN: int = 0
TOOL_COUNT_MAX: int = 1000
ELAPSED_MS_MIN: int = 0
ELAPSED_MS_MAX: int = 86_400_000
LEDGER_TOKENS_MAX: int = 20_000_000
HORIZON_TURNS_MIN: int = 1
HORIZON_TURNS_MAX: int = 64
FORECAST_TURNS_MAX_LEN: int = 64
USD_PER_1K_MIN: Decimal = Decimal("0")
USD_PER_1K_MAX: Decimal = Decimal("1000")
COST_SCALE_EXPONENT: int = -4
COST_QUANTUM: Decimal = Decimal("0.0001")
FORECAST_LATENCY_BUDGET_MS: float = 5.0

SESSION_ID_PATTERN: str = r"^SES-[A-Za-z0-9_-]{4,64}$"
TELEMETRY_ID_PATTERN: str = r"^TEL-[A-Za-z0-9_-]{4,64}$"
EVENT_ID_PATTERN: str = r"^EVT-[A-Za-z0-9_-]{4,64}$"

LimitTokens = Annotated[int, Field(strict=True, ge=LIMIT_TOKENS_MIN, le=LIMIT_TOKENS_MAX)]
MaxTurns = Annotated[int, Field(strict=True, ge=MAX_TURNS_MIN, le=MAX_TURNS_MAX)]
TurnIndex = Annotated[int, Field(strict=True, ge=TURN_INDEX_MIN, le=TURN_INDEX_MAX)]
TurnTokens = Annotated[int, Field(strict=True, ge=TURN_TOKENS_MIN, le=TURN_TOKENS_MAX)]
ToolCount = Annotated[int, Field(strict=True, ge=TOOL_COUNT_MIN, le=TOOL_COUNT_MAX)]
ElapsedMs = Annotated[int, Field(strict=True, ge=ELAPSED_MS_MIN, le=ELAPSED_MS_MAX)]
CumulativeTokens = Annotated[int, Field(strict=True, ge=0, le=LIMIT_TOKENS_MAX)]
ForecastTurnIndex = Annotated[int, Field(strict=True, ge=TURN_INDEX_MIN, le=TURN_INDEX_MAX)]
CostUsd = Annotated[Decimal, Field(strict=True, ge=Decimal("0"), max_digits=18, decimal_places=4)]


# ----------------------------------------------------------------------------
# Enumerations
# ----------------------------------------------------------------------------
class DecisionKind(str, Enum):
    CONTINUE = "CONTINUE"
    FORCE_D3_PRUNING = "FORCE_D3_PRUNING"
    EMERGENCY_HALT = "EMERGENCY_HALT"


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DETERMINISTIC = "DETERMINISTIC"
    BUSINESS = "BUSINESS"
    SECURITY = "SECURITY"


class BreakerState(str, Enum):
    RECEIVED = "RECEIVED"
    INGESTED = "INGESTED"
    FORECASTED = "FORECASTED"
    DECIDED_CONTINUE = "DECIDED_CONTINUE"
    DECIDED_PRUNE = "DECIDED_PRUNE"
    DECIDED_HALT = "DECIDED_HALT"
    RECORDED = "RECORDED"
    REJECTED_INVALID = "REJECTED_INVALID"


class BreakerEvent(str, Enum):
    TELEMETRY_OK = "TELEMETRY_OK"
    VALIDATION_FAIL = "VALIDATION_FAIL"
    FORECAST_OK = "FORECAST_OK"
    FORECAST_FAIL = "FORECAST_FAIL"
    WITHIN_SOFT = "WITHIN_SOFT"
    SOFT_CROSSED = "SOFT_CROSSED"
    HARD_CROSSED = "HARD_CROSSED"
    WAL_COMMIT = "WAL_COMMIT"
    WAL_RETRY_EXHAUSTED = "WAL_RETRY_EXHAUSTED"


TERMINAL_STATES: frozenset = frozenset({BreakerState.RECORDED, BreakerState.REJECTED_INVALID})

_S = BreakerState
_E = BreakerEvent

# delta(S, E) -- exactly 13 explicit transitions; every other pair is fail-closed.
TRANSITION_TABLE: Mapping[Tuple[BreakerState, BreakerEvent], BreakerState] = MappingProxyType(
    {
        (_S.RECEIVED, _E.TELEMETRY_OK): _S.INGESTED,
        (_S.RECEIVED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.INGESTED, _E.FORECAST_OK): _S.FORECASTED,
        (_S.INGESTED, _E.FORECAST_FAIL): _S.REJECTED_INVALID,
        (_S.FORECASTED, _E.WITHIN_SOFT): _S.DECIDED_CONTINUE,
        (_S.FORECASTED, _E.SOFT_CROSSED): _S.DECIDED_PRUNE,
        (_S.FORECASTED, _E.HARD_CROSSED): _S.DECIDED_HALT,
        (_S.DECIDED_CONTINUE, _E.WAL_COMMIT): _S.RECORDED,
        (_S.DECIDED_CONTINUE, _E.WAL_RETRY_EXHAUSTED): _S.REJECTED_INVALID,
        (_S.DECIDED_PRUNE, _E.WAL_COMMIT): _S.RECORDED,
        (_S.DECIDED_PRUNE, _E.WAL_RETRY_EXHAUSTED): _S.REJECTED_INVALID,
        (_S.DECIDED_HALT, _E.WAL_COMMIT): _S.RECORDED,
        (_S.DECIDED_HALT, _E.WAL_RETRY_EXHAUSTED): _S.REJECTED_INVALID,
    }
)

# Failure taxonomy: every failure code is routed to exactly one of the four classes.
FAILURE_ROUTING: Mapping[str, FailureClass] = MappingProxyType(
    {
        "WAL_LOCKED": FailureClass.TRANSIENT,
        "WAL_RETRY_EXHAUSTED": FailureClass.TRANSIENT,
        "VALIDATION_FAIL": FailureClass.DETERMINISTIC,
        "FORECAST_FAIL": FailureClass.DETERMINISTIC,
        "HARD_CROSSED": FailureClass.BUSINESS,
        "TURNS_EXHAUSTED": FailureClass.BUSINESS,
        "LEDGER_MUTATION_ATTEMPT": FailureClass.SECURITY,
        "TYPE_COERCION_ATTEMPT": FailureClass.SECURITY,
    }
)

# Disposition per class. Every disposition is fail-closed (no class maps to "continue").
FAILURE_DISPOSITION: Mapping[FailureClass, str] = MappingProxyType(
    {
        FailureClass.TRANSIENT: "RETRY_BOUNDED_3_THEN_HALT",
        FailureClass.DETERMINISTIC: "REJECT_AND_HALT",
        FailureClass.BUSINESS: "EMERGENCY_HALT",
        FailureClass.SECURITY: "REJECT_AND_HALT",
    }
)


def transition(state: object, event: object) -> BreakerState:
    """Total FSM function delta(S, E). Never raises; unknown input -> REJECTED_INVALID."""
    if not isinstance(state, BreakerState) or not isinstance(event, BreakerEvent):
        return BreakerState.REJECTED_INVALID
    if state in TERMINAL_STATES:
        return state
    return TRANSITION_TABLE.get((state, event), BreakerState.REJECTED_INVALID)


# ----------------------------------------------------------------------------
# Deterministic integer / decimal helpers
# ----------------------------------------------------------------------------
def ceil_div(numerator: int, denominator: int) -> int:
    """Ceiling of numerator / denominator using integers only (denominator > 0)."""
    if denominator <= 0:
        raise ValueError("denominator must be > 0")
    return -((-numerator) // denominator)


def ceil_isqrt(value: int) -> int:
    """Smallest integer r such that r*r >= value (value >= 0)."""
    if value < 0:
        raise ValueError("value must be >= 0")
    root = math.isqrt(value)
    return root if root * root == value else root + 1


def estimate_cost_usd(predicted_tokens: int, usd_per_1k_tokens: Decimal) -> Decimal:
    """Upper-bound cost rounded with ROUND_CEILING to exactly 4 decimals.

    predicted_tokens in [0, LIMIT_TOKENS_MAX]; usd_per_1k_tokens in [0, 1000] (Decimal only).
    """
    if isinstance(predicted_tokens, bool) or not isinstance(predicted_tokens, int):
        raise TypeError("predicted_tokens must be int")
    if not isinstance(usd_per_1k_tokens, Decimal):
        raise TypeError("usd_per_1k_tokens must be Decimal")
    if not 0 <= predicted_tokens <= LIMIT_TOKENS_MAX:
        raise ValueError("predicted_tokens out of range [0, 100000000000]")
    if not usd_per_1k_tokens.is_finite() or not USD_PER_1K_MIN <= usd_per_1k_tokens <= USD_PER_1K_MAX:
        raise ValueError("usd_per_1k_tokens out of range [0, 1000]")
    with localcontext() as ctx:
        ctx.prec = 40
        raw = Decimal(predicted_tokens) * usd_per_1k_tokens / Decimal(1000)
        return raw.quantize(COST_QUANTUM, rounding=ROUND_CEILING)


def derive_ledger_id(prefix: str, *parts: object) -> str:
    """Deterministic ledger id: prefix + first 16 hex chars of sha256 over the joined parts."""
    if prefix not in ("TEL-", "EVT-"):
        raise ValueError("prefix must be 'TEL-' or 'EVT-'")
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return prefix + digest[:16]


# ----------------------------------------------------------------------------
# Immutable DTOs
# ----------------------------------------------------------------------------
class TokenCastBaseDTO(BaseModel):
    """Common immutable configuration for every TokenCast contract."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


class SessionTokenBudgetDTO(TokenCastBaseDTO):
    """Budget assigned to one agent session: soft limit <= hard limit."""

    session_id: str = Field(pattern=SESSION_ID_PATTERN, strict=True)
    soft_limit_tokens: LimitTokens
    hard_limit_tokens: LimitTokens
    max_turns: MaxTurns

    @model_validator(mode="after")
    def _soft_must_not_exceed_hard(self) -> "SessionTokenBudgetDTO":
        if self.soft_limit_tokens > self.hard_limit_tokens:
            raise ValueError("soft_limit_tokens must be <= hard_limit_tokens")
        return self


class TurnObservationTelemetryDTO(TokenCastBaseDTO):
    """Measured telemetry of one completed turn."""

    turn_index: TurnIndex
    prompt_tokens: TurnTokens
    completion_tokens: TurnTokens
    tool_count: ToolCount
    elapsed_ms: ElapsedMs

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class TokenTrajectoryForecastDTO(TokenCastBaseDTO):
    """Deterministic forecast of cumulative token consumption for the session."""

    forecast_turns: Annotated[
        Tuple[ForecastTurnIndex, ...], Field(max_length=FORECAST_TURNS_MAX_LEN)
    ]
    predicted_cumulative_tokens: CumulativeTokens
    confidence_interval: Tuple[CumulativeTokens, CumulativeTokens]

    @field_validator("forecast_turns")
    @classmethod
    def _turns_contiguous_ascending(cls, value: Tuple[int, ...]) -> Tuple[int, ...]:
        for left, right in zip(value, value[1:]):
            if right != left + 1:
                raise ValueError("forecast_turns must be contiguous and ascending")
        return value

    @model_validator(mode="after")
    def _interval_contains_point(self) -> "TokenTrajectoryForecastDTO":
        low, high = self.confidence_interval
        if not low <= self.predicted_cumulative_tokens <= high:
            raise ValueError("confidence_interval must satisfy low <= predicted <= high")
        return self


class BudgetEnforcementDecisionDTO(TokenCastBaseDTO):
    """Oracle decision. estimated_cost_usd is a Decimal with exactly 4 decimals."""

    session_id: str = Field(pattern=SESSION_ID_PATTERN, strict=True)
    decision: DecisionKind
    predicted_overrun: bool = Field(strict=True)
    estimated_cost_usd: CostUsd

    @field_validator("estimated_cost_usd")
    @classmethod
    def _cost_scale_is_exactly_four(cls, value: Decimal) -> Decimal:
        if not value.is_finite() or value.as_tuple().exponent != COST_SCALE_EXPONENT:
            raise ValueError("estimated_cost_usd must have exactly 4 decimal places")
        return value

    @model_validator(mode="after")
    def _overrun_matches_decision(self) -> "BudgetEnforcementDecisionDTO":
        expects_overrun = self.decision is not DecisionKind.CONTINUE
        if self.predicted_overrun != expects_overrun:
            raise ValueError("predicted_overrun is inconsistent with decision")
        return self
