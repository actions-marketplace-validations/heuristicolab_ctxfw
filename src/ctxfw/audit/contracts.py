"""
TRACEKIT HASH LEDGER :: 2_pydantic_contracts.py
===============================================
Signal   : SIG-728856af9bd65ae0
Proposal : PROP-728856af9bd65ae0-H1
Horizon  : HORIZON_1
Source   : arXiv 2609.35659v1 -- "Tracekit: Tamper-Evident Intent-Reasoning-Action Auditing
           for Autonomous Coding Agents"
manifest_hash (CTXFW evaluate_spec_axioms, status VERIFIED, ACI 1.0000):
    7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c

Immutable Pydantic v2 contracts, total FSM, canonical hashing and bound validators for the
hash-chained Intent-Reasoning-Action audit ledger.

Block digest (fixed-width concatenation, hence injective):
    H_t = SHA256( H_{t-1} || I_t || R_t || A_t || timestamp )
with H_{-1} = genesis_hash(session_id) and every operand an ASCII string: four lowercase-hex
digests of 64 characters plus the 27-character canonical UTC timestamp.

Negative invariants enforced by this module
-------------------------------------------
1. A DTO shall never be mutated after construction (frozen=True) and shall never accept an
   undeclared attribute (extra="forbid").
2. A digest shall never have a length different from 64 or characters outside [0-9a-f].
3. A naive or non-UTC datetime shall never be accepted; timestamps shall never decrease.
4. block_seq shall never be negative, non-integer (float, bool, str) or non-contiguous in a chain.
5. transition(S, E) shall never raise: every (state, event) pair maps to a state and every
   unknown pair maps to REJECTED_INVALID (fail-closed).
6. A tampered verdict shall never carry broken_block_seq=None and a clean verdict shall never
   carry a broken_block_seq.
7. A prompt or plan summary shall never be paired with a digest that is not its SHA-256.
8. Hashing shall never use a wall clock, randomness or floating point: the timestamp is an input.
"""

import hashlib
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Annotated, Mapping, Optional, Sequence, Tuple

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# ----------------------------------------------------------------------------
# Closed numeric bounds (single source of truth shared with 3_schema_ddl.sql)
# ----------------------------------------------------------------------------
HASH_HEX_LEN: int = 64
HASH_PATTERN: str = r"^[0-9a-f]{64}$"
BLOCK_SEQ_MIN: int = 0
BLOCK_SEQ_MAX: int = 1_000_000
TOTAL_BLOCKS_MAX: int = 1_000_001
USER_PROMPT_MIN: int = 1
USER_PROMPT_MAX: int = 65_536
PLAN_SUMMARY_MIN: int = 1
PLAN_SUMMARY_MAX: int = 16_384
TOOL_OR_FILE_MIN: int = 1
TOOL_OR_FILE_MAX: int = 512
TIMESTAMP_TEXT_LEN: int = 27
TIMESTAMP_MIN: datetime = datetime(2020, 1, 1, tzinfo=timezone.utc)
TIMESTAMP_MAX: datetime = datetime(2100, 1, 1, tzinfo=timezone.utc)
SEAL_LATENCY_BUDGET_MS: float = 2.0
GENESIS_DOMAIN: str = "TRACEKIT-GENESIS|"

SESSION_ID_PATTERN: str = r"^SES-[A-Za-z0-9_-]{4,64}$"
BLOCK_ID_PATTERN: str = r"^BLK-[A-Za-z0-9_-]{4,64}$"
INTENT_ID_PATTERN: str = r"^INT-[A-Za-z0-9_-]{4,64}$"
REASONING_ID_PATTERN: str = r"^RSN-[A-Za-z0-9_-]{4,64}$"
ACTION_ID_PATTERN: str = r"^ACT-[A-Za-z0-9_-]{4,64}$"
EVENT_ID_PATTERN: str = r"^EVT-[A-Za-z0-9_-]{4,64}$"
TOOL_OR_FILE_PATTERN: str = r"^[^\x00-\x1f\x7f]+$"

_HASH_RE = re.compile(HASH_PATTERN)
_ID_PREFIXES = frozenset({"BLK-", "EVT-", "INT-", "RSN-", "ACT-"})


def _require_utc(value: datetime) -> datetime:
    """Accept only timezone-aware datetimes with a zero offset inside [2020, 2100)."""
    if not isinstance(value, datetime):
        raise ValueError("timestamp must be a datetime")
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise ValueError("naive datetime rejected: timezone-aware UTC required")
    if offset != timedelta(0):
        raise ValueError("non-UTC offset rejected: UTC required")
    if not TIMESTAMP_MIN <= value < TIMESTAMP_MAX:
        raise ValueError("timestamp out of range [2020-01-01, 2100-01-01)")
    return value


AwareUtc = Annotated[datetime, Field(strict=True), AfterValidator(_require_utc)]
Sha256Hex = Annotated[str, Field(pattern=HASH_PATTERN, strict=True)]
BlockSeq = Annotated[int, Field(strict=True, ge=BLOCK_SEQ_MIN, le=BLOCK_SEQ_MAX)]
TotalBlocks = Annotated[int, Field(strict=True, ge=0, le=TOTAL_BLOCKS_MAX)]


# ----------------------------------------------------------------------------
# Enumerations
# ----------------------------------------------------------------------------
class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DETERMINISTIC = "DETERMINISTIC"
    BUSINESS = "BUSINESS"
    SECURITY = "SECURITY"


class LedgerState(str, Enum):
    RECEIVED = "RECEIVED"
    INTENT_CAPTURED = "INTENT_CAPTURED"
    REASONING_CAPTURED = "REASONING_CAPTURED"
    ACTION_CAPTURED = "ACTION_CAPTURED"
    SEALED = "SEALED"
    APPENDED = "APPENDED"
    VERIFYING = "VERIFYING"
    VERIFIED_CLEAN = "VERIFIED_CLEAN"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    REJECTED_INVALID = "REJECTED_INVALID"


class LedgerEvent(str, Enum):
    INTENT_OK = "INTENT_OK"
    REASONING_OK = "REASONING_OK"
    ACTION_OK = "ACTION_OK"
    SEAL_OK = "SEAL_OK"
    WAL_COMMIT = "WAL_COMMIT"
    VERIFY_START = "VERIFY_START"
    CHAIN_INTACT = "CHAIN_INTACT"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    VALIDATION_FAIL = "VALIDATION_FAIL"
    WAL_RETRY_EXHAUSTED = "WAL_RETRY_EXHAUSTED"


TERMINAL_STATES: frozenset = frozenset(
    {LedgerState.VERIFIED_CLEAN, LedgerState.TAMPER_DETECTED, LedgerState.REJECTED_INVALID}
)

_S = LedgerState
_E = LedgerEvent

# delta(S, E) -- exactly 14 explicit transitions; every other pair is fail-closed.
TRANSITION_TABLE: Mapping[Tuple[LedgerState, LedgerEvent], LedgerState] = MappingProxyType(
    {
        (_S.RECEIVED, _E.INTENT_OK): _S.INTENT_CAPTURED,
        (_S.RECEIVED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.INTENT_CAPTURED, _E.REASONING_OK): _S.REASONING_CAPTURED,
        (_S.INTENT_CAPTURED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.REASONING_CAPTURED, _E.ACTION_OK): _S.ACTION_CAPTURED,
        (_S.REASONING_CAPTURED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.ACTION_CAPTURED, _E.SEAL_OK): _S.SEALED,
        (_S.ACTION_CAPTURED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.SEALED, _E.WAL_COMMIT): _S.APPENDED,
        (_S.SEALED, _E.WAL_RETRY_EXHAUSTED): _S.REJECTED_INVALID,
        (_S.APPENDED, _E.VERIFY_START): _S.VERIFYING,
        (_S.VERIFYING, _E.CHAIN_INTACT): _S.VERIFIED_CLEAN,
        (_S.VERIFYING, _E.CHAIN_BROKEN): _S.TAMPER_DETECTED,
        (_S.VERIFYING, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
    }
)

# Failure taxonomy: every failure code is routed to exactly one of the four classes.
FAILURE_ROUTING: Mapping[str, FailureClass] = MappingProxyType(
    {
        "WAL_LOCKED": FailureClass.TRANSIENT,
        "WAL_RETRY_EXHAUSTED": FailureClass.TRANSIENT,
        "VALIDATION_FAIL": FailureClass.DETERMINISTIC,
        "DIGEST_MALFORMED": FailureClass.DETERMINISTIC,
        "TIMESTAMP_INVALID": FailureClass.DETERMINISTIC,
        "SEQ_GAP": FailureClass.BUSINESS,
        "TIMESTAMP_REGRESSION": FailureClass.BUSINESS,
        "APPEND_ON_TAMPERED_SESSION": FailureClass.BUSINESS,
        "CHAIN_MISMATCH": FailureClass.SECURITY,
        "FORGED_PREV_LINK": FailureClass.SECURITY,
        "LEDGER_MUTATION_ATTEMPT": FailureClass.SECURITY,
    }
)

# Disposition per class. Every disposition quarantines the offending block (fail-closed).
FAILURE_DISPOSITION: Mapping[FailureClass, str] = MappingProxyType(
    {
        FailureClass.TRANSIENT: "RETRY_BOUNDED_3_THEN_QUARANTINE",
        FailureClass.DETERMINISTIC: "REJECT_AND_QUARANTINE",
        FailureClass.BUSINESS: "ABORT_AND_QUARANTINE",
        FailureClass.SECURITY: "FLAG_TAMPERED_AND_LATCH",
    }
)


def transition(state: object, event: object) -> LedgerState:
    """Total FSM function delta(S, E). Never raises; unknown input -> REJECTED_INVALID."""
    if not isinstance(state, LedgerState) or not isinstance(event, LedgerEvent):
        return LedgerState.REJECTED_INVALID
    if state in TERMINAL_STATES:
        return state
    return TRANSITION_TABLE.get((state, event), LedgerState.REJECTED_INVALID)


# ----------------------------------------------------------------------------
# Deterministic hashing helpers (no clock, no randomness, no floats)
# ----------------------------------------------------------------------------
def sha256_hex(text: str) -> str:
    """Lowercase-hex SHA-256 of the UTF-8 encoding of text."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_timestamp(value: datetime) -> str:
    """Canonical UTC text YYYY-MM-DDTHH:MM:SS.ffffffZ (exactly 27 characters)."""
    _require_utc(value)
    text = value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    if len(text) != TIMESTAMP_TEXT_LEN:
        raise ValueError("canonical timestamp length is not 27")
    return text


def _require_digest(name: str, value: object) -> str:
    if not isinstance(value, str) or _HASH_RE.match(value) is None:
        raise ValueError(f"{name} must be 64 lowercase hex characters")
    return value


def compute_block_hash(
    prev_block_hash: str,
    intent_digest: str,
    reasoning_digest: str,
    action_digest: str,
    timestamp_utc: datetime,
) -> str:
    """H_t = SHA256(H_{t-1} || I_t || R_t || A_t || timestamp) over fixed-width ASCII operands."""
    material = (
        _require_digest("prev_block_hash", prev_block_hash)
        + _require_digest("intent_digest", intent_digest)
        + _require_digest("reasoning_digest", reasoning_digest)
        + _require_digest("action_digest", action_digest)
        + canonical_timestamp(timestamp_utc)
    )
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def derive_genesis_hash(session_id: str) -> str:
    """H_{-1}: deterministic genesis digest bound to the session id."""
    if not isinstance(session_id, str) or re.match(SESSION_ID_PATTERN, session_id) is None:
        raise ValueError("session_id does not match " + SESSION_ID_PATTERN)
    return sha256_hex(GENESIS_DOMAIN + session_id)


def derive_ledger_id(prefix: str, *parts: object) -> str:
    """Deterministic id: prefix + first 16 hex chars of sha256 over the joined parts."""
    if prefix not in _ID_PREFIXES:
        raise ValueError("prefix must be one of BLK-, EVT-, INT-, RSN-, ACT-")
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return prefix + digest[:16]


# ----------------------------------------------------------------------------
# Immutable DTOs
# ----------------------------------------------------------------------------
class TraceKitBaseDTO(BaseModel):
    """Common immutable configuration for every TraceKit contract."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


class IntentBlockDTO(TraceKitBaseDTO):
    """I_t: typed record of the human instruction; intent_sha256 = SHA-256(user_prompt)."""

    intent_id: str = Field(pattern=INTENT_ID_PATTERN, strict=True)
    user_prompt: str = Field(min_length=USER_PROMPT_MIN, max_length=USER_PROMPT_MAX, strict=True)
    intent_sha256: Sha256Hex

    @model_validator(mode="after")
    def _digest_matches_prompt(self) -> "IntentBlockDTO":
        if sha256_hex(self.user_prompt) != self.intent_sha256:
            raise ValueError("intent_sha256 is not the SHA-256 of user_prompt")
        return self


class ReasoningBlockDTO(TraceKitBaseDTO):
    """R_t: summary of the agent plan; reasoning_sha256 = SHA-256(plan_summary)."""

    reasoning_id: str = Field(pattern=REASONING_ID_PATTERN, strict=True)
    plan_summary: str = Field(min_length=PLAN_SUMMARY_MIN, max_length=PLAN_SUMMARY_MAX, strict=True)
    reasoning_sha256: Sha256Hex

    @model_validator(mode="after")
    def _digest_matches_summary(self) -> "ReasoningBlockDTO":
        if sha256_hex(self.plan_summary) != self.reasoning_sha256:
            raise ValueError("reasoning_sha256 is not the SHA-256 of plan_summary")
        return self


class ActionBlockDTO(TraceKitBaseDTO):
    """A_t: command or patch actually executed; only the payload digest is stored."""

    action_id: str = Field(pattern=ACTION_ID_PATTERN, strict=True)
    tool_or_file: str = Field(
        pattern=TOOL_OR_FILE_PATTERN,
        min_length=TOOL_OR_FILE_MIN,
        max_length=TOOL_OR_FILE_MAX,
        strict=True,
    )
    payload_sha256: Sha256Hex


class HashChainedAuditBlockDTO(TraceKitBaseDTO):
    """Sealed block. Format is validated here; hash consistency is proven by the backward audit."""

    block_id: str = Field(pattern=BLOCK_ID_PATTERN, strict=True)
    session_id: str = Field(pattern=SESSION_ID_PATTERN, strict=True)
    block_seq: BlockSeq
    prev_block_hash: Sha256Hex
    current_block_hash: Sha256Hex
    intent_digest: Sha256Hex
    reasoning_digest: Sha256Hex
    action_digest: Sha256Hex
    timestamp_utc: AwareUtc


class ChainVerificationAuditDTO(TraceKitBaseDTO):
    """Result of a backward audit. broken_block_seq is the first inconsistent position."""

    session_id: str = Field(pattern=SESSION_ID_PATTERN, strict=True)
    total_blocks_audited: TotalBlocks
    is_tampered: bool = Field(strict=True)
    broken_block_seq: Optional[BlockSeq] = None
    verified_at: AwareUtc

    @model_validator(mode="after")
    def _verdict_is_consistent(self) -> "ChainVerificationAuditDTO":
        if self.is_tampered != (self.broken_block_seq is not None):
            raise ValueError("is_tampered must be True if and only if broken_block_seq is set")
        if self.broken_block_seq is not None and self.broken_block_seq >= self.total_blocks_audited:
            raise ValueError("broken_block_seq must be < total_blocks_audited")
        return self


def validate_block_sequence(blocks: Sequence[HashChainedAuditBlockDTO]) -> None:
    """Reject non-monotonic chains: one session, block_seq = 0, 1, 2, ... and non-decreasing time."""
    previous: Optional[HashChainedAuditBlockDTO] = None
    for expected, block in enumerate(blocks):
        if not isinstance(block, HashChainedAuditBlockDTO):
            raise TypeError("blocks must be HashChainedAuditBlockDTO")
        if block.block_seq != expected:
            raise ValueError("block_seq must be contiguous starting at 0")
        if previous is not None:
            if block.session_id != previous.session_id:
                raise ValueError("all blocks must belong to one session")
            if block.timestamp_utc < previous.timestamp_utc:
                raise ValueError("timestamps must not decrease")
        previous = block
