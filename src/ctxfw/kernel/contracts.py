"""Kernel contracts of the Sovereign Pentad (milestone 4.0-M1).

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000
manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3

Contents:
  * ``RuntimeMode`` / ``ModeState`` / ``mode_transition`` / ``parse_mode`` / ``resolve_mode``:
    the ``off | shadow | enforce`` switch (default ``shadow``) as a total, deterministic FSM.
    An invalid value is **never** silently accepted: it raises ``ValueError``.
  * ``AuditEventDTO`` / ``AuditReceiptDTO``: the envelope that crosses the ``AuditPort``.
    It carries **digests only** (the raw prompt/plan/payload never crosses the port), and a
    UTC-aware timestamp supplied by an injected ``Clock``.
  * ``derive_session_id`` / ``new_session_id`` / ``make_audit_event``.

These models are ctxfw-owned and intentionally independent of the sealed TraceKit contracts in
``ctxfw.audit.contracts`` (which stay byte-for-byte untouched); an adapter maps between them.
"""
import hashlib
import os
import secrets
from datetime import datetime
from enum import Enum
from typing import Annotated, Callable, Mapping, Optional, Tuple

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from ctxfw.kernel.clock import Clock, require_utc

__all__ = [
    "AuditEventDTO",
    "AuditReceiptDTO",
    "DEFAULT_MODE",
    "ModeEvent",
    "ModeState",
    "RuntimeMode",
    "derive_session_id",
    "make_audit_event",
    "mode_transition",
    "new_session_id",
    "parse_mode",
    "resolve_mode",
]

# ---------------------------------------------------------------------------------------------
# Bounds (aligned with the sealed TraceKit specs)
# ---------------------------------------------------------------------------------------------
SESSION_ID_PATTERN = r"^SES-[A-Za-z0-9_-]{4,64}$"
HASH_PATTERN = r"^[0-9a-f]{64}$"
USER_PROMPT_MAX = 65_536
PLAN_SUMMARY_MAX = 16_384
TOOL_OR_FILE_MAX = 512
BLOCK_SEQ_MAX = 1_000_000
TOOL_OR_FILE_PATTERN = r"^[^\x00-\x1f\x7f]+$"

Sha256Hex = Annotated[str, Field(strict=True, pattern=HASH_PATTERN)]
SessionId = Annotated[str, Field(strict=True, pattern=SESSION_ID_PATTERN)]
ToolOrFile = Annotated[
    str, Field(strict=True, min_length=1, max_length=TOOL_OR_FILE_MAX, pattern=TOOL_OR_FILE_PATTERN)
]
AwareUtc = Annotated[datetime, Field(strict=True), AfterValidator(require_utc)]
BlockSeq = Annotated[int, Field(strict=True, ge=0, le=BLOCK_SEQ_MAX)]


# ---------------------------------------------------------------------------------------------
# Runtime mode FSM:  delta(S, E)
# ---------------------------------------------------------------------------------------------
class RuntimeMode(str, Enum):
    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


DEFAULT_MODE = RuntimeMode.SHADOW


class ModeState(str, Enum):
    OFF = "OFF"
    SHADOW = "SHADOW"
    ENFORCE = "ENFORCE"
    REJECTED = "REJECTED"  # terminal / absorbing


class ModeEvent(str, Enum):
    SET_OFF = "SET_OFF"
    SET_SHADOW = "SET_SHADOW"
    SET_ENFORCE = "SET_ENFORCE"
    INVALID_VALUE = "INVALID_VALUE"


_MODE_TARGET: Mapping[ModeEvent, ModeState] = {
    ModeEvent.SET_OFF: ModeState.OFF,
    ModeEvent.SET_SHADOW: ModeState.SHADOW,
    ModeEvent.SET_ENFORCE: ModeState.ENFORCE,
    ModeEvent.INVALID_VALUE: ModeState.REJECTED,
}

_VALUE_TO_EVENT: Mapping[str, ModeEvent] = {
    "off": ModeEvent.SET_OFF,
    "shadow": ModeEvent.SET_SHADOW,
    "enforce": ModeEvent.SET_ENFORCE,
}


def mode_transition(state: object, event: object) -> ModeState:
    """Total transition function. ``REJECTED`` absorbs; unknown (S, E) pairs collapse to it."""
    if state is ModeState.REJECTED or not isinstance(state, ModeState):
        return ModeState.REJECTED
    if not isinstance(event, ModeEvent):
        return ModeState.REJECTED
    return _MODE_TARGET[event]


def parse_mode(value: object) -> RuntimeMode:
    """Exact-match parse of ``'off' | 'shadow' | 'enforce'``; anything else raises ``ValueError``."""
    event = _VALUE_TO_EVENT.get(value) if type(value) is str else None  # noqa: E721
    state = mode_transition(ModeState.SHADOW, event if event is not None else ModeEvent.INVALID_VALUE)
    if state is ModeState.REJECTED:
        raise ValueError(f"invalid runtime mode {value!r}; expected one of: off, shadow, enforce")
    return RuntimeMode(state.value.lower())


def resolve_mode(
    env_var: str,
    environ: Optional[Mapping[str, str]] = None,
    default: RuntimeMode = DEFAULT_MODE,
) -> RuntimeMode:
    """Read ``env_var``; unset -> ``default`` (shadow). A set-but-invalid value raises ``ValueError``."""
    source = os.environ if environ is None else environ
    if env_var not in source:
        return default
    return parse_mode(source[env_var])


# ---------------------------------------------------------------------------------------------
# Audit envelope
# ---------------------------------------------------------------------------------------------
class _KernelBaseDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class AuditEventDTO(_KernelBaseDTO):
    """One Intent-Reasoning-Action step expressed as digests (never raw text)."""

    session_id: SessionId
    intent_sha256: Sha256Hex
    reasoning_sha256: Sha256Hex
    tool_or_file: ToolOrFile
    payload_sha256: Sha256Hex
    timestamp_utc: AwareUtc


class AuditReceiptDTO(_KernelBaseDTO):
    """Acknowledgement returned by an ``AuditPort`` after a durable append."""

    session_id: SessionId
    block_seq: BlockSeq
    block_hash: Sha256Hex


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def derive_session_id(*parts: str) -> str:
    """Deterministic ``SES-`` id from caller-supplied parts (replays, tests)."""
    if not parts or any(type(p) is not str for p in parts):  # noqa: E721
        raise ValueError("derive_session_id requires one or more str parts")
    return "SES-" + _sha256_hex("\x1f".join(parts))[:32]


def new_session_id(entropy: Optional[Callable[[int], str]] = None) -> str:
    """Fresh ``SES-`` id. ``entropy`` is injectable; default is ``secrets.token_hex``."""
    token = (secrets.token_hex if entropy is None else entropy)(16)
    return "SES-" + token


def _bounded(name: str, text: object, maximum: int) -> str:
    if type(text) is not str or not (1 <= len(text) <= maximum):  # noqa: E721
        raise ValueError(f"{name} must be a str with length in [1, {maximum}]")
    return text


def make_audit_event(
    session_id: str,
    user_prompt: str,
    plan_summary: str,
    tool_or_file: str,
    payload: str,
    clock: Clock,
) -> AuditEventDTO:
    """Hash the raw inputs at the boundary and build the event. Raw text is not retained."""
    prompt = _bounded("user_prompt", user_prompt, USER_PROMPT_MAX)
    plan = _bounded("plan_summary", plan_summary, PLAN_SUMMARY_MAX)
    # payload digest bound mirrors the larger text bound; empty payloads are invalid (no hollow actions)
    body = _bounded("payload", payload, USER_PROMPT_MAX)
    return AuditEventDTO(
        session_id=session_id,
        intent_sha256=_sha256_hex(prompt),
        reasoning_sha256=_sha256_hex(plan),
        tool_or_file=tool_or_file,
        payload_sha256=_sha256_hex(body),
        timestamp_utc=clock.now(),
    )
