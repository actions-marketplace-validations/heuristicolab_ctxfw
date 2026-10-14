"""TraceKit sealer: pure, deterministic block sealing (milestone 4.0-M1, step P2).

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000 | 9 negative invariants
manifest_hash: 5a5339ac310d5ccd6e435f0652f6294ed641815fe5e2a541a6f95c06d35646e6
Sealed blueprint manifest_hash (TraceKit SIG-728856af9bd65ae0):
    7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c

H_t = SHA256(H_{t-1} || I_t || R_t || A_t || timestamp), over a fixed-width ASCII preimage of exactly
283 bytes: four 64-hex digests (256) plus the 27-character canonical UTC timestamp. The digest format
itself is owned by ``compute_block_hash`` (sealed contracts); this module never reimplements it. It adds
an *independent* preimage check on top: the bytes this module assembles must be exactly 283 long and
hash to the very value ``compute_block_hash`` returns, otherwise sealing is refused.

Purity contract (fabrication directive section 3): no float, no division, no clock, no randomness, no
environment, no disk or network I/O. The timestamp is an argument supplied by the caller.
"""
import re
from datetime import datetime
from typing import Tuple

from ctxfw.audit.contracts import (
    ActionBlockDTO,
    HashChainedAuditBlockDTO,
    IntentBlockDTO,
    ReasoningBlockDTO,
    canonical_timestamp,
    compute_block_hash,
    derive_ledger_id,
    sha256_hex,
)

__all__ = [
    "PREIMAGE_BYTES",
    "PreimageIntegrityError",
    "build_preimage",
    "capture_action",
    "capture_intent",
    "capture_reasoning",
    "capture_triad",
    "seal",
    "seal_block",
]

DIGEST_HEX_LEN = 64
TIMESTAMP_CHARS = 27
PREIMAGE_BYTES = 4 * DIGEST_HEX_LEN + TIMESTAMP_CHARS  # 283

_DIGEST_PATTERN = r"[0-9a-f]{64}"


class PreimageIntegrityError(ValueError):
    """The preimage drifted from the sealed 283-byte format (failure class SECURITY)."""


def _require_digest(name: str, value: object) -> str:
    # fullmatch, not the contract's ``$`` anchor: a trailing newline must never sneak in (284 bytes).
    if type(value) is not str or re.fullmatch(_DIGEST_PATTERN, value) is None:
        raise ValueError(f"{name} must be exactly 64 lowercase hex characters")
    return value


def build_preimage(
    prev_block_hash: str,
    intent_digest: str,
    reasoning_digest: str,
    action_digest: str,
    timestamp_utc: datetime,
) -> bytes:
    """Assemble the fixed-width ASCII preimage; refuse anything that is not exactly 283 bytes."""
    material = (
        _require_digest("prev_block_hash", prev_block_hash)
        + _require_digest("intent_digest", intent_digest)
        + _require_digest("reasoning_digest", reasoning_digest)
        + _require_digest("action_digest", action_digest)
        + canonical_timestamp(timestamp_utc)  # raises on naive / non-UTC / wrong length
    )
    raw = material.encode("ascii")
    if len(raw) != PREIMAGE_BYTES:
        raise PreimageIntegrityError(f"preimage must be exactly {PREIMAGE_BYTES} bytes, got {len(raw)}")
    return raw


def seal_block(
    session_id: str,
    block_seq: int,
    prev_block_hash: str,
    intent_digest: str,
    reasoning_digest: str,
    action_digest: str,
    timestamp_utc: datetime,
) -> HashChainedAuditBlockDTO:
    """Seal one block from digests (the form used by the kernel ``AuditPort``)."""
    preimage = build_preimage(prev_block_hash, intent_digest, reasoning_digest, action_digest, timestamp_utc)
    current = compute_block_hash(prev_block_hash, intent_digest, reasoning_digest, action_digest, timestamp_utc)
    if sha256_hex(preimage.decode("ascii")) != current:
        raise PreimageIntegrityError("independent preimage hash differs from compute_block_hash")
    return HashChainedAuditBlockDTO(
        block_id=derive_ledger_id("BLK-", session_id, block_seq),
        session_id=session_id,
        block_seq=block_seq,
        prev_block_hash=prev_block_hash,
        current_block_hash=current,
        intent_digest=intent_digest,
        reasoning_digest=reasoning_digest,
        action_digest=action_digest,
        timestamp_utc=timestamp_utc,
    )


def seal(
    session_id: str,
    block_seq: int,
    prev_block_hash: str,
    intent: IntentBlockDTO,
    reasoning: ReasoningBlockDTO,
    action: ActionBlockDTO,
    timestamp_utc: datetime,
) -> HashChainedAuditBlockDTO:
    """Seal one block from the typed Intent-Reasoning-Action triad (conformance form)."""
    if not isinstance(intent, IntentBlockDTO):
        raise TypeError("intent must be IntentBlockDTO")
    if not isinstance(reasoning, ReasoningBlockDTO):
        raise TypeError("reasoning must be ReasoningBlockDTO")
    if not isinstance(action, ActionBlockDTO):
        raise TypeError("action must be ActionBlockDTO")
    return seal_block(
        session_id,
        block_seq,
        prev_block_hash,
        intent.intent_sha256,
        reasoning.reasoning_sha256,
        action.payload_sha256,
        timestamp_utc,
    )


# ---------------------------------------------------------------------------------------------
# Triad capture: digest of the text *after* stripping, as the DTOs validate it.
# ---------------------------------------------------------------------------------------------
def capture_intent(session_id: str, block_seq: int, user_prompt: str) -> IntentBlockDTO:
    text = user_prompt.strip() if type(user_prompt) is str else user_prompt
    return IntentBlockDTO(
        intent_id=derive_ledger_id("INT-", session_id, block_seq),
        user_prompt=text,
        intent_sha256=sha256_hex(text),
    )


def capture_reasoning(session_id: str, block_seq: int, plan_summary: str) -> ReasoningBlockDTO:
    text = plan_summary.strip() if type(plan_summary) is str else plan_summary
    return ReasoningBlockDTO(
        reasoning_id=derive_ledger_id("RSN-", session_id, block_seq),
        plan_summary=text,
        reasoning_sha256=sha256_hex(text),
    )


def capture_action(session_id: str, block_seq: int, tool_or_file: str, payload: str) -> ActionBlockDTO:
    """Only the payload digest is retained; the payload itself is never persisted."""
    return ActionBlockDTO(
        action_id=derive_ledger_id("ACT-", session_id, block_seq),
        tool_or_file=tool_or_file,
        payload_sha256=sha256_hex(payload),
    )


def capture_triad(
    session_id: str,
    block_seq: int,
    user_prompt: str,
    plan_summary: str,
    tool_or_file: str,
    payload: str,
) -> Tuple[IntentBlockDTO, ReasoningBlockDTO, ActionBlockDTO]:
    return (
        capture_intent(session_id, block_seq, user_prompt),
        capture_reasoning(session_id, block_seq, plan_summary),
        capture_action(session_id, block_seq, tool_or_file, payload),
    )
