"""TraceKit verifier: pure backward audit of a hash chain (milestone 4.0-M1, step P2).

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000 | 9 negative invariants
manifest_hash: 5a5339ac310d5ccd6e435f0652f6294ed641815fe5e2a541a6f95c06d35646e6
Sealed blueprint manifest_hash (TraceKit SIG-728856af9bd65ae0):
    7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c

For each position ``i`` and in this exact order: block class/session, ``block_seq == i``,
``prev_block_hash`` equals the expected hash (genesis or predecessor), recomputed
``current_block_hash``, non-decreasing time. The first failure fixes ``broken_block_seq = i`` and
``total_blocks_audited = i + 1``. The fail-closed wrapper never raises: malformed input is reported as
tampered with ``broken_block_seq = 0`` and ``total_blocks_audited = 1`` (session ``SES-INVALID`` when the
id itself is invalid).

Honest scope (do not hide): without an external anchor this audit cannot detect tail truncation,
re-sealing of the LAST block, or re-chaining of the whole chain. A re-sealed block that is not last is
reported at ``k + 1`` (its successor's link), not at ``k``.

Purity contract (fabrication directive section 3): no float, no division, no clock, no randomness, no
environment, no disk or network I/O. ``verified_at`` is an argument supplied by the caller. The tamper
latch itself is enforced by the sealed DDL triggers when the verdict is persisted by the store;
``apply_latch`` is the pure rule that a latched session is never reported clean.
"""
import re
from datetime import datetime, timedelta
from typing import Iterable, Optional

from pydantic import ValidationError

from ctxfw.audit.contracts import (
    SESSION_ID_PATTERN,
    TIMESTAMP_MAX,
    TIMESTAMP_MIN,
    ChainVerificationAuditDTO,
    HashChainedAuditBlockDTO,
    compute_block_hash,
    derive_genesis_hash,
)

__all__ = [
    "FAIL_CLOSED_TOTAL",
    "apply_latch",
    "fail_closed_audit",
    "verify_chain",
    "verify_fail_closed",
]

FAIL_CLOSED_TOTAL = 1
INVALID_SESSION_ID = "SES-INVALID"


def _audit(
    session_id: str, total: int, broken: Optional[int], verified_at: datetime
) -> ChainVerificationAuditDTO:
    return ChainVerificationAuditDTO(
        session_id=session_id,
        total_blocks_audited=total,
        is_tampered=broken is not None,
        broken_block_seq=broken,
        verified_at=verified_at,
    )


def verify_chain(
    session_id: str,
    genesis_hash: str,
    blocks: Iterable[HashChainedAuditBlockDTO],
    verified_at: datetime,
) -> ChainVerificationAuditDTO:
    """Backward audit. The first inconsistent position is the verdict; a clean chain is never guessed."""
    chain = tuple(blocks)
    expected_genesis = derive_genesis_hash(session_id)
    if genesis_hash != expected_genesis:
        return _audit(session_id, FAIL_CLOSED_TOTAL, 0, verified_at)
    expected_prev = genesis_hash
    previous: Optional[HashChainedAuditBlockDTO] = None
    for position, block in enumerate(chain):
        consistent = (
            isinstance(block, HashChainedAuditBlockDTO)
            and block.session_id == session_id
            and block.block_seq == position
            and block.prev_block_hash == expected_prev
            and block.current_block_hash
            == compute_block_hash(
                block.prev_block_hash,
                block.intent_digest,
                block.reasoning_digest,
                block.action_digest,
                block.timestamp_utc,
            )
            and (previous is None or block.timestamp_utc >= previous.timestamp_utc)
        )
        if not consistent:
            return _audit(session_id, position + 1, position, verified_at)
        expected_prev = block.current_block_hash
        previous = block
    return _audit(session_id, len(chain), None, verified_at)


def fail_closed_audit(session_id: object, verified_at: datetime = TIMESTAMP_MIN) -> ChainVerificationAuditDTO:
    """The verdict reported for malformed input: tampered, position 0, one block audited."""
    valid = type(session_id) is str and re.fullmatch(SESSION_ID_PATTERN, session_id) is not None
    sid = session_id if valid else INVALID_SESSION_ID
    return _audit(sid, FAIL_CLOSED_TOTAL, 0, verified_at)


def verify_fail_closed(
    session_id: object,
    genesis_hash: object,
    blocks: object,
    verified_at: datetime,
) -> ChainVerificationAuditDTO:
    """Never raises on malformed input; reports it as tampered, never as clean (INV-10)."""
    ts = (
        verified_at
        if (
            isinstance(verified_at, datetime)
            and verified_at.tzinfo is not None
            and verified_at.utcoffset() == timedelta(0)
            and TIMESTAMP_MIN <= verified_at < TIMESTAMP_MAX
        )
        else TIMESTAMP_MIN
    )
    try:
        return verify_chain(session_id, genesis_hash, blocks, ts)  # type: ignore[arg-type]
    except (TypeError, ValueError, ValidationError):
        return fail_closed_audit(session_id, ts)


def apply_latch(
    audit: ChainVerificationAuditDTO, latched_broken_seq: Optional[int]
) -> ChainVerificationAuditDTO:
    """A session already carrying a tampered verdict is never reported clean (INV-09).

    ``latched_broken_seq`` is the ``broken_seq`` of the persisted tampered verdict (``None`` when the
    session is not latched). A tampered audit passes through unchanged; a clean audit of a latched
    session is replaced by a tampered verdict at the latched position.
    """
    if latched_broken_seq is None or audit.is_tampered:
        return audit
    total = max(audit.total_blocks_audited, latched_broken_seq + 1)
    return _audit(audit.session_id, total, latched_broken_seq, audit.verified_at)
