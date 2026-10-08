"""Tests for TraceKit core: sealer, verifier, and store (milestone 4.0-M1, P2).

manifest_hash: 5a5339ac310d5ccd6e435f0652f6294ed641815fe5e2a541a6f95c06d35646e6
"""
from __future__ import annotations

import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ctxfw.audit.contracts import (
    ActionBlockDTO,
    ChainVerificationAuditDTO,
    HashChainedAuditBlockDTO,
    IntentBlockDTO,
    LedgerEvent,
    LedgerState,
    ReasoningBlockDTO,
    canonical_timestamp,
    compute_block_hash,
    derive_genesis_hash,
    derive_ledger_id,
    sha256_hex,
)
from ctxfw.audit.sealer import (
    PREIMAGE_BYTES,
    PreimageIntegrityError,
    build_preimage,
    capture_action,
    capture_intent,
    capture_reasoning,
    capture_triad,
    seal,
    seal_block,
)
from ctxfw.audit.store import (
    BUSY_TIMEOUT_MS,
    EXPECTED_TABLES,
    EXPECTED_TRIGGER_COUNT,
    AppendOutcome,
    LatchPersistenceError,
    LedgerAppendRejected,
    SchemaIntegrityError,
    TRACEKIT_DB_ENV,
    TRACEKIT_DB_NAME,
    TraceKitStore,
    resolve_tracekit_db_path,
)
from ctxfw.audit.verifier import (
    FAIL_CLOSED_TOTAL,
    INVALID_SESSION_ID,
    apply_latch,
    fail_closed_audit,
    verify_chain,
    verify_fail_closed,
)
from ctxfw.kernel.audit_port import AuditPort
from ctxfw.kernel.clock import FixedClock, SystemUtcClock
from ctxfw.kernel.contracts import AuditEventDTO, AuditReceiptDTO, make_audit_event
from ctxfw.kernel.failure import FailureClass

T0 = datetime(2026, 10, 8, 12, 0, 0, 0, tzinfo=timezone.utc)
D1 = sha256_hex("intent-0")
D2 = sha256_hex("reasoning-0")
D3 = sha256_hex("action-0")
PREV0 = derive_genesis_hash("SES-test0001")


# ==============================================================================
# 1. Sealer tests
# ==============================================================================
def test_preimage_constant_is_283_bytes():
    assert PREIMAGE_BYTES == 283


def test_build_preimage_length_and_composition():
    raw = build_preimage(PREV0, D1, D2, D3, T0)
    assert isinstance(raw, bytes)
    assert len(raw) == 283
    assert len(raw) == PREIMAGE_BYTES
    expected = (PREV0 + D1 + D2 + D3 + canonical_timestamp(T0)).encode("ascii")
    assert raw == expected


@pytest.mark.parametrize(
    "bad_digest",
    [
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
        ("a" * 63) + "\n",
        "",
        1234,
        None,
    ],
)
def test_build_preimage_rejects_malformed_digests(bad_digest):
    with pytest.raises(ValueError):
        build_preimage(bad_digest, D1, D2, D3, T0)
    with pytest.raises(ValueError):
        build_preimage(PREV0, bad_digest, D2, D3, T0)
    with pytest.raises(ValueError):
        build_preimage(PREV0, D1, bad_digest, D3, T0)
    with pytest.raises(ValueError):
        build_preimage(PREV0, D1, D2, bad_digest, T0)


def test_build_preimage_rejects_naive_or_non_utc_timestamp():
    naive = datetime(2026, 10, 8, 12, 0, 0)
    with pytest.raises(ValueError):
        build_preimage(PREV0, D1, D2, D3, naive)

    non_utc = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    with pytest.raises(ValueError):
        build_preimage(PREV0, D1, D2, D3, non_utc)


def test_seal_block_deterministic_and_matches_compute_block_hash():
    block1 = seal_block("SES-test0001", 0, PREV0, D1, D2, D3, T0)
    block2 = seal_block("SES-test0001", 0, PREV0, D1, D2, D3, T0)
    assert block1 == block2
    assert block1.block_id == derive_ledger_id("BLK-", "SES-test0001", 0)
    assert block1.session_id == "SES-test0001"
    assert block1.block_seq == 0
    assert block1.prev_block_hash == PREV0
    assert block1.current_block_hash == compute_block_hash(PREV0, D1, D2, D3, T0)
    assert block1.current_block_hash == sha256_hex(build_preimage(PREV0, D1, D2, D3, T0).decode("ascii"))


def test_seal_with_typed_triad():
    intent = capture_intent("SES-test0001", 0, "  prompt 1  ")
    reasoning = capture_reasoning("SES-test0001", 0, "  plan 1  ")
    action = capture_action("SES-test0001", 0, "tool_x", "payload 1")

    assert intent.user_prompt == "prompt 1"
    assert reasoning.plan_summary == "plan 1"
    assert action.tool_or_file == "tool_x"
    assert action.payload_sha256 == sha256_hex("payload 1")
    assert not hasattr(action, "payload")  # payload itself is never retained

    block = seal("SES-test0001", 0, PREV0, intent, reasoning, action, T0)
    assert block.intent_digest == intent.intent_sha256
    assert block.reasoning_digest == reasoning.reasoning_sha256
    assert block.action_digest == action.payload_sha256


def test_seal_triad_type_safety():
    intent = capture_intent("SES-test0001", 0, "p")
    reasoning = capture_reasoning("SES-test0001", 0, "r")
    action = capture_action("SES-test0001", 0, "t", "a")

    with pytest.raises(TypeError, match="intent must be IntentBlockDTO"):
        seal("SES-test0001", 0, PREV0, "not_an_intent", reasoning, action, T0)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="reasoning must be ReasoningBlockDTO"):
        seal("SES-test0001", 0, PREV0, intent, "not_reasoning", action, T0)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="action must be ActionBlockDTO"):
        seal("SES-test0001", 0, PREV0, intent, reasoning, "not_action", T0)  # type: ignore[arg-type]


def test_capture_triad_convenience():
    intent, reasoning, action = capture_triad("SES-test0001", 1, " user p ", " plan s ", "tool_y", "payload_z")
    assert intent.intent_id == derive_ledger_id("INT-", "SES-test0001", 1)
    assert reasoning.reasoning_id == derive_ledger_id("RSN-", "SES-test0001", 1)
    assert action.action_id == derive_ledger_id("ACT-", "SES-test0001", 1)
    assert intent.user_prompt == "user p"
    assert reasoning.plan_summary == "plan s"
    assert action.tool_or_file == "tool_y"


# ==============================================================================
# 2. Verifier tests
# ==============================================================================
def test_verify_chain_empty_is_clean():
    session_id = "SES-empty001"
    genesis = derive_genesis_hash(session_id)
    audit = verify_chain(session_id, genesis, [], T0)
    assert not audit.is_tampered
    assert audit.total_blocks_audited == 0
    assert audit.broken_block_seq is None
    assert audit.session_id == session_id
    assert audit.verified_at == T0


def test_verify_chain_multi_block_clean():
    session_id = "SES-valid001"
    genesis = derive_genesis_hash(session_id)
    blocks = []
    prev = genesis
    for seq in range(4):
        t = T0 + timedelta(seconds=seq)
        b = seal_block(session_id, seq, prev, D1, D2, D3, t)
        blocks.append(b)
        prev = b.current_block_hash

    audit = verify_chain(session_id, genesis, blocks, T0 + timedelta(seconds=10))
    assert not audit.is_tampered
    assert audit.total_blocks_audited == 4
    assert audit.broken_block_seq is None


@pytest.mark.parametrize(
    "tamper_field",
    [
        "intent_digest",
        "reasoning_digest",
        "action_digest",
        "current_block_hash",
        "prev_block_hash",
        "block_seq",
        "session_id",
        "timestamp_utc",
    ],
)
def test_verify_chain_detects_block_tamper(tamper_field):
    session_id = "SES-tamper01"
    genesis = derive_genesis_hash(session_id)
    blocks = []
    prev = genesis
    for seq in range(3):
        t = T0 + timedelta(seconds=seq)
        b = seal_block(session_id, seq, prev, D1, D2, D3, t)
        blocks.append(b)
        prev = b.current_block_hash

    # Corrupt block 1
    b1 = blocks[1]
    kwargs = {
        "block_id": b1.block_id,
        "session_id": b1.session_id,
        "block_seq": b1.block_seq,
        "prev_block_hash": b1.prev_block_hash,
        "current_block_hash": b1.current_block_hash,
        "intent_digest": b1.intent_digest,
        "reasoning_digest": b1.reasoning_digest,
        "action_digest": b1.action_digest,
        "timestamp_utc": b1.timestamp_utc,
    }

    if tamper_field == "intent_digest":
        kwargs["intent_digest"] = sha256_hex("forged_intent")
    elif tamper_field == "reasoning_digest":
        kwargs["reasoning_digest"] = sha256_hex("forged_reasoning")
    elif tamper_field == "action_digest":
        kwargs["action_digest"] = sha256_hex("forged_action")
    elif tamper_field == "current_block_hash":
        kwargs["current_block_hash"] = sha256_hex("forged_hash")
    elif tamper_field == "prev_block_hash":
        kwargs["prev_block_hash"] = sha256_hex("forged_prev")
    elif tamper_field == "block_seq":
        kwargs["block_seq"] = 99
    elif tamper_field == "session_id":
        kwargs["session_id"] = "SES-tamper99"
    elif tamper_field == "timestamp_utc":
        kwargs["timestamp_utc"] = T0 - timedelta(seconds=10)

    blocks[1] = HashChainedAuditBlockDTO(**kwargs)

    audit = verify_chain(session_id, genesis, blocks, T0 + timedelta(seconds=20))
    assert audit.is_tampered
    assert audit.broken_block_seq == 1
    assert audit.total_blocks_audited == 2


def test_verify_fail_closed_on_bad_inputs():
    audit = verify_fail_closed("SES-bad00001", "genesis", "not_a_list", T0)
    assert audit.is_tampered
    assert audit.broken_block_seq == 0
    assert audit.total_blocks_audited == FAIL_CLOSED_TOTAL
    assert audit.verified_at == T0

    # Invalid session format
    audit_bad_sid = verify_fail_closed("INVALID_SESSION", "genesis", [], T0)
    assert audit_bad_sid.is_tampered
    assert audit_bad_sid.session_id == INVALID_SESSION_ID
    assert audit_bad_sid.verified_at == T0


def test_verify_chain_detects_forged_genesis_hash():
    session_id = "SES-forgedgen01"
    forged_genesis = sha256_hex("forged_root")
    b0 = seal_block(session_id, 0, forged_genesis, D1, D2, D3, T0)

    # Even though block 0 links to forged_genesis, audit must reject the invalid genesis
    audit = verify_chain(session_id, forged_genesis, [b0], T0)
    assert audit.is_tampered is True
    assert audit.broken_block_seq == 0
    assert audit.total_blocks_audited == 1

    # Empty chain with forged genesis is also detected
    empty_audit = verify_chain(session_id, forged_genesis, [], T0)
    assert empty_audit.is_tampered is True
    assert empty_audit.broken_block_seq == 0
    assert empty_audit.total_blocks_audited == 1


def test_apply_latch_behavior():
    session_id = "SES-latch001"
    clean_audit = ChainVerificationAuditDTO(
        session_id=session_id,
        total_blocks_audited=3,
        is_tampered=False,
        broken_block_seq=None,
        verified_at=T0,
    )

    # When latched at block 1, clean audit is overridden to tampered
    latched = apply_latch(clean_audit, 1)
    assert latched.is_tampered
    assert latched.broken_block_seq == 1
    assert latched.total_blocks_audited == 3

    # Already tampered audit is preserved
    tampered_audit = ChainVerificationAuditDTO(
        session_id=session_id,
        total_blocks_audited=2,
        is_tampered=True,
        broken_block_seq=0,
        verified_at=T0,
    )
    assert apply_latch(tampered_audit, 1) == tampered_audit

    # Unlatched session remains clean
    assert apply_latch(clean_audit, None) == clean_audit


# ==============================================================================
# 3. Store: WAL initialization and schema validation
# ==============================================================================
def test_store_memory_initialization_and_schema():
    clock = FixedClock(T0)
    with TraceKitStore(":memory:", clock) as store:
        assert store.db_path == ":memory:"
        assert store.pragma("foreign_keys") == 1
        assert store.pragma("busy_timeout") == BUSY_TIMEOUT_MS
        triggers = store.trigger_names()
        assert len(triggers) == EXPECTED_TRIGGER_COUNT
        assert "trg_tracekit_blocks_no_update" in triggers
        assert "trg_tracekit_blocks_tamper_latch" in triggers


def test_store_file_initialization_with_wal(tmp_path):
    db_file = tmp_path / TRACEKIT_DB_NAME
    clock = FixedClock(T0)
    with TraceKitStore(db_file, clock) as store:
        assert store.db_path == str(db_file)
        journal_mode = store.pragma("journal_mode")
        assert str(journal_mode).lower() == "wal"
        assert store.pragma("synchronous") == 1  # NORMAL
        assert len(store.trigger_names()) == EXPECTED_TRIGGER_COUNT


def test_store_refuses_non_tracekit_db_filename(tmp_path):
    clock = FixedClock(T0)
    for bad_name in ["tokens.db", "telemetry.db", "tracekit.sqlite", "other.db"]:
        with pytest.raises(ValueError, match="TraceKitStore opens only tracekit.db"):
            TraceKitStore(tmp_path / bad_name, clock)


def test_resolve_tracekit_db_path_defaults_and_env(tmp_path, monkeypatch):
    monkeypatch.delenv(TRACEKIT_DB_ENV, raising=False)
    resolved = resolve_tracekit_db_path()
    assert resolved.name == TRACEKIT_DB_NAME

    custom = tmp_path / TRACEKIT_DB_NAME
    monkeypatch.setenv(TRACEKIT_DB_ENV, str(custom))
    assert resolve_tracekit_db_path() == custom

    # Invalid env override
    monkeypatch.setenv(TRACEKIT_DB_ENV, str(tmp_path / "wrong.db"))
    with pytest.raises(ValueError, match="file must be named tracekit.db"):
        resolve_tracekit_db_path()


def test_store_validates_schema_integrity_on_extra_trigger(tmp_path):
    db_file = tmp_path / TRACEKIT_DB_NAME
    clock = FixedClock(T0)
    with TraceKitStore(db_file, clock):
        pass  # initialized successfully

    # Corrupt schema: add an unauthorized trigger
    conn = sqlite3.connect(db_file)
    conn.execute(
        "CREATE TRIGGER trg_unauthorized_extra BEFORE INSERT ON tracekit_sessions BEGIN SELECT 1; END;"
    )
    conn.close()

    with pytest.raises(SchemaIntegrityError, match="expected exactly the 12 sealed triggers"):
        TraceKitStore(db_file, clock)


def test_store_validates_schema_integrity_on_altered_sealed_ddl(monkeypatch):
    clock = FixedClock(T0)
    from ctxfw import audit

    # Monkeypatch load_schema_sql to simulate a drifted DDL declaration
    original_sql = audit.load_schema_sql()
    # Remove one trigger definition from DDL
    modified_sql = re.sub(r"CREATE TRIGGER IF NOT EXISTS trg_tracekit_sessions_no_update\b.*?\bEND;", "", original_sql, flags=re.DOTALL)
    monkeypatch.setattr(audit, "load_schema_sql", lambda: modified_sql)

    with pytest.raises(SchemaIntegrityError, match="the sealed DDL no longer declares exactly 12 triggers"):
        TraceKitStore(":memory:", clock)


# ==============================================================================
# 4. Store: append, hash-chaining, and DDL triggers
# ==============================================================================
def test_store_append_digests_chains_correctly():
    clock = FixedClock(T0)
    session_id = "SES-storechain01"
    with TraceKitStore(":memory:", clock) as store:
        outcome0 = store.append_digests(session_id, D1, D2, D3, T0)
        assert outcome0.state is LedgerState.APPENDED
        assert outcome0.block is not None
        assert outcome0.block.block_seq == 0
        assert outcome0.block.prev_block_hash == derive_genesis_hash(session_id)

        t1 = T0 + timedelta(seconds=1)
        outcome1 = store.append_digests(session_id, D1, D2, D3, t1)
        assert outcome1.state is LedgerState.APPENDED
        assert outcome1.block is not None
        assert outcome1.block.block_seq == 1
        assert outcome1.block.prev_block_hash == outcome0.block.current_block_hash

        blocks = store.load_blocks(session_id)
        assert len(blocks) == 2
        assert blocks[0] == outcome0.block
        assert blocks[1] == outcome1.block


def test_store_record_step_and_audit_port():
    clock = FixedClock(T0)
    session_id = "SES-auditport01"
    with TraceKitStore(":memory:", clock) as store:
        outcome = store.record_step(session_id, "prompt a", "plan b", "tool c", "payload d")
        assert outcome.state is LedgerState.APPENDED
        assert outcome.block is not None
        assert outcome.block.block_seq == 0

        # AuditPort.append invocation
        event = AuditEventDTO(
            session_id=session_id,
            intent_sha256=D1,
            reasoning_sha256=D2,
            tool_or_file="tool_test",
            payload_sha256=D3,
            timestamp_utc=T0 + timedelta(seconds=2),
        )
        receipt = store.append(event)
        assert isinstance(receipt, AuditReceiptDTO)
        assert receipt.session_id == session_id
        assert receipt.block_seq == 1
        assert receipt.block_hash == store.load_blocks(session_id)[1].current_block_hash


def test_store_triggers_reject_direct_update_and_delete():
    clock = FixedClock(T0)
    session_id = "SES-immutable01"
    with TraceKitStore(":memory:", clock) as store:
        store.record_step(session_id, "prompt 1", "plan 1", "tool 1", "payload 1")

        # Direct UPDATE on blocks table is forbidden
        with pytest.raises(sqlite3.IntegrityError, match="tracekit_audit_blocks is immutable"):
            store._conn.execute(
                "UPDATE tracekit_audit_blocks SET intent_digest = ? WHERE session_id = ?",
                (sha256_hex("tamper"), session_id),
            )

        # Direct UPDATE on sessions table is forbidden
        with pytest.raises(sqlite3.IntegrityError, match="tracekit_sessions is immutable"):
            store._conn.execute(
                "UPDATE tracekit_sessions SET genesis_hash = ? WHERE session_id = ?",
                (sha256_hex("tamper"), session_id),
            )

        # Direct DELETE on blocks table is forbidden
        with pytest.raises(sqlite3.IntegrityError, match="tracekit_audit_blocks is append-only"):
            store._conn.execute(
                "DELETE FROM tracekit_audit_blocks WHERE session_id = ?",
                (session_id,),
            )


def test_store_triggers_reject_decreasing_timestamp():
    clock = FixedClock(T0)
    session_id = "SES-monotime01"
    with TraceKitStore(":memory:", clock) as store:
        store.append_digests(session_id, D1, D2, D3, T0)
        # Attempt to append with older timestamp
        t_older = T0 - timedelta(seconds=5)
        outcome = store.append_digests(session_id, D1, D2, D3, t_older)
        assert outcome.state is LedgerState.REJECTED_INVALID
        assert outcome.quarantined is True
        assert outcome.failure_class is FailureClass.BUSINESS


# ==============================================================================
# 5. Store: verification and tamper latch activation
# ==============================================================================
def test_store_verify_session_clean():
    clock = FixedClock(T0)
    session_id = "SES-cleanver01"
    with TraceKitStore(":memory:", clock) as store:
        store.append_digests(session_id, D1, D2, D3, T0)
        store.append_digests(session_id, D1, D2, D3, T0 + timedelta(seconds=1))

        audit = store.verify_session(session_id)
        assert not audit.is_tampered
        assert audit.total_blocks_audited == 2
        assert audit.broken_block_seq is None
        assert store.latched_broken_seq(session_id) is None


def test_store_tamper_detection_and_latch_activation():
    clock = FixedClock(T0)
    session_id = "SES-tamperlatch01"
    with TraceKitStore(":memory:", clock) as store:
        # Append block 0 cleanly
        store.append_digests(session_id, D1, D2, D3, T0)

        # Manually forge block 1: valid sequence and prev link, but mismatched current_block_hash
        b0 = store.load_blocks(session_id)[0]
        t1 = T0 + timedelta(seconds=1)
        forged_current_hash = sha256_hex("forged_block_1")
        store._conn.execute(
            "INSERT INTO tracekit_audit_blocks (block_id, session_id, block_seq, prev_block_hash, "
            "current_block_hash, intent_digest, reasoning_digest, action_digest, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                derive_ledger_id("BLK-", session_id, 1),
                session_id,
                1,
                b0.current_block_hash,
                forged_current_hash,
                D1,
                D2,
                D3,
                canonical_timestamp(t1),
            ),
        )

        # Run verification: it must detect tampering at block 1
        audit = store.verify_session(session_id)
        assert audit.is_tampered
        assert audit.broken_block_seq == 1
        assert audit.total_blocks_audited == 2

        # Latch is now active in database
        assert store.latched_broken_seq(session_id) == 1

        # Attempt to append to the latched session must be rejected
        outcome = store.append_digests(session_id, D1, D2, D3, T0 + timedelta(seconds=5))
        assert outcome.state is LedgerState.REJECTED_INVALID
        assert outcome.quarantined is True
        assert outcome.failure_class is FailureClass.BUSINESS
        assert "session tampered: new blocks rejected" in outcome.reason

        # AuditPort.append raises LedgerAppendRejected
        event = AuditEventDTO(
            session_id=session_id,
            intent_sha256=D1,
            reasoning_sha256=D2,
            tool_or_file="tool_test",
            payload_sha256=D3,
            timestamp_utc=T0 + timedelta(seconds=6),
        )
        with pytest.raises(LedgerAppendRejected) as exc_info:
            store.append(event)
        assert exc_info.value.outcome.state is LedgerState.REJECTED_INVALID

        # Re-running verification on latched session never reports clean
        repeat_audit = store.verify_session(session_id)
        assert repeat_audit.is_tampered
        assert repeat_audit.broken_block_seq == 1

        # Tamper stickiness: direct SQL insert of a clean event is blocked by trigger
        with pytest.raises(sqlite3.IntegrityError, match="a clean verdict cannot overwrite a tampered verdict"):
            store._conn.execute(
                "INSERT INTO tracekit_verification_events (event_id, session_id, is_tampered, broken_seq, created_at) "
                "VALUES (?, ?, 0, NULL, ?)",
                (
                    derive_ledger_id("EVT-", session_id, 99),
                    session_id,
                    canonical_timestamp(T0 + timedelta(seconds=10)),
                ),
            )


def test_store_unknown_session_verify_fail_closed():
    clock = FixedClock(T0)
    with TraceKitStore(":memory:", clock) as store:
        audit = store.verify_session("SES-unknown999")
        assert audit.is_tampered
        assert audit.broken_block_seq == 0
        assert audit.total_blocks_audited == FAIL_CLOSED_TOTAL


def test_store_append_naive_timestamp_deterministic_rejection():
    clock = FixedClock(T0)
    session_id = "SES-naive001"
    with TraceKitStore(":memory:", clock) as store:
        naive = datetime(2026, 10, 8, 12, 0, 0)
        outcome = store.append_digests(session_id, D1, D2, D3, naive)
        assert outcome.state is LedgerState.REJECTED_INVALID
        assert outcome.quarantined is True
        assert outcome.failure_class is FailureClass.DETERMINISTIC


def test_store_append_wal_retry_exhausted_transient_rejection(monkeypatch):
    clock = FixedClock(T0)
    session_id = "SES-walretry01"
    with TraceKitStore(":memory:", clock) as store:
        from ctxfw.kernel.retry import RetryExhausted

        def fail_retry(op, *args, **kwargs):
            raise RetryExhausted(sqlite3.OperationalError("database is locked"), 3)

        monkeypatch.setattr("ctxfw.audit.store.run_with_wal_retry", fail_retry)
        outcome = store.append_digests(session_id, D1, D2, D3, T0)
        assert outcome.state is LedgerState.REJECTED_INVALID
        assert outcome.quarantined is True
        assert outcome.failure_class is FailureClass.TRANSIENT
        assert "WAL retries exhausted" in outcome.reason


def test_store_latch_persistence_error_on_verdict_failure(monkeypatch):
    clock = FixedClock(T0)
    session_id = "SES-persistfail01"
    with TraceKitStore(":memory:", clock) as store:
        # Pre-seed a clean block
        store.append_digests(session_id, D1, D2, D3, T0)

        # Force audit to appear tampered and fail during persist
        def fail_persist(audit):
            raise sqlite3.IntegrityError("disk failure")

        monkeypatch.setattr(store, "_persist_verdict_txn", fail_persist)
        monkeypatch.setattr(
            "ctxfw.audit.store.verify_fail_closed",
            lambda sid, genesis, blocks, verified_at: ChainVerificationAuditDTO(
                session_id=sid,
                total_blocks_audited=1,
                is_tampered=True,
                broken_block_seq=0,
                verified_at=verified_at,
            ),
        )

        with pytest.raises(LatchPersistenceError) as exc_info:
            store.verify_session(session_id)
        assert exc_info.value.audit.is_tampered is True


def test_append_outcome_invariants():
    # Valid APPENDED
    dummy_block = seal_block("SES-outcome001", 0, PREV0, D1, D2, D3, T0)
    ok = AppendOutcome(LedgerState.APPENDED, None, dummy_block, False, "ok")
    assert ok.state is LedgerState.APPENDED

    # Invalid APPENDED combinations
    with pytest.raises(ValueError, match="an APPENDED outcome carries a block and no failure"):
        AppendOutcome(LedgerState.APPENDED, FailureClass.SECURITY, dummy_block, False, "invalid")
    with pytest.raises(ValueError, match="an APPENDED outcome carries a block and no failure"):
        AppendOutcome(LedgerState.APPENDED, None, None, False, "invalid")
    with pytest.raises(ValueError, match="an APPENDED outcome carries a block and no failure"):
        AppendOutcome(LedgerState.APPENDED, None, dummy_block, True, "invalid")

    # Invalid REJECTED_INVALID combinations
    with pytest.raises(ValueError, match="a REJECTED_INVALID outcome carries a failure class"):
        AppendOutcome(LedgerState.REJECTED_INVALID, None, None, True, "invalid")
    with pytest.raises(ValueError, match="a REJECTED_INVALID outcome carries a failure class"):
        AppendOutcome(LedgerState.REJECTED_INVALID, FailureClass.SECURITY, None, False, "invalid")


def test_store_implements_audit_port():
    clock = FixedClock(T0)
    with TraceKitStore(":memory:", clock) as store:
        assert isinstance(store, AuditPort)


def test_store_record_step_type_safety_rejects_non_str_payload():
    clock = FixedClock(T0)
    session_id = "SES-typesafe01"
    with TraceKitStore(":memory:", clock) as store:
        # None payload must not raise TypeError; must return fail-closed outcome
        outcome_none = store.record_step(session_id, "prompt", "plan", "tool", None)
        assert outcome_none.state is LedgerState.REJECTED_INVALID
        assert outcome_none.quarantined is True
        assert outcome_none.failure_class is FailureClass.DETERMINISTIC

        # Integer payload must not raise TypeError
        outcome_int = store.record_step(session_id, "prompt", "plan", "tool", 12345)
        assert outcome_int.state is LedgerState.REJECTED_INVALID
        assert outcome_int.quarantined is True
        assert outcome_int.failure_class is FailureClass.DETERMINISTIC


def test_store_forged_prev_block_link_security_failure_class():
    clock = FixedClock(T0)
    session_id = "SES-forgedprev01"
    with TraceKitStore(":memory:", clock) as store:
        store.append_digests(session_id, D1, D2, D3, T0)

        # Attempt to insert a block with a mismatched prev_block_hash
        bad_prev = sha256_hex("forged_prev_hash")
        with pytest.raises(sqlite3.IntegrityError, match="prev_block_hash does not match") as exc_info:
            store._conn.execute(
                "INSERT INTO tracekit_audit_blocks (block_id, session_id, block_seq, prev_block_hash, "
                "current_block_hash, intent_digest, reasoning_digest, action_digest, created_at) "
                "VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    derive_ledger_id("BLK-", session_id, 1),
                    session_id,
                    bad_prev,
                    sha256_hex("h1"),
                    D1,
                    D2,
                    D3,
                    canonical_timestamp(T0 + timedelta(seconds=1)),
                ),
            )
        from ctxfw.audit.store import _classify_integrity_error

        assert _classify_integrity_error(exc_info.value) is FailureClass.SECURITY


def test_store_concurrent_independent_connections_same_session(tmp_path):
    db_file = tmp_path / TRACEKIT_DB_NAME
    clock = SystemUtcClock()

    with TraceKitStore(db_file, clock) as s1, TraceKitStore(db_file, clock) as s2:
        session_id = "SES-concurrent01"
        errors = []

        def worker1():
            try:
                res = s1.record_step(session_id, "prompt 1", "plan 1", "tool 1", "payload 1")
                assert res.state is LedgerState.APPENDED
            except Exception as e:
                errors.append(e)

        def worker2():
            try:
                res = s2.record_step(session_id, "prompt 2", "plan 2", "tool 2", "payload 2")
                assert res.state is LedgerState.APPENDED
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker1)
        t2 = threading.Thread(target=worker2)
        t1.start()
        t2.start()
        t1.join(timeout=10.0)
        t2.join(timeout=10.0)

        assert not errors, f"Concurrent worker errors: {errors}"
        blocks = s1.load_blocks(session_id)
        assert len(blocks) == 2
        assert blocks[0].block_seq == 0
        assert blocks[1].block_seq == 1
        assert blocks[1].prev_block_hash == blocks[0].current_block_hash

        audit = s1.verify_session(session_id)
        assert not audit.is_tampered
        assert audit.total_blocks_audited == 2

