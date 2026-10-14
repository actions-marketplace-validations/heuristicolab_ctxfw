"""
tests/test_tracekit_integration.py — End-to-End TraceKit Integration & Stdio Hygiene Matrix
Axiom Manifest Hash: f1e4295bef2f28f87c0364875bba0ea956fa38bdb1bcf0fb0671f4b4242d1a6e

Validates:
  1. CLI subcommand `ctxfw trace verify` across clean, populated, and tampered states.
  2. Passive shadow audit interception during `handle_tools_call` in `src/ctxfw/mcp.py`.
  3. Strict stdio isolation (zero leak bytes, pure JSON-RPC frames over Content-Length & line-delimited streams).
  4. Integration with `ctxfw doctor` diagnostics and anchor attestation.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
import pytest

from ctxfw.audit.contracts import (
    HashChainedAuditBlockDTO,
    canonical_timestamp,
    compute_block_hash,
    derive_genesis_hash,
)
from ctxfw.audit.store import TraceKitStore, resolve_tracekit_db_path
from ctxfw.audit.verifier import verify_chain
from ctxfw.cli.main import handle_trace_command, run_trace_verify
from ctxfw.installer import run_doctor
from ctxfw.kernel.clock import FixedClock, SystemUtcClock
from ctxfw.mcp import MCPServer


@pytest.fixture
def isolated_tracekit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Provides an isolated tracekit.db file and overrides CTXFW_TRACEKIT_DB."""
    db_file = tmp_path / "tracekit.db"
    monkeypatch.setenv("CTXFW_TRACEKIT_DB", str(db_file))
    return db_file


def test_cli_trace_verify_empty_and_unpopulated(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that ctxfw trace verify handles non-existent or empty database gracefully."""
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    # 1. Non-existent database
    code = run_trace_verify(str(isolated_tracekit_db))
    assert code == 0
    out = buf.getvalue()
    assert "Chain Status:" in out
    assert "Total Blocks Audited:" in out
    assert "Latest Block Digest:" in out
    assert "Tamper Detected:" in out
    assert "tamper_detected:       False" in out
    assert "0" in out

    # 2. handle_trace_command dispatch
    buf.seek(0)
    buf.truncate(0)
    cmd_code = handle_trace_command(["verify", "--db", str(isolated_tracekit_db)])
    assert cmd_code == 0
    assert "tamper_detected:       False" in buf.getvalue()


def test_cli_trace_verify_populated_clean(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that ctxfw trace verify audits populated blocks and reports clean status."""
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        res1 = store.record_step(
            session_id="SES-2026-clean-01",
            user_prompt="Optimize imports in core.py",
            plan_summary="Parse AST and prune unused symbols",
            tool_or_file="prune_file",
            payload="import os\nimport sys\n",
        )
        assert res1.block is not None

        clock.advance(timedelta(seconds=1.5))
        res2 = store.record_step(
            session_id="SES-2026-clean-01",
            user_prompt="Build topological bundle",
            plan_summary="Construct dependency graph",
            tool_or_file="resolve_context_bundle",
            payload="bundle: target=core.py",
        )
        assert res2.block is not None

    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    exit_code = run_trace_verify(str(isolated_tracekit_db))
    assert exit_code == 0
    output = buf.getvalue()

    assert "VERIFIED_CLEAN" in output
    assert "Total Blocks Audited:" in output
    assert "2" in output
    assert "tamper_detected:       False" in output
    assert res2.block.current_block_hash in output


def test_cli_trace_verify_detects_tampering(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that offline tampering with block digests is immediately detected and flagged."""
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        store.record_step(
            session_id="SES-2026-tamper-01",
            user_prompt="Original user prompt",
            plan_summary="Original plan summary",
            tool_or_file="mcp_tool",
            payload="original payload",
        )
        clock.advance(timedelta(seconds=2.0))
        store.record_step(
            session_id="SES-2026-tamper-01",
            user_prompt="Second step",
            plan_summary="Second plan",
            tool_or_file="mcp_tool",
            payload="second payload",
        )

    # Perform offline adversary tampering by altering stored intent_digest
    conn = sqlite3.connect(str(isolated_tracekit_db))
    conn.execute("DROP TRIGGER trg_tracekit_blocks_no_update")
    conn.execute(
        "UPDATE tracekit_audit_blocks SET intent_digest = ? WHERE block_seq = 0",
        ("0" * 64,),
    )
    conn.commit()
    conn.close()

    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    exit_code = run_trace_verify(str(isolated_tracekit_db))
    assert exit_code == 1
    output = buf.getvalue()

    assert "TAMPER_DETECTED" in output
    assert "Tamper Detected:       \033[38;5;196mTrue" in output or "Tamper Detected:" in output
    assert "tamper_detected:       True" in output
    assert "broken at block 0" in output


def test_mcp_prune_file_records_audit_block(isolated_tracekit_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that MCP prune_file tool execution transparently records an audit block in tracekit.db."""
    monkeypatch.setenv("CTXFW_AUDIT_MODE", "shadow")

    target_code = "def calculate_finops(amount: float) -> float:\n    # internal logic\n    return amount * 0.42\n"
    target_file = tmp_path / "sample_service.py"
    target_file.write_text(target_code, encoding="utf-8")

    server = MCPServer()
    params = {
        "name": "prune_file",
        "arguments": {
            "path": str(target_file),
            "depth": "interface",
        },
    }

    result = server.handle_tools_call(params)
    assert result.get("isError") is False
    assert len(result["content"]) == 1
    assert "calculate_finops" in result["content"][0]["text"]

    # Verify that block was sealed in tracekit.db
    assert isolated_tracekit_db.is_file()
    with TraceKitStore(isolated_tracekit_db, clock=SystemUtcClock()) as store:
        blocks = store.load_blocks(server.session_id)
        assert len(blocks) == 1
        block = blocks[0]
        assert block.block_seq == 0
        assert block.session_id == server.session_id
        assert len(block.current_block_hash) == 64

        # Run formal backward audit
        audit = verify_chain(
            session_id=server.session_id,
            genesis_hash=derive_genesis_hash(server.session_id),
            blocks=blocks,
            verified_at=datetime.now(timezone.utc),
        )
        assert audit.is_tampered is False
        assert audit.total_blocks_audited == 1


def test_mcp_audit_mode_off_bypasses(isolated_tracekit_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that CTXFW_AUDIT_MODE='off' completely bypasses ledger recording (zero overhead)."""
    monkeypatch.setenv("CTXFW_AUDIT_MODE", "off")

    target_file = tmp_path / "off_test.py"
    target_file.write_text("def test_fn(): pass\n", encoding="utf-8")

    server = MCPServer()
    params = {
        "name": "prune_file",
        "arguments": {"path": str(target_file)},
    }
    result = server.handle_tools_call(params)
    assert result.get("isError") is False

    # The database file should not even be created if off
    if isolated_tracekit_db.is_file():
        conn = sqlite3.connect(str(isolated_tracekit_db))
        count = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        assert count == 0
        conn.close()


def test_mcp_shadow_mode_fail_silent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Asserts that errors in the shadow audit ledger never crash or interrupt MCP tool responses."""
    monkeypatch.setenv("CTXFW_AUDIT_MODE", "shadow")
    # Point DB to an invalid uncreatable path or mock store failure
    bad_db = tmp_path / "non_existent_folder" / "sub" / "invalid_name.db"
    monkeypatch.setenv("CTXFW_TRACEKIT_DB", str(bad_db))

    target_file = tmp_path / "dummy.py"
    target_file.write_text("class TestClass: pass\n", encoding="utf-8")

    stderr_buf = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr_buf)

    server = MCPServer()
    params = {
        "name": "prune_file",
        "arguments": {"path": str(target_file)},
    }

    # Must execute smoothly without raising
    result = server.handle_tools_call(params)
    assert result.get("isError") is False
    assert "class TestClass" in result["content"][0]["text"]


def test_stdio_loop_hygiene_and_content_length_zero_leak_bytes(
    isolated_tracekit_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    CRITICAL: Validates 100% pure JSON-RPC frames over stdio loop with zero leak bytes.
    Ensures Content-Length framing and line-delimited messages work seamlessly while
    passive shadow auditing records blocks in tracekit.db without writing a single stray byte to stdout.
    """
    monkeypatch.setenv("CTXFW_AUDIT_MODE", "shadow")

    target_code = "def process_data(value: int) -> int:\n    return value * 2\n"
    target_file = tmp_path / "data_processor.py"
    target_file.write_text(target_code, encoding="utf-8")

    # Frame 1: Line-delimited initialize
    frame1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

    # Frame 2: Content-Length framed tools/call for prune_file
    call_prune = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "prune_file",
            "arguments": {"path": str(target_file)},
        },
    })
    frame2 = f"Content-Length: {len(call_prune.encode('utf-8'))}\r\n\r\n{call_prune}"

    # Frame 3: Line-delimited evaluate_spec_axioms
    spec_content = (
        "# Architectural Brief\n"
        "## Invariants\n"
        "- The system shall never leak memory.\n"
        "- The system shall never accept invalid tokens.\n"
        "- The system shall never drop audit events.\n"
        "- The system shall never write non-JSON to stdout.\n"
        "- The system shall never expose raw preimages.\n"
    )
    frame3 = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "evaluate_spec_axioms",
            "arguments": {"brief_text": spec_content},
        },
    })

    # Frame 4: Content-Length framed ping
    ping_payload = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "ping"})
    frame4 = f"Content-Length: {len(ping_payload.encode('utf-8'))}\r\n\r\n{ping_payload}"

    # Combined stream with various blank lines / spacing
    raw_input_stream = f"{frame1}\n\n{frame2}\n{frame3}\n\n{frame4}\n"

    mock_stdin = io.StringIO(raw_input_stream)
    mock_stdout = io.StringIO()
    mock_stderr = io.StringIO()

    monkeypatch.setattr(sys, "stdin", mock_stdin)
    monkeypatch.setattr(sys, "stdout", mock_stdout)
    monkeypatch.setattr(sys, "stderr", mock_stderr)

    server = MCPServer()
    server.run_stdio_loop()

    # Verify stdout hygiene: Every line must be strict, valid JSON-RPC
    stdout_raw = mock_stdout.getvalue()
    stdout_lines = [ln.strip() for ln in stdout_raw.splitlines() if ln.strip()]

    assert len(stdout_lines) == 4, f"Expected 4 response frames, got {len(stdout_lines)}: {stdout_lines}"

    parsed_responses = []
    for line in stdout_lines:
        try:
            parsed = json.loads(line)
            assert parsed.get("jsonrpc") == "2.0"
            parsed_responses.append(parsed)
        except Exception as e:
            pytest.fail(f"Non-JSON pollution detected on stdout! Line: {line!r}, error: {e}")

    # Check Frame 1 (initialize)
    assert parsed_responses[0]["id"] == 1
    assert "capabilities" in parsed_responses[0]["result"]

    # Check Frame 2 (prune_file)
    assert parsed_responses[1]["id"] == 2
    assert parsed_responses[1]["result"]["isError"] is False
    assert "def process_data" in parsed_responses[1]["result"]["content"][0]["text"]

    # Check Frame 3 (evaluate_spec_axioms)
    assert parsed_responses[2]["id"] == 3
    assert parsed_responses[2]["result"]["isError"] is False

    # Check Frame 4 (ping)
    assert parsed_responses[3]["id"] == 4
    assert parsed_responses[3]["result"] == {}

    # Verify stderr isolation
    stderr_raw = mock_stderr.getvalue()
    assert "context-firewall-mcp" in stderr_raw
    assert "Server listening on stdio" in stderr_raw

    # Verify blocks were persisted in tracekit.db
    with TraceKitStore(isolated_tracekit_db, clock=SystemUtcClock()) as store:
        blocks = store.load_blocks(server.session_id)
        # Exactly 2 tool calls made: prune_file and evaluate_spec_axioms
        assert len(blocks) == 2
        assert blocks[0].block_seq == 0
        assert blocks[1].block_seq == 1
        assert blocks[1].prev_block_hash == blocks[0].current_block_hash

        audit = verify_chain(
            session_id=server.session_id,
            genesis_hash=derive_genesis_hash(server.session_id),
            blocks=blocks,
            verified_at=datetime.now(timezone.utc),
        )
        assert audit.is_tampered is False
        assert audit.total_blocks_audited == 2


def test_doctor_reports_tracekit_anchor(isolated_tracekit_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that ctxfw doctor inspects tracekit.db in read-only mode and reports anchor hash."""
    # 1. Without anchor file
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        res = store.record_step("SES-2026-doc-01", "doctor prompt", "doctor plan", "doctor_tool", "payload")
        assert res.block is not None
        latest_hash = res.block.current_block_hash

    report1 = run_doctor(project_root=tmp_path)
    check1 = next((c for c in report1.checks if c.name == "TraceKit Ledger Audit"), None)
    assert check1 is not None
    assert check1.status == "OK"
    assert "Chain status: INTACT (1 blocks)" in check1.details
    assert f"Anchor hash: {latest_hash}" in check1.details

    # 2. With explicit .tracekit.anchor file
    anchor_file = tmp_path / ".tracekit.anchor"
    custom_anchor = "a" * 64
    anchor_file.write_text(custom_anchor, encoding="utf-8")

    report2 = run_doctor(project_root=tmp_path)
    check2 = next((c for c in report2.checks if c.name == "TraceKit Ledger Audit"), None)
    assert check2 is not None
    assert check2.status == "OK"
    assert f"Anchor hash: {custom_anchor}" in check2.details


def test_cli_trace_verify_session_not_found_fails_closed(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that querying a non-existent session triggers fail-closed tamper detection (INV-10)."""
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        store.record_step("SES-2026-exist-01", "prompt", "plan", "tool", "payload")

    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    code = run_trace_verify(str(isolated_tracekit_db), session_id="SES-DOES-NOT-EXIST")
    assert code == 1
    out = buf.getvalue()
    assert "TAMPER_DETECTED (SESSION NOT FOUND)" in out
    assert "tamper_detected:       True" in out


def test_cli_trace_verify_corrupted_block_data_fails_closed(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that offline corruption of block fields fails closed with TAMPER_DETECTED rather than crashing."""
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        store.record_step("SES-2026-corrupt-01", "prompt", "plan", "tool", "payload")

    # Offline adversarial corruption of timestamp into an unparseable format
    conn = sqlite3.connect(str(isolated_tracekit_db))
    conn.execute("DROP TRIGGER trg_tracekit_blocks_no_update")
    conn.execute("UPDATE tracekit_audit_blocks SET created_at = ?", ("2026-99-99T99:99:99.999999Z",))
    conn.commit()
    conn.close()

    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    code = run_trace_verify(str(isolated_tracekit_db))
    assert code == 1
    out = buf.getvalue()
    assert "TAMPER_DETECTED" in out
    assert "tamper_detected:       True" in out


def test_cli_trace_verify_schema_tampering_detected(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that dropping a sealed table is flagged as schema tampering."""
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        store.record_step("SES-2026-schema-01", "prompt", "plan", "tool", "payload")

    conn = sqlite3.connect(str(isolated_tracekit_db))
    conn.execute("DROP TABLE tracekit_sessions")
    conn.commit()
    conn.close()

    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)

    code = run_trace_verify(str(isolated_tracekit_db))
    assert code == 1
    out = buf.getvalue()
    assert "TAMPER_DETECTED (SCHEMA CORRUPTED)" in out
    assert "tamper_detected:       True" in out


def test_doctor_detects_corrupted_block_and_schema_tampering(isolated_tracekit_db: Path, tmp_path: Path):
    """Asserts that doctor diagnoses corrupted blocks and dropped tables as FAIL with TAMPER_DETECTED."""
    clock = FixedClock(datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    with TraceKitStore(isolated_tracekit_db, clock=clock) as store:
        store.record_step("SES-2026-doc-corrupt", "prompt", "plan", "tool", "payload")

    conn = sqlite3.connect(str(isolated_tracekit_db))
    conn.execute("DROP TRIGGER trg_tracekit_blocks_no_update")
    conn.execute("UPDATE tracekit_audit_blocks SET created_at = ?", ("2026-99-99T99:99:99.999999Z",))
    conn.commit()
    conn.close()

    report = run_doctor(project_root=tmp_path)
    chk = next((c for c in report.checks if c.name == "TraceKit Ledger Audit"), None)
    assert chk is not None
    assert chk.status == "FAIL"
    assert "TAMPER_DETECTED" in chk.details

    # Schema tampering test
    conn2 = sqlite3.connect(str(isolated_tracekit_db))
    conn2.execute("DROP TABLE tracekit_sessions")
    conn2.commit()
    conn2.close()

    report2 = run_doctor(project_root=tmp_path)
    chk2 = next((c for c in report2.checks if c.name == "TraceKit Ledger Audit"), None)
    assert chk2 is not None
    assert chk2.status == "FAIL"
    assert "missing sealed tables" in chk2.details


def test_mcp_handle_tools_call_none_arguments(isolated_tracekit_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Asserts that null arguments dictionary in tool calls does not raise AttributeError and records shadow audit."""
    monkeypatch.setenv("CTXFW_AUDIT_MODE", "shadow")

    server = MCPServer()
    params = {"name": "prune_file", "arguments": None}

    result = server.handle_tools_call(params)
    assert result.get("isError") is True
    assert "Parameter 'path' is required" in result["content"][0]["text"]

    # Verify shadow audit block was recorded
    with TraceKitStore(isolated_tracekit_db, clock=SystemUtcClock()) as store:
        blocks = store.load_blocks(server.session_id)
        assert len(blocks) == 1
        assert blocks[0].block_seq == 0

