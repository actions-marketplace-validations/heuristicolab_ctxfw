# manifest_hash: 11b623b097312b17d33c0ba6b7984b5a1954a133506e93dd813af794b22c0f0f
"""
tests/test_closed_loop_m2.py — Closed-Loop Integration Test Suite (M2-P3)
Axiom Manifest Hash: 11b623b097312b17d33c0ba6b7984b5a1954a133506e93dd813af794b22c0f0f

Verifies closed-loop integration:
  1. test_topological_reactive_degradation_under_budget_pressure
  2. test_topological_containment_under_emergency_halt
  3. test_mcp_pre_execution_path_traversal_blocking
  4. test_mcp_pre_execution_rule_intent_blocking
  5. test_tracekit_ledger_seals_circuit_and_security_events
  6. test_stdio_loop_hygiene_under_closed_loop_enforcement
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import pytest

from ctxfw.audit.store import TraceKitStore
from ctxfw.audit.verifier import verify_chain
from ctxfw.budget.contracts import (
    DecisionKind,
    SessionTokenBudgetDTO,
    TurnObservationTelemetryDTO,
)
from ctxfw.budget.store import TokenCastStore
from ctxfw.cli.main import run_trace_verify
from ctxfw.core.contracts import PruningDepth
from ctxfw.core.topological import ContextFirewallEngine, TopologicalContextBundleDTO
from ctxfw.kernel.clock import SystemUtcClock
from ctxfw.mcp import MCPServer
from ctxfw.rules.compiler import RulesCompiler
from ctxfw.rules.contracts import EnforcementVerdict
from ctxfw.rules.store import RulesStore


def test_topological_reactive_degradation_under_budget_pressure(tmp_path: Path):
    """
    Demonstrates that under TRIPPED, the bundle collapses peripheral dependencies to D3,
    achieving a significantly higher mass elision than under CLOSED.
    """
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "from service import OrderService\n\n"
        "def main():\n"
        "    s = OrderService()\n"
        "    return s.submit_order(100)\n",
        encoding="utf-8",
    )

    service_py = tmp_path / "service.py"
    service_py.write_text(
        "from repository import OrderRepository\n\n"
        "class OrderService:\n"
        '    """Enterprise service orchestrating order lifecycle and validations."""\n'
        "    def __init__(self):\n"
        "        self.repo = OrderRepository()\n\n"
        "    def submit_order(self, amount: int) -> int:\n"
        '        """Submit and validate a transactional order with audit checks."""\n'
        "        if amount <= 0:\n"
        '            raise ValueError("Amount must be strictly positive")\n'
        "        return self.repo.create(amount)\n\n"
        "    def cancel_order(self, order_id: str) -> bool:\n"
        '        """Cancel an existing order and refund the balance."""\n'
        "        return True\n\n"
        "    def calculate_tax(self, amount: int, rate: float) -> int:\n"
        '        """Calculate applicable sales tax."""\n'
        "        return int(amount * rate)\n",
        encoding="utf-8",
    )

    repo_py = tmp_path / "repository.py"
    repo_py.write_text(
        "class OrderRepository:\n"
        '    """Database repository for transactional order records."""\n'
        "    SCHEMA_VERSION = 3\n\n"
        "    def __init__(self):\n"
        "        self._records = []\n\n"
        "    def create(self, amount: int) -> int:\n"
        '        """Persist a new order record into the database."""\n'
        "        self._records.append(amount)\n"
        "        return len(self._records)\n\n"
        "    def find_all(self):\n"
        '        """Retrieve all active records."""\n'
        "        return list(self._records)\n",
        encoding="utf-8",
    )

    engine = ContextFirewallEngine(project_root=tmp_path)

    # 1. CLOSED execution: nominal distances (D0 full, D1 interface, D2 nominal)
    bundle_closed = engine.build_context("app.py", breaker_state="CLOSED")
    assert "app.py" in bundle_closed.entries
    assert "service.py" in bundle_closed.entries
    assert bundle_closed.entries["service.py"].depth == PruningDepth.INTERFACE
    # Check that method signatures and docstrings are retained in INTERFACE mode
    closed_service_code = bundle_closed.entries["service.py"].pruned_code
    assert "submit_order" in closed_service_code
    assert "calculate_tax" in closed_service_code
    closed_chars = sum(len(e.pruned_code) for e in bundle_closed.entries.values())

    # 2. TRIPPED execution: peripheral dependencies collapse to D3 interfaces (NOMINAL with stripped docs)
    # and transitive modules (D2+) collapse into ambient manifest
    bundle_tripped = engine.build_context("app.py", breaker_state="TRIPPED")
    assert "app.py" in bundle_tripped.entries
    assert "service.py" in bundle_tripped.entries
    assert bundle_tripped.entries["service.py"].depth == PruningDepth.NOMINAL
    tripped_service_code = bundle_tripped.entries["service.py"].pruned_code
    # In NOMINAL mode with stripped docs, method bodies and signatures are elided
    assert "submit_order" not in tripped_service_code
    assert "calculate_tax" not in tripped_service_code
    assert bundle_tripped.ambient_manifest is not None
    assert "repository" in bundle_tripped.ambient_manifest

    tripped_chars = sum(len(e.pruned_code) for e in bundle_tripped.entries.values())
    assert tripped_chars < closed_chars
    elision_diff = closed_chars - tripped_chars
    assert elision_diff > 100

    # 3. Dynamic build_context_with_budget integration with TokenCast & TraceKit stores
    tokencast_db = tmp_path / "tokencast.db"
    tracekit_db = tmp_path / "tracekit.db"
    tokencast_store = TokenCastStore(tokencast_db)
    tracekit_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())

    budget = SessionTokenBudgetDTO(
        session_id="SES-tripped-001",
        soft_limit_tokens=5000,
        hard_limit_tokens=20000,
        max_turns=10,
    )
    tokencast_store.create_session_budget(budget)
    tokencast_store.record_turn_telemetry(budget.session_id, 0, 1000, 200)
    tokencast_store.record_turn_telemetry(budget.session_id, 1, 1200, 300)

    history = [
        TurnObservationTelemetryDTO(turn_index=0, prompt_tokens=1000, completion_tokens=200, tool_count=1, elapsed_ms=50),
        TurnObservationTelemetryDTO(turn_index=1, prompt_tokens=1200, completion_tokens=300, tool_count=1, elapsed_ms=50),
    ]
    bundle_from_budget = engine.build_context_with_budget(
        "app.py",
        budget=budget,
        history=history,
        horizon_turns=3,
        tokencast_store=tokencast_store,
        tracekit_store=tracekit_store,
    )
    assert bundle_from_budget.entries["service.py"].depth == PruningDepth.NOMINAL
    events = tokencast_store.get_enforcement_events(budget.session_id)
    assert len(events) >= 1
    assert events[-1]["decision"] == "FORCE_D3_PRUNING"

    blocks = tracekit_store.load_blocks(budget.session_id)
    assert len(blocks) >= 1

    # 4. MCP Server resolve_context_bundle with dynamic budget resolution
    mcp_server = MCPServer(
        tokencast_store=tokencast_store,
        tracekit_store=tracekit_store,
        session_id=budget.session_id,
    )
    mcp_res = mcp_server.handle_tools_call({
        "name": "resolve_context_bundle",
        "arguments": {
            "target_file": str(app_py),
            "project_root": str(tmp_path),
            "session_id": budget.session_id,
        },
    })
    assert mcp_res["isError"] is False
    mcp_text = mcp_res["content"][0]["text"]
    assert "File: service.py [NOMINAL]" in mcp_text
    service_part = mcp_text.split("### File: service.py")[1].split("###")[0]
    assert "submit_order" not in service_part
    assert "calculate_tax" not in service_part
    assert "AMBIENT MANIFEST [D3]" in mcp_text

    tokencast_store.close()
    tracekit_store.close()


def test_topological_containment_under_emergency_halt(tmp_path: Path):
    """
    Demonstrates that under HALTED, dependency resolution is aborted immediately
    and an immutable containment payload is returned without AST traversal.
    """
    app_py = tmp_path / "app.py"
    app_py.write_text("import service\n", encoding="utf-8")

    engine = ContextFirewallEngine(project_root=tmp_path)
    halt_dir = tmp_path / "halt"
    halt_dir.mkdir(parents=True, exist_ok=True)
    tokencast_db = halt_dir / "tokencast.db"
    tracekit_db = halt_dir / "tracekit.db"
    tokencast_store = TokenCastStore(tokencast_db)
    tracekit_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())

    # 1. Direct breaker_state="HALTED"
    session_halted_id = "SES-halted-001"
    bundle_halted = engine.build_context(
        "app.py",
        breaker_state="HALTED",
        session_id=session_halted_id,
        tokencast_store=tokencast_store,
        tracekit_store=tracekit_store,
    )
    assert len(bundle_halted.entries) == 0
    assert bundle_halted.containment_notice is not None
    assert "HALTED" in bundle_halted.containment_notice
    prompt = bundle_halted.to_prompt()
    assert "# CONTEXT BUNDLE CONTAINED" in prompt
    assert bundle_halted.containment_notice in prompt

    events = tokencast_store.get_enforcement_events(session_halted_id)
    assert len(events) >= 1
    assert events[-1]["decision"] == "EMERGENCY_HALT"

    # 2. build_context_with_budget under hard limit overrun
    session_halted_id2 = "SES-halted-002"
    tight_budget = SessionTokenBudgetDTO(
        session_id=session_halted_id2,
        soft_limit_tokens=1000,
        hard_limit_tokens=2000,
        max_turns=10,
    )
    history_over = [
        TurnObservationTelemetryDTO(turn_index=0, prompt_tokens=1500, completion_tokens=800, tool_count=1, elapsed_ms=50),
    ]
    bundle_budget_halted = engine.build_context_with_budget(
        "app.py",
        budget=tight_budget,
        history=history_over,
        tokencast_store=tokencast_store,
        tracekit_store=tracekit_store,
    )
    assert len(bundle_budget_halted.entries) == 0
    assert bundle_budget_halted.containment_notice is not None
    assert "HALTED" in bundle_budget_halted.containment_notice

    # 3. Via MCPServer resolve_context_bundle
    mcp_server = MCPServer(
        tokencast_store=tokencast_store,
        tracekit_store=tracekit_store,
        session_id=session_halted_id,
    )
    res_mcp = mcp_server.handle_tools_call({
        "name": "resolve_context_bundle",
        "arguments": {
            "target_file": str(app_py),
            "project_root": str(tmp_path),
            "session_id": session_halted_id,
        },
    })
    assert res_mcp["isError"] is False
    assert "# CONTEXT BUNDLE CONTAINED" in res_mcp["content"][0]["text"]

    tokencast_store.close()
    tracekit_store.close()


def test_mcp_pre_execution_path_traversal_blocking(tmp_path: Path):
    """
    Sends malicious tool calls (%252e%252e, /../etc/passwd) to prune_file and
    resolve_context_bundle, verifying clean rejection with POLICY_BLOCKED and isError=True,
    as well as verification that rule_enforcement_logs records BLOCKED even when non-path guards are active.
    """
    rules_db = tmp_path / "rules_trav.db"
    rule_store = RulesStore(rules_db)

    # Compile a command-only guard to ensure active_guards has no path guards initially
    manifest, _, _ = RulesCompiler.compile_text("CLAUDE.md", "- never run `rm -rf`\n")
    assert manifest is not None
    rule_store.persist_manifest(manifest)

    server = MCPServer(rules_store=rule_store, guards=manifest.guards)

    # 1. prune_file with double-encoded traversal
    call_1 = {
        "name": "prune_file",
        "arguments": {"path": "%252e%252e/etc/passwd"},
    }
    res_1 = server.handle_tools_call(call_1)
    assert res_1["isError"] is True
    assert res_1.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_1["content"][0]["text"]
    assert "Security violation detected by RulesEnforcer" in res_1["content"][0]["text"]

    # Verify enforcement log recorded a BLOCKED verdict for the system security guard
    sys_guard = rule_store.ensure_system_guard()
    logs_trav = rule_store.get_logs(sys_guard.guard_id)
    assert len(logs_trav) >= 1
    assert logs_trav[0]["verdict"] == "BLOCKED"

    # 2. resolve_context_bundle with root-escaping path in target_file
    call_2 = {
        "name": "resolve_context_bundle",
        "arguments": {"target_file": "/../etc/shadow"},
    }
    res_2 = server.handle_tools_call(call_2)
    assert res_2["isError"] is True
    assert res_2.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_2["content"][0]["text"]
    assert "Security violation detected by RulesEnforcer" in res_2["content"][0]["text"]

    # 3. resolve_context_bundle with root-escaping path in project_root
    call_3 = {
        "name": "resolve_context_bundle",
        "arguments": {"target_file": "app.py", "project_root": "/../etc"},
    }
    res_3 = server.handle_tools_call(call_3)
    assert res_3["isError"] is True
    assert res_3.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_3["content"][0]["text"]

    # 4. Via process_raw_line (JSON-RPC stdio protocol level)
    raw_req = json.dumps({
        "jsonrpc": "2.0",
        "id": "req-traversal-01",
        "method": "tools/call",
        "params": {
            "name": "prune_file",
            "arguments": {"path": "../../secret.key"},
        },
    })
    raw_resp = server.process_raw_line(raw_req)
    assert raw_resp is not None
    rpc_obj = json.loads(raw_resp)
    assert rpc_obj["result"]["isError"] is True
    assert rpc_obj["result"]["policyViolation"] is True
    assert "POLICY_BLOCKED" in rpc_obj["result"]["content"][0]["text"]

    raw_req_bundle = json.dumps({
        "jsonrpc": "2.0",
        "id": "req-traversal-02",
        "method": "tools/call",
        "params": {
            "name": "resolve_context_bundle",
            "arguments": {"target_file": "/../etc/passwd"},
        },
    })
    raw_resp_bundle = server.process_raw_line(raw_req_bundle)
    assert raw_resp_bundle is not None
    rpc_obj_bundle = json.loads(raw_resp_bundle)
    assert rpc_obj_bundle["result"]["isError"] is True
    assert rpc_obj_bundle["result"]["policyViolation"] is True
    assert "POLICY_BLOCKED" in rpc_obj_bundle["result"]["content"][0]["text"]

    rule_store.close()


def test_mcp_pre_execution_rule_intent_blocking(tmp_path: Path):
    """
    Configures compiled rule guards (e.g. PATH_DENY on src/auth/session.py and .env)
    and verifies that targeted tool calls are blocked with logging in rule_enforcement_logs.
    """
    rules_db = tmp_path / "rules.db"
    rule_store = RulesStore(rules_db)

    manifest, _, _ = RulesCompiler.compile_text(
        "CLAUDE.md",
        "- do not edit `src/auth/session.py`\n- never read `.env`\n",
    )
    assert manifest is not None
    rule_store.persist_manifest(manifest)

    server = MCPServer(rules_store=rule_store, guards=manifest.guards)

    # 1. Target banned file src/auth/session.py
    res_auth = server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": "src/auth/session.py"},
    })
    assert res_auth["isError"] is True
    assert res_auth.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_auth["content"][0]["text"]

    # Verify log entry in rule_enforcement_logs for the matched guard
    auth_guard_id = manifest.guards[0].guard_id
    logs_auth = rule_store.get_logs(auth_guard_id)
    assert len(logs_auth) >= 1
    assert logs_auth[0]["verdict"] == "BLOCKED"

    # 2. Target banned file .env
    res_env = server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": ".env"},
    })
    assert res_env["isError"] is True
    assert res_env.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_env["content"][0]["text"]

    env_guard_id = manifest.guards[1].guard_id
    logs_env = rule_store.get_logs(env_guard_id)
    assert len(logs_env) >= 1
    assert logs_env[0]["verdict"] == "BLOCKED"

    rule_store.close()


def test_tracekit_ledger_seals_circuit_and_security_events(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Verifies that TraceKitStore seals security violation blocks and budget decisions,
    and that ctxfw trace verify and verify_chain audit and certify the hash chain.
    """
    tracekit_db = tmp_path / "tracekit.db"
    monkeypatch.setenv("CTXFW_TRACEKIT_DB", str(tracekit_db))

    clock = SystemUtcClock()
    trace_store = TraceKitStore(tracekit_db, clock=clock)

    session_id = "SES-tracekit-sealed-01"
    server = MCPServer(tracekit_store=trace_store, session_id=session_id)

    # 1. Trigger security violation (path traversal)
    server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": "%252e%252e/passwd", "session_id": session_id},
    })

    # 2. Trigger budget breaker event via build_context_with_budget
    app_file = tmp_path / "app.py"
    app_file.write_text("print('hello')\n", encoding="utf-8")

    engine = ContextFirewallEngine(project_root=tmp_path)
    budget = SessionTokenBudgetDTO(
        session_id=session_id,
        soft_limit_tokens=500,
        hard_limit_tokens=1000,
        max_turns=10,
    )
    history = [
        TurnObservationTelemetryDTO(turn_index=0, prompt_tokens=600, completion_tokens=200, tool_count=1, elapsed_ms=10),
    ]
    engine.build_context_with_budget(
        target_file="app.py",
        budget=budget,
        history=history,
        tracekit_store=trace_store,
    )

    # 3. Load sealed blocks and verify cryptographic continuity
    blocks = trace_store.load_blocks(session_id)
    assert len(blocks) >= 2

    # Audit the session chain via store verify_session
    audit = trace_store.verify_session(session_id)
    assert audit.is_tampered is False
    assert audit.broken_block_seq is None
    assert audit.total_blocks_audited == len(blocks)

    # Direct cryptographic verification using verify_chain function
    audit_chain = verify_chain(
        session_id=session_id,
        genesis_hash=blocks[0].prev_block_hash,
        blocks=blocks,
        verified_at=clock.now(),
    )
    assert audit_chain.is_tampered is False
    assert audit_chain.broken_block_seq is None
    assert audit_chain.total_blocks_audited == len(blocks)

    # Run CLI trace verify
    exit_code = run_trace_verify(str(tracekit_db))
    assert exit_code == 0

    trace_store.close()


def test_stdio_loop_hygiene_under_closed_loop_enforcement(tmp_path: Path):
    """
    Executes MCPServer.run_stdio_loop with allowed and blocked requests,
    verifying ZERO residual bytes in stdout outside JSON-RPC frames.
    """
    tracekit_db = tmp_path / "tracekit.db"
    rules_db = tmp_path / "rules.db"

    rule_store = RulesStore(rules_db)
    manifest, _, _ = RulesCompiler.compile_text("CLAUDE.md", "- do not edit `src/auth/session.py`\n")
    assert manifest is not None
    rule_store.persist_manifest(manifest)

    trace_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())
    server = MCPServer(
        tracekit_store=trace_store,
        rules_store=rule_store,
        guards=manifest.guards,
    )

    requests = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "prune_file", "arguments": {"path": "%252e%252e/escape"}}}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "prune_file", "arguments": {"path": "src/auth/session.py"}}}),
        json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "resolve_context_bundle", "arguments": {"target_file": "/../etc/shadow"}}}),
        json.dumps({"jsonrpc": "2.0", "id": 6, "method": "ping", "params": {}}),
    ]
    stream_input = "\n".join(requests) + "\n"

    stdin_buf = io.StringIO(stream_input)
    stdout_buf = io.StringIO()

    orig_stdin = sys.stdin
    orig_stdout = sys.stdout
    sys.stdin = stdin_buf
    sys.stdout = stdout_buf

    try:
        server.run_stdio_loop()
    finally:
        sys.stdin = orig_stdin
        sys.stdout = orig_stdout

    raw_output = stdout_buf.getvalue()
    lines = [l.strip() for l in raw_output.split("\n") if l.strip()]
    assert len(lines) == 6

    # Every single line in stdout MUST be a valid JSON-RPC 2.0 object
    for line in lines:
        parsed = json.loads(line)
        assert parsed.get("jsonrpc") == "2.0"
        assert "id" in parsed

    # Assert that blocked requests returned policy violations
    resp_traversal = json.loads(lines[1])
    assert resp_traversal["result"]["isError"] is True
    assert resp_traversal["result"]["policyViolation"] is True
    assert "POLICY_BLOCKED" in resp_traversal["result"]["content"][0]["text"]

    resp_rule = json.loads(lines[3])
    assert resp_rule["result"]["isError"] is True
    assert resp_rule["result"]["policyViolation"] is True
    assert "POLICY_BLOCKED" in resp_rule["result"]["content"][0]["text"]

    resp_traversal_bundle = json.loads(lines[4])
    assert resp_traversal_bundle["result"]["isError"] is True
    assert resp_traversal_bundle["result"]["policyViolation"] is True
    assert "POLICY_BLOCKED" in resp_traversal_bundle["result"]["content"][0]["text"]

