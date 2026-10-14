# manifest_hash: 0823534213f7266f79184a2f24e71680fd24cb9c5971f58eab7c2dd124023a7c
"""
tests/test_closed_loop_m4.py — Closed-Loop SWE-Gate Integration Test Suite (M4-P3)
Axiom Manifest Hash: 0823534213f7266f79184a2f24e71680fd24cb9c5971f58eab7c2dd124023a7c
Sealed Blueprint Manifest Hash: 8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f

Verifies closed-loop integration of SWE-Gate (SweGateInspector -> SweGateVerifier -> SweGateStore)
into MCPServer and TraceKitStore:
  1. test_mcp_swegate_allow_merge_clean_patch_and_tracekit_seal
  2. test_mcp_swegate_rejects_green_tests_with_architectural_violations
  3. test_mcp_swegate_fail_closed_on_malformed_diff_and_functional_failures
  4. test_tracekit_cli_trace_verify_certifies_swegate_closed_loop_chain
  5. test_stdio_loop_purity_under_swegate_allow_and_reject
  6. test_m4_p3_files_carry_manifest_hash_and_no_crlf
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys

import pytest

from ctxfw.audit.contracts import sha256_hex
from ctxfw.audit.store import TraceKitStore
from ctxfw.audit.verifier import verify_chain
from ctxfw.cli.main import run_trace_verify
from ctxfw.kernel.clock import SystemUtcClock
from ctxfw.mcp import MCPServer
from ctxfw.sara import SaraStore
from ctxfw.storage.cache import LocalSemanticCache
from ctxfw.swegate import (
    ArchitecturalConstraintRuleDTO,
    GateState,
    GateVerdict,
    SweGateStore,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_M4_P3_MANIFEST_HASH = (
    "0823534213f7266f79184a2f24e71680fd24cb9c5971f58eab7c2dd124023a7c"
)

CLEAN_DIFF = (
    "--- a/src/service/billing.py\n"
    "+++ b/src/service/billing.py\n"
    "@@ -1,2 +1,4 @@\n"
    " def compute_total(subtotal: int) -> int:\n"
    "+    if subtotal < 0:\n"
    "+        return 0\n"
    "     return subtotal\n"
)

DISALLOWED_IMPORT_DIFF = (
    "--- a/src/service/client.py\n"
    "+++ b/src/service/client.py\n"
    "@@ -1,2 +1,4 @@\n"
    "+import requests\n"
    "+from requests.adapters import HTTPAdapter\n"
    " def ping() -> bool:\n"
    "     return True\n"
)

TYPE_IGNORE_DIFF = (
    "--- a/src/service/types_mod.py\n"
    "+++ b/src/service/types_mod.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def coerce_val(x: object) -> int:\n"
    "+    return x.missing_attr  # type: ignore[attr-defined]\n"
    "     return 0\n"
)

HIGH_COMPLEXITY_DIFF = (
    "--- a/src/service/router.py\n"
    "+++ b/src/service/router.py\n"
    "@@ -1,2 +1,7 @@\n"
    " def route(code: int, flag: bool, extra: bool) -> int:\n"
    "+    if code == 1 and flag or extra:\n"
    "+        for idx in range(code):\n"
    "+            while idx < 0:\n"
    "+                pass\n"
    "+    return 1\n"
    "     return 0\n"
)

COMBINED_VIOLATIONS_DIFF = (
    "--- a/src/service/unsafe_patch.py\n"
    "+++ b/src/service/unsafe_patch.py\n"
    "@@ -1,2 +1,5 @@\n"
    "+import requests\n"
    " def run_patch(a: int, b: int) -> int:\n"
    "+    if a > 0 and b > 0 or a == b:\n"
    "+        return a.bad  # type: ignore[attr-defined]\n"
    "     return 0\n"
)


def test_mcp_swegate_allow_merge_clean_patch_and_tracekit_seal(tmp_path: Path):
    """
    Verifies that a clean unified diff with passing functional tests (tests_passed=64,
    tests_failed=0), cyclomatic_delta=1 <= max_cyclomatic_delta=3, zero '# type: ignore',
    and zero disallowed imports passes SWE-Gate with ALLOW_MERGE (PASS_GATE), persists
    in SweGateStore, seals SWE_GATE_ALLOW in TraceKitStore, and allows apply_patch /
    resolve_context_bundle / prune_file to complete.
    """
    swegate_db = tmp_path / "swegate_allow.db"
    tracekit_db = tmp_path / "tracekit.db"
    sara_db = tmp_path / "sara_allow.db"
    cache_db = tmp_path / "cache_allow.db"

    swegate_store = SweGateStore(swegate_db)
    tracekit_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())
    sara_store = SaraStore(sara_db)
    cache = LocalSemanticCache(str(cache_db))

    default_rule = ArchitecturalConstraintRuleDTO(
        rule_id="RULE-m4-allow-01",
        max_cyclomatic_delta=3,
        forbid_type_ignores=True,
        disallowed_import_modules=("requests", " boto3".strip()),
    )

    session_id = "SES-m4-allow-001"
    server = MCPServer(
        cache=cache,
        tracekit_store=tracekit_store,
        sara_store=sara_store,
        swegate_store=swegate_store,
        swegate_rule=default_rule,
        session_id=session_id,
    )

    # Verify evaluate_patch is exposed in tools/list with annotations and outputSchema
    tools_resp = server.handle_tools_list({})
    tool_map = {t["name"]: t for t in tools_resp["tools"]}
    assert "evaluate_patch" in tool_map
    assert "diff_text" in tool_map["evaluate_patch"]["inputSchema"]["required"]
    assert "content" in tool_map["evaluate_patch"]["outputSchema"]["required"]
    assert "isError" in tool_map["evaluate_patch"]["outputSchema"]["required"]

    commit_1 = "a" * 40
    res_eval = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": commit_1,
                "author_kind": "AGENT",
                "pr_id": 42,
                "tests_passed": 64,
                "tests_failed": 0,
                "repo_name": "heuristico/ctxfw",
            },
        }
    )
    assert res_eval.isError is False
    assert res_eval["isError"] is False
    assert res_eval["sweGateRejected"] is False
    assert res_eval["sweGateVerdict"] == "ALLOW_MERGE"
    assert res_eval["sweGateState"] == "PASS_GATE"
    assert res_eval["cyclomaticDelta"] == 1
    assert res_eval["architecturalViolations"] == []
    eval_id_1 = res_eval["evaluationId"]
    assert isinstance(eval_id_1, str) and eval_id_1.startswith("EVL-")

    report_json = json.loads(res_eval["content"][0]["text"])
    assert report_json["evaluation_id"] == eval_id_1
    assert report_json["gate_verdict"] == GateVerdict.ALLOW_MERGE.value
    assert report_json["gate_state"] == GateState.PASS_GATE.value
    assert report_json["cyclomatic_delta"] == 1
    assert report_json["architectural_violations"] == []

    # Verify SweGateStore persistence
    stored_eval = swegate_store.get_evaluation(eval_id_1)
    assert stored_eval is not None
    assert stored_eval["evaluation_id"] == eval_id_1
    assert stored_eval["commit_sha"] == commit_1
    assert stored_eval["functional_passed"] is True
    assert stored_eval["gate_verdict"] == "ALLOW_MERGE"
    assert stored_eval["violations_count"] == 0
    assert swegate_store.get_violations(eval_id_1) == []

    # Verify apply_patch writes target_file when ALLOW_MERGE
    proj = tmp_path / "proj_allow"
    proj.mkdir()
    billing_py = proj / "billing.py"
    billing_py.write_text(
        "def compute_total(subtotal: int) -> int:\n    return subtotal\n",
        encoding="utf-8",
    )
    updated_source = (
        "def compute_total(subtotal: int) -> int:\n"
        "    if subtotal < 0:\n"
        "        return 0\n"
        "    return subtotal\n"
    )
    res_apply = server.handle_tools_call(
        {
            "name": "apply_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "b" * 40,
                "tests_passed": 64,
                "tests_failed": 0,
                "target_file": str(billing_py),
                "new_content": updated_source,
            },
        }
    )
    assert res_apply["isError"] is False
    assert res_apply["sweGateVerdict"] == "ALLOW_MERGE"
    assert res_apply["patchApplied"] is True
    assert billing_py.read_text(encoding="utf-8") == updated_source

    # Verify resolve_context_bundle with diff_text runs SWE-Gate first and overlays metadata
    res_bundle = server.handle_tools_call(
        {
            "name": "resolve_context_bundle",
            "arguments": {
                "target_file": str(billing_py),
                "project_root": str(proj),
                "diff_text": CLEAN_DIFF,
                "commit_sha": "c" * 40,
                "tests_passed": 64,
                "tests_failed": 0,
            },
        }
    )
    assert res_bundle["isError"] is False
    assert res_bundle["sweGateVerdict"] == "ALLOW_MERGE"
    assert res_bundle["sweGateState"] == "PASS_GATE"
    assert res_bundle["evaluationId"].startswith("EVL-")
    assert "### File: billing.py [FULL]" in res_bundle["content"][0]["text"]

    # Verify TraceKitStore sealed SWE_GATE_ALLOW blocks
    blocks = tracekit_store.load_blocks(session_id)
    assert len(blocks) >= 3
    expected_payload_1 = (
        f"SWE_GATE_ALLOW: eval_id={eval_id_1} commit={commit_1} delta=1 state=PASS_GATE"
    )
    expected_action_digest_1 = sha256_hex(expected_payload_1)
    assert any(b.action_digest == expected_action_digest_1 for b in blocks)
    assert tracekit_store.verify_session(session_id).is_tampered is False

    swegate_store.close()
    sara_store.close()
    tracekit_store.close()


def test_mcp_swegate_rejects_green_tests_with_architectural_violations(tmp_path: Path):
    """
    Tests the core SWE-Gate dilemma in live MCP closed-loop execution:
    functional tests are 100% green (tests_passed=644, tests_failed=0),
    yet the patch introduces architectural violations:
      - Case A: Disallowed imports (import requests, from requests.adapters import HTTPAdapter)
      - Case B: Forbidden '# type: ignore[attr-defined]'
      - Case C: Excessive cyclomatic complexity (cyclomatic_delta=5 > max_cyclomatic_delta=2)
      - Case D: Combined violations in apply_patch / propose_patch / prune_file,
        confirming target_file on disk is NEVER modified when rejected.
    """
    swegate_db = tmp_path / "swegate_reject.db"
    tracekit_db = tmp_path / "tracekit.db"
    sara_db = tmp_path / "sara_reject.db"
    cache_db = tmp_path / "cache_reject.db"

    swegate_store = SweGateStore(swegate_db)
    tracekit_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())
    sara_store = SaraStore(sara_db)
    cache = LocalSemanticCache(str(cache_db))

    session_id = "SES-m4-reject-001"
    server = MCPServer(
        cache=cache,
        tracekit_store=tracekit_store,
        sara_store=sara_store,
        swegate_store=swegate_store,
        swegate_rule={
            "rule_id": "RULE-m4-strict",
            "max_cyclomatic_delta": 2,
            "forbid_type_ignores": True,
            "disallowed_import_modules": ["requests", "urllib3"],
        },
        session_id=session_id,
    )

    # Case A: Disallowed import with 644 passing tests and 0 failures
    res_imp = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": DISALLOWED_IMPORT_DIFF,
                "commit_sha": "1" * 40,
                "tests_passed": 644,
                "tests_failed": 0,
            },
        }
    )
    assert res_imp.isError is True
    assert res_imp["isError"] is True
    assert res_imp["sweGateRejected"] is True
    assert res_imp["policyViolation"] is True
    assert res_imp["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_imp["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"
    assert res_imp["architecturalViolations"] == [
        "DISALLOWED_IMPORT|requests@src/service/client.py:1",
        "DISALLOWED_IMPORT|requests.adapters@src/service/client.py:2",
    ]
    eval_imp = res_imp["evaluationId"]
    v_imp = swegate_store.get_violations(eval_imp)
    assert len(v_imp) == 2
    assert v_imp[0]["violation_type"] == "DISALLOWED_IMPORT"
    assert v_imp[0]["symbol_or_file"] == "requests@src/service/client.py:1"
    assert v_imp[1]["violation_type"] == "DISALLOWED_IMPORT"
    assert v_imp[1]["symbol_or_file"] == "requests.adapters@src/service/client.py:2"

    # Case B: Forbidden '# type: ignore[attr-defined]' with 644 passing tests
    res_ti = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": TYPE_IGNORE_DIFF,
                "commit_sha": "2" * 40,
                "tests_passed": 644,
                "tests_failed": 0,
            },
        }
    )
    assert res_ti["isError"] is True
    assert res_ti["sweGateRejected"] is True
    assert res_ti["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_ti["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"
    assert res_ti["architecturalViolations"] == [
        "TYPE_IGNORE|src/service/types_mod.py:2"
    ]
    eval_ti = res_ti["evaluationId"]
    v_ti = swegate_store.get_violations(eval_ti)
    assert len(v_ti) == 1
    assert v_ti[0]["violation_type"] == "TYPE_IGNORE"
    assert v_ti[0]["symbol_or_file"] == "src/service/types_mod.py:2"

    # Case C: Excessive cyclomatic complexity (delta=5 > max_cyclomatic_delta=2)
    res_cc = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": HIGH_COMPLEXITY_DIFF,
                "commit_sha": "3" * 40,
                "tests_passed": 644,
                "tests_failed": 0,
            },
        }
    )
    assert res_cc["isError"] is True
    assert res_cc["sweGateRejected"] is True
    assert res_cc["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_cc["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"
    assert res_cc["cyclomaticDelta"] == 5
    assert res_cc["architecturalViolations"] == ["CYCLOMATIC_DELTA|total:5>2"]
    eval_cc = res_cc["evaluationId"]
    v_cc = swegate_store.get_violations(eval_cc)
    assert len(v_cc) == 1
    assert v_cc[0]["violation_type"] == "CYCLOMATIC_DELTA"
    assert v_cc[0]["symbol_or_file"] == "total:5>2"

    # Case D: Combined violations in apply_patch & prune_file; target file on disk is NEVER modified
    target_file = tmp_path / "unsafe_patch.py"
    original_disk_content = "def run_patch(a: int, b: int) -> int:\n    return 0\n"
    target_file.write_text(original_disk_content, encoding="utf-8")

    res_apply_reject = server.handle_tools_call(
        {
            "name": "apply_patch",
            "arguments": {
                "diff_text": COMBINED_VIOLATIONS_DIFF,
                "commit_sha": "4" * 40,
                "tests_passed": 644,
                "tests_failed": 0,
                "target_file": str(target_file),
                "new_content": "import requests\n# MUTATED\n",
            },
        }
    )
    assert res_apply_reject["isError"] is True
    assert res_apply_reject["sweGateRejected"] is True
    assert res_apply_reject["patchApplied"] is False
    assert res_apply_reject["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_apply_reject["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"
    assert res_apply_reject["architecturalViolations"] == [
        "TYPE_IGNORE|src/service/unsafe_patch.py:4",
        "DISALLOWED_IMPORT|requests@src/service/unsafe_patch.py:1",
        "CYCLOMATIC_DELTA|total:3>2",
    ]
    assert target_file.read_text(encoding="utf-8") == original_disk_content

    # Also verify prune_file with rejected diff_text halts before pruning
    res_prune_reject = server.handle_tools_call(
        {
            "name": "prune_file",
            "arguments": {
                "path": str(target_file),
                "diff_text": COMBINED_VIOLATIONS_DIFF,
                "commit_sha": "5" * 40,
                "tests_passed": 644,
                "tests_failed": 0,
            },
        }
    )
    assert res_prune_reject["isError"] is True
    assert res_prune_reject["sweGateRejected"] is True
    assert "SWE_GATE_REJECTED:" in res_prune_reject["content"][0]["text"]
    assert "def run_patch" not in res_prune_reject["content"][0]["text"]

    # Verify TraceKitStore sealed SWE_GATE_REJECT blocks
    blocks = tracekit_store.load_blocks(session_id)
    assert len(blocks) == 5
    expected_reject_payload = (
        f"SWE_GATE_REJECT: eval_id={eval_imp} state=REJECT_NON_FUNCTIONAL_REGRESSION "
        "delta=0 violations=DISALLOWED_IMPORT|requests@src/service/client.py:1,"
        "DISALLOWED_IMPORT|requests.adapters@src/service/client.py:2"
    )
    assert any(b.action_digest == sha256_hex(expected_reject_payload) for b in blocks)
    assert tracekit_store.verify_session(session_id).is_tampered is False

    swegate_store.close()
    sara_store.close()
    tracekit_store.close()


def test_mcp_swegate_fail_closed_on_malformed_diff_and_functional_failures(
    tmp_path: Path,
):
    """
    Verifies:
      1. Clean diff with failing functional tests (tests_passed=10, tests_failed=1) is rejected
         with REJECT_ARCHITECTURAL_VIOLATION (REJECT_NON_FUNCTIONAL_REGRESSION).
      2. Malformed diff, empty diff, mismatched diff_size_bytes, invalid commit_sha, and invalid
         rule parameters collapse fail-closed to REJECTED_INVALID with ['INVALID_INPUT|patch'],
         persisting the finding in swe_gate_violation_findings and sealing in TraceKitStore.
    """
    swegate_db = tmp_path / "swegate_failclosed.db"
    tracekit_db = tmp_path / "tracekit.db"

    swegate_store = SweGateStore(swegate_db)
    tracekit_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())

    session_id = "SES-m4-failclosed-01"
    server = MCPServer(
        tracekit_store=tracekit_store,
        swegate_store=swegate_store,
        session_id=session_id,
    )

    # 1. Clean diff but functional tests failed (tests_passed=10, tests_failed=1)
    res_func_fail = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "f" * 40,
                "tests_passed": 10,
                "tests_failed": 1,
            },
        }
    )
    assert res_func_fail["isError"] is True
    assert res_func_fail["sweGateRejected"] is True
    assert res_func_fail["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_func_fail["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"
    assert res_func_fail["architecturalViolations"] == []
    assert "FUNCTIONAL_TESTS_FAILED" in res_func_fail["content"][0]["text"]
    eval_func_id = res_func_fail["evaluationId"]
    row_func = swegate_store.get_evaluation(eval_func_id)
    assert row_func is not None
    assert row_func["functional_passed"] is False
    assert row_func["gate_verdict"] == "REJECT_ARCHITECTURAL_VIOLATION"

    # 2. Malformed unified diff (no hunk headers) -> REJECTED_INVALID + INVALID_INPUT|patch
    res_malformed = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": "not a valid unified diff at all\n",
                "commit_sha": "e" * 40,
                "tests_passed": 50,
                "tests_failed": 0,
            },
        }
    )
    assert res_malformed["isError"] is True
    assert res_malformed["sweGateRejected"] is True
    assert res_malformed["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_malformed["sweGateState"] == "REJECTED_INVALID"
    assert res_malformed["architecturalViolations"] == ["INVALID_INPUT|patch"]
    eval_mal_id = res_malformed["evaluationId"]
    v_mal = swegate_store.get_violations(eval_mal_id)
    assert len(v_mal) == 1
    assert v_mal[0]["violation_type"] == "INVALID_INPUT"
    assert v_mal[0]["symbol_or_file"] == "patch"

    # 3. Mismatched diff_size_bytes -> REJECTED_INVALID + INVALID_INPUT|patch
    res_mismatch = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "d" * 40,
                "diff_size_bytes": 99999,
                "tests_passed": 50,
                "tests_failed": 0,
            },
        }
    )
    assert res_mismatch["isError"] is True
    assert res_mismatch["sweGateState"] == "REJECTED_INVALID"
    assert res_mismatch["architecturalViolations"] == ["INVALID_INPUT|patch"]
    v_mis = swegate_store.get_violations(res_mismatch["evaluationId"])
    assert len(v_mis) == 1
    assert v_mis[0]["violation_type"] == "INVALID_INPUT"

    # 4. Invalid commit_sha (not 40 lowercase hex chars) -> REJECTED_INVALID + INVALID_INPUT|patch
    res_bad_sha = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "INVALID-SHA-UPPERCASE",
                "tests_passed": 50,
                "tests_failed": 0,
            },
        }
    )
    assert res_bad_sha["isError"] is True
    assert res_bad_sha["sweGateState"] == "REJECTED_INVALID"
    assert res_bad_sha["architecturalViolations"] == ["INVALID_INPUT|patch"]
    v_sha = swegate_store.get_violations(res_bad_sha["evaluationId"])
    assert len(v_sha) == 1
    assert v_sha[0]["violation_type"] == "INVALID_INPUT"
    assert v_sha[0]["symbol_or_file"] == "patch"

    # 5. Contradictory functional_verdict (PASSED with tests_failed=2) -> REJECTED_INVALID
    res_contra = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "9" * 40,
                "tests_passed": 10,
                "tests_failed": 2,
                "functional_verdict": "PASSED",
            },
        }
    )
    assert res_contra["isError"] is True
    assert res_contra["sweGateState"] == "REJECTED_INVALID"
    assert res_contra["architecturalViolations"] == ["INVALID_INPUT|patch"]

    # 6. Invalid rule parameter (max_cyclomatic_delta=-1) + invalid repo_id fallback via propose_patch
    res_bad_rule = server.handle_tools_call(
        {
            "name": "propose_patch",
            "arguments": {
                "patch_diff": CLEAN_DIFF,
                "commit_sha": "8" * 40,
                "max_cyclomatic_delta": -1,
                "repo_id": "INVALID_REPO_ID",
            },
        }
    )
    assert res_bad_rule["isError"] is True
    assert res_bad_rule["sweGateState"] == "REJECTED_INVALID"
    assert res_bad_rule["architecturalViolations"] == ["INVALID_INPUT|patch"]

    # 7. Simulated internal verifier exception -> fail-closed REJECTED_INVALID
    from unittest.mock import patch

    with patch(
        "ctxfw.swegate.gate.SweGateVerifier.evaluate_traced",
        side_effect=RuntimeError("simulated internal SWE-Gate fault"),
    ):
        res_fault = server.handle_tools_call(
            {
                "name": "evaluate_patch",
                "arguments": {
                    "diff_text": CLEAN_DIFF,
                    "commit_sha": "7" * 40,
                    "tests_passed": 20,
                    "tests_failed": 0,
                },
            }
        )
    assert res_fault["isError"] is True
    assert res_fault["sweGateRejected"] is True
    assert res_fault["sweGateState"] == "REJECTED_INVALID"
    assert res_fault["architecturalViolations"] == ["INVALID_INPUT|patch"]

    # 8. Lone UTF-16 surrogate in diff_text and repo_name -> fail-closed REJECTED_INVALID
    res_surrogate = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n+\ud800\n",
                "commit_sha": "6" * 40,
                "repo_name": "surrogate-\ud800-repo",
                "user_prompt": "audit-\ud800-prompt",
            },
        }
    )
    assert res_surrogate["isError"] is True
    assert res_surrogate["sweGateRejected"] is True
    assert res_surrogate["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_surrogate["sweGateState"] == "REJECTED_INVALID"
    assert res_surrogate["architecturalViolations"] == ["INVALID_INPUT|patch"]
    v_surr = swegate_store.get_violations(res_surrogate["evaluationId"])
    assert len(v_surr) == 1
    assert v_surr[0]["violation_type"] == "INVALID_INPUT"

    # 9. WAL retry exhaustion after DECIDED_PASS -> must emit REJECT_ARCHITECTURAL_VIOLATION (never ALLOW_MERGE)
    with patch.object(
        swegate_store,
        "record_evaluation",
        return_value=(None, GateState.REJECTED_INVALID, [0.02, 0.04, 0.08]),
    ):
        res_wal_exhaust = server.handle_tools_call(
            {
                "name": "evaluate_patch",
                "arguments": {
                    "diff_text": CLEAN_DIFF,
                    "commit_sha": "5" * 40,
                    "tests_passed": 20,
                    "tests_failed": 0,
                },
            }
        )
    assert res_wal_exhaust["isError"] is True
    assert res_wal_exhaust["sweGateRejected"] is True
    assert res_wal_exhaust["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert res_wal_exhaust["sweGateState"] == "REJECTED_INVALID"
    assert res_wal_exhaust["evaluationId"] is None

    # 10. apply_patch targeting an existing directory (unwriteable target_file) -> preserves sweGate metadata & no duplicate TraceKit block
    res_dir_target = server.handle_tools_call(
        {
            "name": "apply_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "4" * 40,
                "tests_passed": 20,
                "tests_failed": 0,
                "target_file": str(tmp_path),
                "new_content": "def compute_total(subtotal: int) -> int:\n    return 0\n",
            },
        }
    )
    assert res_dir_target["isError"] is True
    assert res_dir_target["patchApplied"] is False
    assert res_dir_target["sweGateRecorded"] is True
    assert "SWE_GATE_APPLY_ERROR:" in res_dir_target["content"][0]["text"]

    blocks = tracekit_store.load_blocks(session_id)
    assert len(blocks) == 10
    assert tracekit_store.verify_session(session_id).is_tampered is False

    swegate_store.close()
    tracekit_store.close()


def test_tracekit_cli_trace_verify_certifies_swegate_closed_loop_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """
    Executes a multi-step session across ALLOW_MERGE, REJECT_ARCHITECTURAL_VIOLATION,
    and REJECTED_INVALID, and certifies the cryptographic hash chain in tracekit.db
    via TraceKitStore.verify_session, verify_chain, and CLI run_trace_verify.
    """
    tracekit_db = tmp_path / "tracekit.db"
    swegate_db = tmp_path / "swegate_chain.db"
    monkeypatch.setenv("CTXFW_TRACEKIT_DB", str(tracekit_db))
    monkeypatch.setenv("CTXFW_SWEGATE_DB", str(swegate_db))

    clock = SystemUtcClock()
    trace_store = TraceKitStore(tracekit_db, clock=clock)
    swegate_store = SweGateStore(swegate_db)

    session_id = "SES-m4-tracekit-001"
    server = MCPServer(
        tracekit_store=trace_store,
        swegate_store=swegate_store,
        swegate_rule={
            "rule_id": "RULE-m4-chain",
            "max_cyclomatic_delta": 2,
            "forbid_type_ignores": True,
            "disallowed_import_modules": ["requests"],
        },
        session_id=session_id,
    )

    # Step 1: ALLOW_MERGE
    r1 = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": CLEAN_DIFF,
                "commit_sha": "1" * 40,
                "tests_passed": 100,
                "tests_failed": 0,
            },
        }
    )
    assert r1["isError"] is False
    assert r1["sweGateState"] == "PASS_GATE"

    # Step 2: REJECT_NON_FUNCTIONAL_REGRESSION (green tests, banned import)
    r2 = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": DISALLOWED_IMPORT_DIFF,
                "commit_sha": "2" * 40,
                "tests_passed": 100,
                "tests_failed": 0,
            },
        }
    )
    assert r2["isError"] is True
    assert r2["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"

    # Step 3: REJECTED_INVALID (malformed diff)
    r3 = server.handle_tools_call(
        {
            "name": "evaluate_patch",
            "arguments": {
                "diff_text": "bad diff content",
                "commit_sha": "3" * 40,
                "tests_passed": 100,
                "tests_failed": 0,
            },
        }
    )
    assert r3["isError"] is True
    assert r3["sweGateState"] == "REJECTED_INVALID"

    blocks = trace_store.load_blocks(session_id)
    assert len(blocks) == 3

    expected_reasoning = sha256_hex("SWE-Gate CI verification on evaluate_patch")
    assert all(b.reasoning_digest == expected_reasoning for b in blocks)

    # Verify via TraceKitStore.verify_session
    audit_session = trace_store.verify_session(session_id)
    assert audit_session.is_tampered is False
    assert audit_session.broken_block_seq is None
    assert audit_session.total_blocks_audited == 3

    # Verify via standalone verify_chain
    audit_chain = verify_chain(
        session_id=session_id,
        genesis_hash=blocks[0].prev_block_hash,
        blocks=blocks,
        verified_at=clock.now(),
    )
    assert audit_chain.is_tampered is False
    assert audit_chain.broken_block_seq is None
    assert audit_chain.total_blocks_audited == 3

    # Verify via CLI run_trace_verify
    out_buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out_buf)
    exit_code = run_trace_verify(str(tracekit_db))
    assert exit_code == 0
    assert "VERIFIED_CLEAN" in out_buf.getvalue()

    swegate_store.close()
    trace_store.close()


def test_stdio_loop_purity_under_swegate_allow_and_reject(tmp_path: Path):
    """
    Executes MCPServer.run_stdio_loop() over simulated stdin/stdout/stderr with both
    line-delimited and Content-Length framed JSON-RPC requests (tools/list, evaluate_patch allow,
    evaluate_patch reject, evaluate_patch invalid input), asserting 100% pure JSON-RPC 2.0
    frames on stdout and zero leaked bytes.
    """
    swegate_db = tmp_path / "swegate_stdio.db"
    tracekit_db = tmp_path / "tracekit.db"
    cache_db = tmp_path / "cache_stdio.db"

    swegate_store = SweGateStore(swegate_db)
    trace_store = TraceKitStore(tracekit_db, clock=SystemUtcClock())
    cache = LocalSemanticCache(str(cache_db))

    server = MCPServer(
        cache=cache,
        tracekit_store=trace_store,
        swegate_store=swegate_store,
        swegate_rule={
            "rule_id": "RULE-m4-stdio",
            "max_cyclomatic_delta": 2,
            "forbid_type_ignores": True,
            "disallowed_import_modules": ["requests"],
        },
        session_id="SES-m4-stdio-001",
    )

    req_list = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    req_allow = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "evaluate_patch",
                "arguments": {
                    "diff_text": CLEAN_DIFF,
                    "commit_sha": "a" * 40,
                    "tests_passed": 32,
                    "tests_failed": 0,
                },
            },
        }
    )
    req_reject_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "evaluate_patch",
                "arguments": {
                    "diff_text": TYPE_IGNORE_DIFF,
                    "commit_sha": "b" * 40,
                    "tests_passed": 32,
                    "tests_failed": 0,
                },
            },
        }
    )
    req_reject_framed = (
        f"Content-Length: {len(req_reject_body.encode('utf-8'))}\r\n\r\n{req_reject_body}"
    )
    req_invalid = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "evaluate_patch",
                "arguments": {
                    "diff_text": "",
                    "commit_sha": "bad",
                },
            },
        }
    )

    stream_input = f"{req_list}\n{req_allow}\n{req_reject_framed}\n{req_invalid}\n"

    stdin_buf = io.StringIO(stream_input)
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    orig_stdin, orig_stdout, orig_stderr = sys.stdin, sys.stdout, sys.stderr
    sys.stdin, sys.stdout, sys.stderr = stdin_buf, stdout_buf, stderr_buf
    try:
        server.run_stdio_loop()
    finally:
        sys.stdin, sys.stdout, sys.stderr = orig_stdin, orig_stdout, orig_stderr

    raw_stdout = stdout_buf.getvalue()
    lines = [line.strip() for line in raw_stdout.split("\n") if line.strip()]
    assert len(lines) == 4

    frames = []
    for line in lines:
        parsed = json.loads(line)
        assert parsed.get("jsonrpc") == "2.0"
        assert "id" in parsed
        frames.append(parsed)

    # Frame 1: tools/list includes evaluate_patch
    tool_names = [t["name"] for t in frames[0]["result"]["tools"]]
    assert "evaluate_patch" in tool_names

    # Frame 2: ALLOW_MERGE
    assert frames[1]["id"] == 2
    assert frames[1]["result"]["isError"] is False
    assert frames[1]["result"]["sweGateVerdict"] == "ALLOW_MERGE"
    assert frames[1]["result"]["sweGateState"] == "PASS_GATE"

    # Frame 3: REJECT_ARCHITECTURAL_VIOLATION (TYPE_IGNORE)
    assert frames[2]["id"] == 3
    assert frames[2]["result"]["isError"] is True
    assert frames[2]["result"]["sweGateRejected"] is True
    assert frames[2]["result"]["sweGateVerdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert frames[2]["result"]["sweGateState"] == "REJECT_NON_FUNCTIONAL_REGRESSION"
    assert frames[2]["result"]["architecturalViolations"] == [
        "TYPE_IGNORE|src/service/types_mod.py:2"
    ]

    # Frame 4: REJECTED_INVALID
    assert frames[3]["id"] == 4
    assert frames[3]["result"]["isError"] is True
    assert frames[3]["result"]["sweGateState"] == "REJECTED_INVALID"
    assert frames[3]["result"]["architecturalViolations"] == ["INVALID_INPUT|patch"]


def test_m4_p3_files_carry_manifest_hash_and_no_crlf():
    """
    Verifies that src/ctxfw/mcp.py and tests/test_closed_loop_m4.py carry the M4-P3
    manifest_hash on Line 1 and contain zero CRLF (\\r) bytes.
    """
    expected_header = f"# manifest_hash: {EXPECTED_M4_P3_MANIFEST_HASH}"
    targets = [
        REPO_ROOT / "src" / "ctxfw" / "mcp.py",
        REPO_ROOT / "tests" / "test_closed_loop_m4.py",
    ]
    for path in targets:
        raw = path.read_bytes()
        assert b"\r" not in raw, f"CRLF detected in {path}"
        first_line = raw.decode("utf-8").split("\n", 1)[0]
        assert first_line == expected_header, f"Line 1 mismatch in {path}: {first_line!r}"
