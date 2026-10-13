"""Gate G9 for ctxfw.rules: vendored Claude Rules Compiler blueprint files must stay byte-for-byte sealed.

manifest_hash: 66f8c88b0407bc071195d430d5f467a35d4de570bc5e8c9069dc51e96d11d1f5
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys

import pytest
from pydantic import ValidationError

from ctxfw.rules import (
    CONTRACTS_PATH,
    MANIFEST_PATH,
    SCHEMA_PATH,
    DirectiveRule,
    EnforcementVerdict,
    RuleClassifier,
    load_manifest,
    load_schema_sql,
)

BLUEPRINT_MANIFEST_HASH = "b5b8e1cd10ce8beeed6b076f4726d19b361a6ce2f5d480c2bb2aa437986822d3"
EXPECTED_CONTRACTS_SHA256 = "088c37e36fa524dd3aca85dc8ae618d3f295133bf1ae9215ac13494f9ba32100"
EXPECTED_SCHEMA_SHA256 = "3564a1aa1910316864dbfde929d11b8563a96063bcab8a34445cdf579b859ca8"


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_manifest_is_the_sealed_rules_manifest():
    manifest = load_manifest()
    assert manifest["signal_id"] == "SIG-1d0a63f087edb904"
    assert manifest["blueprint_id"] == "BP-SIG-1d0a63f087edb904-CLAUDE-RULES-COMPILER"
    assert manifest["proposal_id"] == "PROP-1d0a63f087edb904-H2"
    assert manifest["horizon"] == "HORIZON_2"
    assert manifest["ctxfw"]["status"] == "VERIFIED"
    assert manifest["ctxfw"]["aci_score"] == 1.0
    assert manifest["ctxfw"]["manifest_hash"] == BLUEPRINT_MANIFEST_HASH
    assert manifest["hermetic_compiler"]["passed_tests"] == 28


def test_vendored_contracts_and_schema_match_sealed_sha256():
    deliverables = load_manifest()["deliverables"]
    assert deliverables["specs/2_pydantic_contracts.py"]["sha256"] == EXPECTED_CONTRACTS_SHA256
    assert deliverables["specs/3_schema_ddl.sql"]["sha256"] == EXPECTED_SCHEMA_SHA256
    assert _sha256(CONTRACTS_PATH) == EXPECTED_CONTRACTS_SHA256
    assert _sha256(SCHEMA_PATH) == EXPECTED_SCHEMA_SHA256


def test_vendored_files_carry_the_blueprint_hash_header():
    assert BLUEPRINT_MANIFEST_HASH in CONTRACTS_PATH.read_text(encoding="utf-8")
    assert BLUEPRINT_MANIFEST_HASH in load_schema_sql()


def test_vendored_files_have_no_crlf():
    for path in (CONTRACTS_PATH, SCHEMA_PATH, MANIFEST_PATH):
        assert b"\r" not in path.read_bytes(), f"{path.name} was rewritten with CR (line-ending drift)"


def test_rules_package_import_is_lazy():
    code = (
        "import sys, ctxfw.rules;"
        "print([m for m in sys.modules if m=='ctxfw.rules.contracts'])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_normative_classes_import_and_instantiation():
    from ctxfw.rules import (
        CompiledAstGuardDTO,
        CompiledRuleManifestDTO,
        FileFormat,
        NaturalLanguageRuleDTO,
        PatternType,
        RuleComplianceAuditDTO,
        RuleIntent,
        RuleSourceFileDTO,
    )

    # Validate architecture aliases
    assert DirectiveRule is NaturalLanguageRuleDTO
    assert RuleClassifier is RuleIntent

    # EnforcementVerdict
    assert EnforcementVerdict.ALLOW.value == "ALLOW"
    assert EnforcementVerdict.BLOCKED.value == "BLOCKED"

    # DirectiveRule / NaturalLanguageRuleDTO
    rule = DirectiveRule(
        rule_id="RULE-test-0001",
        raw_directive="never invoke dangerous_sink() directly",
        rule_intent=RuleIntent.AST_DENY,
        line_number=42,
    )
    assert rule.rule_id == "RULE-test-0001"
    assert rule.rule_intent is RuleIntent.AST_DENY
    assert rule.line_number == 42

    # CompiledAstGuardDTO
    guard = CompiledAstGuardDTO(
        guard_id="GRD-guard-0001",
        rule_id="RULE-test-0001",
        pattern_type=PatternType.AST_CALL,
        target_symbol_or_path="dangerous_sink",
        is_strict_deny=True,
    )
    assert guard.guard_id == "GRD-guard-0001"
    assert guard.rule_intent is RuleIntent.AST_DENY
    assert guard.is_strict_deny is True

    # RuleSourceFileDTO
    source = RuleSourceFileDTO(
        file_path=".cursorrules",
        file_format=FileFormat.CURSORRULES,
        sha256="e" * 64,
    )
    assert source.file_format is FileFormat.CURSORRULES

    # RuleComplianceAuditDTO
    audit = RuleComplianceAuditDTO.build(
        file_scanned="src/module.py",
        violations=(),
    )
    assert audit.is_compliant is True
    assert len(audit.audit_sha256) == 64

    # CompiledRuleManifestDTO
    manifest = CompiledRuleManifestDTO(
        manifest_id="MNF-test-0001",
        source=source,
        guards=(guard,),
        unenforceable_rule_ids=(),
        compiled_rules_count=1,
    )
    assert manifest.compiled_rules_count == 1
    assert len(manifest.guards) == 1


def test_strict_exception_handling_and_negative_invariants():
    from ctxfw.rules import (
        CompiledAstGuardDTO,
        CompiledRuleManifestDTO,
        FileFormat,
        NaturalLanguageRuleDTO,
        PatternType,
        RuleComplianceAuditDTO,
        RuleIntent,
        RuleSourceFileDTO,
        audit_digest,
        derive_guard_id,
        derive_manifest_id,
        derive_rule_id,
        detect_file_format,
        sha256_hex,
    )

    # INV-01: Guard shall never be non-strict deny
    with pytest.raises(ValidationError, match="a compiled guard shall never be a non-strict deny"):
        CompiledAstGuardDTO(
            guard_id="GRD-allow-fail",
            rule_id="RULE-valid-01",
            pattern_type=PatternType.COMMAND_PREFIX,
            target_symbol_or_path="ls",
            is_strict_deny=False,  # must raise
        )

    # INV-06: Wildcard-only targets shall never be accepted
    for bad_target in ("*", "**", "/", "."):
        with pytest.raises(ValidationError, match="wildcard-only targets shall never be accepted"):
            CompiledAstGuardDTO(
                guard_id="GRD-wildcard-1",
                rule_id="RULE-valid-01",
                pattern_type=PatternType.PATH_PREFIX,
                target_symbol_or_path=bad_target,
                is_strict_deny=True,
            )

    # Control characters in target symbol
    with pytest.raises(ValueError, match="target shall never contain control characters"):
        CompiledAstGuardDTO(
            guard_id="GRD-ctrl-0001",
            rule_id="RULE-valid-01",
            pattern_type=PatternType.COMMAND_PREFIX,
            target_symbol_or_path="rm -rf\x00/secret",
            is_strict_deny=True,
        )

    # Path traversal in path targets must be rejected
    with pytest.raises(ValidationError, match="path targets shall never contain traversal segments"):
        CompiledAstGuardDTO(
            guard_id="GRD-traversal-1",
            rule_id="RULE-valid-01",
            pattern_type=PatternType.PATH_PREFIX,
            target_symbol_or_path="etc/../passwd",
            is_strict_deny=True,
        )

    # Duplicate violations detected must be rejected
    with pytest.raises(ValidationError, match="duplicate violations shall never be reported"):
        RuleComplianceAuditDTO(
            file_scanned="test.py",
            violations_detected=("GRD-dup-00001", "GRD-dup-00001"),
            is_compliant=False,
            audit_sha256="0" * 64,
        )

    # Unknown file format raises ValueError (fail-closed)
    with pytest.raises(ValueError, match="unknown rules file format"):
        detect_file_format("config.unknown_ext")

    # Valid file format detections
    assert detect_file_format(".cursorrules") is FileFormat.CURSORRULES
    assert detect_file_format("rules.yaml") is FileFormat.YAML
    assert detect_file_format("rules.yml") is FileFormat.YAML
    assert detect_file_format("CLAUDE.md") is FileFormat.MARKDOWN
    assert detect_file_format("doc.markdown") is FileFormat.MARKDOWN

    # Pure deterministic helpers
    assert len(sha256_hex("test")) == 64
    r_id = derive_rule_id("CLAUDE.md", 10, "never deploy")
    assert r_id.startswith("RULE-") and len(r_id) == 21
    g_id = derive_guard_id(r_id)
    assert g_id.startswith("GRD-") and len(g_id) == 20
    m_id = derive_manifest_id("CLAUDE.md", "0" * 64)
    assert m_id.startswith("MNF-") and len(m_id) == 20

    # Manifest consistency: INV-09 (compiled_rules_count must equal len(guards))
    dummy_source = RuleSourceFileDTO(file_path="CLAUDE.md", file_format=FileFormat.MARKDOWN, sha256="a" * 64)
    valid_guard = CompiledAstGuardDTO(
        guard_id="GRD-ok-0001",
        rule_id="RULE-valid-01",
        pattern_type=PatternType.COMMAND_PREFIX,
        target_symbol_or_path="rm",
        is_strict_deny=True,
    )
    with pytest.raises(ValidationError, match="compiled_rules_count must equal the number of emitted guards"):
        CompiledRuleManifestDTO(
            manifest_id="MNF-mismatch-1",
            source=dummy_source,
            guards=(valid_guard,),
            unenforceable_rule_ids=(),
            compiled_rules_count=2,
        )

    # Manifest duplicate guard_id rejection
    with pytest.raises(ValidationError, match="duplicate guard_id values shall never be emitted"):
        CompiledRuleManifestDTO(
            manifest_id="MNF-dup-guard",
            source=dummy_source,
            guards=(valid_guard, valid_guard),
            unenforceable_rule_ids=(),
            compiled_rules_count=2,
        )

    # Manifest overlap between enforced and unenforceable
    with pytest.raises(ValidationError, match="a rule shall never be both enforced and unenforceable"):
        CompiledRuleManifestDTO(
            manifest_id="MNF-overlap",
            source=dummy_source,
            guards=(valid_guard,),
            unenforceable_rule_ids=("RULE-valid-01",),
            compiled_rules_count=1,
        )

    # Compliance audit consistency
    with pytest.raises(ValidationError, match="is_compliant must hold if and only if there are no violations"):
        RuleComplianceAuditDTO(
            file_scanned="src/main.py",
            violations_detected=("GRD-ok-0001",),
            is_compliant=True,
            audit_sha256=audit_digest("src/main.py", ("GRD-ok-0001",)),
        )

    # Immutability (frozen=True)
    rule = NaturalLanguageRuleDTO(
        rule_id="RULE-immutable",
        raw_directive="never fail",
        rule_intent=RuleIntent.PATH_DENY,
        line_number=1,
    )
    with pytest.raises(ValidationError):
        rule.raw_directive = "mutated"  # type: ignore[misc]

    # Extra fields rejected (extra="forbid")
    with pytest.raises(ValidationError):
        NaturalLanguageRuleDTO(
            rule_id="RULE-extra-fail",
            raw_directive="never fail",
            rule_intent=RuleIntent.PATH_DENY,
            line_number=1,
            forbidden_field=True,  # type: ignore[call-arg]
        )


def test_rules_fsm_total_and_fail_closed():
    from ctxfw.rules import (
        FAILURE_ROUTING,
        INTENT_TO_PATTERN,
        PATTERN_TO_INTENT,
        TERMINAL_STATES,
        CompilerEvent,
        CompilerState,
        FailureClass,
        PatternType,
        RuleIntent,
        transition,
    )

    # Terminal states
    assert CompilerState.EMITTED in TERMINAL_STATES
    assert CompilerState.REJECTED_INVALID in TERMINAL_STATES

    # Standard transitions
    assert transition(CompilerState.RECEIVED, CompilerEvent.PARSE_OK) is CompilerState.PARSED
    assert transition(CompilerState.RECEIVED, CompilerEvent.VALIDATION_FAIL) is CompilerState.REJECTED_INVALID
    assert transition(CompilerState.PARSED, CompilerEvent.CLAUSES_FOUND) is CompilerState.EXTRACTED
    assert transition(CompilerState.PARSED, CompilerEvent.NO_CLAUSES) is CompilerState.EMITTED
    assert transition(CompilerState.PARSED, CompilerEvent.PARSE_FAIL) is CompilerState.REJECTED_INVALID
    assert transition(CompilerState.EXTRACTED, CompilerEvent.COMPILE_OK) is CompilerState.COMPILED
    assert transition(CompilerState.COMPILED, CompilerEvent.EMIT_OK) is CompilerState.EMITTED

    # Total: unknown state or event collapses to REJECTED_INVALID
    assert transition("invalid_state", CompilerEvent.PARSE_OK) is CompilerState.REJECTED_INVALID
    assert transition(CompilerState.RECEIVED, "invalid_event") is CompilerState.REJECTED_INVALID
    assert transition("garbage", "garbage") is CompilerState.REJECTED_INVALID

    # Intent <-> Pattern bijection
    for intent in RuleIntent:
        pat = INTENT_TO_PATTERN[intent]
        assert PATTERN_TO_INTENT[pat] is intent

    # Failure routing fail-closed check
    for f_class, route in FAILURE_ROUTING.items():
        assert isinstance(f_class, FailureClass)
        assert "REJECTED_INVALID" in route or "UNENFORCEABLE" in route


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 35, 0), reason="sealed DDL requires SQLite >= 3.35")
def test_sealed_schema_loads_and_has_append_only_triggers(tmp_path):
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(load_schema_sql())
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"compiled_rule_manifests", "compiled_ast_guards", "rule_enforcement_logs"} <= tables

        triggers = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert len(triggers) == 6
        assert "trg_manifests_no_update" in triggers
        assert "trg_guards_no_update" in triggers
        assert "trg_enforcement_no_update" in triggers
        assert "trg_guards_within_declared_count" in triggers
        assert "trg_guards_no_direct_delete" in triggers
        assert "trg_enforcement_no_direct_delete" in triggers

        # 1. Insert parent manifest with declared count = 1
        conn.execute(
            "INSERT INTO compiled_rule_manifests (manifest_id, source_file_path, file_sha256, compiled_rules_count) "
            "VALUES ('MNF-test-append', 'CLAUDE.md', '1111111111111111111111111111111111111111111111111111111111111111', 1)"
        )
        # UPDATE on manifests forbidden
        with pytest.raises(sqlite3.IntegrityError, match="RULES_INV_08: compiled manifests are append-only"):
            conn.execute("UPDATE compiled_rule_manifests SET compiled_rules_count = 5 WHERE manifest_id = 'MNF-test-append'")

        # 2. Insert guard 1 (count == 1)
        conn.execute(
            "INSERT INTO compiled_ast_guards (guard_id, manifest_id, rule_intent, target_expression) "
            "VALUES ('GRD-guard01', 'MNF-test-append', 'COMMAND_DENY', 'rm')"
        )

        # UPDATE on guards forbidden
        with pytest.raises(sqlite3.IntegrityError, match="RULES_INV_08: compiled guards are append-only"):
            conn.execute("UPDATE compiled_ast_guards SET target_expression = 'kill' WHERE guard_id = 'GRD-guard01'")

        # Inserting guard 2 exceeds declared compiled_rules_count (1) -> triggers abort
        with pytest.raises(sqlite3.IntegrityError, match="RULES_INV_09: guards exceed the declared compiled_rules_count"):
            conn.execute(
                "INSERT INTO compiled_ast_guards (guard_id, manifest_id, rule_intent, target_expression) "
                "VALUES ('GRD-guard02', 'MNF-test-append', 'COMMAND_DENY', 'dd')"
            )

        # 3. Insert enforcement log for guard 1
        conn.execute(
            "INSERT INTO rule_enforcement_logs (log_id, guard_id, tool_call_attempted, verdict) "
            "VALUES ('LOG-log001', 'GRD-guard01', 'rm -rf /', 'BLOCKED')"
        )

        # UPDATE on enforcement logs forbidden
        with pytest.raises(sqlite3.IntegrityError, match="RULES_INV_08: enforcement logs are append-only"):
            conn.execute("UPDATE rule_enforcement_logs SET verdict = 'ALLOW' WHERE log_id = 'LOG-log001'")

        # Direct DELETE on guard forbidden
        with pytest.raises(sqlite3.IntegrityError, match="RULES_INV_08: guards are removable only by cascade from the parent manifest"):
            conn.execute("DELETE FROM compiled_ast_guards WHERE guard_id = 'GRD-guard01'")

        # Direct DELETE on enforcement log forbidden
        with pytest.raises(sqlite3.IntegrityError, match="RULES_INV_08: enforcement logs are removable only by cascade from the parent guard"):
            conn.execute("DELETE FROM rule_enforcement_logs WHERE log_id = 'LOG-log001'")
    finally:
        conn.close()

    # 4. On-disk SQLite WAL concurrency & multi-threaded contention
    import threading
    db_file = tmp_path / "rules_concurrency.db"
    init_conn = sqlite3.connect(db_file)
    init_conn.execute("PRAGMA foreign_keys=ON")
    init_conn.executescript(load_schema_sql())
    init_conn.execute(
        "INSERT INTO compiled_rule_manifests (manifest_id, source_file_path, file_sha256, compiled_rules_count) "
        "VALUES ('MNF-th-concurrency', '.cursorrules', '2222222222222222222222222222222222222222222222222222222222222222', 1)"
    )
    init_conn.execute(
        "INSERT INTO compiled_ast_guards (guard_id, manifest_id, rule_intent, target_expression) "
        "VALUES ('GRD-th-parent', 'MNF-th-concurrency', 'AST_DENY', 'eval')"
    )
    init_conn.commit()
    init_conn.close()

    worker_errors = []
    def thread_worker(worker_id: int):
        try:
            w_conn = sqlite3.connect(db_file, timeout=5.0)
            w_conn.execute("PRAGMA busy_timeout=5000")
            w_conn.execute("PRAGMA foreign_keys=ON")
            w_conn.execute(
                "INSERT INTO rule_enforcement_logs (log_id, guard_id, tool_call_attempted, verdict) "
                f"VALUES ('LOG-th-{worker_id:04d}', 'GRD-th-parent', 'eval(payload)', 'BLOCKED')"
            )
            w_conn.commit()
            w_conn.close()
        except Exception as exc:
            worker_errors.append(exc)

    threads = [threading.Thread(target=thread_worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not worker_errors, f"Thread errors: {worker_errors}"
    check_conn = sqlite3.connect(db_file)
    count = check_conn.execute(
        "SELECT COUNT(*) FROM rule_enforcement_logs WHERE guard_id='GRD-th-parent'"
    ).fetchone()[0]
    check_conn.close()
    assert count == 10

