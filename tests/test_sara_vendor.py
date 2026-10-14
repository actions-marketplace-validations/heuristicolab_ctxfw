# manifest_hash: 46c18f0959a0f31e56e83b719078e1331678c6ed972bdbc93ef075205f583f98
"""Gate G9 for ctxfw.sara: vendored SARA Induction Firewall blueprint files must stay byte-for-byte sealed.

Validates:
1. Exact SHA-256 match for contracts.py and schema.sql against blueprint_manifest.json.
2. Complete absence of carriage return (\\r) bytes across all vendored files (zero CRLF).
3. Clean and lazy import of ctxfw.sara (zero heavy dependencies loaded at import time).
4. Pydantic v2 DTO instantiation, immutability (frozen=True, extra="forbid"),
   strict risk_score range [0.0, 1.0], and NaN/Inf rejection.
5. Deterministic total FSM transition(S, E), terminal states, and fail-closed collapse.
6. Schema loading, triggers of immutability (no UPDATE on logs/payloads/policies,
   no direct DELETE on quarantine, quarantine restricted to QUARANTINE_TOOL verdict).
7. Multi-threaded contention under SQLite WAL mode (10 concurrent worker threads).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ctxfw.sara import (
    CONTRACTS_PATH,
    MANIFEST_PATH,
    SCHEMA_PATH,
    AuthorizedPolicyDTO,
    UntrustedObservationDTO,
    load_manifest,
    load_schema_sql,
)

BLUEPRINT_MANIFEST_HASH = "51d819312f8dd802981a7b7d97b9d6397316738ded76c94161a9f147411c94ea"
EXPECTED_CONTRACTS_SHA256 = "8849908c9668138707bff87543e55708a0c5bbd00fcd58ac82cd515a32d83fb8"
EXPECTED_SCHEMA_SHA256 = "c0bba491b5e321f6025375ed579a31e4c8cc1644fd8b2910365a0670e251ca98"


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_manifest_is_the_sealed_sara_manifest():
    manifest = load_manifest()
    assert manifest["signal_id"] == "SIG-0d2acf53b92882b0"
    assert manifest["blueprint_id"] == "BP-SIG-0d2acf53b92882b0-SARA"
    assert manifest["proposal_id"] == "PROP-0d2acf53b92882b0-H2"
    assert manifest["horizon"] == "HORIZON_2"
    assert manifest["architecture_standard"] == "HEURISTICO_LAB_SOVEREIGN_BLUEPRINT_V2"
    assert manifest["merkle_root_sha256"] == "302bcd173a0d6ebdd506c4a2741b4301e75a2c4a4c9405b658b2c2cc208cbadb"
    assert manifest["ctxfw"]["status"] == "VERIFIED"
    assert manifest["ctxfw"]["aci_score"] == 1.0
    assert manifest["ctxfw"]["manifest_hash"] == BLUEPRINT_MANIFEST_HASH
    assert manifest["hermetic_compiler"]["ast_valid"] is True
    assert manifest["hermetic_compiler"]["ddl_valid"] is True
    assert manifest["hermetic_compiler"]["semantic_gate_enforced"] is True
    assert manifest["hermetic_compiler"]["passed_tests"] == 20


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
    from ctxfw.sara import PACKAGE_DIR

    for path in (CONTRACTS_PATH, SCHEMA_PATH, MANIFEST_PATH, PACKAGE_DIR / "__init__.py"):
        assert b"\r" not in path.read_bytes(), f"{path.name} was rewritten with CR (line-ending drift)"


def test_sara_package_import_is_lazy():
    code = (
        "import sys, ctxfw.sara;"
        "assert 'ctxfw.sara.contracts' not in sys.modules;"
        "print([m for m in sys.modules if m=='ctxfw.sara.contracts'])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"

    code_access = (
        "import sys, ctxfw.sara;"
        "mod = ctxfw.sara.contracts;"
        "assert 'ctxfw.sara.contracts' in sys.modules;"
        "print('ACCESS_OK')"
    )
    out_access = subprocess.run([sys.executable, "-c", code_access], capture_output=True, text=True, check=True)
    assert out_access.stdout.strip() == "ACCESS_OK"


def test_pydantic_v2_dtos_instantiation_and_invariants():
    from ctxfw.sara import (
        AuthorizationPolicyRuleDTO,
        AuthorizationVerdictDTO,
        DirectiveKind,
        InductionDirectiveDTO,
        RawToolObservationDTO,
        SourceType,
        ToolExecutionSourceDTO,
        VerdictKind,
        observation_digest,
    )

    # Architectural alias parity
    assert UntrustedObservationDTO is RawToolObservationDTO
    assert AuthorizedPolicyDTO is AuthorizationPolicyRuleDTO

    # 1. ToolExecutionSourceDTO
    source = ToolExecutionSourceDTO(
        tool_name="bash_runner",
        source_type=SourceType.LOCAL_STDIO,
        execution_id="EXE-test12345678",
    )
    assert source.tool_name == "bash_runner"
    assert source.source_type == SourceType.LOCAL_STDIO
    assert source.execution_id == "EXE-test12345678"

    # Immutability: frozen=True
    with pytest.raises(ValidationError):
        source.tool_name = "mutated_runner"  # type: ignore[misc]

    # Negative invariant: extra="forbid"
    with pytest.raises(ValidationError):
        ToolExecutionSourceDTO(
            tool_name="bash_runner",
            source_type=SourceType.LOCAL_STDIO,
            execution_id="EXE-test12345678",
            unauthorized_extra_field="malicious",  # type: ignore[call-arg]
        )

    # Regex validation on ToolExecutionSourceDTO
    with pytest.raises(ValidationError):
        ToolExecutionSourceDTO(tool_name="123bad", source_type=SourceType.LOCAL_STDIO, execution_id="EXE-test12345678")

    with pytest.raises(ValidationError):
        ToolExecutionSourceDTO(tool_name="bash_runner", source_type=SourceType.LOCAL_STDIO, execution_id="INVALID-EXE-ID")

    # 2. RawToolObservationDTO / UntrustedObservationDTO
    payload = "echo 'hello world'"
    obs = RawToolObservationDTO.from_raw(
        source=source,
        raw_output=payload,
    )
    assert obs.raw_output == payload
    assert obs.observation_sha256 == observation_digest(payload)
    assert obs.source.execution_id == "EXE-test12345678"

    # Boundary and oversize raw_output [0, 65536]
    max_payload = "A" * 65536
    obs_max = RawToolObservationDTO.from_raw(source=source, raw_output=max_payload)
    assert len(obs_max.raw_output) == 65536
    with pytest.raises(ValidationError):
        RawToolObservationDTO.from_raw(source=source, raw_output="A" * 65537)

    # Negative invariant: NUL byte rejected
    with pytest.raises(ValidationError, match="raw_output shall never contain a NUL byte"):
        RawToolObservationDTO.from_raw(
            source=source,
            raw_output="malicious\x00payload",
        )

    # Negative invariant: timezone-aware UTC required
    with pytest.raises(ValidationError, match="observed_at must be timezone-aware UTC"):
        RawToolObservationDTO(
            source=source,
            raw_output="test",
            observed_at=datetime.now(),  # naive datetime
            observation_sha256=observation_digest("test"),
        )

    # Negative invariant: non-UTC timezone rejected
    with pytest.raises(ValidationError, match="observed_at must be timezone-aware UTC"):
        from datetime import timezone as dt_tz, timedelta as dt_td
        RawToolObservationDTO(
            source=source,
            raw_output="test",
            observed_at=datetime.now(dt_tz(dt_td(hours=-6))),
            observation_sha256=observation_digest("test"),
        )

    # Negative invariant: digest mismatch rejected
    with pytest.raises(ValidationError, match="observation_sha256 does not match SHA-256"):
        RawToolObservationDTO(
            source=source,
            raw_output="test",
            observed_at=datetime.now(timezone.utc),
            observation_sha256="0" * 64,
        )

    # 3. InductionDirectiveDTO
    directive = InductionDirectiveDTO(
        directive_kind=DirectiveKind.SHELL_COMMAND,
        directive_text="rm -rf /tmp/data",
        start_offset=10,
        end_offset=26,
        confidence=0.92,
        within_allowlist=False,
    )
    assert directive.confidence == 0.92
    assert directive.within_allowlist is False

    # Negative invariant: end_offset preceding start_offset
    with pytest.raises(ValidationError, match="end_offset shall never precede start_offset"):
        InductionDirectiveDTO(
            directive_kind=DirectiveKind.SHELL_COMMAND,
            directive_text="rm -rf /",
            start_offset=20,
            end_offset=10,
            confidence=0.5,
        )

    # Negative invariant: confidence boundaries [0.0, 1.0] and NaN/Inf rejection
    d_zero = InductionDirectiveDTO(directive_kind=DirectiveKind.SHELL_COMMAND, directive_text="ls", start_offset=0, end_offset=2, confidence=0.0)
    d_one = InductionDirectiveDTO(directive_kind=DirectiveKind.SHELL_COMMAND, directive_text="ls", start_offset=0, end_offset=2, confidence=1.0)
    assert d_zero.confidence == 0.0
    assert d_one.confidence == 1.0

    with pytest.raises(ValidationError):
        InductionDirectiveDTO(
            directive_kind=DirectiveKind.SHELL_COMMAND,
            directive_text="test",
            start_offset=0,
            end_offset=4,
            confidence=1.5,
        )

    with pytest.raises(ValidationError):
        InductionDirectiveDTO(
            directive_kind=DirectiveKind.SHELL_COMMAND,
            directive_text="test",
            start_offset=0,
            end_offset=4,
            confidence=-0.01,
        )

    with pytest.raises(ValidationError):
        InductionDirectiveDTO(
            directive_kind=DirectiveKind.SHELL_COMMAND,
            directive_text="test",
            start_offset=0,
            end_offset=4,
            confidence=float("nan"),
        )

    with pytest.raises(ValidationError):
        InductionDirectiveDTO(
            directive_kind=DirectiveKind.SHELL_COMMAND,
            directive_text="test",
            start_offset=0,
            end_offset=4,
            confidence=float("inf"),
        )

    # 4. AuthorizationPolicyRuleDTO / AuthorizedPolicyDTO
    policy = AuthorizedPolicyDTO(
        policy_id="POL-valid001",
        tool_name="bash_runner",
        allowed_commands=("ls", "cat", "grep"),
        allowed_path_prefixes=("/var/log", "/tmp/safe"),
        policy_mask=15,
    )
    assert policy.policy_id == "POL-valid001"
    assert policy.policy_mask == 15

    # Boundary policy_mask [0, 4294967295]
    p_min = AuthorizedPolicyDTO(policy_id="POL-mask001", tool_name="bash_runner", policy_mask=0)
    p_max = AuthorizedPolicyDTO(policy_id="POL-mask002", tool_name="bash_runner", policy_mask=4294967295)
    assert p_min.policy_mask == 0
    assert p_max.policy_mask == 4294967295
    with pytest.raises(ValidationError):
        AuthorizedPolicyDTO(policy_id="POL-maskbad1", tool_name="bash_runner", policy_mask=-1)
    with pytest.raises(ValidationError):
        AuthorizedPolicyDTO(policy_id="POL-maskbad2", tool_name="bash_runner", policy_mask=4294967296)

    # Negative invariant: wildcards rejected
    with pytest.raises(ValidationError, match="wildcard allowlist items shall never be accepted"):
        AuthorizedPolicyDTO(
            policy_id="POL-badwild01",
            tool_name="bash_runner",
            allowed_commands=("*",),
            policy_mask=1,
        )

    # Negative invariant: path traversal rejected
    with pytest.raises(ValidationError, match="path traversal segments shall never appear in the allowlist"):
        AuthorizedPolicyDTO(
            policy_id="POL-badtrav01",
            tool_name="bash_runner",
            allowed_path_prefixes=("/var/log/../etc",),
            policy_mask=1,
        )

    # Negative invariant: duplicate allowlist items rejected
    with pytest.raises(ValidationError, match="duplicate allowlist items shall never be accepted"):
        AuthorizedPolicyDTO(
            policy_id="POL-baddup01",
            tool_name="bash_runner",
            allowed_commands=("ls", "ls"),
            policy_mask=1,
        )

    # 5. AuthorizationVerdictDTO
    verdict_allow = AuthorizationVerdictDTO(
        execution_id="EXE-allow001234",
        tool_name="bash_runner",
        verdict=VerdictKind.ALLOW,
        risk_score=0.15,
    )
    assert verdict_allow.verdict == VerdictKind.ALLOW
    assert verdict_allow.violation_reason is None

    verdict_quarantine = AuthorizationVerdictDTO(
        execution_id="EXE-quar001234",
        tool_name="bash_runner",
        verdict=VerdictKind.QUARANTINE_TOOL,
        risk_score=0.85,
        violation_reason="Critical prompt injection directive detected",
    )
    assert verdict_quarantine.verdict == VerdictKind.QUARANTINE_TOOL
    assert verdict_quarantine.violation_reason is not None

    # Boundary risk_scores (0.0 and 1.0)
    v_zero = AuthorizationVerdictDTO(execution_id="EXE-bound001", tool_name="bash_runner", verdict=VerdictKind.ALLOW, risk_score=0.0)
    v_one = AuthorizationVerdictDTO(execution_id="EXE-bound002", tool_name="bash_runner", verdict=VerdictKind.QUARANTINE_TOOL, risk_score=1.0, violation_reason="max risk")
    assert v_zero.risk_score == 0.0
    assert v_one.risk_score == 1.0

    # Negative invariant: risk_score out of [0.0, 1.0]
    with pytest.raises(ValidationError):
        AuthorizationVerdictDTO(
            execution_id="EXE-badscore01",
            tool_name="bash_runner",
            verdict=VerdictKind.ALLOW,
            risk_score=-0.05,
        )

    with pytest.raises(ValidationError):
        AuthorizationVerdictDTO(
            execution_id="EXE-badscore02",
            tool_name="bash_runner",
            verdict=VerdictKind.QUARANTINE_TOOL,
            risk_score=1.20,
            violation_reason="Exceeded maximum",
        )

    # Negative invariant: NaN and Inf rejected
    with pytest.raises(ValidationError):
        AuthorizationVerdictDTO(
            execution_id="EXE-badnan01",
            tool_name="bash_runner",
            verdict=VerdictKind.ALLOW,
            risk_score=float("nan"),
        )

    with pytest.raises(ValidationError):
        AuthorizationVerdictDTO(
            execution_id="EXE-badinf01",
            tool_name="bash_runner",
            verdict=VerdictKind.ALLOW,
            risk_score=float("inf"),
        )

    # Negative invariant: inconsistent verdict with risk_score thresholds
    with pytest.raises(ValidationError, match="verdict is inconsistent with risk_score thresholds"):
        AuthorizationVerdictDTO(
            execution_id="EXE-inconsistent01",
            tool_name="bash_runner",
            verdict=VerdictKind.ALLOW,
            risk_score=0.90,  # 0.90 requires QUARANTINE_TOOL
        )

    # Negative invariant: non-ALLOW verdict requires violation_reason
    with pytest.raises(ValidationError, match="non-ALLOW verdicts require a violation_reason"):
        AuthorizationVerdictDTO(
            execution_id="EXE-noreason01",
            tool_name="bash_runner",
            verdict=VerdictKind.STRIP_COMMANDS,
            risk_score=0.45,
            violation_reason=None,
        )


def test_sara_fsm_total_and_fail_closed():
    from ctxfw.sara import (
        FAILURE_ROUTING,
        TERMINAL_STATES,
        FailureClass,
        SaraEvent,
        SaraState,
        VerdictKind,
        transition,
        verdict_for_risk,
    )

    # Terminal states
    assert SaraState.AUDITED in TERMINAL_STATES
    assert SaraState.REJECTED_INVALID in TERMINAL_STATES
    assert TERMINAL_STATES == frozenset({SaraState.AUDITED, SaraState.REJECTED_INVALID})

    # Standard state transitions delta(S, E)
    assert transition(SaraState.INGRESSED, SaraEvent.SANITIZE_OK) is SaraState.SANITIZED
    assert transition(SaraState.INGRESSED, SaraEvent.VALIDATION_FAIL) is SaraState.REJECTED_INVALID
    assert transition(SaraState.SANITIZED, SaraEvent.PARSE_OK) is SaraState.PARSED
    assert transition(SaraState.SANITIZED, SaraEvent.ESCAPE_PATTERN_DETECTED) is SaraState.QUARANTINED
    assert transition(SaraState.SANITIZED, SaraEvent.PARSE_FAIL) is SaraState.REJECTED_INVALID
    assert transition(SaraState.PARSED, SaraEvent.RISK_LOW) is SaraState.AUTHORIZED_ALLOW
    assert transition(SaraState.PARSED, SaraEvent.RISK_MEDIUM) is SaraState.AUTHORIZED_STRIPPED
    assert transition(SaraState.PARSED, SaraEvent.RISK_HIGH) is SaraState.QUARANTINED
    assert transition(SaraState.AUTHORIZED_ALLOW, SaraEvent.WAL_COMMIT) is SaraState.AUDITED
    assert transition(SaraState.AUTHORIZED_STRIPPED, SaraEvent.WAL_COMMIT) is SaraState.AUDITED
    assert transition(SaraState.QUARANTINED, SaraEvent.WAL_COMMIT) is SaraState.AUDITED

    # Total determinism over all 8 states x 9 events (72 pairs)
    from ctxfw.sara import SARA_TRANSITIONS
    for state in SaraState:
        for event in SaraEvent:
            nxt = transition(state, event)
            assert isinstance(nxt, SaraState)
            assert nxt is transition(state, event)
            # Terminal states are strict sinks
            if state in TERMINAL_STATES:
                assert nxt is SaraState.REJECTED_INVALID
            elif (state, event) in SARA_TRANSITIONS:
                assert nxt is SARA_TRANSITIONS[(state, event)]
            else:
                assert nxt is SaraState.REJECTED_INVALID

    # Immutability of transitions map
    with pytest.raises(TypeError):
        SARA_TRANSITIONS[(SaraState.QUARANTINED, SaraEvent.RISK_LOW)] = SaraState.AUTHORIZED_ALLOW  # type: ignore[index]

    # Total function guarantee: any undefined transition collapses to REJECTED_INVALID
    assert transition("UNKNOWN_STATE", SaraEvent.SANITIZE_OK) is SaraState.REJECTED_INVALID  # type: ignore[arg-type]
    assert transition(SaraState.INGRESSED, "UNKNOWN_EVENT") is SaraState.REJECTED_INVALID  # type: ignore[arg-type]
    assert transition("GARBAGE", "GARBAGE") is SaraState.REJECTED_INVALID  # type: ignore[arg-type]
    assert transition(SaraState.AUDITED, SaraEvent.WAL_COMMIT) is SaraState.REJECTED_INVALID

    # Failure taxonomy routing (all 4 failure classes mapped)
    assert len(FAILURE_ROUTING) == 4
    assert FAILURE_ROUTING[FailureClass.TRANSIENT] == "RETRY_MAX_3_THEN_QUARANTINE_TOOL"
    assert FAILURE_ROUTING[FailureClass.DETERMINISTIC] == "REJECTED_INVALID"
    assert FAILURE_ROUTING[FailureClass.BUSINESS] == "STRIP_COMMANDS_OR_QUARANTINE_TOOL"
    assert FAILURE_ROUTING[FailureClass.SECURITY] == "QUARANTINE_TOOL"

    # Risk threshold mappings and boundary precision
    assert verdict_for_risk(0.00) is VerdictKind.ALLOW
    assert verdict_for_risk(0.2999) is VerdictKind.ALLOW
    assert verdict_for_risk(0.30) is VerdictKind.STRIP_COMMANDS
    assert verdict_for_risk(0.7999) is VerdictKind.STRIP_COMMANDS
    assert verdict_for_risk(0.80) is VerdictKind.QUARANTINE_TOOL
    assert verdict_for_risk(1.00) is VerdictKind.QUARANTINE_TOOL


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 35, 0), reason="sealed DDL requires SQLite >= 3.35")
def test_sealed_schema_loads_and_has_immutability_triggers():
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(load_schema_sql())

        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"sara_authorized_policies", "sara_tool_execution_logs", "sara_quarantine_payloads"} <= tables

        triggers = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert len(triggers) == 5
        assert "trg_sara_logs_no_update" in triggers
        assert "trg_sara_quarantine_no_update" in triggers
        assert "trg_sara_policies_no_update" in triggers
        assert "trg_sara_quarantine_requires_verdict" in triggers
        assert "trg_sara_quarantine_no_direct_delete" in triggers

        # Invariant INV-09: raw_output column is not in logs table
        log_columns = [row[1] for row in conn.execute("PRAGMA table_info(sara_tool_execution_logs)")]
        assert "raw_output" not in log_columns

        # 1. Policy immutability: UPDATE prohibited
        conn.execute(
            "INSERT INTO sara_authorized_policies (policy_id, tool_name, policy_mask) "
            "VALUES ('POL-test001', 'bash_runner', 3)"
        )
        with pytest.raises(sqlite3.IntegrityError, match="SARA_INV_04: allowlist policies are immutable"):
            conn.execute("UPDATE sara_authorized_policies SET policy_mask = 7 WHERE policy_id = 'POL-test001'")

        # 2. Execution log immutability: UPDATE prohibited
        conn.execute(
            "INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) "
            "VALUES ('EXE-allow-001', 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0.1, 'ALLOW')"
        )
        with pytest.raises(sqlite3.IntegrityError, match="SARA_INV_08: audit rows are append-only"):
            conn.execute("UPDATE sara_tool_execution_logs SET risk_score = 0.9 WHERE execution_id = 'EXE-allow-001'")

        # 3. Quarantine requires QUARANTINE_TOOL verdict (ALLOW and STRIP_COMMANDS rejected)
        with pytest.raises(sqlite3.IntegrityError, match="SARA_INV_09: raw_output may only be stored for QUARANTINE_TOOL verdicts"):
            conn.execute(
                "INSERT INTO sara_quarantine_payloads (quarantine_id, execution_id, raw_output, violation_reason) "
                "VALUES ('QRN-bad-001', 'EXE-allow-001', 'payload', 'disallowed')"
            )

        conn.execute(
            "INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) "
            "VALUES ('EXE-strip-001', 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0.5, 'STRIP_COMMANDS')"
        )
        with pytest.raises(sqlite3.IntegrityError, match="SARA_INV_09: raw_output may only be stored for QUARANTINE_TOOL verdicts"):
            conn.execute(
                "INSERT INTO sara_quarantine_payloads (quarantine_id, execution_id, raw_output, violation_reason) "
                "VALUES ('QRN-bad-002', 'EXE-strip-001', 'payload', 'disallowed')"
            )

        # Orphan quarantine row rejected
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO sara_quarantine_payloads (quarantine_id, execution_id, raw_output, violation_reason) "
                "VALUES ('QRN-orphan-001', 'EXE-missing-001', 'payload', 'missing parent')"
            )

        # 4. Insert log with QUARANTINE_TOOL verdict and valid quarantine payload
        conn.execute(
            "INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) "
            "VALUES ('EXE-quar-001', 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0.95, 'QUARANTINE_TOOL')"
        )
        conn.execute(
            "INSERT INTO sara_quarantine_payloads (quarantine_id, execution_id, raw_output, violation_reason) "
            "VALUES ('QRN-good-001', 'EXE-quar-001', 'malicious code', 'injection risk')"
        )

        # 5. Quarantine payload immutability: UPDATE prohibited
        with pytest.raises(sqlite3.IntegrityError, match="SARA_INV_06: quarantined payloads are immutable"):
            conn.execute("UPDATE sara_quarantine_payloads SET raw_output = 'tampered' WHERE quarantine_id = 'QRN-good-001'")

        # 6. Quarantine payload deletion: direct DELETE prohibited
        with pytest.raises(sqlite3.IntegrityError, match="SARA_INV_06: quarantined payloads are removable only by cascade"):
            conn.execute("DELETE FROM sara_quarantine_payloads WHERE quarantine_id = 'QRN-good-001'")

        # 7. Cascade deletion: deleting parent log cascade-removes quarantine payload
        conn.execute("DELETE FROM sara_tool_execution_logs WHERE execution_id = 'EXE-quar-001'")
        remaining = conn.execute("SELECT COUNT(*) FROM sara_quarantine_payloads WHERE quarantine_id = 'QRN-good-001'").fetchone()[0]
        assert remaining == 0
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

        # 8. Schema DDL CHECK constraints
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) VALUES ('EXE-chk-001', 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 1.5, 'ALLOW')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) VALUES ('EXE-chk-002', 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', -0.1, 'ALLOW')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) VALUES ('EXE-chk-003', 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0.1, 'INVALID_VERDICT')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) VALUES ('EXE-chk-004', 'bash_runner', 'not-a-valid-sha256', 0.1, 'ALLOW')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_authorized_policies (policy_id, tool_name, policy_mask) VALUES ('POL-chk-001', 'bash_runner', 4294967296)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_authorized_policies (policy_id, tool_name, policy_mask) VALUES ('POL-chk-002', 'bash_runner', -1)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO sara_authorized_policies (policy_id, tool_name, policy_mask) VALUES ('POL-chk-dup', 'bash_runner', 3)")
    finally:
        conn.close()


def test_sqlite_wal_multithread_contention(tmp_path):
    """10 worker threads concurrently inserting audit logs and quarantined payloads under SQLite WAL mode."""
    db_file = tmp_path / "sara_wal_contention.db"

    # Initialize database with schema
    init_conn = sqlite3.connect(db_file)
    init_conn.execute("PRAGMA journal_mode=WAL")
    init_conn.execute("PRAGMA foreign_keys=ON")
    init_conn.executescript(load_schema_sql())
    init_conn.commit()
    init_conn.close()

    worker_errors: list[Exception] = []

    def thread_worker(worker_id: int):
        try:
            w_conn = sqlite3.connect(db_file, timeout=10.0)
            w_conn.execute("PRAGMA busy_timeout=10000")
            w_conn.execute("PRAGMA foreign_keys=ON")
            exe_id = f"EXE-worker-{worker_id:04d}"
            if worker_id % 2 == 0:
                with w_conn:
                    w_conn.execute(
                        "INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) "
                        "VALUES (?, 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0.05, 'ALLOW')",
                        (exe_id,),
                    )
            else:
                qrn_id = f"QRN-worker-{worker_id:04d}"
                with w_conn:
                    w_conn.execute(
                        "INSERT INTO sara_tool_execution_logs (execution_id, tool_name, observation_sha256, risk_score, verdict) "
                        "VALUES (?, 'bash_runner', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0.95, 'QUARANTINE_TOOL')",
                        (exe_id,),
                    )
                    w_conn.execute(
                        "INSERT INTO sara_quarantine_payloads (quarantine_id, execution_id, raw_output, violation_reason) "
                        "VALUES (?, ?, ?, 'injection risk detected')",
                        (qrn_id, exe_id, "malicious_payload_" * 100),
                    )
            w_conn.close()
        except Exception as exc:
            worker_errors.append(exc)

    threads = [threading.Thread(target=thread_worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not worker_errors, f"Thread errors encountered: {worker_errors}"

    check_conn = sqlite3.connect(db_file)
    count = check_conn.execute("SELECT COUNT(*) FROM sara_tool_execution_logs WHERE execution_id LIKE 'EXE-worker-%'").fetchone()[0]
    quar_count = check_conn.execute("SELECT COUNT(*) FROM sara_quarantine_payloads WHERE quarantine_id LIKE 'QRN-worker-%'").fetchone()[0]
    fk_check = check_conn.execute("PRAGMA foreign_key_check").fetchall()
    integrity = check_conn.execute("PRAGMA integrity_check").fetchone()[0]
    check_conn.close()
    assert count == 10
    assert quar_count == 5
    assert fk_check == []
    assert integrity == "ok"
