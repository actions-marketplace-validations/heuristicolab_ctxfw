# manifest_hash: 0dd507acac7dc966a16fa69ccffcb7a51797ce899ca6edab88837448ad38d415
"""
tests/test_v41_finops_team_gate.py — Verification Suite for CTXFW v4.1.0
Axiom Manifest Hash: 0dd507acac7dc966a16fa69ccffcb7a51797ce899ca6edab88837448ad38d415

Validates:
  1. LiveBench & LLM Pricing Matrix + Auto-Detection Precedence (AXIOM-V41-1)
  2. Multi-Turn Session Compounding & LiveBench Pareto Arbitrage (AXIOM-V41-2)
  3. Privacy-Preserving Team Export & Tamper-Evident Team Merge (AXIOM-V41-3, AXIOM-V41-4)
  4. Fail-Closed `ctxfw gate` CLI Verification for CI/CD PRs (AXIOM-V41-5)
  5. Dynamic Model Pricing in Proxy Telemetry & SQLite WAL Non-Destructive Migration (AXIOM-V41-7)
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from ctxfw.cli.main import (
    export_report_json,
    generate_share_report,
    handle_config_command,
    handle_gate_command,
    handle_report_command,
    merge_team_reports,
)
from ctxfw.config import load_config, set_config_value
from ctxfw.core.contracts import OptimizationResultDTO, PruningDepth
from ctxfw.finops import (
    compute_arbitrage_recommendation,
    compute_compounded_savings,
    load_model_matrix,
    resolve_active_model,
    resolve_model_spec,
)
from ctxfw.storage.cache import LocalSemanticCache


def test_finops_model_matrix_livebench_and_auto_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verifies bundled LiveBench + pricing matrix and deterministic model auto-detection hierarchy."""
    catalog = load_model_matrix()
    assert "claude-opus-4-20250514" in catalog
    assert "claude-sonnet-4-20250514" in catalog
    assert "gpt-4.1" in catalog
    assert "gemini-2.5-pro" in catalog

    opus = resolve_model_spec("claude-opus-4")
    assert opus.input_price_per_m == 15.0
    assert opus.output_price_per_m == 75.0
    assert opus.livebench_coding_score == 82.4

    sonnet = resolve_model_spec("sonnet")
    assert sonnet.input_price_per_m == 3.0
    assert sonnet.livebench_coding_score == 80.1

    # 1. Explicit model parameter wins
    explicit = resolve_active_model(explicit_model="gpt-4.1", project_root=tmp_path)
    assert explicit.model_id == "gpt-4.1"
    assert explicit.input_price_per_m == 2.0

    # 2. Environment variable wins over workspace/global config
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-4")
    env_resolved = resolve_active_model(project_root=tmp_path)
    assert env_resolved.model_id == "claude-opus-4-20250514"
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)

    # 3. Workspace .claude/settings.json or .ctxfwrc wins over global config
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "settings.json").write_text(json.dumps({"model": "gemini-2.5-pro"}), encoding="utf-8")
    ws_resolved = resolve_active_model(project_root=tmp_path)
    assert ws_resolved.model_id == "gemini-2.5-pro"
    assert ws_resolved.input_price_per_m == 1.25

    # 4. Global config set finops.model automatically updates input_price_per_m & output_price_per_m
    cfg_file = tmp_path / "user_config.json"
    updated_cfg = set_config_value("finops.model", "claude-opus-4", custom_path=cfg_file)
    assert updated_cfg.finops.model == "claude-opus-4"
    assert updated_cfg.finops.input_price_per_m == 15.0
    assert updated_cfg.finops.output_price_per_m == 75.0


def test_finops_multi_turn_compounding_and_arbitrage_bounds():
    """Verifies multi-turn session compounding math, numerical bounds (AXIOM-V41-2), and LiveBench arbitrage."""
    opus = resolve_model_spec("claude-opus-4")
    comp = compute_compounded_savings(tokens_saved=100_000, model_spec=opus, compounding_factor=4.2)
    # 100k tokens @ $15/1M = $1.50 direct; compounded 4.2x = $6.30
    assert comp["direct_1turn_usd"] == 1.5
    assert comp["compounded_session_tokens"] == 420_000
    assert comp["compounded_session_usd"] == 6.3

    # Out-of-bounds compounding factor rejected (AXIOM-V41-2)
    with pytest.raises(ValueError, match="compounding_factor"):
        compute_compounded_savings(tokens_saved=1000, model_spec=opus, compounding_factor=0.5)
    with pytest.raises(ValueError, match="compounding_factor"):
        compute_compounded_savings(tokens_saved=1000, model_spec=opus, compounding_factor=25.0)
    with pytest.raises(ValueError, match="NaN"):
        compute_compounded_savings(tokens_saved=1000, model_spec=opus, compounding_factor=float("nan"))

    # Arbitrage recommendation from Claude Opus 4 -> Claude Sonnet 4
    arb = compute_arbitrage_recommendation(
        model_spec=opus,
        evaluated_tokens=500_000,
        tokens_saved=350_000,
        compounding_factor=4.2,
    )
    assert arb["has_arbitrage"] is True
    assert arb["target_model"] == "claude-sonnet-4-20250514"
    assert arb["quality_retention_pct"] == 97.2
    assert arb["cost_reduction_pct"] == 80.0
    assert "97.2% LiveBench coding intelligence" in arb["recommendation"]


def test_team_export_json_and_tamper_evident_team_merge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    """
    Verifies privacy-preserving `--export-json` (AXIOM-V41-3) and tamper-evident
    `--team-merge` consolidation across multiple developers and repositories (AXIOM-V41-4).
    """
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setattr("ctxfw.config.get_canonical_config_path", lambda: cfg_path)
    set_config_value("finops.model", "claude-opus-4", custom_path=cfg_path)

    # Developer 1 database (working on payments-service and core-sdk)
    db_dev1 = tmp_path / "dev1_tokens.db"
    repo_payments = tmp_path / "payments-service"
    repo_payments.mkdir()
    (repo_payments / ".git").mkdir()

    repo_sdk = tmp_path / "core-sdk"
    repo_sdk.mkdir()
    (repo_sdk / "pyproject.toml").write_text("[project]\nname='core-sdk'\n", encoding="utf-8")

    cache1 = LocalSemanticCache(db_path=str(db_dev1))
    cache1.set(
        "k1",
        OptimizationResultDTO(
            pruned_code="def charge(): ...",
            original_chars=40_000,
            pruned_chars=8_000,
            estimated_tokens_saved=8_000,
            savings_percentage=80.0,
            cache_hit=False,
            execution_ms=1.0,
            depth=PruningDepth.INTERFACE,
        ),
        project_root=repo_payments,
    )
    cache1.set(
        "k2",
        OptimizationResultDTO(
            pruned_code="def sdk(): ...",
            original_chars=20_000,
            pruned_chars=4_000,
            estimated_tokens_saved=4_000,
            savings_percentage=80.0,
            cache_hit=False,
            execution_ms=1.0,
            depth=PruningDepth.INTERFACE,
        ),
        project_root=repo_sdk,
    )
    cache1.close()

    # Developer 2 database (working on payments-service)
    db_dev2 = tmp_path / "dev2_tokens.db"
    cache2 = LocalSemanticCache(db_path=str(db_dev2))
    cache2.set(
        "k3",
        OptimizationResultDTO(
            pruned_code="def settle(): ...",
            original_chars=60_000,
            pruned_chars=12_000,
            estimated_tokens_saved=12_000,
            savings_percentage=80.0,
            cache_hit=False,
            execution_ms=1.0,
            depth=PruningDepth.INTERFACE,
        ),
        project_root=repo_payments,
    )
    cache2.close()

    snap1 = tmp_path / "dev1.json"
    snap2 = tmp_path / "dev2.json"

    rc1 = handle_report_command(["--db", str(db_dev1), "--export-json", str(snap1), "--dev-alias", "alice"])
    rc2 = handle_report_command(["--db", str(db_dev2), "--export-json", str(snap2), "--dev-alias", "bob"])
    assert rc1 == 0
    assert rc2 == 0

    raw_snap1 = snap1.read_text(encoding="utf-8")
    # AXIOM-V41-3: Zero source code, zero raw paths, zero plain developer aliases
    assert "def charge" not in raw_snap1
    assert str(tmp_path) not in raw_snap1
    assert "alice" not in raw_snap1

    # Verify unlicensed --team-merge fails closed (exit code 1)
    monkeypatch.delenv("CTXFW_LICENSE_KEY", raising=False)
    monkeypatch.setenv("CTXFW_OFFLINE_LICENSE_CHECK", "1")
    rc_unlic = handle_report_command(["--team-merge", str(snap1), str(snap2)])
    assert rc_unlic == 1
    assert "CTXFW LICENSE REQUIRED" in capsys.readouterr().err

    valid_test_key = (
        "CTXFW-TEAM-PRO-eyJleHAiOiIyMDM2LTEwLTE4VDAwOjAwOjAwWiIsImlhdCI6IjIwMjYtMTAtMjFUMDA6MDA6MDBaIiwiaWQiOiJMSUMtQ0ktVEVTVC1WQUxJRCIsIm1heF9kZXZzIjoxNSwibWF4X3JlcG9zIjo1LCJvcmciOiJoZXVyaXN0aWNvLWNpIiwidGllciI6IlRFQU1fUFJPIn0."
        "WO38JeAWRcqT-94JGZEF0pDENNr37pRLbWl3fv7p2Ez9WQL_44X2sKBGxcTpbcFZFIza4FQej-AydLLfASA81SuuoN_bY5Byt0fuFxKPAUY4F-071Cv9urgnIzzHhxI7nqOwVM72KFvXCDndywZPZrPMYQElx0Pv5trQrZc5ECVto3en-B4SFj9jBrdl3JXGCMghWFJjGbPGlWgIbQ66gUo9zXciyf8Frvi4QCfJGuUc8ku-QqrY8tNK1DW3DNaMI93uIoSQqPjqtpCe62G2ZovxxaW-sQgo8X3wv_7hn-ytDr_HGHBzEsqBMc-n7FsNp2VPlHuQw4xbgPCnKk_PUA"
    )
    monkeypatch.setenv("CTXFW_LICENSE_KEY", valid_test_key)

    # Merge both developer snapshots via CLI
    merged_out = tmp_path / "team_report.md"
    rc_merge = handle_report_command(["--team-merge", str(snap1), str(snap2), "--output", str(merged_out)])
    assert rc_merge == 0
    merged_text = merged_out.read_text(encoding="utf-8")

    assert "Consolidated across **2 Verified Developer Nodes**" in merged_text
    assert "`payments-service`" in merged_text
    assert "`core-sdk`" in merged_text
    assert "24,000" in merged_text  # 8k + 4k + 12k tokens saved

    # AXIOM-V41-4: Tamper with snap1 and verify fail-closed rejection
    tampered_data = json.loads(raw_snap1)
    tampered_data["tokens_saved"] = 999_999
    tampered_file = tmp_path / "tampered.json"
    tampered_file.write_text(json.dumps(tampered_data), encoding="utf-8")

    capsys.readouterr()
    rc_tamper = handle_report_command(["--team-merge", str(tampered_file), str(snap2)])
    assert rc_tamper == 1
    err_out = capsys.readouterr().err
    assert "SECURITY_TAMPER_DETECTED" in err_out


def test_ctxfw_gate_cli_allow_and_fail_closed_reject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    """
    Verifies `ctxfw gate` CLI command:
      - Returns exit code 1 (`LICENSE_REQUIRED` / `LICENSE_EXPIRED` / `LICENSE_REVOKED`) without an active license.
      - Returns exit code 0 (`ALLOW_MERGE`) on clean diffs with green tests and valid license.
      - Returns exit code 1 (`REJECT_ARCHITECTURAL_VIOLATION`) on `# type: ignore`,
        disallowed imports, cyclomatic complexity spikes, or failed functional tests (AXIOM-V41-5).
    """
    from ctxfw.finops.licensing import LicenseStatus, verify_license_key

    swegate_db = tmp_path / "gate_test.db"
    summary_file = tmp_path / "github_step_summary.md"
    monkeypatch.setenv("CTXFW_SWEGATE_DB", str(swegate_db))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    monkeypatch.setenv("CTXFW_OFFLINE_LICENSE_CHECK", "1")

    valid_test_key = (
        "CTXFW-TEAM-PRO-eyJleHAiOiIyMDM2LTEwLTE4VDAwOjAwOjAwWiIsImlhdCI6IjIwMjYtMTAtMjFUMDA6MDA6MDBaIiwiaWQiOiJMSUMtQ0ktVEVTVC1WQUxJRCIsIm1heF9kZXZzIjoxNSwibWF4X3JlcG9zIjo1LCJvcmciOiJoZXVyaXN0aWNvLWNpIiwidGllciI6IlRFQU1fUFJPIn0."
        "WO38JeAWRcqT-94JGZEF0pDENNr37pRLbWl3fv7p2Ez9WQL_44X2sKBGxcTpbcFZFIza4FQej-AydLLfASA81SuuoN_bY5Byt0fuFxKPAUY4F-071Cv9urgnIzzHhxI7nqOwVM72KFvXCDndywZPZrPMYQElx0Pv5trQrZc5ECVto3en-B4SFj9jBrdl3JXGCMghWFJjGbPGlWgIbQ66gUo9zXciyf8Frvi4QCfJGuUc8ku-QqrY8tNK1DW3DNaMI93uIoSQqPjqtpCe62G2ZovxxaW-sQgo8X3wv_7hn-ytDr_HGHBzEsqBMc-n7FsNp2VPlHuQw4xbgPCnKk_PUA"
    )
    expired_test_key = (
        "CTXFW-TEAM-TRIAL-eyJleHAiOiIyMDI1LTAxLTA4VDAwOjAwOjAwWiIsImlhdCI6IjIwMjUtMDEtMDFUMDA6MDA6MDBaIiwiaWQiOiJMSUMtQ0ktVEVTVC1FWFBJUkVEIiwibWF4X2RldnMiOjE1LCJtYXhfcmVwb3MiOjUsIm9yZyI6ImFjbWUtZXhwaXJlZCIsInRpZXIiOiJURUFNX1RSSUFMIn0."
        "F1uVYVfKQ0GlKPnUKdTkQ9l90Mfgeg6pZ6qK1YrLg1htMl8RKBA2vRIUG2vvcCxmua8l2f4Bhnm_DhYlaPBABTaGDhP60uXqWnQ5TIFkAilsQBaoL7NtxjUlG-mE7Kd8TS36KbI7DhzvPMW_Mx6TR-n2op8CrE58G6TW79WiXspq6ZfvYEwilv3WFMLwhOZN6VCl5RyU67VSGm2g4Izn-0AFu7bljUPBngiV-BLDij7fqOmgJPK1G_O_Bf28IJV-HqrXXnGQcndYcG7oyWE7qxfTAq4oAKj--Run36Eg_u-cEtAPUaWQoR7UCUvh6sVtbdkfoO1gShHU_h-pW0udPA"
    )

    # Verify expired, tampered, and revoked license detection
    assert verify_license_key(expired_test_key, check_revocation=False).status is LicenseStatus.EXPIRED
    assert verify_license_key(valid_test_key[:-4] + "AAAA", check_revocation=False).status is LicenseStatus.QUARANTINED
    assert (
        verify_license_key(valid_test_key, revoked_ids_override={"LIC-CI-TEST-VALID"}).status
        is LicenseStatus.REVOKED
    )

    monkeypatch.setenv("CTXFW_LICENSE_KEY", valid_test_key)

    clean_diff = (
        "diff --git a/src/service.py b/src/service.py\n"
        "--- a/src/service.py\n"
        "+++ b/src/service.py\n"
        "@@ -1,2 +1,4 @@\n"
        " def compute(x: int) -> int:\n"
        "+    if x > 0:\n"
        "+        return x * 2\n"
        "     return x\n"
    )
    clean_diff_file = tmp_path / "clean.diff"
    clean_diff_file.write_text(clean_diff, encoding="utf-8", newline="\n")

    rc_allow = handle_gate_command(
        [
            "--diff",
            str(clean_diff_file),
            "--tests-passed",
            "120",
            "--tests-failed",
            "0",
            "--max-cyclomatic-delta",
            "3",
            "--repo-name",
            "heuristico/ctxfw",
            "--json",
        ]
    )
    assert rc_allow == 0
    json_allow = json.loads(capsys.readouterr().out)
    assert json_allow["verdict"] == "ALLOW_MERGE"
    assert json_allow["state"] == "PASS_GATE"
    assert json_allow["cyclomatic_delta"] == 1
    assert "ALLOW_MERGE" in summary_file.read_text(encoding="utf-8")

    # Violating diff (contains # type: ignore and disallowed import requests)
    bad_diff = (
        "diff --git a/src/service.py b/src/service.py\n"
        "--- a/src/service.py\n"
        "+++ b/src/service.py\n"
        "@@ -1,2 +1,4 @@\n"
        "+import requests\n"
        " def compute(x: int) -> int:\n"
        "+    y = x  # type: ignore[assignment]\n"
        "     return x\n"
    )
    bad_diff_file = tmp_path / "bad.diff"
    bad_diff_file.write_text(bad_diff, encoding="utf-8", newline="\n")

    rc_reject = handle_gate_command(
        [
            "--diff",
            str(bad_diff_file),
            "--tests-passed",
            "120",
            "--tests-failed",
            "0",
            "--disallow-import",
            "requests",
            "--json",
        ]
    )
    assert rc_reject == 1
    json_reject = json.loads(capsys.readouterr().out)
    assert json_reject["verdict"] == "REJECT_ARCHITECTURAL_VIOLATION"
    assert any("TYPE_IGNORE" in v for v in json_reject["architectural_violations"])
    assert any("DISALLOWED_IMPORT" in v for v in json_reject["architectural_violations"])

    # Clean diff but failed functional tests -> must fail closed (exit code 1)
    rc_failed_tests = handle_gate_command(
        [
            "--diff",
            str(clean_diff_file),
            "--tests-passed",
            "119",
            "--tests-failed",
            "1",
            "--json",
        ]
    )
    assert rc_failed_tests == 1


def test_dante_sara_benchmark_action_and_pentad_wal() -> None:
    """Verifies the reproducible 24-vector SARA prompt-injection benchmark, GitHub Action manifest, and Pentad WAL check."""
    from benchmarks.run_sara_security_benchmark import run_benchmark
    from ctxfw.installer import run_doctor

    summary = run_benchmark(persist_to_canonical_sara=False)
    assert summary["corpus_size"] == 24
    assert summary["adversarial_vectors"] == 16
    assert summary["benign_vectors"] == 8
    assert summary["recall_pct"] == 100.0
    assert summary["false_positive_rate_pct"] == 0.0
    assert summary["network_egress_calls"] == 0

    action_yml = Path(__file__).resolve().parents[1] / "action.yml"
    assert action_yml.is_file()
    action_text = action_yml.read_text(encoding="utf-8")
    assert "CTXFW_LICENSE_KEY" in action_text
    assert "ctxfw gate" in action_text

    doc_report = run_doctor()
    check_names = {c.name: c for c in doc_report.checks}
    assert "Sovereign Pentad WAL Ledgers" in check_names
    assert check_names["Sovereign Pentad WAL Ledgers"].status == "OK"

