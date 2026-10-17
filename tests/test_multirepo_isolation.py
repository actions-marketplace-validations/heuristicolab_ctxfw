# manifest_hash: 73a24a0ac04e9142a8ce9684758e0e947583f8bb96d8884503482686d6aba6e5
"""
tests/test_multirepo_isolation.py — Multi-Workspace Rule, D3 Index, and FinOps Attribution Tests
"""
from __future__ import annotations

from pathlib import Path
import sqlite3

from ctxfw.cli.main import generate_share_report
from ctxfw.core.topological import ContextFirewallEngine
from ctxfw.mcp import MCPServer
from ctxfw.rules.store import RulesStore
from ctxfw.storage.cache import LocalSemanticCache, resolve_project_identity


def test_resolve_project_identity_walk_up_and_determinism(tmp_path: Path):
    """Verifies workspace root detection from nested files and deterministic REPO-<hex16> IDs."""
    repo_a = tmp_path / "fintech-core"
    (repo_a / "src" / "api").mkdir(parents=True)
    (repo_a / "pyproject.toml").write_text("[project]\nname='fintech'\n", encoding="utf-8")
    target = repo_a / "src" / "api" / "routes.py"
    target.write_text("def status():\n    return 200\n", encoding="utf-8")

    pid1, pname1 = resolve_project_identity(target)
    pid2, pname2 = resolve_project_identity(repo_a)
    assert pid1 == pid2
    assert pid1.startswith("REPO-") and len(pid1) == 21
    assert pname1 == "fintech-core"
    assert pname2 == "fintech-core"

    pid_none, pname_none = resolve_project_identity(None)
    assert pid_none == "REPO-0000000000000000"
    assert pname_none == "global"


def test_multirepo_rule_isolation_prevents_cross_workspace_contamination(tmp_path: Path):
    """
    Verifies that compiled .cursorrules / CLAUDE.md guards from Repo A never block
    or contaminate tool calls targeting Repo B, and vice versa.
    """
    repo_a = tmp_path / "repo_alpha"
    repo_b = tmp_path / "repo_beta"
    repo_a.mkdir()
    repo_b.mkdir()

    # Repo A forbids reading vault_alpha.py, but allows vault_beta.py
    (repo_a / ".cursorrules").write_text(
        "- never read `vault_alpha.py`\n",
        encoding="utf-8",
    )
    (repo_a / "vault_alpha.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (repo_a / "vault_beta.py").write_text("def b():\n    return 2\n", encoding="utf-8")

    # Repo B forbids reading vault_beta.py, but allows vault_alpha.py
    (repo_b / "CLAUDE.md").write_text(
        "- do not read `vault_beta.py`\n",
        encoding="utf-8",
    )
    (repo_b / "vault_alpha.py").write_text("def a_clean():\n    return 10\n", encoding="utf-8")
    (repo_b / "vault_beta.py").write_text("def b_secret():\n    return 20\n", encoding="utf-8")

    rules_db = tmp_path / "shared_rules.db"
    cache_db = tmp_path / "shared_tokens.db"
    server = MCPServer(
        cache=LocalSemanticCache(cache_db),
        rules_store=RulesStore(rules_db),
    )

    # 1. In Repo A: vault_alpha.py is BLOCKED, vault_beta.py is ALLOWED
    res_a_blocked = server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": str(repo_a / "vault_alpha.py"), "project_root": str(repo_a)},
    })
    assert res_a_blocked["isError"] is True
    assert res_a_blocked.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_a_blocked["content"][0]["text"]

    res_a_allowed = server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": str(repo_a / "vault_beta.py"), "project_root": str(repo_a)},
    })
    assert res_a_allowed["isError"] is False

    # 2. Switch to Repo B on the SAME MCPServer & RulesStore:
    # vault_alpha.py MUST BE ALLOWED in Repo B (no leak from Repo A!)
    res_b_allowed = server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": str(repo_b / "vault_alpha.py"), "project_root": str(repo_b)},
    })
    assert res_b_allowed["isError"] is False

    # And vault_beta.py MUST BE BLOCKED in Repo B by Repo B's own CLAUDE.md
    res_b_blocked = server.handle_tools_call({
        "name": "prune_file",
        "arguments": {"path": str(repo_b / "vault_beta.py"), "project_root": str(repo_b)},
    })
    assert res_b_blocked["isError"] is True
    assert res_b_blocked.get("policyViolation") is True
    assert "POLICY_BLOCKED" in res_b_blocked["content"][0]["text"]


def test_multirepo_d3_symbol_index_isolation_on_identical_relative_paths(tmp_path: Path):
    """
    Verifies that two repositories having identical relative module paths (e.g. 'src/main.py')
    maintain isolated D3 symbol cartography entries in LocalSemanticCache.
    """
    cache = LocalSemanticCache(tmp_path / "d3_shared.db")
    repo_a = tmp_path / "project_one"
    repo_b = tmp_path / "project_two"
    repo_a.mkdir()
    repo_b.mkdir()
    (repo_a / "pyproject.toml").write_text("[project]\nname='one'\n", encoding="utf-8")
    (repo_b / "pyproject.toml").write_text("[project]\nname='two'\n", encoding="utf-8")

    cache.set_d3_symbols_batch(
        [("src/main.py", "sha_a", 1000.0, ["AlphaEngine", "run_alpha"])],
        project_root=repo_a,
    )
    cache.set_d3_symbols_batch(
        [("src/main.py", "sha_b", 2000.0, ["BetaService", "run_beta"])],
        project_root=repo_b,
    )

    res_a = cache.get_d3_symbols_batch(["src/main.py"], project_root=repo_a)
    res_b = cache.get_d3_symbols_batch(["src/main.py"], project_root=repo_b)

    assert res_a["src/main.py"][2] == ["AlphaEngine", "run_alpha"]
    assert res_b["src/main.py"][2] == ["BetaService", "run_beta"]
    cache.close()


def test_multirepo_tokens_cache_migration_and_per_repository_finops_report(tmp_path: Path):
    """
    Verifies idempotent schema migration on legacy tokens_cache (zero data loss)
    and accurate Per-Repository FinOps Breakdown in generate_share_report.
    """
    db_file = tmp_path / "legacy_tokens.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE tokens_cache (
            cache_key TEXT PRIMARY KEY,
            pruned_code TEXT NOT NULL,
            pruning_depth TEXT NOT NULL DEFAULT 'interface',
            original_chars INTEGER NOT NULL,
            pruned_chars INTEGER NOT NULL,
            estimated_tokens_saved INTEGER NOT NULL,
            savings_percentage REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.execute(
        """
        INSERT INTO tokens_cache
        (cache_key, pruned_code, pruning_depth, original_chars, pruned_chars, estimated_tokens_saved, savings_percentage)
        VALUES ('legacy_k1', 'def f(): ...', 'interface', 4000, 800, 800, 80.0)
        """
    )
    conn.commit()
    conn.close()

    # Initialize LocalSemanticCache over legacy DB -> must migrate without dropping legacy_k1
    cache = LocalSemanticCache(db_file)
    assert cache.get("legacy_k1") is not None

    # Create two distinct repositories and run ContextFirewallEngine
    repo_museum = tmp_path / "museo-filosofia"
    repo_museum.mkdir()
    (repo_museum / "pyproject.toml").write_text("[project]\nname='museo'\n", encoding="utf-8")
    (repo_museum / "events.py").write_text(
        "import schedule_helper\n\ndef book_venue(guest: str) -> str:\n    x = guest.strip()\n    return schedule_helper.confirm(x)\n",
        encoding="utf-8",
    )
    (repo_museum / "schedule_helper.py").write_text(
        "def confirm(name: str) -> str:\n    msg = f'Confirmed: {name}'\n    return msg\n",
        encoding="utf-8",
    )

    repo_metaverse = tmp_path / "metaverse-mexico"
    repo_metaverse.mkdir()
    (repo_metaverse / "pyproject.toml").write_text("[project]\nname='metaverse'\n", encoding="utf-8")
    (repo_metaverse / "portal.py").write_text(
        "def enter_world(user_id: int) -> bool:\n    valid = user_id > 0\n    return valid\n",
        encoding="utf-8",
    )

    eng_museum = ContextFirewallEngine(project_root=repo_museum, cache=cache)
    eng_museum.build_context(repo_museum / "events.py")

    eng_meta = ContextFirewallEngine(project_root=repo_metaverse, cache=cache)
    eng_meta.build_context(repo_metaverse / "portal.py")
    cache.close()

    report_md = generate_share_report(db_path=str(db_file))
    assert "## 2. Per-Repository FinOps Breakdown" in report_md
    assert "`museo-filosofia`" in report_md
    assert "`metaverse-mexico`" in report_md
    assert "`[legacy/global]`" in report_md
    assert "C:\\" not in report_md
    assert "/home/" not in report_md
