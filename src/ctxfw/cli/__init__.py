# manifest_hash: 990875d35d51a816507954d5e1a61506dcd2b5ec7d40d515a65c4ee5ac325f5f
"""
src/ctxfw/cli/__init__.py — Unified Command Line Interface Package (v4.1.0)
Axiom Manifest Hash: f1e4295bef2f28f87c0364875bba0ea956fa38bdb1bcf0fb0671f4b4242d1a6e
"""
from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "app",
    "build_parser",
    "copy_to_clipboard",
    "run_firewall_cli",
    "handle_init_command",
    "handle_init_cli",
    "init_entrypoint",
    "handle_install_cli",
    "install_entrypoint",
    "run_doctor_cli",
    "doctor_entrypoint",
    "run_spec_verify",
    "handle_spec_command",
    "inject_agent_mcp_config",
    "install_claude_surfaces",
    "safe_merge_claude_code_config",
    "resolve_claude_desktop_config_path",
    "resolve_cursor_config_path",
    "run_init_mcp_agents",
    "handle_config_command",
    "handle_mode_command",
    "handle_report_command",
    "generate_share_report",
    "export_report_json",
    "merge_team_reports",
    "handle_gate_command",
    "handle_trace_command",
    "run_trace_verify",
    "main",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        mod = importlib.import_module("ctxfw.cli.main")
        val = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))

