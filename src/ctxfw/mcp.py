# manifest_hash: 0823534213f7266f79184a2f24e71680fd24cb9c5971f58eab7c2dd124023a7c
"""
src/ctxfw/mcp.py — Model Context Protocol (MCP) Server over stdio (v3.4.0)
manifest_hash: 0823534213f7266f79184a2f24e71680fd24cb9c5971f58eab7c2dd124023a7c
Exposes deterministic context pruning and topological bundle resolution
to AI agents (Cursor, Claude Code, Windsurf) using JSON-RPC 2.0.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, Optional, Sequence
import uuid

from ctxfw.core.contracts import (
    OptimizationRequestDTO,
    OptimizationResultDTO,
    PruningDepth,
    SupportedLanguage,
)
from ctxfw.core.pruner import DeterministicContextPruner
from ctxfw.core.topological import ContextFirewallEngine
from ctxfw.storage.cache import LocalSemanticCache
from ctxfw import __version__

_SWEGATE_TOOLS = frozenset(
    {
        "evaluate_patch",
        "swe_gate_evaluate",
        "verify_patch",
        "apply_patch",
        "propose_patch",
        "refactor_patch",
    }
)


class ToolResult(dict):
    """Tool invocation result supporting dictionary access and .isError attribute."""

    @property
    def isError(self) -> bool:
        return bool(self.get("isError", False))


class MCPServer:
    """Model Context Protocol server implementing JSON-RPC 2.0 over stdio."""

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "context-firewall-mcp"
    SERVER_VERSION = f"{__version__}"

    def __init__(
        self,
        cache: Optional[LocalSemanticCache] = None,
        tracekit_store: Optional[Any] = None,
        session_id: Optional[str] = None,
        rules_store: Optional[Any] = None,
        tokencast_store: Optional[Any] = None,
        guards: Optional[Any] = None,
        sara_store: Optional[Any] = None,
        sara_policy: Optional[Any] = None,
        swegate_store: Optional[Any] = None,
        swegate_rule: Optional[Any] = None,
        swegate_repo_id: Optional[str] = None,
    ):
        self.running = True
        self.cache = cache or LocalSemanticCache()
        self._tracekit_store = tracekit_store
        self._rules_store = rules_store
        self._tokencast_store = tokencast_store
        self._sara_store = sara_store
        self._sara_policy = sara_policy
        self._swegate_store = swegate_store
        self._swegate_rule = swegate_rule
        self._swegate_repo_id = swegate_repo_id
        self._guards = tuple(guards) if guards is not None else ()
        self.session_id = session_id or os.environ.get("CTXFW_SESSION_ID")
        self._enforce_seq = 0

    def _get_tracekit_store(self):
        """Lazily initialize TraceKitStore on canonical or overridden tracekit.db path."""
        if self._tracekit_store is None:
            from ctxfw.audit.store import TraceKitStore, resolve_tracekit_db_path
            from ctxfw.kernel.clock import SystemUtcClock

            db_path = resolve_tracekit_db_path()
            self._tracekit_store = TraceKitStore(db_path, clock=SystemUtcClock())
        return self._tracekit_store

    def _get_rules_store(self):
        """Lazily initialize RulesStore on canonical rules.db path."""
        if self._rules_store is None:
            from ctxfw.rules.store import RulesStore
            from ctxfw.storage.cache import get_canonical_cache_path

            db_path = Path(get_canonical_cache_path()).parent / "rules.db"
            self._rules_store = RulesStore(db_path)
        return self._rules_store

    def _get_tokencast_store(self):
        """Lazily initialize TokenCastStore on canonical tokencast.db path."""
        if self._tokencast_store is None:
            from ctxfw.budget.store import TokenCastStore
            from ctxfw.storage.cache import get_canonical_cache_path

            db_path = Path(get_canonical_cache_path()).parent / "tokencast.db"
            self._tokencast_store = TokenCastStore(db_path)
        return self._tokencast_store

    def _get_sara_store(self):
        """Lazily initialize SaraStore on canonical sara.db path."""
        if self._sara_store is None:
            from ctxfw.sara.store import SaraStore
            from ctxfw.storage.cache import get_canonical_cache_path

            env_db = os.environ.get("CTXFW_SARA_DB")
            if env_db:
                db_path = Path(env_db)
            else:
                db_path = Path(get_canonical_cache_path()).parent / "sara.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._sara_store = SaraStore(db_path)
        return self._sara_store

    def _get_swegate_store(self):
        """Lazily initialize SweGateStore on canonical swegate.db path."""
        if self._swegate_store is None:
            from ctxfw.storage.cache import get_canonical_cache_path
            from ctxfw.swegate.store import SweGateStore

            env_db = os.environ.get("CTXFW_SWEGATE_DB")
            if env_db:
                db_path = Path(env_db)
            else:
                db_path = Path(get_canonical_cache_path()).parent / "swegate.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._swegate_store = SweGateStore(db_path)
        return self._swegate_store

    def _get_swegate_rule(self, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Resolve active SWE-Gate ArchitecturalConstraintRuleDTO for patch inspection."""
        from ctxfw.swegate.contracts import ArchitecturalConstraintRuleDTO

        args = arguments if isinstance(arguments, dict) else {}
        if "rule" in args:
            cand = args["rule"]
            if isinstance(cand, ArchitecturalConstraintRuleDTO):
                return cand
            if isinstance(cand, dict):
                data = dict(cand)
                if isinstance(data.get("disallowed_import_modules"), list):
                    data["disallowed_import_modules"] = tuple(data["disallowed_import_modules"])
                return ArchitecturalConstraintRuleDTO(**data)
            return cand

        rule_keys = (
            "rule_id",
            "max_cyclomatic_delta",
            "forbid_type_ignores",
            "disallowed_import_modules",
        )
        has_arg_overrides = any(k in args for k in rule_keys)

        if not has_arg_overrides and self._swegate_rule is not None:
            if isinstance(self._swegate_rule, ArchitecturalConstraintRuleDTO):
                return self._swegate_rule
            if isinstance(self._swegate_rule, dict):
                data = {
                    "rule_id": "RULE-mcp-default",
                    "max_cyclomatic_delta": 10,
                    "forbid_type_ignores": True,
                    "disallowed_import_modules": (),
                }
                data.update(self._swegate_rule)
                if isinstance(data.get("disallowed_import_modules"), list):
                    data["disallowed_import_modules"] = tuple(data["disallowed_import_modules"])
                return ArchitecturalConstraintRuleDTO(**data)
            return self._swegate_rule

        base_rule_id = "RULE-mcp-default"
        base_max_delta = 10
        base_forbid_ignores = True
        base_disallowed: Any = ()

        if isinstance(self._swegate_rule, ArchitecturalConstraintRuleDTO):
            base_rule_id = self._swegate_rule.rule_id
            base_max_delta = self._swegate_rule.max_cyclomatic_delta
            base_forbid_ignores = self._swegate_rule.forbid_type_ignores
            base_disallowed = self._swegate_rule.disallowed_import_modules
        elif isinstance(self._swegate_rule, dict):
            base_rule_id = self._swegate_rule.get("rule_id", base_rule_id)
            base_max_delta = self._swegate_rule.get("max_cyclomatic_delta", base_max_delta)
            base_forbid_ignores = self._swegate_rule.get("forbid_type_ignores", base_forbid_ignores)
            base_disallowed = self._swegate_rule.get("disallowed_import_modules", base_disallowed)
        elif self._swegate_rule is not None:
            return self._swegate_rule

        rule_id = args["rule_id"] if "rule_id" in args else base_rule_id
        max_delta = args["max_cyclomatic_delta"] if "max_cyclomatic_delta" in args else base_max_delta
        forbid_ignores = args["forbid_type_ignores"] if "forbid_type_ignores" in args else base_forbid_ignores
        disallowed = args["disallowed_import_modules"] if "disallowed_import_modules" in args else base_disallowed
        if isinstance(disallowed, list):
            disallowed = tuple(disallowed)

        return ArchitecturalConstraintRuleDTO(
            rule_id=rule_id,
            max_cyclomatic_delta=max_delta,
            forbid_type_ignores=forbid_ignores,
            disallowed_import_modules=disallowed,
        )

    def _get_sara_policy(self, tool_name: str):
        """Resolve active SARA AuthorizationPolicyRuleDTO for the given MCP tool."""
        from ctxfw.sara.contracts import AuthorizationPolicyRuleDTO

        if self._sara_policy is not None:
            if isinstance(self._sara_policy, dict):
                if tool_name in self._sara_policy:
                    cand = self._sara_policy[tool_name]
                    if isinstance(cand, AuthorizationPolicyRuleDTO):
                        return cand
                    if isinstance(cand, dict):
                        return AuthorizationPolicyRuleDTO(**cand)
                    return cand
                if "policy_id" in self._sara_policy:
                    data = dict(self._sara_policy)
                    data["tool_name"] = tool_name
                    return AuthorizationPolicyRuleDTO(**data)
            elif isinstance(self._sara_policy, AuthorizationPolicyRuleDTO):
                if self._sara_policy.tool_name == tool_name:
                    return self._sara_policy
                return AuthorizationPolicyRuleDTO(
                    policy_id=self._sara_policy.policy_id,
                    tool_name=tool_name,
                    allowed_commands=self._sara_policy.allowed_commands,
                    allowed_path_prefixes=self._sara_policy.allowed_path_prefixes,
                    policy_mask=self._sara_policy.policy_mask,
                )
            else:
                return self._sara_policy
        return AuthorizationPolicyRuleDTO(
            policy_id=f"POL-mcp-{tool_name[:48]}",
            tool_name=tool_name,
            allowed_commands=(),
            allowed_path_prefixes=(),
            policy_mask=0,
        )

    def _get_active_guards(self, project_root: Optional[Path] = None) -> tuple[Any, ...]:
        """Load active compiled guards from instance, store, or workspace rule files."""
        if self._guards:
            return self._guards
        store = self._get_rules_store()
        guards = tuple(store.get_all_guards())
        if guards:
            return guards
        if project_root and project_root.is_dir():
            for rule_name in ("CLAUDE.md", ".cursorrules"):
                rf = project_root / rule_name
                if rf.is_file():
                    try:
                        from ctxfw.rules.compiler import RulesCompiler

                        manifest, _, _ = RulesCompiler.compile_file(rf)
                        store.persist_manifest(manifest)
                        return manifest.guards
                    except Exception:
                        pass
        return ()

    def _record_shadow_audit(self, params: Dict[str, Any], result: Dict[str, Any]) -> None:
        """
        Passive fail-silent hook to record Intent-Reasoning-Action audit block in tracekit.db.
        Strictly enforces:
          - Zero writes to sys.stdout (JSON-RPC purity).
          - Completely fail-silent in shadow mode (never interrupts or alters tool response).
          - Total bypass if CTXFW_AUDIT_MODE == 'off'.
        """
        try:
            audit_mode = os.environ.get("CTXFW_AUDIT_MODE", "shadow").lower().strip()
            if audit_mode in ("off", "disabled", "false", "0"):
                return

            if not isinstance(params, dict):
                params = {}
            tool_name = params.get("name", "unknown_tool")
            arguments = params.get("arguments")
            if not isinstance(arguments, dict):
                arguments = {}

            session_id = (
                arguments.get("session_id")
                or params.get("session_id")
                or self.session_id
            )
            if not session_id or not re.match(r"^SES-[A-Za-z0-9_-]{4,64}$", str(session_id)):
                from ctxfw.kernel.contracts import new_session_id

                self.session_id = new_session_id()
                session_id = self.session_id

            user_prompt = (
                arguments.get("user_prompt")
                or arguments.get("prompt")
                or f"MCP tool call: {tool_name}"
            )
            user_prompt = str(user_prompt)[:65536]
            if not user_prompt.strip():
                user_prompt = f"MCP tool call: {tool_name}"

            plan_summary = (
                arguments.get("plan_summary")
                or arguments.get("plan")
                or f"Execute MCP tool {tool_name}"
            )
            plan_summary = str(plan_summary)[:16384]
            if not plan_summary.strip():
                plan_summary = f"Execute MCP tool {tool_name}"

            target_val = arguments.get("path") or arguments.get("target_file") or tool_name
            tool_or_file = re.sub(r"[\x00-\x1f\x7f]", "", str(target_val))[:512]
            if not tool_or_file.strip():
                tool_or_file = str(tool_name)[:512]
            if not tool_or_file.strip():
                tool_or_file = "tool"

            if isinstance(result, dict) and "content" in result:
                contents = result.get("content", [])
                text_pieces = [c.get("text", "") for c in contents if isinstance(c, dict)]
                payload_str = "\n".join(text_pieces)
            else:
                payload_str = json.dumps(result, sort_keys=True)
            if not payload_str:
                payload_str = "{}"
            payload_str = payload_str[:65536]

            store = self._get_tracekit_store()
            outcome = store.record_step(
                session_id=session_id,
                user_prompt=user_prompt,
                plan_summary=plan_summary,
                tool_or_file=tool_or_file,
                payload=payload_str,
            )
            if outcome.is_rejected:
                try:
                    sys.stderr.write(f"[TraceKit Shadow Error] Append rejected [{outcome.failure_class}]: {outcome.reason}\n")
                    sys.stderr.flush()
                except Exception:
                    pass
        except Exception as exc:
            try:
                sys.stderr.write(f"[TraceKit Shadow Error] {exc}\n")
                sys.stderr.flush()
            except Exception:
                pass

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handles MCP protocol handshake."""
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": f"{__version__}",
            },
        }

    def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Lists available context compacting tools."""
        tool_annotations = {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }

        return {
            "tools": [
                {
                    "name": "prune_file",
                    "description": (
                        "Extract semantic interfaces, types, pydantic models, sanitized raises, and signatures "
                        "from a source file while replacing procedural bodies with AST stubs. Use this when you "
                        "only need to inspect contracts or APIs of an individual dependency without ingesting "
                        "raw implementation code. Does not modify files on disk (pure in-memory AST operation)."
                    ),
                    "annotations": tool_annotations,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute or relative path to the source file",
                            },
                            "depth": {
                                "type": "string",
                                "description": "Pruning depth: 'full', 'interface', or 'nominal'",
                                "default": "interface",
                            },
                            "strip_docs": {
                                "type": "boolean",
                                "description": "Whether to strip docstrings entirely",
                                "default": False,
                            },
                            "language": {
                                "type": "string",
                                "description": "Programming language (python, typescript, javascript, go, java)",
                                "default": "python",
                            },
                        },
                        "required": ["path"],
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "array",
                                "description": "Semantic interface stubs extracted via in-memory Tree-Sitter AST",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["text"]},
                                        "text": {"type": "string", "description": "Pruned source code with AST stubs"},
                                    },
                                    "required": ["type", "text"],
                                },
                            },
                            "isError": {
                                "type": "boolean",
                                "description": "True if pruning encountered a fatal parsing or file resolution failure",
                            },
                        },
                        "required": ["content", "isError"],
                    },
                },
                {
                    "name": "resolve_context_bundle",
                    "description": (
                        "Calculate topological dependency graph distances (D0 full target, D1 interface stubs, "
                        "D2 nominal symbols) for an active target file and compile a token-pruned Markdown context bundle. "
                        "Use this as your primary context builder before editing a file in a multi-module project. "
                        "For inspecting isolated files, use prune_file instead. Read-only operation."
                    ),
                    "annotations": tool_annotations,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_file": {
                                "type": "string",
                                "description": "Path to the active target file in editing (D0)",
                            },
                            "project_root": {
                                "type": "string",
                                "description": "Root directory of the project. Defaults to target file's directory.",
                            },
                            "breaker_state": {
                                "type": "string",
                                "description": "Optional circuit breaker state (CLOSED, TRIPPED, HALTED) or decision kind",
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Session identifier (SES-...) to connect with TokenCast budget tracking",
                            },
                        },
                        "required": ["target_file"],
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "array",
                                "description": "Compiled topological Markdown prompt context bundle",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["text"]},
                                        "text": {"type": "string", "description": "Token-optimized Markdown context bundle"},
                                    },
                                    "required": ["type", "text"],
                                },
                            },
                            "isError": {
                                "type": "boolean",
                                "description": "True if dependency resolution or file traversal failed",
                            },
                        },
                        "required": ["content", "isError"],
                    },
                },
                {
                    "name": "evaluate_spec_axioms",
                    "description": (
                        "Evaluate an architectural brief against formal determinism rules, negative invariant floors, "
                        "and the Axiom Completeness Index (ACI 1.0000). Use this during intake or planning phases "
                        "before writing code. Pure analytical evaluation with no side effects."
                    ),
                    "annotations": tool_annotations,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "brief_text": {
                                "type": "string",
                                "description": "Markdown content of the architectural intake brief to evaluate",
                            },
                        },
                        "required": ["brief_text"],
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "array",
                                "description": "JSON-serialized architectural determinism verification report",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["text"]},
                                        "text": {
                                            "type": "string",
                                            "description": "JSON report containing aci_score, negative_invariants_count, extracted_never_clauses, status, remediation_notes, and manifest_hash",
                                        },
                                    },
                                    "required": ["type", "text"],
                                },
                            },
                            "isError": {
                                "type": "boolean",
                                "description": "True if brief specification evaluation encountered an unhandled error",
                            },
                        },
                        "required": ["content", "isError"],
                    },
                },
                {
                    "name": "evaluate_patch",
                    "description": (
                        "Verify a unified git diff patch against SWE-Gate architectural constraints "
                        "(cyclomatic complexity delta, forbidden '# type: ignore' suppressions, "
                        "disallowed module imports) and functional test results before allowing merge. "
                        "Persists audit records in SweGateStore and seals cryptographic blocks in TraceKitStore."
                    ),
                    "annotations": tool_annotations,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "diff_text": {
                                "type": "string",
                                "description": "Unified diff text of the candidate patch",
                            },
                            "commit_sha": {
                                "type": "string",
                                "description": "40-character lowercase hex commit SHA",
                            },
                            "author_kind": {
                                "type": "string",
                                "description": "Patch author kind: 'AGENT' or 'HUMAN'",
                                "default": "AGENT",
                            },
                            "pr_id": {
                                "type": "integer",
                                "description": "Pull request identifier (>= 1)",
                                "default": 1,
                            },
                            "diff_size_bytes": {
                                "type": "integer",
                                "description": "Exact UTF-8 byte length of diff_text",
                            },
                            "tests_passed": {
                                "type": "integer",
                                "description": "Count of passing functional tests",
                                "default": 1,
                            },
                            "tests_failed": {
                                "type": "integer",
                                "description": "Count of failing functional tests",
                                "default": 0,
                            },
                            "functional_verdict": {
                                "type": "string",
                                "description": "Functional test suite verdict: 'PASSED' or 'FAILED'",
                            },
                            "max_cyclomatic_delta": {
                                "type": "integer",
                                "description": "Maximum allowed cyclomatic complexity delta",
                                "default": 10,
                            },
                            "forbid_type_ignores": {
                                "type": "boolean",
                                "description": "Whether introducing '# type: ignore' is forbidden",
                                "default": True,
                            },
                            "disallowed_import_modules": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of banned module names that the patch must not import",
                            },
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name (e.g. 'heuristico/ctxfw')",
                                "default": "heuristico/ctxfw",
                            },
                            "repo_id": {
                                "type": "string",
                                "description": "Optional repository identifier (REPO-...)",
                            },
                        },
                        "required": ["diff_text"],
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "array",
                                "description": "JSON-serialized SWE-Gate verification report or rejection message",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["text"]},
                                        "text": {
                                            "type": "string",
                                            "description": "SWE-Gate audit report or rejection details",
                                        },
                                    },
                                    "required": ["type", "text"],
                                },
                            },
                            "isError": {
                                "type": "boolean",
                                "description": "True if the patch was rejected by SWE-Gate or failed validation",
                            },
                        },
                        "required": ["content", "isError"],
                    },
                },
            ]
        }

    def _enforce_swegate_patch(
        self,
        *,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        """Verify candidate patch diff via the closed-loop SWE-Gate CI pipeline."""
        import sqlite3
        from pydantic import ValidationError
        from ctxfw.swegate.contracts import (
            REPO_ID_PATTERN,
            FunctionalTestResultDTO,
            GateState,
            GateVerdict,
            PatchInspectionAuditDTO,
            PatchMetadataDTO,
            ViolationType,
            format_violation,
            sha256_hex,
        )
        from ctxfw.swegate.gate import SweGateVerifier

        raw_prompt = str(user_prompt)[:65536] if user_prompt is not None else ""
        safe_prompt = raw_prompt.encode("utf-8", errors="replace").decode("utf-8")
        if not safe_prompt.strip():
            safe_prompt = f"MCP tool call: {tool_name}"

        if "diff_text" in arguments:
            diff_text = arguments.get("diff_text")
        elif "patch_diff" in arguments:
            diff_text = arguments.get("patch_diff")
        else:
            diff_text = arguments.get("diff")

        swegate_store = self._get_swegate_store()
        raw_repo_name = arguments.get("repo_name", "heuristico/ctxfw")
        if isinstance(raw_repo_name, str):
            clean_repo_name = (
                raw_repo_name.encode("utf-8", errors="replace")
                .decode("utf-8")
                .strip()[:200]
            )
        else:
            clean_repo_name = ""
        repo_name = clean_repo_name if clean_repo_name else "heuristico/ctxfw"
        raw_repo_id = arguments.get("repo_id") or self._swegate_repo_id
        valid_repo_id = (
            raw_repo_id
            if isinstance(raw_repo_id, str)
            and re.fullmatch(REPO_ID_PATTERN, raw_repo_id) is not None
            else None
        )
        try:
            resolved_repo_id = swegate_store.register_repository(
                repo_name,
                repo_id=valid_repo_id,
            )
        except (sqlite3.Error, ValueError, TypeError):
            resolved_repo_id = swegate_store.register_repository("heuristico/ctxfw")

        meta: Any = None
        try:
            if "meta" in arguments:
                cand_meta = arguments["meta"]
                if isinstance(cand_meta, PatchMetadataDTO):
                    meta = cand_meta
                elif isinstance(cand_meta, dict):
                    meta = PatchMetadataDTO(**cand_meta)
                else:
                    meta = cand_meta
            else:
                commit_sha = arguments.get("commit_sha", "0" * 40)
                author_kind = arguments.get("author_kind", "AGENT")
                pr_id = arguments.get("pr_id", 1)
                diff_size_bytes = (
                    arguments["diff_size_bytes"]
                    if "diff_size_bytes" in arguments
                    else (len(diff_text.encode("utf-8")) if isinstance(diff_text, str) else 0)
                )
                meta = PatchMetadataDTO(
                    commit_sha=commit_sha,
                    author_kind=author_kind,
                    pr_id=pr_id,
                    diff_size_bytes=diff_size_bytes,
                )
        except (ValidationError, ValueError, TypeError):
            meta = None

        functional: Any = None
        try:
            if "functional" in arguments:
                cand_func = arguments["functional"]
                if isinstance(cand_func, FunctionalTestResultDTO):
                    functional = cand_func
                elif isinstance(cand_func, dict):
                    functional = FunctionalTestResultDTO(**cand_func)
                else:
                    functional = cand_func
            else:
                t_passed = arguments.get("tests_passed", 1)
                t_failed = arguments.get("tests_failed", 0)
                default_fv = (
                    "PASSED"
                    if (
                        isinstance(t_failed, int)
                        and not isinstance(t_failed, bool)
                        and t_failed == 0
                        and isinstance(t_passed, int)
                        and not isinstance(t_passed, bool)
                        and t_passed >= 1
                    )
                    else "FAILED"
                )
                f_verdict = arguments.get("functional_verdict", default_fv)
                functional = FunctionalTestResultDTO(
                    tests_passed=t_passed,
                    tests_failed=t_failed,
                    functional_verdict=f_verdict,
                )
        except (ValidationError, ValueError, TypeError):
            functional = None

        rule: Any = None
        try:
            rule = self._get_swegate_rule(arguments)
        except (ValidationError, ValueError, TypeError):
            rule = None

        try:
            audit, trace = SweGateVerifier.evaluate_traced(meta, functional, rule, diff_text)
        except Exception:
            audit = PatchInspectionAuditDTO(
                is_functional_passed=False,
                cyclomatic_delta=0,
                architectural_violations=(
                    format_violation(ViolationType.INVALID_INPUT, "patch"),
                ),
                gate_verdict=GateVerdict.REJECT_ARCHITECTURAL_VIOLATION,
            )
            trace = [GateState.RECEIVED, GateState.REJECTED_INVALID]

        safe_diff_for_hash = (
            str(diff_text or "invalid").encode("utf-8", errors="replace").decode("utf-8")
        )
        fallback_commit_sha = sha256_hex(safe_diff_for_hash)[:40]

        decided_state = trace[-1] if trace else GateState.REJECTED_INVALID
        eval_id: Optional[str] = None
        final_state: GateState = GateState.REJECTED_INVALID
        try:
            if (
                decided_state in (GateState.DECIDED_PASS, GateState.DECIDED_REJECT)
                and isinstance(meta, PatchMetadataDTO)
            ):
                eval_id, final_state, _naps = swegate_store.record_evaluation(
                    resolved_repo_id,
                    meta,
                    audit,
                    decided_state=decided_state,
                )
            else:
                fallback_meta = (
                    meta
                    if isinstance(meta, PatchMetadataDTO)
                    else PatchMetadataDTO(
                        commit_sha=fallback_commit_sha,
                        author_kind="AGENT",
                        pr_id=1,
                        diff_size_bytes=1,
                    )
                )
                eval_id, _persisted_state, _naps = swegate_store.record_evaluation(
                    resolved_repo_id,
                    fallback_meta,
                    audit,
                    decided_state=GateState.DECIDED_REJECT,
                )
                final_state = GateState.REJECTED_INVALID
        except Exception as store_exc:
            final_state = GateState.REJECTED_INVALID
            try:
                sys.stderr.write(f"[SWE-Gate Store Error] {store_exc}\n")
                sys.stderr.flush()
            except Exception:
                pass

        effective_commit = (
            meta.commit_sha
            if isinstance(meta, PatchMetadataDTO)
            else fallback_commit_sha
        )
        if audit.gate_verdict is GateVerdict.ALLOW_MERGE and final_state is GateState.PASS_GATE:
            tk_payload = (
                f"SWE_GATE_ALLOW: eval_id={eval_id} commit={effective_commit} "
                f"delta={audit.cyclomatic_delta} state={final_state.value}"
            )
        else:
            tk_payload = (
                f"SWE_GATE_REJECT: eval_id={eval_id} state={final_state.value} "
                f"delta={audit.cyclomatic_delta} violations={','.join(audit.architectural_violations)}"
            )
        try:
            tracekit = self._get_tracekit_store()
            tracekit.record_step(
                session_id=session_id,
                user_prompt=safe_prompt,
                plan_summary=f"SWE-Gate CI verification on {tool_name}",
                tool_or_file="swe_gate.eval",
                payload=tk_payload[:65536],
            )
        except Exception as tk_exc:
            try:
                sys.stderr.write(f"[TraceKit SWE-Gate Error] {tk_exc}\n")
                sys.stderr.flush()
            except Exception:
                pass

        if audit.gate_verdict is GateVerdict.ALLOW_MERGE and final_state is GateState.PASS_GATE:
            payload_report = {
                "evaluation_id": eval_id,
                "repo_id": resolved_repo_id,
                "commit_sha": effective_commit,
                "gate_verdict": audit.gate_verdict.value,
                "gate_state": final_state.value,
                "is_functional_passed": audit.is_functional_passed,
                "cyclomatic_delta": audit.cyclomatic_delta,
                "architectural_violations": list(audit.architectural_violations),
            }
            return {
                "content": [{"type": "text", "text": json.dumps(payload_report, indent=2)}],
                "isError": False,
                "sweGateRejected": False,
                "sweGateVerdict": "ALLOW_MERGE",
                "sweGateState": "PASS_GATE",
                "evaluationId": eval_id,
                "cyclomaticDelta": audit.cyclomatic_delta,
                "architecturalViolations": [],
                "sweGateRecorded": True,
            }

        violations_list = list(audit.architectural_violations)
        reason_parts = list(violations_list)
        if not audit.is_functional_passed:
            reason_parts.append("FUNCTIONAL_TESTS_FAILED")
        reason_str = ", ".join(reason_parts) if reason_parts else final_state.value
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"SWE_GATE_REJECTED: Patch verification failed "
                        f"[{final_state.value}]: {reason_str}"
                    ),
                }
            ],
            "isError": True,
            "sweGateRejected": True,
            "sweGateVerdict": GateVerdict.REJECT_ARCHITECTURAL_VIOLATION.value,
            "sweGateState": final_state.value,
            "evaluationId": eval_id,
            "cyclomaticDelta": audit.cyclomatic_delta,
            "architecturalViolations": violations_list,
            "policyViolation": True,
            "sweGateRecorded": True,
        }

    def _enforce_sara_observation(
        self,
        *,
        tool_name: str,
        output_text: str,
        raw_sources: Sequence[str] = (),
        session_id: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        """Inspect and authorize untrusted tool output via the closed-loop SARA pipeline."""
        from ctxfw.sara.audit import derive_quarantine_id
        from ctxfw.sara.contracts import (
            MAX_DIRECTIVES_PER_OBSERVATION,
            MAX_RAW_OUTPUT_CHARS,
            AuthorizationVerdictDTO,
            RawToolObservationDTO,
            SaraState,
            SourceType,
            ToolExecutionSourceDTO,
            VerdictKind,
            observation_digest,
            verdict_for_risk,
        )
        from ctxfw.sara.gate import RuntimeAuthorizationGate, _build_violation_reason
        from ctxfw.sara.induction import InductionParser
        from ctxfw.sara.lexical import LexicalSanitizer

        execution_id = f"EXE-{uuid.uuid4().hex[:16]}"
        safe_prompt = str(user_prompt)[:65536] if user_prompt is not None else ""
        if not safe_prompt.strip():
            safe_prompt = f"MCP tool call: {tool_name}"

        sara_store = None

        try:
            sara_store = self._get_sara_store()
            policy = self._get_sara_policy(tool_name)

            LexicalSanitizer.validate_raw(output_text)
            for src in raw_sources:
                LexicalSanitizer.validate_raw(src)

            source_dto = ToolExecutionSourceDTO(
                tool_name=tool_name,
                source_type=SourceType.FILE_READ,
                execution_id=execution_id,
            )
            obs_dto = RawToolObservationDTO.from_raw(
                source=source_dto,
                raw_output=output_text,
            )
            verdict, trace = RuntimeAuthorizationGate.authorize_traced(obs_dto, policy)
            all_verdicts = [verdict]

            for src in raw_sources:
                if src == output_text:
                    continue
                src_obs = RawToolObservationDTO.from_raw(
                    source=source_dto,
                    raw_output=src,
                )
                src_verdict, src_trace = RuntimeAuthorizationGate.authorize_traced(
                    src_obs, policy
                )
                all_verdicts.append(src_verdict)
                if src_verdict.risk_score > verdict.risk_score:
                    obs_dto = src_obs
                    verdict = src_verdict
                    trace = src_trace

            # Merge distinct directives across output_text and all raw_sources
            merged_directives = list(verdict.directives)
            seen_keys = {
                (d.directive_kind, d.directive_text, d.within_allowlist)
                for d in merged_directives
            }
            for v in all_verdicts:
                for d in v.directives:
                    key = (d.directive_kind, d.directive_text, d.within_allowlist)
                    if (
                        key not in seen_keys
                        and len(merged_directives) < MAX_DIRECTIVES_PER_OBSERVATION
                    ):
                        seen_keys.add(key)
                        merged_directives.append(d)

            if len(merged_directives) > len(verdict.directives):
                merged_tuple = tuple(merged_directives[:MAX_DIRECTIVES_PER_OBSERVATION])
                merged_risk = max(
                    verdict.risk_score,
                    InductionParser.compute_risk_score(merged_tuple),
                )
                merged_kind = verdict_for_risk(merged_risk)
                tool_mismatch = policy.tool_name != source_dto.tool_name
                merged_reason = _build_violation_reason(
                    merged_kind,
                    merged_risk,
                    merged_tuple,
                    tool_mismatch,
                )
                verdict = AuthorizationVerdictDTO(
                    execution_id=execution_id,
                    tool_name=tool_name,
                    verdict=merged_kind,
                    risk_score=merged_risk,
                    directives=merged_tuple,
                    violation_reason=merged_reason,
                )

            sara_store.audit_commit(
                obs_dto,
                verdict,
                state=trace[-1] if trace else None,
            )
        except Exception as exc:
            reason = f"Fail-closed quarantine ({type(exc).__name__}): {exc}".strip()[:512]
            if not reason:
                reason = "Fail-closed quarantine: invalid observation or runtime fault"
            verdict = AuthorizationVerdictDTO(
                execution_id=execution_id,
                tool_name=tool_name,
                verdict=VerdictKind.QUARANTINE_TOOL,
                risk_score=1.0,
                directives=(),
                violation_reason=reason,
            )
            raw_for_quarantine = (
                output_text if isinstance(output_text, str) else str(output_text)
            )
            for src in raw_sources:
                if isinstance(src, str) and (
                    len(src) > MAX_RAW_OUTPUT_CHARS or "\x00" in src
                ):
                    raw_for_quarantine = src
                    break
            bounded_raw = raw_for_quarantine.replace("\x00", "")[:MAX_RAW_OUTPUT_CHARS]
            try:
                if sara_store is None:
                    sara_store = self._get_sara_store()
                sara_store.audit_commit_fail_closed(
                    verdict,
                    observation_sha256=observation_digest(bounded_raw),
                    raw_output=bounded_raw,
                    state=SaraState.QUARANTINED,
                )
            except Exception as audit_exc:
                try:
                    sys.stderr.write(f"[SARA Audit Error] {audit_exc}\n")
                    sys.stderr.flush()
                except Exception:
                    pass

        if verdict.verdict is VerdictKind.ALLOW:
            clean_text = LexicalSanitizer.sanitize(
                output_text, reject_null_bytes=True
            ).sanitized_text
            return {
                "content": [{"type": "text", "text": clean_text}],
                "isError": False,
            }

        if verdict.verdict is VerdictKind.STRIP_COMMANDS:
            neutralized_text = LexicalSanitizer.neutralize(
                output_text, verdict.directives
            )
            try:
                tracekit = self._get_tracekit_store()
                tracekit.record_step(
                    session_id=session_id,
                    user_prompt=safe_prompt,
                    plan_summary=f"SARA runtime authorization gate on {tool_name}",
                    tool_or_file="sara.gate",
                    payload=f"SARA_STRIPPED: {verdict.violation_reason}",
                )
            except Exception as tk_exc:
                try:
                    sys.stderr.write(f"[TraceKit SARA Error] {tk_exc}\n")
                    sys.stderr.flush()
                except Exception:
                    pass

            return {
                "content": [{"type": "text", "text": neutralized_text}],
                "isError": False,
                "saraVerdict": "STRIP_COMMANDS",
                "saraStripped": True,
            }

        quarantine_id = derive_quarantine_id(verdict.execution_id)
        try:
            tracekit = self._get_tracekit_store()
            tracekit.record_step(
                session_id=session_id,
                user_prompt=safe_prompt,
                plan_summary=f"SARA runtime authorization gate on {tool_name}",
                tool_or_file="sara.gate",
                payload=f"SARA_QUARANTINED: {verdict.violation_reason}",
            )
        except Exception as tk_exc:
            try:
                sys.stderr.write(f"[TraceKit SARA Error] {tk_exc}\n")
                sys.stderr.flush()
            except Exception:
                pass

        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        "SARA_QUARANTINED: Indirect prompt injection or unauthorized "
                        f"action induction detected: {verdict.violation_reason}"
                    ),
                }
            ],
            "isError": True,
            "saraQuarantined": True,
            "saraVerdict": "QUARANTINE_TOOL",
            "quarantineId": quarantine_id,
            "policyViolation": True,
        }

    def handle_tools_call(
        self, params: Any, arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Dispatches tool execution with closed-loop security enforcement, budget degradation, and shadow audit."""
        if isinstance(params, str):
            params = {"name": params, "arguments": arguments if isinstance(arguments, dict) else {}}
        elif not isinstance(params, dict):
            params = {}
        tool_name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}

        session_id = (
            arguments.get("session_id")
            or params.get("session_id")
            or self.session_id
        )
        if not session_id or not re.match(r"^SES-[A-Za-z0-9_-]{4,64}$", str(session_id)):
            from ctxfw.kernel.contracts import new_session_id

            self.session_id = new_session_id()
            session_id = self.session_id

        raw_user_prompt = (
            arguments.get("user_prompt")
            or arguments.get("prompt")
            or f"MCP tool call: {tool_name}"
        )
        user_prompt = (
            str(raw_user_prompt)
            .encode("utf-8", errors="replace")
            .decode("utf-8")[:65536]
        )
        if not user_prompt.strip():
            user_prompt = f"MCP tool call: {tool_name}"

        # 1. Closed-Loop Security Pre-Execution Interception
        from ctxfw.rules.enforcer import RulesEnforcer, normalize_path
        from ctxfw.rules.contracts import EnforcementVerdict

        # 1a. Extract candidate paths to validate against traversal
        candidate_paths: list[tuple[str, str]] = []
        for p_key in ("path", "target_file", "project_root"):
            val = arguments.get(p_key)
            if val is not None and isinstance(val, str) and val.strip():
                candidate_paths.append((p_key, val.strip()))

        traversal_violation: Optional[str] = None
        offending_path: Optional[str] = None
        for p_key, p_val in candidate_paths:
            try:
                normalize_path(p_val)
            except ValueError as exc:
                traversal_violation = f"Path traversal attempt or invalid encoding detected in argument '{p_key}': {p_val} ({exc})"
                offending_path = p_val
                break

        blocked_reason: Optional[str] = None
        rule_store = self._get_rules_store()

        if traversal_violation:
            blocked_reason = traversal_violation
            self._enforce_seq += 1
            sys_guard = rule_store.ensure_system_guard()
            eval_guards = (sys_guard,) + tuple(self._get_active_guards())
            offending_call = (
                f"{tool_name} {offending_path or ''}"
                .encode("utf-8", errors="replace")
                .decode("utf-8")
                .strip()
            )
            try:
                rule_store.enforce_and_log(
                    eval_guards,
                    offending_call,
                    seq=self._enforce_seq,
                )
            except Exception:
                pass
        else:
            # 1b. Check active rule guards against raw tool call
            proj_root_path = None
            if arguments.get("project_root"):
                try:
                    proj_root_path = Path(arguments["project_root"]).resolve()
                except Exception:
                    pass
            elif arguments.get("target_file"):
                try:
                    proj_root_path = Path(arguments["target_file"]).resolve().parent
                except Exception:
                    pass
            elif arguments.get("path"):
                try:
                    proj_root_path = Path(arguments["path"]).resolve().parent
                except Exception:
                    pass

            if proj_root_path is None:
                try:
                    proj_root_path = Path.cwd()
                except Exception:
                    pass

            active_guards = self._get_active_guards(project_root=proj_root_path)
            if active_guards:
                args_repr = " ".join(
                    str(v).encode("utf-8", errors="replace").decode("utf-8")
                    for k, v in arguments.items()
                    if k not in ("diff_text", "patch_diff", "diff", "new_content", "brief_text")
                    and isinstance(v, (str, int, float))
                    and not isinstance(v, bool)
                )
                raw_tool_call = f"{tool_name} {args_repr}".strip()

                self._enforce_seq += 1
                verdict, matched_ids = rule_store.enforce_and_log(
                    active_guards, raw_tool_call, seq=self._enforce_seq
                )
                if verdict is EnforcementVerdict.BLOCKED:
                    blocked_reason = f"Security rule guard violated: {', '.join(matched_ids) if matched_ids else 'policy match'}"

        if blocked_reason:
            try:
                tracekit = self._get_tracekit_store()
                tracekit.record_step(
                    session_id=session_id,
                    user_prompt=str(user_prompt)[:65536],
                    plan_summary=f"Security policy enforcement on {tool_name}",
                    tool_or_file="rules.enforcer",
                    payload=f"SECURITY_VIOLATION: {blocked_reason}",
                )
            except Exception as exc:
                try:
                    sys.stderr.write(f"[TraceKit Security Error] {exc}\n")
                    sys.stderr.flush()
                except Exception:
                    pass

            return ToolResult({
                "content": [
                    {
                        "type": "text",
                        "text": f"POLICY_BLOCKED: Security violation detected by RulesEnforcer: {blocked_reason}",
                    }
                ],
                "isError": True,
                "policyViolation": True,
            })

        result: Dict[str, Any]
        swegate_overlay: Optional[Dict[str, Any]] = None
        try:
            if tool_name in _SWEGATE_TOOLS:
                result = self._enforce_swegate_patch(
                    tool_name=tool_name,
                    arguments=arguments,
                    session_id=session_id,
                    user_prompt=str(user_prompt),
                )
                if (
                    tool_name == "apply_patch"
                    and not result.get("isError")
                    and isinstance(arguments.get("target_file"), str)
                    and arguments["target_file"].strip()
                    and isinstance(arguments.get("new_content"), str)
                ):
                    try:
                        target_p = Path(arguments["target_file"]).resolve()
                        target_p.parent.mkdir(parents=True, exist_ok=True)
                        target_p.write_text(
                            arguments["new_content"], encoding="utf-8", newline="\n"
                        )
                        result["patchApplied"] = True
                    except (OSError, UnicodeError) as io_exc:
                        result["isError"] = True
                        result["patchApplied"] = False
                        result["content"] = [
                            {
                                "type": "text",
                                "text": f"SWE_GATE_APPLY_ERROR: Failed to write target_file: {io_exc}",
                            }
                        ]
                elif tool_name == "apply_patch":
                    result["patchApplied"] = False

            elif tool_name == "prune_file":
                if any(k in arguments for k in ("diff_text", "patch_diff", "diff")):
                    gate_res = self._enforce_swegate_patch(
                        tool_name=tool_name,
                        arguments=arguments,
                        session_id=session_id,
                        user_prompt=str(user_prompt),
                    )
                    if gate_res.get("isError"):
                        return ToolResult(gate_res)
                    swegate_overlay = gate_res

                file_path_str = arguments.get("path")
                if not file_path_str:
                    result = {
                        "content": [{"type": "text", "text": "Parameter 'path' is required."}],
                        "isError": True,
                    }
                else:
                    file_path = Path(file_path_str).resolve()
                    if not file_path.is_file():
                        result = {
                            "content": [{"type": "text", "text": f"File not found: {file_path}"}],
                            "isError": True,
                        }
                    else:
                        from ctxfw.sara.contracts import MAX_RAW_OUTPUT_CHARS

                        try:
                            code = file_path.read_text(encoding="utf-8")
                        except UnicodeDecodeError:
                            code = "\x00<corrupted_utf8_observation>"

                        if len(code) > MAX_RAW_OUTPUT_CHARS or "\x00" in code:
                            result = self._enforce_sara_observation(
                                tool_name="prune_file",
                                output_text=code,
                                raw_sources=(code,),
                                session_id=session_id,
                                user_prompt=str(user_prompt),
                            )
                        else:
                            depth_val = arguments.get("depth", "interface").lower()
                            depth_enum = PruningDepth(depth_val) if depth_val in PruningDepth._value2member_map_ else PruningDepth.INTERFACE
                            strip_docs = bool(arguments.get("strip_docs", False))
                            lang_val = arguments.get("language", "python").lower()
                            lang_enum = SupportedLanguage(lang_val) if lang_val in SupportedLanguage._value2member_map_ else SupportedLanguage.PYTHON

                            cache_key = LocalSemanticCache.generate_key(
                                source_code=code,
                                rules_version=DeterministicContextPruner.RULES_VERSION,
                                strip_docs=strip_docs,
                                depth=depth_enum.value,
                                language=lang_enum.value,
                            )
                            cached = self.cache.get(cache_key)
                            dto: Optional[OptimizationResultDTO] = None
                            if cached is not None:
                                pruned_code = cached.pruned_code
                            else:
                                req = OptimizationRequestDTO(
                                    source_code=code,
                                    language=lang_enum,
                                    strip_docs=strip_docs,
                                    depth=depth_enum,
                                    sanitize_raises=True,
                                )
                                pruned_code, orig_c, pruned_c, saved, pct, ms = DeterministicContextPruner.prune(req)
                                dto = OptimizationResultDTO(
                                    pruned_code=pruned_code,
                                    original_chars=orig_c,
                                    pruned_chars=pruned_c,
                                    estimated_tokens_saved=saved,
                                    savings_percentage=pct,
                                    cache_hit=False,
                                    execution_ms=ms,
                                    depth=depth_enum,
                                )

                            result = self._enforce_sara_observation(
                                tool_name="prune_file",
                                output_text=pruned_code,
                                raw_sources=(code,),
                                session_id=session_id,
                                user_prompt=str(user_prompt),
                            )
                            if dto is not None and not result.get("saraQuarantined"):
                                self.cache.set(cache_key, dto)

            elif tool_name == "resolve_context_bundle":
                if any(k in arguments for k in ("diff_text", "patch_diff", "diff")):
                    gate_res = self._enforce_swegate_patch(
                        tool_name=tool_name,
                        arguments=arguments,
                        session_id=session_id,
                        user_prompt=str(user_prompt),
                    )
                    if gate_res.get("isError"):
                        return ToolResult(gate_res)
                    swegate_overlay = gate_res

                target_file_str = arguments.get("target_file")
                if not target_file_str:
                    result = {
                        "content": [{"type": "text", "text": "Parameter 'target_file' is required."}],
                        "isError": True,
                    }
                else:
                    target_file = Path(target_file_str).resolve()
                    if not target_file.is_file():
                        result = {
                            "content": [{"type": "text", "text": f"Target file not found: {target_file}"}],
                            "isError": True,
                        }
                    else:
                        from ctxfw.sara.contracts import MAX_RAW_OUTPUT_CHARS

                        try:
                            target_raw = target_file.read_text(encoding="utf-8")
                        except UnicodeDecodeError:
                            target_raw = "\x00<corrupted_utf8_observation>"

                        if len(target_raw) > MAX_RAW_OUTPUT_CHARS or "\x00" in target_raw:
                            result = self._enforce_sara_observation(
                                tool_name="resolve_context_bundle",
                                output_text=target_raw,
                                raw_sources=(target_raw,),
                                session_id=session_id,
                                user_prompt=str(user_prompt),
                            )
                        else:
                            project_root_str = arguments.get("project_root")
                            if project_root_str:
                                project_root = Path(project_root_str).resolve()
                            else:
                                project_root = target_file.parent.resolve()

                            firewall = ContextFirewallEngine(project_root=project_root, cache=self.cache)
                            bundle = firewall.build_context(
                                target_file,
                                breaker_state=arguments.get("breaker_state"),
                                session_id=session_id,
                                tokencast_store=self._get_tokencast_store(),
                                tracekit_store=self._get_tracekit_store(),
                            )

                            raw_sources_list: list[str] = [target_raw]
                            candidate_rels = list(bundle.entries.keys())
                            try:
                                for rel_p, dist in firewall.graph.get_distances(target_file).items():
                                    if dist <= 3 and rel_p not in candidate_rels:
                                        candidate_rels.append(rel_p)
                            except Exception:
                                pass

                            for rel_path in candidate_rels:
                                dep_path = (project_root / rel_path).resolve()
                                if dep_path.is_file():
                                    try:
                                        dep_raw = dep_path.read_text(encoding="utf-8")
                                    except UnicodeDecodeError:
                                        dep_raw = "\x00<corrupted_utf8_observation>"
                                    if dep_raw not in raw_sources_list:
                                        raw_sources_list.append(dep_raw)

                            result = self._enforce_sara_observation(
                                tool_name="resolve_context_bundle",
                                output_text=bundle.to_prompt(),
                                raw_sources=tuple(raw_sources_list),
                                session_id=session_id,
                                user_prompt=str(user_prompt),
                            )

            elif tool_name == "evaluate_spec_axioms":
                brief_text = arguments.get("brief_text")
                if brief_text is None:
                    result = {
                        "content": [{"type": "text", "text": "Parameter 'brief_text' is required."}],
                        "isError": True,
                    }
                else:
                    from ctxfw.sieve.engine import evaluate_specification

                    res = evaluate_specification(str(brief_text))
                    payload = {
                        "aci_score": res.aci_score,
                        "negative_invariants_count": res.negative_invariants_count,
                        "extracted_never_clauses": res.extracted_never_clauses,
                        "status": res.status,
                        "remediation_notes": res.remediation_notes,
                        "manifest_hash": res.manifest_hash,
                    }
                    result = {
                        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                        "isError": False,
                    }

            else:
                result = {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True,
                }

        except Exception as exc:
            result = {
                "content": [{"type": "text", "text": f"Tool execution error: {str(exc)}"}],
                "isError": True,
            }

        if swegate_overlay is not None and not result.get("isError"):
            for k in (
                "sweGateRejected",
                "sweGateVerdict",
                "sweGateState",
                "evaluationId",
                "cyclomaticDelta",
                "architecturalViolations",
            ):
                if k in swegate_overlay:
                    result[k] = swegate_overlay[k]

        if not result.get("saraQuarantined") and not result.get("sweGateRecorded"):
            self._record_shadow_audit(params, result)
        return ToolResult(result)

    def dispatch(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single JSON-RPC 2.0 request."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Notifications (no id) do not produce responses
        if method == "notifications/initialized":
            return None

        if method == "initialize":
            result = self.handle_initialize(params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        elif method == "tools/list":
            result = self.handle_tools_list(params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        elif method == "tools/call":
            result = self.handle_tools_call(params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        else:
            if req_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}",
                    },
                }
            return None

    def process_raw_line(self, raw_line: str) -> Optional[str]:
        """Parses and dispatches a single raw line string from stdin."""
        line = raw_line.strip()
        if not line:
            return None

        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("JSON-RPC request must be a JSON object.")
        except Exception as err:
            error_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {str(err)}",
                },
            }
            return json.dumps(error_resp)

        resp = self.dispatch(req)
        if resp is not None:
            return json.dumps(resp)
        return None

    def run_stdio_loop(self):
        """Runs continuous JSON-RPC loop over sys.stdin and sys.stdout."""
        print(f"[{self.SERVER_NAME}] Server listening on stdio (MCP v{self.PROTOCOL_VERSION})", file=sys.stderr, flush=True)

        try:
            while self.running:
                line = sys.stdin.readline()
                if not line:
                    break

                line_stripped = line.strip()
                if not line_stripped:
                    continue

                # Support Content-Length framing (LSP / JSON-RPC framing)
                if line_stripped.lower().startswith("content-length:"):
                    try:
                        content_length = int(line_stripped.split(":", 1)[1].strip())
                        while True:
                            header = sys.stdin.readline()
                            if not header or header.strip() == "":
                                break
                        body = sys.stdin.read(content_length)
                        output = self.process_raw_line(body)
                    except Exception as e:
                        sys.stderr.write(f"Framing error: {e}\n")
                        sys.stderr.flush()
                        continue
                else:
                    # Standard line-delimited JSON-RPC
                    output = self.process_raw_line(line)

                if output:
                    sys.stdout.write(output + "\n")
                    sys.stdout.flush()
        finally:
            if self._tracekit_store is not None:
                try:
                    self._tracekit_store.close()
                except Exception:
                    pass
            if self._rules_store is not None:
                try:
                    self._rules_store.close()
                except Exception:
                    pass
            if self._tokencast_store is not None:
                try:
                    self._tokencast_store.close()
                except Exception:
                    pass
            if self._sara_store is not None:
                try:
                    self._sara_store.close()
                except Exception:
                    pass
            if self._swegate_store is not None:
                try:
                    self._swegate_store.close()
                except Exception:
                    pass


def main():
    server = MCPServer()
    server.run_stdio_loop()


if __name__ == "__main__":
    main()
