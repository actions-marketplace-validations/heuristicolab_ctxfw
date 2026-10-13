# manifest_hash: 11b623b097312b17d33c0ba6b7984b5a1954a133506e93dd813af794b22c0f0f
"""
src/ctxfw/mcp.py — Model Context Protocol (MCP) Server over stdio (v3.4.0)
manifest_hash: 11b623b097312b17d33c0ba6b7984b5a1954a133506e93dd813af794b22c0f0f
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
    ):
        self.running = True
        self.cache = cache or LocalSemanticCache()
        self._tracekit_store = tracekit_store
        self._rules_store = rules_store
        self._tokencast_store = tokencast_store
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
            ]
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

        user_prompt = (
            arguments.get("user_prompt")
            or arguments.get("prompt")
            or f"MCP tool call: {tool_name}"
        )

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
            offending_call = f"{tool_name} {offending_path or ''}".strip()
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
                    str(v)
                    for k, v in arguments.items()
                    if isinstance(v, (str, int, float)) and not isinstance(v, bool)
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
        try:
            if tool_name == "prune_file":
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
                        code = file_path.read_text(encoding="utf-8")
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
                        if cached is not None:
                            result = {
                                "content": [{"type": "text", "text": cached.pruned_code}],
                                "isError": False,
                            }
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
                            self.cache.set(cache_key, dto)

                            result = {
                                "content": [{"type": "text", "text": pruned_code}],
                                "isError": False,
                            }

            elif tool_name == "resolve_context_bundle":
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

                        result = {
                            "content": [{"type": "text", "text": bundle.to_prompt()}],
                            "isError": False,
                        }

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


def main():
    server = MCPServer()
    server.run_stdio_loop()


if __name__ == "__main__":
    main()
