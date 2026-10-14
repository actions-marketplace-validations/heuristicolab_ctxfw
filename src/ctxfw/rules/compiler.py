# manifest_hash: 862e0dc20133fe81f2ce12812b86d74068db80cce8566a3b71d2d406db72c549
"""
Claude Rules Compiler :: Deterministic Rules Compiler Engine
============================================================
Compiles natural language normative directives into deterministic AST/command/path guards.
Enforces total FSM state progression and deduplication.
"""
from __future__ import annotations

import re
from typing import Sequence

from ctxfw.rules.contracts import (
    INTENT_TO_PATTERN,
    CompiledAstGuardDTO,
    CompiledRuleManifestDTO,
    CompilerEvent,
    CompilerState,
    NaturalLanguageRuleDTO,
    PatternType,
    RuleIntent,
    RuleSourceFileDTO,
    derive_guard_id,
    derive_manifest_id,
    derive_rule_id,
    detect_file_format,
    sha256_hex,
    transition,
)
from ctxfw.rules.extractor import extract_normative_clauses

__all__ = ["RulesCompiler"]

_CONDITIONAL_RE = re.compile(
    r"\b(unless|except|only when|only if|provided that|if and only if)\b",
    re.IGNORECASE,
)

_KNOWN_BINARIES = (
    "rm",
    "git",
    "sudo",
    "curl",
    "bash",
    "sh",
    "python",
    "python3",
    "pip",
    "npm",
    "yarn",
    "pnpm",
    "docker",
    "kubectl",
    "wget",
    "kill",
    "chmod",
    "chown",
    "dd",
)

_STOPWORDS = frozenset(
    {"this", "any", "all", "the", "that", "a", "an", "it", "to", "in", "or", "and", "some"}
)


def _clean_path(path_str: str) -> str:
    norm = path_str.strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.rstrip("/")


def _classify_backtick(content: str) -> tuple[RuleIntent, str] | None:
    """Classify backticked expression into (RuleIntent, target)."""
    parts = content.split()
    if not parts:
        return None
    first = parts[0].lower()
    first_base = first.split("/")[-1]

    # If it starts with a known binary or has command flags, it's a command
    if first in _KNOWN_BINARIES or first_base in _KNOWN_BINARIES or any(p.startswith("-") for p in parts):
        cmd_m = re.search(
            r"^(rm(?:\s+-[a-zA-Z]+)?|git(?:\s+[a-z]+(?:\s+--[a-z]+)?)?|sudo|curl|bash|sh|python\d*|pip|npm|yarn|docker|kubectl|wget|kill|chmod|chown|dd)",
            content,
            re.IGNORECASE,
        )
        if cmd_m:
            return RuleIntent.COMMAND_DENY, cmd_m.group(1).strip()
        if len(parts) >= 2 and parts[1].startswith("-"):
            return RuleIntent.COMMAND_DENY, f"{parts[0]} {parts[1]}"
        return RuleIntent.COMMAND_DENY, parts[0]

    # Path with slash, backslash, known extension, or hidden file
    if "/" in content or "\\" in content or _has_file_extension(content):
        norm_content = _clean_path(content)
        if norm_content and not _is_wildcard(norm_content) and ".." not in norm_content.split("/"):
            return RuleIntent.PATH_DENY, norm_content

    # Default fallback for single-word / non-path backtick is command
    if not _is_wildcard(content):
        return RuleIntent.COMMAND_DENY, content

    return None


def _classify(directive: str) -> tuple[RuleIntent, str] | None:
    """Deterministically classify a directive into (RuleIntent, target) or None."""
    # 1. Conditionals are unenforceable deterministically -> None
    if _CONDITIONAL_RE.search(directive):
        return None

    # 2. Lexical AST calls (raw sql -> raw_query, eval, exec, os.system, pickle.loads)
    if re.search(r"\braw\s+sql\b", directive, re.IGNORECASE):
        return RuleIntent.AST_DENY, "raw_query"
    if re.search(r"\bos\.system\b", directive):
        return RuleIntent.AST_DENY, "os.system"
    if re.search(r"\bpickle\.loads\b", directive):
        return RuleIntent.AST_DENY, "pickle.loads"
    eval_m = re.search(r"\b(eval|exec)\b", directive)
    if eval_m:
        return RuleIntent.AST_DENY, eval_m.group(1)

    # Backticked AST call like `dangerous_sink()`
    paren_call_m = re.search(r"`([a-zA-Z0-9_\.]+)\(\)`", directive)
    if paren_call_m:
        sym = paren_call_m.group(1).strip()
        if sym and not _is_wildcard(sym):
            return RuleIntent.AST_DENY, sym

    # 3. Import deny (import <module> / from <module>)
    import_m = re.search(r"\b(?:import|from)\s+`?([a-zA-Z0-9_\.]+)`?", directive, re.IGNORECASE)
    if import_m:
        mod = import_m.group(1).strip()
        if mod.lower() not in _STOPWORDS and not _is_wildcard(mod):
            return RuleIntent.IMPORT_DENY, mod

    # 4. Check for backticked targets: `target`
    backtick_match = re.search(r"`([^`]+)`", directive)
    if backtick_match:
        bt_classified = _classify_backtick(backtick_match.group(1).strip())
        if bt_classified is not None:
            return bt_classified

    # 5. Command deny (known binaries: rm, git, sudo, curl, bash, etc.)
    cmd_m = re.search(
        r"\b(rm(?:\s+-[a-zA-Z]+)?|git(?:\s+[a-z]+(?:\s+--[a-z]+)?)?|sudo|curl|bash|sh|python\d*|pip|npm|yarn|docker|kubectl|wget|kill|chmod|chown|dd)\b",
        directive,
        re.IGNORECASE,
    )
    if cmd_m:
        cmd_target = cmd_m.group(1).strip()
        if not _is_wildcard(cmd_target):
            return RuleIntent.COMMAND_DENY, cmd_target

    # 6. Path deny (paths with / or known file extensions / hidden .env)
    path_m = re.search(
        r"(\.env[a-zA-Z0-9_.-]*|[a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+|[a-zA-Z0-9_.-]+\.(?:env|pem|key|py|json|yaml|yml|toml|secret|conf))\b",
        directive,
        re.IGNORECASE,
    )
    if path_m:
        target_path = _clean_path(path_m.group(1).strip())
        if target_path and not _is_wildcard(target_path) and ".." not in target_path.split("/"):
            return RuleIntent.PATH_DENY, target_path

    return None


def _is_wildcard(s: str) -> bool:
    return s in ("*", "**", "/", ".", "\\")


def _has_file_extension(s: str) -> bool:
    return any(
        s.endswith(ext)
        for ext in (
            ".env",
            ".pem",
            ".key",
            ".py",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".secret",
            ".conf",
            ".txt",
        )
    ) or s.startswith(".env")


def _tentative_intent(directive: str) -> RuleIntent:
    """Best-effort rule intent for unenforceable natural language rules."""
    lowered = directive.lower()
    if "import" in lowered:
        return RuleIntent.IMPORT_DENY
    if any(b in lowered for b in _KNOWN_BINARIES):
        return RuleIntent.COMMAND_DENY
    if "/" in lowered or ".env" in lowered:
        return RuleIntent.PATH_DENY
    if any(k in lowered for k in ("eval", "exec", "sql", "call")):
        return RuleIntent.AST_DENY
    return RuleIntent.COMMAND_DENY


class RulesCompiler:
    """Compiles rules files into deterministic AST guards with complete FSM trace."""

    @classmethod
    def compile_text(
        cls,
        file_path: str,
        text: str,
    ) -> tuple[CompiledRuleManifestDTO | None, tuple[NaturalLanguageRuleDTO, ...], list[CompilerState]]:
        """Compile rules file text into manifest, rules, and FSM transition trace."""
        state = CompilerState.RECEIVED
        trace: list[CompilerState] = [state]

        try:
            file_format = detect_file_format(file_path)
            clauses = extract_normative_clauses(file_path, text)
        except ValueError:
            state = transition(state, CompilerEvent.VALIDATION_FAIL)
            trace.append(state)
            return None, (), trace

        state = transition(state, CompilerEvent.PARSE_OK)
        trace.append(state)

        source = RuleSourceFileDTO(
            file_path=file_path,
            file_format=file_format,
            sha256=sha256_hex(text),
        )

        if not clauses:
            state = transition(state, CompilerEvent.NO_CLAUSES)
            trace.append(state)
            manifest = CompiledRuleManifestDTO(
                manifest_id=derive_manifest_id(file_path, source.sha256),
                source=source,
                guards=(),
                unenforceable_rule_ids=(),
                compiled_rules_count=0,
            )
            return manifest, (), trace

        state = transition(state, CompilerEvent.CLAUSES_FOUND)
        trace.append(state)

        all_rules: list[NaturalLanguageRuleDTO] = []
        guards: list[CompiledAstGuardDTO] = []
        unenforceable_ids: list[str] = []
        seen_targets: set[tuple[PatternType, str]] = set()

        for line_no, directive in clauses:
            rule_id = derive_rule_id(file_path, line_no, directive)
            classified = _classify(directive)

            if classified is None:
                unenforceable_ids.append(rule_id)
                rule = NaturalLanguageRuleDTO(
                    rule_id=rule_id,
                    raw_directive=directive,
                    rule_intent=_tentative_intent(directive),
                    line_number=line_no,
                )
                all_rules.append(rule)
            else:
                intent, target = classified
                pattern_type = INTENT_TO_PATTERN[intent]
                dedup_key = (pattern_type, target)

                if dedup_key not in seen_targets:
                    seen_targets.add(dedup_key)
                    guard_id = derive_guard_id(rule_id)
                    guard = CompiledAstGuardDTO(
                        guard_id=guard_id,
                        rule_id=rule_id,
                        pattern_type=pattern_type,
                        target_symbol_or_path=target,
                        is_strict_deny=True,
                    )
                    guards.append(guard)

                rule = NaturalLanguageRuleDTO(
                    rule_id=rule_id,
                    raw_directive=directive,
                    rule_intent=intent,
                    line_number=line_no,
                )
                all_rules.append(rule)

        if guards and not unenforceable_ids:
            state = transition(state, CompilerEvent.COMPILE_OK)
        else:
            state = transition(state, CompilerEvent.COMPILE_PARTIAL)
        trace.append(state)

        state = transition(state, CompilerEvent.EMIT_OK)
        trace.append(state)

        manifest = CompiledRuleManifestDTO(
            manifest_id=derive_manifest_id(file_path, source.sha256),
            source=source,
            guards=tuple(guards),
            unenforceable_rule_ids=tuple(unenforceable_ids),
            compiled_rules_count=len(guards),
        )

        return manifest, tuple(all_rules), trace
