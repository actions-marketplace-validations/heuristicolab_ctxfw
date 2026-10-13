# manifest_hash: ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
"""
SWE-Gate Deterministic Lexical Diff & Complexity Inspector (M4-P2)
==================================================================
Signal   : SIG-673052a2a791ec2b
Proposal : PROP-673052a2a791ec2b-H1
Horizon  : HORIZON_1
M4-P2 manifest_hash:
    ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
Sealed blueprint manifest_hash (VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f
Subagent attestation manifest_hash (VERIFIED, ACI 1.0000):
    b043387c0db2235d6cd63145a1def598a6975ead7d2cd4c9560928b9c14a0145

Purely lexical unified-diff parser, cyclomatic complexity delta counter,
type-suppression detector, and disallowed-import scanner.
Zero dynamic execution, zero syntax-tree compilation, zero clock/randomness/IO.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .contracts import (
    DIFF_LINES_MAX,
    VIOLATIONS_MAX,
    ArchitecturalConstraintRuleDTO,
    PatchMetadataDTO,
    ViolationType,
    format_violation,
)

__all__ = [
    "ReferenceInspector",
    "SweGateInspector",
    "count_decisions",
    "extract_imports",
    "inspect_patch",
    "parse_diff",
]

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DECISION_RE = re.compile(r"\b(if|elif|for|while|except|and|or)\b")
_CASE_RE = re.compile(r"^\s*case\b.*:\s*$")
_TYPE_IGNORE_RE = re.compile(r"#\s*type\s*:\s*ignore\b")
_FROM_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\b")
_IMPORT_RE = re.compile(r"^\s*import\s+(.+)$")
_MODNAME_RE = re.compile(r"^([A-Za-z_][\w.]*)")
_DYNAMIC_RE = re.compile(
    r'(?:importlib\.import_module|__import__)\(\s*["\']([A-Za-z_][\w.]*)["\']\s*\)'
)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_HEADER_PREFIXES = (
    "diff ",
    "index ",
    "new file mode",
    "deleted file mode",
    "old mode",
    "new mode",
    "similarity index",
    "rename from",
    "rename to",
    "copy from",
    "copy to",
    "Binary files",
)


def _code_portion(text: str) -> str:
    """Text without single-line string literals and without trailing comment."""
    if '"' not in text and "'" not in text and "#" not in text:
        return text
    return _STRING_RE.sub("", text).split("#", 1)[0]


def _clean_path(raw: str) -> str:
    path = raw.split("\t")[0].strip()
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    return path


class SweGateInspector:
    """Deterministic lexical unified-diff parser and architectural constraint inspector."""

    @staticmethod
    def parse(
        diff_text: str,
    ) -> List[Tuple[str, List[Tuple[int, str]], List[Tuple[int, str]]]]:
        """Parse a unified diff into (path, added_lines, removed_lines) tuples."""
        if not isinstance(diff_text, str):
            raise ValueError("DIFF_MALFORMED")
        if diff_text.strip() == "":
            raise ValueError("DIFF_EMPTY")
        lines = diff_text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if len(lines) > DIFF_LINES_MAX:
            raise ValueError("DIFF_MALFORMED")

        files: List[Tuple[str, List[Tuple[int, str]], List[Tuple[int, str]]]] = []
        current: Optional[Tuple[str, List[Tuple[int, str]], List[Tuple[int, str]]]] = None
        old_path: Optional[str] = None
        hunks = 0
        i = 0
        while i < len(lines):
            line = lines[i]
            m = _HUNK_RE.match(line)
            if m:
                if current is None:
                    raise ValueError("DIFF_MALFORMED")
                hunks += 1
                old_no = int(m.group(1))
                old_left = int(m.group(2)) if m.group(2) is not None else 1
                new_no = int(m.group(3))
                new_left = int(m.group(4)) if m.group(4) is not None else 1
                i += 1
                while old_left > 0 or new_left > 0:
                    if i >= len(lines):
                        raise ValueError("DIFF_MALFORMED")
                    body = lines[i]
                    tag = body[:1]
                    if tag == "\\":
                        i += 1
                        continue
                    if tag in (" ", ""):
                        old_left -= 1
                        new_left -= 1
                        old_no += 1
                        new_no += 1
                    elif tag == "-":
                        old_left -= 1
                        current[2].append((old_no, body[1:]))
                        old_no += 1
                    elif tag == "+":
                        new_left -= 1
                        current[1].append((new_no, body[1:]))
                        new_no += 1
                    else:
                        raise ValueError("DIFF_MALFORMED")
                    if old_left < 0 or new_left < 0:
                        raise ValueError("DIFF_MALFORMED")
                    i += 1
                continue
            if line.startswith("--- "):
                old_path = _clean_path(line[4:])
            elif line.startswith("+++ "):
                new_path = _clean_path(line[4:])
                path = old_path if new_path == "/dev/null" else new_path
                if not path or path == "/dev/null":
                    raise ValueError("DIFF_MALFORMED")
                current = (path, [], [])
                files.append(current)
                old_path = None
            elif line.startswith(_HEADER_PREFIXES) or line.startswith("\\"):
                pass
            else:
                raise ValueError("DIFF_MALFORMED")
            i += 1

        if hunks == 0:
            raise ValueError("DIFF_MALFORMED")
        return [(f[0], f[1], f[2]) for f in files]

    @staticmethod
    def decisions(text: str) -> int:
        """Count lexical decision points in a single line of Python code."""
        code = _code_portion(text)
        count = len(_DECISION_RE.findall(code))
        if _CASE_RE.match(code):
            count += 1
        return count

    @staticmethod
    def imports(text: str) -> List[str]:
        """Extract imported module names from a single line of Python code."""
        code = _code_portion(text)
        found: List[str] = []
        m_from = _FROM_RE.match(code)
        if m_from:
            mod = m_from.group(1)
            if not mod.startswith("."):
                found.append(mod)
        else:
            m_imp = _IMPORT_RE.match(code)
            if m_imp:
                for part in m_imp.group(1).split(","):
                    m_mod = _MODNAME_RE.match(part.strip())
                    if m_mod:
                        found.append(m_mod.group(1))
        for dynamic in _DYNAMIC_RE.finditer(text):
            found.append(dynamic.group(1))
        return found

    @classmethod
    def inspect(
        cls,
        meta: PatchMetadataDTO,
        rule: ArchitecturalConstraintRuleDTO,
        diff_text: str,
    ) -> Tuple[int, Tuple[str, ...]]:
        """Inspect a unified diff against architectural constraints.

        Returns (cyclomatic_delta, architectural_violations).
        """
        if not isinstance(meta, PatchMetadataDTO) or not isinstance(
            rule, ArchitecturalConstraintRuleDTO
        ):
            raise ValueError("VALIDATION_FAIL")
        if not isinstance(diff_text, str):
            raise ValueError("DIFF_MALFORMED")
        if len(diff_text.encode("utf-8")) != meta.diff_size_bytes:
            raise ValueError("DIFF_SIZE_MISMATCH")

        delta = 0
        type_ignores: List[str] = []
        disallowed: List[str] = []

        for path, added, removed in cls.parse(diff_text):
            if not path.endswith(".py"):
                continue
            for lineno, text in added:
                delta += cls.decisions(text)
                if rule.forbid_type_ignores and _TYPE_IGNORE_RE.search(text):
                    type_ignores.append(
                        format_violation(
                            ViolationType.TYPE_IGNORE, path + ":" + str(lineno)
                        )
                    )
                for module in cls.imports(text):
                    for banned in rule.disallowed_import_modules:
                        if module == banned or module.startswith(banned + "."):
                            disallowed.append(
                                format_violation(
                                    ViolationType.DISALLOWED_IMPORT,
                                    module + "@" + path + ":" + str(lineno),
                                )
                            )
                            break
            for _lineno, text in removed:
                delta -= cls.decisions(text)

        found = type_ignores + disallowed
        if delta > rule.max_cyclomatic_delta:
            found.append(
                format_violation(
                    ViolationType.CYCLOMATIC_DELTA,
                    "total:" + str(delta) + ">" + str(rule.max_cyclomatic_delta),
                )
            )
        unique = list(dict.fromkeys(found))
        return delta, tuple(unique[:VIOLATIONS_MAX])


ReferenceInspector = SweGateInspector
parse_diff = SweGateInspector.parse
count_decisions = SweGateInspector.decisions
extract_imports = SweGateInspector.imports
inspect_patch = SweGateInspector.inspect
