# manifest_hash: 862e0dc20133fe81f2ce12812b86d74068db80cce8566a3b71d2d406db72c549
"""
Claude Rules Compiler :: Normative Clause Extractor
===================================================
Extracts normative clauses from .cursorrules, CLAUDE.md, YAML, and Markdown files.
Strictly rejects files exceeding 256 KB, null bytes, and rule-relaxation bypass attempts.
"""
from __future__ import annotations

import re

from ctxfw.rules.contracts import (
    MAX_FILE_CHARS,
    MAX_RULES_PER_FILE,
    detect_file_format,
)

__all__ = [
    "extract_normative_clauses",
]

_NORMATIVE_RE = re.compile(
    r"\b(do not|don'?t|never|must not|shall not)\b",
    re.IGNORECASE,
)

_RELAX_VERBS = r"(?:ignore|ignored|ignoring|override|overridden|overriding|overrides|disable|disabled|disabling|disables|bypass|bypassed|bypassing|bypasses|relax|relaxed|relaxing|relaxes)"
_RELAX_NOUNS = r"(?:deny|guard|rule|restriction|permission)s?"

_RELAX_RE = re.compile(
    rf"(\b{_RELAX_VERBS}\b.*?\b{_RELAX_NOUNS}\b|\b{_RELAX_NOUNS}\b.*?\b{_RELAX_VERBS}\b)",
    re.IGNORECASE | re.DOTALL,
)


def _prepare_clauses(text: str) -> list[tuple[int, str]]:
    """Clean and split text into candidate sentences with their 1-indexed line numbers."""
    in_code_block = False
    clauses: list[tuple[int, str]] = []

    for line_idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()

        # Ignore markdown code blocks
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue

        # Ignore empty lines and comment lines
        if not stripped or stripped.startswith("#"):
            continue

        # Clean bullets, quotes, and YAML keys/delimiters
        cleaned = stripped
        cleaned = re.sub(r"^[-*+>]\s+", "", cleaned)
        cleaned = re.sub(r"^\d+\.\s+", "", cleaned)
        cleaned = re.sub(r"^[a-zA-Z0-9_-]+\s*:\s*", "", cleaned)
        cleaned = cleaned.strip("{}[],\"'").strip()

        if not cleaned:
            continue

        # Split into sentences on sentence terminators while preserving line association.
        # Uses punctuation followed by whitespace and an uppercase letter, or semicolons,
        # to avoid incorrectly splitting on file extensions (.py, .env) or abbreviations.
        sentences = [s.strip() for s in re.split(r"(?<=\.)\s+(?=[A-Z])|(?<=;)\s+", cleaned) if s.strip()]
        for sentence in sentences:
            if _NORMATIVE_RE.search(sentence):
                # Clean trailing period if not part of an ellipsis or extension
                norm_sentence = sentence.rstrip(".") if sentence.endswith(".") and not sentence.endswith("..") else sentence
                if norm_sentence:
                    clauses.append((line_idx, norm_sentence))

    return clauses


def extract_normative_clauses(file_path: str, text: str) -> list[tuple[int, str]]:
    """Extract normative clauses from rules text.

    Raises:
      ValueError: If text > 256 KB, contains null bytes, attempts rule relaxation,
                  has an unsupported format, or exceeds MAX_RULES_PER_FILE clauses.
    """
    if len(text) > MAX_FILE_CHARS:
        raise ValueError(f"text exceeds maximum allowed length of {MAX_FILE_CHARS} characters")

    if "\x00" in text:
        raise ValueError("null characters are strictly forbidden in rule source text")

    # Detect format (fails-closed with ValueError on unknown format)
    detect_file_format(file_path)

    # Check for adversarial rule relaxation / evasion attempts
    if _RELAX_RE.search(text):
        raise ValueError("rule relaxation or bypass attempt detected (evasion prohibited)")

    clauses = _prepare_clauses(text)

    if len(clauses) > MAX_RULES_PER_FILE:
        raise ValueError(
            f"extracted clauses ({len(clauses)}) exceed maximum limit of {MAX_RULES_PER_FILE} per file"
        )

    return clauses
