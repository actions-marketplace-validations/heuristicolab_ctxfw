"""
Claude Rules Compiler :: Contratos Inmutables Pydantic v2.
Signal: SIG-1d0a63f087edb904 | Proposal: PROP-1d0a63f087edb904-H2
ctxfw manifest_hash: b5b8e1cd10ce8beeed6b076f4726d19b361a6ce2f5d480c2bb2aa437986822d3
Protocol: CTXFW Axiomatic Gateway (status: VERIFIED, ACI: 1.0000)

Garantias:
  - Todos los DTOs: frozen=True, extra="forbid", str_strip_whitespace=True, validate_default=True.
  - INV-01: todo guard compilado es deny estricto; no existe constructor de reglas allow.
  - INV-06: targets comodin-only ('*', '**', '/', '.') jamas se aceptan (sin guards deny-all).
  - INV-09: compiled_rules_count siempre coincide con len(guards) del manifiesto.
  - FSM de dos etapas, total y determinista: transition(S, E), terminales EMITTED / REJECTED_INVALID.
"""
import hashlib
import re
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Cotas globales (fuente unica de verdad para contratos, DDL y pruebas)
# ---------------------------------------------------------------------------
MAX_FILE_CHARS = 262144
MAX_FILE_PATH_CHARS = 512
MAX_DIRECTIVE_CHARS = 1024
MAX_TARGET_CHARS = 256
MAX_RULES_PER_FILE = 256
MAX_LINE_NUMBER = 65536
MAX_TOOL_CALL_CHARS = 4096
COMPILE_LATENCY_BUDGET_MS = 2.0

FILE_PATH_PATTERN = r"^[^\x00]{1,512}$"
SHA256_PATTERN = r"^[a-f0-9]{64}$"
RULE_ID_PATTERN = r"^RULE-[A-Za-z0-9_-]{4,64}$"
GUARD_ID_PATTERN = r"^GRD-[A-Za-z0-9_-]{4,64}$"
MANIFEST_ID_PATTERN = r"^MNF-[A-Za-z0-9_-]{4,64}$"
LOG_ID_PATTERN = r"^LOG-[A-Za-z0-9_-]{4,64}$"

_WILDCARD_ONLY_RE = re.compile(r"^[*/.\\]+$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Enumeraciones canonicas
# ---------------------------------------------------------------------------
class FileFormat(str, Enum):
    MARKDOWN = "MARKDOWN"
    CURSORRULES = "CURSORRULES"
    YAML = "YAML"


class RuleIntent(str, Enum):
    PATH_DENY = "PATH_DENY"
    COMMAND_DENY = "COMMAND_DENY"
    AST_DENY = "AST_DENY"
    IMPORT_DENY = "IMPORT_DENY"


class PatternType(str, Enum):
    PATH_PREFIX = "PATH_PREFIX"
    COMMAND_PREFIX = "COMMAND_PREFIX"
    AST_CALL = "AST_CALL"
    IMPORT_MODULE = "IMPORT_MODULE"


class EnforcementVerdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCKED = "BLOCKED"


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DETERMINISTIC = "DETERMINISTIC"
    BUSINESS = "BUSINESS"
    SECURITY = "SECURITY"


INTENT_TO_PATTERN: Mapping[RuleIntent, PatternType] = MappingProxyType(
    {
        RuleIntent.PATH_DENY: PatternType.PATH_PREFIX,
        RuleIntent.COMMAND_DENY: PatternType.COMMAND_PREFIX,
        RuleIntent.AST_DENY: PatternType.AST_CALL,
        RuleIntent.IMPORT_DENY: PatternType.IMPORT_MODULE,
    }
)
PATTERN_TO_INTENT: Mapping[PatternType, RuleIntent] = MappingProxyType(
    {pattern: intent for intent, pattern in INTENT_TO_PATTERN.items()}
)


# ---------------------------------------------------------------------------
# FSM determinista total de dos etapas: delta(S, E) -> S'
# ---------------------------------------------------------------------------
class CompilerState(str, Enum):
    RECEIVED = "RECEIVED"
    PARSED = "PARSED"
    EXTRACTED = "EXTRACTED"
    COMPILED = "COMPILED"
    COMPILED_PARTIAL = "COMPILED_PARTIAL"
    EMITTED = "EMITTED"
    REJECTED_INVALID = "REJECTED_INVALID"


class CompilerEvent(str, Enum):
    PARSE_OK = "PARSE_OK"
    VALIDATION_FAIL = "VALIDATION_FAIL"
    CLAUSES_FOUND = "CLAUSES_FOUND"
    NO_CLAUSES = "NO_CLAUSES"
    PARSE_FAIL = "PARSE_FAIL"
    COMPILE_OK = "COMPILE_OK"
    COMPILE_PARTIAL = "COMPILE_PARTIAL"
    COMPILE_FAIL = "COMPILE_FAIL"
    EMIT_OK = "EMIT_OK"
    WAL_RETRY_EXHAUSTED = "WAL_RETRY_EXHAUSTED"


TERMINAL_STATES = frozenset({CompilerState.EMITTED, CompilerState.REJECTED_INVALID})

COMPILER_TRANSITIONS: Mapping[Tuple[CompilerState, CompilerEvent], CompilerState] = MappingProxyType(
    {
        (CompilerState.RECEIVED, CompilerEvent.PARSE_OK): CompilerState.PARSED,
        (CompilerState.RECEIVED, CompilerEvent.VALIDATION_FAIL): CompilerState.REJECTED_INVALID,
        (CompilerState.PARSED, CompilerEvent.CLAUSES_FOUND): CompilerState.EXTRACTED,
        (CompilerState.PARSED, CompilerEvent.NO_CLAUSES): CompilerState.EMITTED,
        (CompilerState.PARSED, CompilerEvent.PARSE_FAIL): CompilerState.REJECTED_INVALID,
        (CompilerState.EXTRACTED, CompilerEvent.COMPILE_OK): CompilerState.COMPILED,
        (CompilerState.EXTRACTED, CompilerEvent.COMPILE_PARTIAL): CompilerState.COMPILED_PARTIAL,
        (CompilerState.EXTRACTED, CompilerEvent.COMPILE_FAIL): CompilerState.REJECTED_INVALID,
        (CompilerState.COMPILED, CompilerEvent.EMIT_OK): CompilerState.EMITTED,
        (CompilerState.COMPILED_PARTIAL, CompilerEvent.EMIT_OK): CompilerState.EMITTED,
        (CompilerState.COMPILED, CompilerEvent.WAL_RETRY_EXHAUSTED): CompilerState.REJECTED_INVALID,
        (CompilerState.COMPILED_PARTIAL, CompilerEvent.WAL_RETRY_EXHAUSTED): CompilerState.REJECTED_INVALID,
    }
)

# Taxonomia de fallos: clase -> enrutamiento fail-closed.
FAILURE_ROUTING: Mapping[FailureClass, str] = MappingProxyType(
    {
        FailureClass.TRANSIENT: "RETRY_MAX_3_THEN_REJECTED_INVALID",
        FailureClass.DETERMINISTIC: "REJECTED_INVALID",
        FailureClass.BUSINESS: "UNENFORCEABLE_REPORT_COMPILED_PARTIAL",
        FailureClass.SECURITY: "BLOCKED_OR_REJECTED_INVALID",
    }
)


def transition(state: CompilerState, event: CompilerEvent) -> CompilerState:
    """delta(S, E): funcion total; todo par indefinido colapsa a REJECTED_INVALID."""
    return COMPILER_TRANSITIONS.get((state, event), CompilerState.REJECTED_INVALID)


# ---------------------------------------------------------------------------
# Funciones puras deterministas (identificadores y digests)
# ---------------------------------------------------------------------------
def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def detect_file_format(file_path: str) -> FileFormat:
    """Infiere el formato por nombre; desconocido => ValueError (DETERMINISTIC, fail-closed)."""
    name = file_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".cursorrules") or name == ".cursorrules":
        return FileFormat.CURSORRULES
    if name.endswith((".yaml", ".yml")):
        return FileFormat.YAML
    if name.endswith((".md", ".markdown")):
        return FileFormat.MARKDOWN
    raise ValueError("unknown rules file format: " + name)


def derive_rule_id(file_path: str, line_number: int, raw_directive: str) -> str:
    return "RULE-" + sha256_hex(f"{file_path}:{line_number}:{raw_directive}")[:16]


def derive_guard_id(rule_id: str) -> str:
    return "GRD-" + sha256_hex(rule_id)[:16]


def derive_manifest_id(file_path: str, file_sha256: str) -> str:
    return "MNF-" + sha256_hex(f"{file_path}:{file_sha256}")[:16]


def audit_digest(file_scanned: str, violations: Tuple[str, ...]) -> str:
    """SHA-256 del registro canonico: ruta + violaciones ordenadas, una por linea."""
    return sha256_hex("\n".join([file_scanned, *sorted(violations)]))


# ---------------------------------------------------------------------------
# Base inmutable
# ---------------------------------------------------------------------------
class RulesBaseDTO(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


# ---------------------------------------------------------------------------
# DTOs canonicos
# ---------------------------------------------------------------------------
class RuleSourceFileDTO(RulesBaseDTO):
    """Archivo de origen de reglas (CLAUDE.md, .cursorrules o YAML) con su digest."""

    file_path: str = Field(..., min_length=1, max_length=MAX_FILE_PATH_CHARS, pattern=FILE_PATH_PATTERN)
    file_format: FileFormat
    sha256: str = Field(..., min_length=64, max_length=64, pattern=SHA256_PATTERN)


class NaturalLanguageRuleDTO(RulesBaseDTO):
    """Clausula normativa extraida del lenguaje natural y clasificada por intencion."""

    rule_id: str = Field(..., min_length=9, max_length=69, pattern=RULE_ID_PATTERN)
    raw_directive: str = Field(..., min_length=1, max_length=MAX_DIRECTIVE_CHARS)
    rule_intent: RuleIntent
    line_number: int = Field(..., ge=1, le=MAX_LINE_NUMBER)


class CompiledAstGuardDTO(RulesBaseDTO):
    """Guard determinista compilado: siempre deny estricto (INV-01), nunca comodin (INV-06)."""

    guard_id: str = Field(..., min_length=8, max_length=68, pattern=GUARD_ID_PATTERN)
    rule_id: str = Field(..., min_length=9, max_length=69, pattern=RULE_ID_PATTERN)
    pattern_type: PatternType
    target_symbol_or_path: str = Field(..., min_length=1, max_length=MAX_TARGET_CHARS)
    is_strict_deny: bool = True

    @field_validator("is_strict_deny")
    @classmethod
    def require_strict_deny(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("a compiled guard shall never be a non-strict deny")
        return value

    @field_validator("target_symbol_or_path")
    @classmethod
    def reject_wildcard_and_control_chars(cls, value: str) -> str:
        if _WILDCARD_ONLY_RE.match(value):
            raise ValueError("wildcard-only targets shall never be accepted (no deny-all guards)")
        if _CONTROL_CHARS_RE.search(value):
            raise ValueError("target shall never contain control characters")
        return value

    @model_validator(mode="after")
    def reject_traversal_in_path_targets(self) -> "CompiledAstGuardDTO":
        if self.pattern_type is PatternType.PATH_PREFIX:
            if ".." in self.target_symbol_or_path.replace("\\", "/").split("/"):
                raise ValueError("path targets shall never contain traversal segments")
        return self

    @property
    def rule_intent(self) -> RuleIntent:
        return PATTERN_TO_INTENT[self.pattern_type]


class RuleComplianceAuditDTO(RulesBaseDTO):
    """Resultado de auditar un archivo contra los guards compilados."""

    file_scanned: str = Field(..., min_length=1, max_length=MAX_FILE_PATH_CHARS, pattern=FILE_PATH_PATTERN)
    violations_detected: Tuple[str, ...] = Field(default=(), max_length=MAX_RULES_PER_FILE)
    is_compliant: bool
    audit_sha256: str = Field(..., min_length=64, max_length=64, pattern=SHA256_PATTERN)

    @field_validator("violations_detected")
    @classmethod
    def validate_violation_ids(cls, items: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(set(items)) != len(items):
            raise ValueError("duplicate violations shall never be reported")
        for item in items:
            if re.match(GUARD_ID_PATTERN, item) is None:
                raise ValueError("violations must be referenced by guard_id")
        return items

    @model_validator(mode="after")
    def verify_consistency_and_digest(self) -> "RuleComplianceAuditDTO":
        if self.is_compliant != (len(self.violations_detected) == 0):
            raise ValueError("is_compliant must hold if and only if there are no violations")
        if audit_digest(self.file_scanned, self.violations_detected) != self.audit_sha256:
            raise ValueError("audit_sha256 does not match the canonical audit record")
        return self

    @classmethod
    def build(cls, file_scanned: str, violations: Tuple[str, ...]) -> "RuleComplianceAuditDTO":
        ordered = tuple(sorted(violations))
        return cls(
            file_scanned=file_scanned,
            violations_detected=ordered,
            is_compliant=len(ordered) == 0,
            audit_sha256=audit_digest(file_scanned.strip(), ordered),
        )


class CompiledRuleManifestDTO(RulesBaseDTO):
    """Manifiesto compilado: guards emitidos y clausulas no ejecutables reportadas (INV-04, INV-09)."""

    manifest_id: str = Field(..., min_length=8, max_length=68, pattern=MANIFEST_ID_PATTERN)
    source: RuleSourceFileDTO
    guards: Tuple[CompiledAstGuardDTO, ...] = Field(default=(), max_length=MAX_RULES_PER_FILE)
    unenforceable_rule_ids: Tuple[str, ...] = Field(default=(), max_length=MAX_RULES_PER_FILE)
    compiled_rules_count: int = Field(..., ge=0, le=MAX_RULES_PER_FILE)

    @field_validator("unenforceable_rule_ids")
    @classmethod
    def validate_unenforceable_ids(cls, items: Tuple[str, ...]) -> Tuple[str, ...]:
        for item in items:
            if re.match(RULE_ID_PATTERN, item) is None:
                raise ValueError("unenforceable ids must match the rule_id pattern")
        return items

    @model_validator(mode="after")
    def verify_manifest_consistency(self) -> "CompiledRuleManifestDTO":
        if self.compiled_rules_count != len(self.guards):
            raise ValueError("compiled_rules_count must equal the number of emitted guards")
        guard_ids = [g.guard_id for g in self.guards]
        if len(set(guard_ids)) != len(guard_ids):
            raise ValueError("duplicate guard_id values shall never be emitted")
        enforced = {g.rule_id for g in self.guards}
        if enforced & set(self.unenforceable_rule_ids):
            raise ValueError("a rule shall never be both enforced and unenforceable")
        if len(self.guards) + len(self.unenforceable_rule_ids) > MAX_RULES_PER_FILE:
            raise ValueError("clauses per file exceed 256")
        return self
