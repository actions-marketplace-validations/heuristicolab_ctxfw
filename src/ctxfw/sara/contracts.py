"""
SARA Runtime Authorization :: Contratos Inmutables Pydantic v2.
Signal: SIG-0d2acf53b92882b0 | Proposal: PROP-0d2acf53b92882b0-H2
ctxfw manifest_hash: 51d819312f8dd802981a7b7d97b9d6397316738ded76c94161a9f147411c94ea
Protocol: CTXFW Axiomatic Gateway (status: VERIFIED, ACI: 1.0000)

Garantias:
  - Todos los DTOs: frozen=True, extra="forbid", str_strip_whitespace=True, validate_default=True.
  - INV-03: ninguna mutacion posterior a la instanciacion; ningun campo no declarado.
  - INV-07: risk_score en el intervalo cerrado [0.0, 1.0]; NaN/Inf rechazados.
  - INV-01/04/05: la observacion jamas porta autoridad; politica default-deny.
  - FSM determinista total delta(S, E) con estados terminales AUDITED / REJECTED_INVALID.
"""
import hashlib
import math
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Cotas globales (fuente unica de verdad para contratos, DDL y pruebas)
# ---------------------------------------------------------------------------
MAX_RAW_OUTPUT_CHARS = 65536
MAX_DIRECTIVES_PER_OBSERVATION = 64
MAX_DIRECTIVE_TEXT_CHARS = 1024
MAX_POLICY_ITEMS = 128
MAX_POLICY_ITEM_CHARS = 256
MAX_POLICY_MASK = 4294967295
RISK_QUARANTINE_THRESHOLD = 0.80
RISK_STRIP_THRESHOLD = 0.30
GATE_LATENCY_BUDGET_MS = 2.0

TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_]{1,63}$"
EXECUTION_ID_PATTERN = r"^EXE-[A-Za-z0-9_-]{8,64}$"
POLICY_ID_PATTERN = r"^POL-[A-Za-z0-9_-]{4,64}$"
SHA256_PATTERN = r"^[a-f0-9]{64}$"


# ---------------------------------------------------------------------------
# Enumeraciones canonicas
# ---------------------------------------------------------------------------
class SourceType(str, Enum):
    LOCAL_STDIO = "LOCAL_STDIO"
    NETWORK_API = "NETWORK_API"
    FILE_READ = "FILE_READ"


class VerdictKind(str, Enum):
    ALLOW = "ALLOW"
    STRIP_COMMANDS = "STRIP_COMMANDS"
    QUARANTINE_TOOL = "QUARANTINE_TOOL"


class DirectiveKind(str, Enum):
    SHELL_COMMAND = "SHELL_COMMAND"
    FILE_PATH_ACCESS = "FILE_PATH_ACCESS"
    ROLE_OVERRIDE = "ROLE_OVERRIDE"
    HIDDEN_ESCAPE = "HIDDEN_ESCAPE"


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DETERMINISTIC = "DETERMINISTIC"
    BUSINESS = "BUSINESS"
    SECURITY = "SECURITY"


# ---------------------------------------------------------------------------
# FSM determinista total: delta(S, E) -> S'
# ---------------------------------------------------------------------------
class SaraState(str, Enum):
    INGRESSED = "INGRESSED"
    SANITIZED = "SANITIZED"
    PARSED = "PARSED"
    AUTHORIZED_ALLOW = "AUTHORIZED_ALLOW"
    AUTHORIZED_STRIPPED = "AUTHORIZED_STRIPPED"
    QUARANTINED = "QUARANTINED"
    REJECTED_INVALID = "REJECTED_INVALID"
    AUDITED = "AUDITED"


class SaraEvent(str, Enum):
    SANITIZE_OK = "SANITIZE_OK"
    VALIDATION_FAIL = "VALIDATION_FAIL"
    PARSE_OK = "PARSE_OK"
    ESCAPE_PATTERN_DETECTED = "ESCAPE_PATTERN_DETECTED"
    PARSE_FAIL = "PARSE_FAIL"
    RISK_LOW = "RISK_LOW"
    RISK_MEDIUM = "RISK_MEDIUM"
    RISK_HIGH = "RISK_HIGH"
    WAL_COMMIT = "WAL_COMMIT"


TERMINAL_STATES = frozenset({SaraState.AUDITED, SaraState.REJECTED_INVALID})

SARA_TRANSITIONS: Mapping[Tuple[SaraState, SaraEvent], SaraState] = MappingProxyType(
    {
        (SaraState.INGRESSED, SaraEvent.SANITIZE_OK): SaraState.SANITIZED,
        (SaraState.INGRESSED, SaraEvent.VALIDATION_FAIL): SaraState.REJECTED_INVALID,
        (SaraState.SANITIZED, SaraEvent.PARSE_OK): SaraState.PARSED,
        (SaraState.SANITIZED, SaraEvent.ESCAPE_PATTERN_DETECTED): SaraState.QUARANTINED,
        (SaraState.SANITIZED, SaraEvent.PARSE_FAIL): SaraState.REJECTED_INVALID,
        (SaraState.PARSED, SaraEvent.RISK_LOW): SaraState.AUTHORIZED_ALLOW,
        (SaraState.PARSED, SaraEvent.RISK_MEDIUM): SaraState.AUTHORIZED_STRIPPED,
        (SaraState.PARSED, SaraEvent.RISK_HIGH): SaraState.QUARANTINED,
        (SaraState.AUTHORIZED_ALLOW, SaraEvent.WAL_COMMIT): SaraState.AUDITED,
        (SaraState.AUTHORIZED_STRIPPED, SaraEvent.WAL_COMMIT): SaraState.AUDITED,
        (SaraState.QUARANTINED, SaraEvent.WAL_COMMIT): SaraState.AUDITED,
    }
)

# Taxonomia de fallos: clase -> estado/veredicto de enrutamiento fail-closed.
FAILURE_ROUTING: Mapping[FailureClass, str] = MappingProxyType(
    {
        FailureClass.TRANSIENT: "RETRY_MAX_3_THEN_QUARANTINE_TOOL",
        FailureClass.DETERMINISTIC: "REJECTED_INVALID",
        FailureClass.BUSINESS: "STRIP_COMMANDS_OR_QUARANTINE_TOOL",
        FailureClass.SECURITY: "QUARANTINE_TOOL",
    }
)


def transition(state: SaraState, event: SaraEvent) -> SaraState:
    """delta(S, E): funcion total; todo par indefinido colapsa a REJECTED_INVALID."""
    return SARA_TRANSITIONS.get((state, event), SaraState.REJECTED_INVALID)


def verdict_for_risk(risk_score: float) -> VerdictKind:
    """Mapeo determinista riesgo -> veredicto (umbrales 0.30 / 0.80)."""
    if risk_score >= RISK_QUARANTINE_THRESHOLD:
        return VerdictKind.QUARANTINE_TOOL
    if risk_score >= RISK_STRIP_THRESHOLD:
        return VerdictKind.STRIP_COMMANDS
    return VerdictKind.ALLOW


def observation_digest(raw_output: str) -> str:
    """SHA-256 hexadecimal en minusculas del UTF-8 de la salida canonica (sin espacios perifericos)."""
    return hashlib.sha256(raw_output.strip().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Base inmutable
# ---------------------------------------------------------------------------
class SaraBaseDTO(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


# ---------------------------------------------------------------------------
# DTOs canonicos
# ---------------------------------------------------------------------------
class ToolExecutionSourceDTO(SaraBaseDTO):
    """Identificador de origen de una observacion de herramienta."""

    tool_name: str = Field(..., min_length=2, max_length=64, pattern=TOOL_NAME_PATTERN)
    source_type: SourceType
    execution_id: str = Field(..., min_length=12, max_length=68, pattern=EXECUTION_ID_PATTERN)


class RawToolObservationDTO(SaraBaseDTO):
    """Salida cruda (no confiable) de la herramienta con timestamp UTC y digest SHA-256."""

    source: ToolExecutionSourceDTO
    raw_output: str = Field(..., min_length=0, max_length=MAX_RAW_OUTPUT_CHARS)
    observed_at: datetime
    observation_sha256: str = Field(..., min_length=64, max_length=64, pattern=SHA256_PATTERN)

    @field_validator("raw_output")
    @classmethod
    def reject_nul_byte(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("raw_output shall never contain a NUL byte")
        return value

    @field_validator("observed_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if offset is None or offset != timedelta(0):
            raise ValueError("observed_at must be timezone-aware UTC")
        return value

    @model_validator(mode="after")
    def verify_digest(self) -> "RawToolObservationDTO":
        if observation_digest(self.raw_output) != self.observation_sha256:
            raise ValueError("observation_sha256 does not match SHA-256(raw_output)")
        return self

    @classmethod
    def from_raw(
        cls,
        source: ToolExecutionSourceDTO,
        raw_output: str,
        observed_at: Optional[datetime] = None,
    ) -> "RawToolObservationDTO":
        """Construye la observacion calculando el digest canonico."""
        return cls(
            source=source,
            raw_output=raw_output,
            observed_at=observed_at or datetime.now(timezone.utc),
            observation_sha256=observation_digest(raw_output),
        )


class InductionDirectiveDTO(SaraBaseDTO):
    """Directiva imperativa detectada dentro de una salida de herramienta (senal de revision)."""

    directive_kind: DirectiveKind
    directive_text: str = Field(..., min_length=1, max_length=MAX_DIRECTIVE_TEXT_CHARS)
    start_offset: int = Field(..., ge=0, le=MAX_RAW_OUTPUT_CHARS)
    end_offset: int = Field(..., ge=0, le=MAX_RAW_OUTPUT_CHARS)
    confidence: float = Field(..., ge=0.0, le=1.0, allow_inf_nan=False)
    within_allowlist: bool = False

    @model_validator(mode="after")
    def verify_span(self) -> "InductionDirectiveDTO":
        if self.end_offset < self.start_offset:
            raise ValueError("end_offset shall never precede start_offset")
        return self


class AuthorizationPolicyRuleDTO(SaraBaseDTO):
    """Regla de autorizacion: lista blanca inmutable de comandos y prefijos de ruta (default-deny)."""

    policy_id: str = Field(..., min_length=8, max_length=68, pattern=POLICY_ID_PATTERN)
    tool_name: str = Field(..., min_length=2, max_length=64, pattern=TOOL_NAME_PATTERN)
    allowed_commands: Tuple[str, ...] = Field(default=(), max_length=MAX_POLICY_ITEMS)
    allowed_path_prefixes: Tuple[str, ...] = Field(default=(), max_length=MAX_POLICY_ITEMS)
    policy_mask: int = Field(..., ge=0, le=MAX_POLICY_MASK)

    @field_validator("allowed_commands", "allowed_path_prefixes")
    @classmethod
    def validate_allowlist_items(cls, items: Tuple[str, ...]) -> Tuple[str, ...]:
        seen = set()
        for item in items:
            if not 1 <= len(item) <= MAX_POLICY_ITEM_CHARS:
                raise ValueError("allowlist item length must be within [1, 256]")
            if item.strip() in ("*", "/", "**"):
                raise ValueError("wildcard allowlist items shall never be accepted (default-deny)")
            if ".." in item.replace("\\", "/").split("/"):
                raise ValueError("path traversal segments shall never appear in the allowlist")
            if item in seen:
                raise ValueError("duplicate allowlist items shall never be accepted")
            seen.add(item)
        return items


class AuthorizationVerdictDTO(SaraBaseDTO):
    """Veredicto final de la Aduana de Autorizacion de Runtime."""

    execution_id: str = Field(..., min_length=12, max_length=68, pattern=EXECUTION_ID_PATTERN)
    tool_name: str = Field(..., min_length=2, max_length=64, pattern=TOOL_NAME_PATTERN)
    verdict: VerdictKind
    risk_score: float = Field(..., ge=0.0, le=1.0, allow_inf_nan=False)
    directives: Tuple[InductionDirectiveDTO, ...] = Field(
        default=(), max_length=MAX_DIRECTIVES_PER_OBSERVATION
    )
    violation_reason: Optional[str] = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def verify_threshold_consistency(self) -> "AuthorizationVerdictDTO":
        if math.isnan(self.risk_score):
            raise ValueError("risk_score shall never be NaN")
        if verdict_for_risk(self.risk_score) is not self.verdict:
            raise ValueError("verdict is inconsistent with risk_score thresholds (0.30 / 0.80)")
        if self.verdict is not VerdictKind.ALLOW and self.violation_reason is None:
            raise ValueError("non-ALLOW verdicts require a violation_reason")
        return self
