"""AuditPort: the hexagonal port through which modules append to the tamper-evident ledger.

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000
manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3

``ModeGatedAuditPort`` encodes the two-plane failure policy decided for v4.0:

  * ``off``     -> no-op, the inner port is never called (3.9.1 behaviour parity).
  * ``shadow``  -> best effort; any failure is swallowed (observability plane, fail-silent) and
                   optionally reported to ``on_error``. The caller's flow is never altered.
  * ``enforce`` -> fail-closed; failures (and a missing adapter) propagate to the caller.

Nothing here prints; diagnostics are the caller's responsibility (stderr only).
"""
from typing import Callable, Optional, Protocol, runtime_checkable

from ctxfw.kernel.contracts import AuditEventDTO, AuditReceiptDTO, RuntimeMode

__all__ = ["AuditPort", "AuditUnavailableError", "ModeGatedAuditPort"]


@runtime_checkable
class AuditPort(Protocol):
    def append(self, event: AuditEventDTO) -> AuditReceiptDTO:  # pragma: no cover - protocol
        ...


class AuditUnavailableError(RuntimeError):
    """``enforce`` mode without a usable audit adapter (fail-closed)."""


class ModeGatedAuditPort:
    def __init__(
        self,
        inner: Optional[AuditPort],
        mode: RuntimeMode,
        on_error: Optional[Callable[[BaseException], None]] = None,
    ) -> None:
        if not isinstance(mode, RuntimeMode):
            raise ValueError("mode must be a RuntimeMode")
        self._inner = inner
        self._mode = mode
        self._on_error = on_error

    @property
    def mode(self) -> RuntimeMode:
        return self._mode

    def append(self, event: AuditEventDTO) -> Optional[AuditReceiptDTO]:
        if self._mode is RuntimeMode.OFF:
            return None
        if self._inner is None:
            if self._mode is RuntimeMode.ENFORCE:
                raise AuditUnavailableError("enforce mode requires an audit adapter")
            return None
        if self._mode is RuntimeMode.ENFORCE:
            return self._inner.append(event)
        try:  # shadow: never alter the caller's flow
            return self._inner.append(event)
        except Exception as error:  # noqa: BLE001 - observability plane is fail-silent by design
            if self._on_error is not None:
                try:
                    self._on_error(error)
                except Exception:  # noqa: BLE001 - the error hook itself must never propagate
                    pass
            return None
