"""In-memory UTXO-inspired state transitions for certificate outputs."""

from dataclasses import dataclass
from typing import Any

from huc.certificate import is_expired, verify_certificate


class LedgerError(ValueError):
    """Raised when a ledger state transition is invalid."""


@dataclass(frozen=True)
class Output:
    output_id: str
    certificate_id: str
    state: str
    data: dict[str, Any]


class HucLedger:
    """A process-local test ledger; not distributed or persistent."""

    def __init__(self) -> None:
        self._unspent: dict[str, Output] = {}
        self._issued: set[str] = set()
        self._history: list[dict[str, str]] = []

    @property
    def history(self) -> tuple[dict[str, str], ...]:
        return tuple(self._history)

    def issue(self, certificate: dict[str, Any]) -> str:
        if not verify_certificate(certificate):
            raise LedgerError("Certificate signature or identifier is invalid.")
        cert_id = certificate["certificate_id"]
        output_id = f"{cert_id}:0"
        if cert_id in self._issued:
            raise LedgerError("Certificate has already been issued to this ledger.")
        self._issued.add(cert_id)
        self._unspent[output_id] = Output(output_id, cert_id, "active", certificate)
        self._history.append({"action": "issue", "certificate_id": cert_id})
        return output_id

    def revoke(self, output_id: str, reason: str) -> str:
        current = self._unspent.get(output_id)
        if current is None or current.state != "active":
            raise LedgerError("Output does not exist or has already been consumed.")
        del self._unspent[output_id]
        revocation_id = f"{current.certificate_id}:revocation"
        self._unspent[revocation_id] = Output(
            revocation_id,
            current.certificate_id,
            "revoked",
            {"reason": reason, "consumed_output": output_id},
        )
        self._history.append({"action": "revoke", "certificate_id": current.certificate_id})
        return revocation_id

    def verify_active(self, output_id: str) -> bool:
        output = self._unspent.get(output_id)
        return bool(
            output
            and output.state == "active"
            and verify_certificate(output.data)
            and not is_expired(output.data)
        )

    def get_output(self, output_id: str) -> Output | None:
        return self._unspent.get(output_id)
