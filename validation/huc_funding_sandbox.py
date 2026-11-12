"""Deterministic, in-memory funding sandbox; never contacts a payment provider."""
from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from typing import Any


ZERO_HASH = "0" * 64
CENT = Decimal("0.01")
_HEX_256 = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)


def _money(value: str | int | float | Decimal) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("Invalid monetary amount")
    try:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Invalid monetary amount")
        amount = Decimal(str(value))
        if not amount.is_finite():
            raise ValueError("Invalid monetary amount")
        amount = amount.quantize(CENT, rounding=ROUND_HALF_EVEN)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("Invalid monetary amount") from exc
    if amount <= 0:
        raise ValueError("Amount must be a positive finite value")
    return amount


def _canonical(value: Any) -> bytes:
    """Canonical JSON: stable key order, UTF-8, no NaN/Infinity."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _snapshot(value: Any) -> Any:
    """Detach nested mutable values and reject values outside canonical JSON."""
    return json.loads(_canonical(value).decode("utf-8"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class FundingSandbox:
    """Synthetic contribution/payment lifecycle with idempotency and hash-chained evidence."""

    def __init__(self) -> None:
        self._intents: dict[str, dict[str, Any]] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._refund_keys: dict[str, tuple[str, str]] = {}
        self._events: list[dict[str, Any]] = []
        self._balance = Decimal("0.00")

    @property
    def synthetic_balance(self) -> str:
        return f"{self._balance:.2f}"

    def _append_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = {
            "sequence": len(self._events) + 1,
            "event_type": event_type,
            "payload": _snapshot(payload),
            "previous_hash": self._events[-1]["event_hash"] if self._events else ZERO_HASH,
        }
        event = {**body, "event_hash": _digest(body)}
        # Store an independent snapshot; never expose the stored nested structures.
        self._events.append(_snapshot(event))
        return _snapshot(event)

    def create_intent(
        self, *, reference_id: str, amount: str | int | float | Decimal,
        idempotency_key: str, currency: str = "USD",
        certificate_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(reference_id, str) or not reference_id.strip():
            raise ValueError("reference_id is required")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key) > 128:
            raise ValueError("A valid idempotency key is required")
        if currency != "USD":
            raise ValueError("Sandbox currently supports synthetic USD only")
        value = _money(amount)
        if certificate_sha256 is not None:
            if not isinstance(certificate_sha256, str) or not _HEX_256.fullmatch(certificate_sha256):
                raise ValueError("certificate_sha256 must be a 32-byte hexadecimal digest")
            certificate_sha256 = certificate_sha256.lower()
        request = {
            "reference_id": reference_id,
            "amount": f"{value:.2f}",
            "currency": currency,
            "certificate_sha256": certificate_sha256,
        }
        request_hash = _digest(request)
        if idempotency_key in self._idempotency:
            previous_hash, intent_id = self._idempotency[idempotency_key]
            if previous_hash != request_hash:
                raise ValueError("Idempotency key reused with different request")
            return _snapshot(self._intents[intent_id])
        intent_id = _digest({"idempotency_key": idempotency_key, "request_hash": request_hash})[:32]
        intent = {
            "intent_id": intent_id, **request, "status": "created",
            "captured_amount": "0.00", "refunded_amount": "0.00",
        }
        self._intents[intent_id] = intent
        self._idempotency[idempotency_key] = (request_hash, intent_id)
        self._append_event("INTENT_CREATED", intent)
        return _snapshot(intent)

    def authorize(self, intent_id: str) -> dict[str, Any]:
        intent = self._get(intent_id)
        if intent["status"] == "authorized":
            return _snapshot(intent)
        if intent["status"] != "created":
            raise ValueError("Only a created intent can be authorized")
        intent["status"] = "authorized"
        self._append_event("INTENT_AUTHORIZED", {"intent_id": intent_id})
        return _snapshot(intent)

    def capture(self, intent_id: str) -> dict[str, Any]:
        intent = self._get(intent_id)
        if intent["status"] == "captured":
            return _snapshot(intent)
        if intent["status"] != "authorized":
            raise ValueError("Only an authorized intent can be captured")
        amount = Decimal(intent["amount"])
        intent["captured_amount"] = f"{amount:.2f}"
        intent["status"] = "captured"
        self._balance += amount
        self._append_event("INTENT_CAPTURED", {"intent_id": intent_id, "amount": f"{amount:.2f}"})
        return _snapshot(intent)

    def refund(
        self, intent_id: str, *, amount: str | int | float | Decimal,
        idempotency_key: str,
    ) -> dict[str, Any]:
        intent = self._get(intent_id)
        if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key) > 128:
            raise ValueError("A valid refund idempotency key is required")
        value = _money(amount)
        request_hash = _digest({"intent_id": intent_id, "amount": f"{value:.2f}"})
        if idempotency_key in self._refund_keys:
            previous_hash, previous_intent_id = self._refund_keys[idempotency_key]
            if previous_hash != request_hash or previous_intent_id != intent_id:
                raise ValueError("Refund idempotency key reused with different request")
            return _snapshot(intent)
        if intent["status"] not in {"captured", "partially_refunded"}:
            raise ValueError("Only captured funds can be refunded")
        captured = Decimal(intent["captured_amount"])
        refunded = Decimal(intent["refunded_amount"])
        if value > captured - refunded:
            raise ValueError("Refund exceeds remaining captured amount")
        new_refunded = refunded + value
        new_status = "refunded" if new_refunded == captured else "partially_refunded"
        # Record the event before committing state, so a serialization failure cannot
        # leave balance/intent changed without corresponding evidence.
        self._append_event("INTENT_REFUNDED", {
            "intent_id": intent_id, "amount": f"{value:.2f}",
            "total_refunded": f"{new_refunded:.2f}",
        })
        intent["refunded_amount"] = f"{new_refunded:.2f}"
        intent["status"] = new_status
        self._balance -= value
        self._refund_keys[idempotency_key] = (request_hash, intent_id)
        return _snapshot(intent)

    def _get(self, intent_id: str) -> dict[str, Any]:
        try:
            return self._intents[intent_id]
        except (KeyError, TypeError) as exc:
            raise ValueError("Unknown sandbox intent") from exc

    def evidence(self) -> dict[str, Any]:
        events = _snapshot(self._events)
        return {
            "schema": "HUC-FUNDING-SANDBOX-EVIDENCE-1",
            "mode": "SYNTHETIC_NO_EXTERNAL_PROVIDER",
            "currency": "USD",
            "synthetic_balance": self.synthetic_balance,
            "events": events,
            "event_count": len(events),
            "event_head_hash": events[-1]["event_hash"] if events else ZERO_HASH,
            "event_chain_valid": self.verify_event_chain(events),
        }

    def verify_event_chain(self, events: list[dict[str, Any]] | None = None) -> bool:
        """Verify a supplied exported chain, or this sandbox's stored chain."""
        if events is None:
            events = self._events
        if not isinstance(events, list):
            return False
        previous = ZERO_HASH
        try:
            for index, event in enumerate(events, start=1):
                if not isinstance(event, dict):
                    return False
                body = {
                    "sequence": event["sequence"],
                    "event_type": event["event_type"],
                    "payload": event["payload"],
                    "previous_hash": event["previous_hash"],
                }
                if event["sequence"] != index or event["previous_hash"] != previous:
                    return False
                event_hash = event["event_hash"]
                if not isinstance(event_hash, str) or not _HEX_256.fullmatch(event_hash):
                    return False
                if event_hash != _digest(body):
                    return False
                previous = event_hash
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        return True
