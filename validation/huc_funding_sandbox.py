"""Deterministic, in-memory funding sandbox. It never contacts a payment provider.

This module is test infrastructure only. All balances and transactions are synthetic.
"""
from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any


def _money(value: str | int | float | Decimal) -> Decimal:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Invalid monetary amount") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError("Amount must be a positive finite value")
    return amount


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
        previous = self._events[-1]["event_hash"] if self._events else "0" * 64
        # Snapshot payloads: later state transitions must not mutate historical evidence.
        payload_snapshot = json.loads(_canonical(payload).decode("utf-8"))
        body = {
            "sequence": len(self._events) + 1,
            "event_type": event_type,
            "payload": payload_snapshot,
            "previous_hash": previous,
        }
        event = {**body, "event_hash": _digest(body)}
        self._events.append(event)
        return event

    def create_intent(
        self,
        *,
        reference_id: str,
        amount: str | int | float | Decimal,
        idempotency_key: str,
        currency: str = "USD",
        certificate_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not reference_id.strip():
            raise ValueError("reference_id is required")
        if not idempotency_key or len(idempotency_key) > 128:
            raise ValueError("A valid idempotency key is required")
        if currency != "USD":
            raise ValueError("Sandbox currently supports synthetic USD only")
        value = _money(amount)
        if certificate_sha256 is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", certificate_sha256):
            raise ValueError("certificate_sha256 must be a 32-byte hexadecimal digest")
        request = {
            "reference_id": reference_id,
            "amount": f"{value:.2f}",
            "currency": currency,
            "certificate_sha256": certificate_sha256.lower() if certificate_sha256 else None,
        }
        request_hash = _digest(request)
        if idempotency_key in self._idempotency:
            previous_hash, intent_id = self._idempotency[idempotency_key]
            if previous_hash != request_hash:
                raise ValueError("Idempotency key reused with different request")
            return dict(self._intents[intent_id])
        intent_id = _digest({"idempotency_key": idempotency_key, "request_hash": request_hash})[:32]
        intent = {
            "intent_id": intent_id,
            **request,
            "status": "created",
            "captured_amount": "0.00",
            "refunded_amount": "0.00",
        }
        self._intents[intent_id] = intent
        self._idempotency[idempotency_key] = (request_hash, intent_id)
        self._append_event("INTENT_CREATED", intent)
        return dict(intent)

    def authorize(self, intent_id: str) -> dict[str, Any]:
        intent = self._get(intent_id)
        if intent["status"] == "authorized":
            return dict(intent)
        if intent["status"] != "created":
            raise ValueError("Only a created intent can be authorized")
        intent["status"] = "authorized"
        self._append_event("INTENT_AUTHORIZED", {"intent_id": intent_id})
        return dict(intent)

    def capture(self, intent_id: str) -> dict[str, Any]:
        intent = self._get(intent_id)
        if intent["status"] == "captured":
            return dict(intent)
        if intent["status"] != "authorized":
            raise ValueError("Only an authorized intent can be captured")
        amount = Decimal(intent["amount"])
        self._balance += amount
        intent["captured_amount"] = f"{amount:.2f}"
        intent["status"] = "captured"
        self._append_event("INTENT_CAPTURED", {"intent_id": intent_id, "amount": f"{amount:.2f}"})
        return dict(intent)

    def refund(
        self,
        intent_id: str,
        *,
        amount: str | int | float | Decimal,
        idempotency_key: str,
    ) -> dict[str, Any]:
        intent = self._get(intent_id)
        value = _money(amount)
        request_hash = _digest({"intent_id": intent_id, "amount": f"{value:.2f}"})
        if idempotency_key in self._refund_keys:
            previous_hash, previous_result = self._refund_keys[idempotency_key]
            if previous_hash != request_hash:
                raise ValueError("Refund idempotency key reused with different request")
            return dict(self._intents[intent_id])
        if intent["status"] not in {"captured", "partially_refunded"}:
            raise ValueError("Only captured funds can be refunded")
        captured = Decimal(intent["captured_amount"])
        refunded = Decimal(intent["refunded_amount"])
        if value > captured - refunded:
            raise ValueError("Refund exceeds remaining captured amount")
        refunded += value
        self._balance -= value
        intent["refunded_amount"] = f"{refunded:.2f}"
        intent["status"] = "refunded" if refunded == captured else "partially_refunded"
        self._refund_keys[idempotency_key] = (request_hash, intent_id)
        self._append_event("INTENT_REFUNDED", {
            "intent_id": intent_id,
            "amount": f"{value:.2f}",
            "total_refunded": f"{refunded:.2f}",
        })
        return dict(intent)

    def _get(self, intent_id: str) -> dict[str, Any]:
        try:
            return self._intents[intent_id]
        except KeyError as exc:
            raise ValueError("Unknown sandbox intent") from exc

    def evidence(self) -> dict[str, Any]:
        return {
            "schema": "HUC-FUNDING-SANDBOX-EVIDENCE-1",
            "mode": "SYNTHETIC_NO_EXTERNAL_PROVIDER",
            "currency": "USD",
            "synthetic_balance": self.synthetic_balance,
            "events": [dict(event) for event in self._events],
            "event_count": len(self._events),
            "event_head_hash": self._events[-1]["event_hash"] if self._events else "0" * 64,
            "event_chain_valid": self.verify_event_chain(),
        }

    def verify_event_chain(self) -> bool:
        previous = "0" * 64
        for index, event in enumerate(self._events, start=1):
            body = {key: event[key] for key in ("sequence", "event_type", "payload", "previous_hash")}
            if event["sequence"] != index or event["previous_hash"] != previous:
                return False
            if event["event_hash"] != _digest(body):
                return False
            previous = event["event_hash"]
        return True
