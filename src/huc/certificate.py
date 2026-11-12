"""Certificate creation and cryptographic verification."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from huc.crypto import sign_payload, verify_signature


def canonical_json(value: dict[str, Any]) -> bytes:
    """Serialize JSON deterministically for hashing and signing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def certificate_id(payload: dict[str, Any]) -> str:
    """Derive a stable identifier from the canonical unsigned payload."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def issue_certificate(
    private_key: Ed25519PrivateKey,
    issuer_public_key: str,
    subject: str,
    claims: dict[str, Any],
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Create a signed certificate. Times are UTC ISO-8601 strings."""
    payload: dict[str, Any] = {
        "schema": "huc-certificate/0.1",
        "issuer": issuer_public_key,
        "subject": subject,
        "claims": claims,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
    }
    return {
        **payload,
        "certificate_id": certificate_id(payload),
        "signature": sign_payload(private_key, canonical_json(payload)),
    }


def verify_certificate(certificate: dict[str, Any]) -> bool:
    """Verify certificate identifier and issuer signature."""
    required = {
        "schema", "issuer", "subject", "claims", "issued_at",
        "expires_at", "certificate_id", "signature",
    }
    if not isinstance(certificate, dict) or set(certificate) != required:
        return False
    payload = {
        key: certificate[key]
        for key in required
        if key not in {"certificate_id", "signature"}
    }
    return (
        certificate["certificate_id"] == certificate_id(payload)
        and verify_signature(
            certificate["issuer"], canonical_json(payload), certificate["signature"]
        )
    )


def is_expired(certificate: dict[str, Any]) -> bool:
    """Check optional expiry against UTC; invalid or timezone-naive values fail closed."""
    expires_at = certificate.get("expires_at")
    if expires_at is None:
        return False
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            return True
        return datetime.now(timezone.utc) >= expiry.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        return True
