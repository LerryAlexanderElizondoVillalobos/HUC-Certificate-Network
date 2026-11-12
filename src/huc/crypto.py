"""Ed25519 helpers used by the HUC prototype."""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate an issuer key pair and return the raw public key as base64."""
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, base64.b64encode(public_bytes).decode("ascii")


def sign_payload(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign canonical payload bytes and return a base64 signature."""
    return base64.b64encode(private_key.sign(payload)).decode("ascii")


def verify_signature(public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
    """Return False for malformed keys/signatures or invalid signatures."""
    try:
        public_bytes = base64.b64decode(public_key_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, payload)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False
