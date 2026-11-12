"""HUC 0.8.0 external X.509 adapter and single-use authorization registry.

This adapter consumes externally issued X.509 credentials; it never issues or
replaces government certificates. Revocation checking must be supplied by an
institutional CRL/OCSP integration before production use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtensionOID

SCHEMA = "HUC-080-SINGLE-USE-AUTHORIZATION"
ZERO = "0" * 64


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def load_cert(path: str | Path) -> x509.Certificate:
    raw = Path(path).read_bytes()
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        return x509.load_der_x509_certificate(raw)


def _verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            raise ValueError("Unsupported issuer public-key algorithm")
    except InvalidSignature as exc:
        raise ValueError("Invalid X.509 certificate signature") from exc


def verify_government_certificate(
    certificate: x509.Certificate,
    chain: list[x509.Certificate],
    trust_roots: list[x509.Certificate],
    *,
    at_time: int | None = None,
    require_digital_signature: bool = True,
) -> dict[str, Any]:
    """Validate a supplied leaf->intermediate chain against explicitly pinned roots.

    This is a bounded path validator, not a complete RFC 5280 implementation.
    It deliberately fails closed for missing issuers and unsupported constraints.
    """
    if not trust_roots:
        raise ValueError("At least one out-of-band pinned trust root is required")
    now = at_time if at_time is not None else int(time.time())
    path = [certificate, *chain]
    root_fingerprints = {fingerprint(root) for root in trust_roots}
    if fingerprint(certificate) in root_fingerprints:
        raise ValueError("A trust root cannot be used as the end-entity certificate")
    for index, cert in enumerate(path):
        before = int(cert.not_valid_before_utc.timestamp())
        after = int(cert.not_valid_after_utc.timestamp())
        if not before <= now <= after:
            raise ValueError("X.509 certificate is not currently valid")
        if index == 0:
            try:
                constraints = cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS).value
                if constraints.ca:
                    raise ValueError("End-entity certificate must not be a CA")
            except x509.ExtensionNotFound:
                raise ValueError("End-entity certificate lacks BasicConstraints")
            if require_digital_signature:
                try:
                    usage = cert.extensions.get_extension_for_oid(
                        ExtensionOID.KEY_USAGE).value
                    if not usage.digital_signature:
                        raise ValueError("Certificate KeyUsage disallows digitalSignature")
                except x509.ExtensionNotFound:
                    raise ValueError("Certificate lacks KeyUsage")
        else:
            try:
                constraints = cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS).value
                if not constraints.ca:
                    raise ValueError("Intermediate certificate is not a CA")
            except x509.ExtensionNotFound:
                raise ValueError("Issuer certificate lacks BasicConstraints")
        issuer = path[index + 1] if index + 1 < len(path) else None
        if issuer is None:
            candidates = [root for root in trust_roots if cert.issuer == root.subject]
            if not candidates:
                raise ValueError("Certificate chain does not terminate at a pinned trust root")
            issuer = candidates[0]
        if cert.issuer != issuer.subject:
            raise ValueError("X.509 issuer/subject chain mismatch")
        _verify_cert_signature(cert, issuer)
    terminal = path[-1]
    if fingerprint(terminal) not in root_fingerprints:
        if not any(terminal.issuer == root.subject for root in trust_roots):
            raise ValueError("Untrusted terminal issuer")
        root = next(root for root in trust_roots if terminal.issuer == root.subject)
        _verify_cert_signature(terminal, root)
    return {
        "chain_valid": True,
        "certificate_sha256_der": fingerprint(certificate),
        "issuer": certificate.issuer.rfc4514_string(),
        "subject": certificate.subject.rfc4514_string(),
        "serial_number": str(certificate.serial_number),
        "revocation_status": "NOT_CHECKED",
        "production_ready": False,
        "warning": "CRL/OCSP status and complete RFC 5280 policy processing are not implemented by this adapter.",
    }


def _sign(private_key: Any, message: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return private_key.sign(message)
    raise ValueError("Unsupported certificate signing-key algorithm")


def _verify_signature(public_key: Any, signature: bytes, message: bytes) -> None:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, message)
        else:
            raise ValueError("Unsupported certificate public-key algorithm")
    except InvalidSignature as exc:
        raise ValueError("Invalid HUC authorization signature") from exc


def create_single_use_authorization(
    certificate: x509.Certificate,
    private_key: Any,
    *,
    outpoint: str,
    operation: str,
    resource_id: str,
    expires_at: int,
    nonce: str,
) -> dict[str, Any]:
    if not all(isinstance(v, str) and v.strip() for v in
               (outpoint, operation, resource_id, nonce)):
        raise ValueError("outpoint, operation, resource_id and nonce are required")
    if expires_at <= int(time.time()):
        raise ValueError("Authorization expiry must be in the future")
    if certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("Private key does not match the X.509 certificate")
    payload = {
        "schema": SCHEMA, "certificate_sha256_der": fingerprint(certificate),
        "outpoint": outpoint, "operation": operation, "resource_id": resource_id,
        "expires_at": expires_at, "nonce": nonce,
    }
    signature = _sign(private_key, b"HUC-080-AUTHORIZATION-V1\x00" + canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


def verify_single_use_authorization(
    authorization: dict[str, Any], certificate: x509.Certificate,
) -> dict[str, Any]:
    payload = authorization.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ValueError("Unknown HUC authorization schema")
    if payload.get("certificate_sha256_der") != fingerprint(certificate):
        raise ValueError("Authorization is not bound to this X.509 certificate")
    if payload.get("expires_at", 0) <= int(time.time()):
        raise ValueError("HUC authorization has expired")
    try:
        signature = base64.b64decode(authorization["signature"], validate=True)
    except Exception as exc:
        raise ValueError("Malformed authorization signature") from exc
    _verify_signature(certificate.public_key(), signature,
                      b"HUC-080-AUTHORIZATION-V1\x00" + canonical(payload))
    return {"signature_valid": True, "outpoint": payload["outpoint"],
            "operation": payload["operation"], "resource_id": payload["resource_id"]}


class LinuxUserRuntime:
    """Create HUC state under the current Linux user's private state directory.

    No root privileges, setuid bit, or system-wide daemon are required.
    """
    def __init__(self, state_dir: str | Path | None = None):
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise RuntimeError("Linux User Mode requires a POSIX user runtime")
        if state_dir is None:
            xdg = os.environ.get("XDG_STATE_HOME")
            if xdg:
                base = Path(xdg).expanduser()
                if not base.is_absolute():
                    raise ValueError("XDG_STATE_HOME must be an absolute path")
                state = base / "huc"
            else:
                home = os.environ.get("HOME")
                if not home:
                    raise RuntimeError("HOME or XDG_STATE_HOME must be configured")
                state = Path(home).expanduser() / ".local" / "state" / "huc"
        else:
            state = Path(state_dir).expanduser()

        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = state.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("HUC state path must be a real directory, not a symlink")
        if info.st_uid != os.getuid():
            raise PermissionError("HUC state directory must belong to the current user")
        os.chmod(state, 0o700)
        self.state_dir = state
        self.database = state / "utxo.sqlite3"
        self.registry = SingleUseUTXORegistry(self.database)

    def permissions(self) -> dict[str, int]:
        return {
            "state_dir": stat.S_IMODE(self.state_dir.stat().st_mode),
            "database": stat.S_IMODE(self.database.stat().st_mode),
        }


class SingleUseUTXORegistry:
    """SQLite atomic consume-once registry; all replicas need a consensus layer."""
    def __init__(self, database: str | Path):
        self.database = str(database)
        db_path = Path(self.database)
        db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if db_path.exists() or db_path.is_symlink():
            info = db_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RuntimeError("HUC database path must be a regular file, not a symlink")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise PermissionError("HUC database must belong to the current user")
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS consumed (
                outpoint TEXT PRIMARY KEY, txid TEXT NOT NULL UNIQUE,
                authorization_sha256 TEXT NOT NULL, consumed_at INTEGER NOT NULL
            )""")
        if db_path.exists():
            os.chmod(db_path, 0o600)

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def consume(self, authorization: dict[str, Any],
                certificate: x509.Certificate) -> dict[str, Any]:
        verified = verify_single_use_authorization(authorization, certificate)
        outpoint = verified["outpoint"]
        auth_hash = hashlib.sha256(canonical(authorization)).hexdigest()
        txid = hashlib.sha256(canonical({"outpoint": outpoint,
            "authorization_sha256": auth_hash})).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO consumed VALUES (?, ?, ?, ?)",
                           (outpoint, txid, auth_hash, int(time.time())))
                db.execute("COMMIT")
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK")
                raise ValueError("UTXO already consumed: double-use rejected")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return {"consumed": True, "outpoint": outpoint, "txid": txid,
                "single_use_enforced": True}
