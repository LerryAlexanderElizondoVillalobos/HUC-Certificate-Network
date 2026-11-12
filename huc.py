#!/usr/bin/env python3
"""LAEV HUC 0.5.0 — X.509 + complementary consensus certificate + logical UTXO.

This is a laboratory reference implementation. The JSONL ledger is a local,
signed event log with UTXO-like single-spend rules; it is NOT a blockchain,
distributed consensus protocol, or public certification authority.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import NameOID

VERSION = "0.5.0"
LEDGER_SCHEMA = "LAEV-HUC-UTXO-1"
CC_TYPE = "LAEV-HUC-CC"
CC_VERSION = "1"
POLICY_SCHEMA = "LAEV-HUC-CONSENSUS-POLICY-1"
ANCHOR_SCHEMA = "LAEV-HUC-TRUST-ANCHOR-1"
CA_CERT = "ca_certificate.pem"
CA_KEY = "ca_private_key.pem"
LEDGER_PUB = "ledger_public.pem"
LEDGER_KEY = "ledger_private.pem"
POLICY_FILE = "consensus_policy.json"
ANCHOR_FILE = "trust_anchor.json"
LEDGER_FILE = "utxo_ledger.jsonl"
CERT_DIR = "certificates"
AUTH_DIR = "authorities"
MAX_CERT_DAYS = 825
MAX_JSON_SAFE_INT = 9007199254740991


# HUC canonical JSON profile: sorted ASCII member names, UTF-8, no insignificant
# whitespace, no floating point values, and integers limited to IEEE-754 safe
# range. Cross-language production deployments should use full RFC 8785 JCS.
def _reject_unsafe_numbers(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("HUC canonical JSON no permite números de punto flotante")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_JSON_SAFE_INT:
        raise ValueError("Entero fuera del rango seguro JSON")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError("Las claves JSON del protocolo deben ser ASCII")
            _reject_unsafe_numbers(item)
    elif isinstance(value, list):
        for item in value:
            _reject_unsafe_numbers(item)


def canonical_json(value: Any) -> bytes:
    _reject_unsafe_numbers(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    dt = dt or now_utc()
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def pem_public(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def der_public(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def der_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def cert_hash(cert: x509.Certificate) -> str:
    return sha256(der_cert(cert))


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_name, mode)
        except OSError:
            pass
        os.replace(tmp_name, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n", mode)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Propiedad JSON duplicada: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Constante JSON no permitida: {value}")))


def read_json(path: Path) -> dict[str, Any]:
    try:
        obj = strict_json_loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"JSON inválido en {path}: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError(f"Se esperaba un objeto JSON en {path}")
    return obj


def save_private(key: Any, path: Path) -> None:
    # Demonstration-only unencrypted private-key storage. Production must use
    # encrypted key custody, HSM/KMS, rotation, backup and access controls.
    raw = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    atomic_write(path, raw, 0o600)


def load_private(path: Path) -> Any:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_ed_public_pem(text: str) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(text.encode("ascii"))
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("La clave de autoridad no es Ed25519")
    return key


def public_key_pem_text(key: Any) -> str:
    return pem_public(key).decode("ascii")


def cert_bounds(cert: x509.Certificate) -> tuple[datetime, datetime]:
    before = getattr(cert, "not_valid_before_utc", None)
    after = getattr(cert, "not_valid_after_utc", None)
    if before is None:
        before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if after is None:
        after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def load_policy(workspace: Path) -> dict[str, Any]:
    policy = read_json(workspace / POLICY_FILE)
    if policy.get("schema") != POLICY_SCHEMA:
        raise ValueError("Esquema de política HUC no reconocido")
    authorities = policy.get("authorities")
    threshold = policy.get("threshold")
    if not isinstance(authorities, list) or not authorities:
        raise ValueError("La política no define autoridades")
    if not isinstance(threshold, int) or threshold < 1 or threshold > len(authorities):
        raise ValueError("Umbral de consenso inválido")
    ids = [a.get("authority_id") for a in authorities]
    if len(ids) != len(set(ids)) or any(not isinstance(x, str) for x in ids):
        raise ValueError("Identificadores de autoridad repetidos o inválidos")
    public_key_hashes = []
    for authority in authorities:
        pub = load_ed_public_pem(authority["public_key_pem"])
        public_key_hashes.append(sha256(der_public(pub)))
        if not isinstance(authority.get("permissions"), list):
            raise ValueError("Permisos de autoridad inválidos")
    if len(public_key_hashes) != len(set(public_key_hashes)):
        raise ValueError("Dos autoridades no pueden compartir la misma clave pública")
    return policy


def policy_hash(policy: dict[str, Any]) -> str:
    return sha256(canonical_json(policy))


def trust_anchor_hash(anchor: dict[str, Any]) -> str:
    return sha256(canonical_json(anchor))


def trust_material(workspace: Path, expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    anchor = read_json(workspace / ANCHOR_FILE)
    if anchor.get("schema") != ANCHOR_SCHEMA:
        raise ValueError("Ancla de confianza no reconocida")
    actual_anchor_hash = trust_anchor_hash(anchor)
    if expected_anchor_sha256 and actual_anchor_hash.lower() != expected_anchor_sha256.strip().lower():
        raise ValueError("La huella externa del ancla no coincide")
    policy = load_policy(workspace)
    ca_cert = x509.load_pem_x509_certificate((workspace / CA_CERT).read_bytes())
    ledger_public = serialization.load_pem_public_key((workspace / LEDGER_PUB).read_bytes())
    if not isinstance(ledger_public, ed25519.Ed25519PublicKey):
        raise ValueError("La clave del ledger no es Ed25519")
    if anchor.get("ca_certificate_der_sha256") != sha256(der_cert(ca_cert)):
        raise ValueError("El certificado CA no coincide con el ancla")
    if anchor.get("ledger_public_key_der_sha256") != sha256(der_public(ledger_public)):
        raise ValueError("La clave del ledger no coincide con el ancla")
    if anchor.get("consensus_policy_sha256") != policy_hash(policy):
        raise ValueError("La política de consenso no coincide con el ancla")
    return {"anchor": anchor, "anchor_sha256": actual_anchor_hash,
            "policy": policy, "policy_sha256": policy_hash(policy),
            "ca_cert": ca_cert, "ledger_public": ledger_public}


def _verify_ca(ca_cert: x509.Certificate) -> None:
    if ca_cert.subject != ca_cert.issuer:
        raise ValueError("El certificado CA de demostración debe ser autofirmado")
    pub = ca_cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("La CA debe usar RSA en esta versión")
    try:
        pub.verify(ca_cert.signature, ca_cert.tbs_certificate_bytes,
                   padding.PKCS1v15(), ca_cert.signature_hash_algorithm)
    except InvalidSignature as exc:
        raise ValueError("Firma autofirmada de CA inválida") from exc
    try:
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("CA sin BasicConstraints") from exc
    if not bc.ca:
        raise ValueError("BasicConstraints de CA no está en true")


def initialize(workspace: Path, ca_name: str = "LAEV HUC Demonstration CA",
                threshold: int = 2, authority_count: int = 3,
                authority_public_files: list[Path] | None = None) -> dict[str, Any]:
    workspace = workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    protected = [CA_CERT, CA_KEY, LEDGER_PUB, LEDGER_KEY, POLICY_FILE, ANCHOR_FILE, LEDGER_FILE]
    if any((workspace / name).exists() for name in protected):
        raise FileExistsError("El workspace ya está inicializado; no se sobrescriben claves")
    external_authorities: list[dict[str, Any]] = []
    if authority_public_files:
        if len(authority_public_files) < 2 or len(authority_public_files) > 7:
            raise ValueError("Se requieren entre 2 y 7 descriptores públicos independientes")
        for descriptor_path in authority_public_files:
            descriptor = read_json(Path(descriptor_path))
            authority_id = descriptor.get("authority_id")
            public_key_pem = descriptor.get("public_key_pem")
            permissions = descriptor.get("permissions", ["ISSUE", "RENEW", "REVOKE"])
            if not isinstance(authority_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", authority_id):
                raise ValueError(f"Identificador de autoridad inválido en {descriptor_path}")
            load_ed_public_pem(public_key_pem)
            if not isinstance(permissions, list) or not permissions or any(
                permission not in {"ISSUE", "RENEW", "REVOKE"} for permission in permissions
            ):
                raise ValueError(f"Permisos inválidos en {descriptor_path}")
            external_authorities.append({
                "authority_id": authority_id,
                "public_key_pem": public_key_pem,
                "permissions": sorted(set(permissions)),
            })
        if len({a["authority_id"] for a in external_authorities}) != len(external_authorities):
            raise ValueError("Hay identificadores de autoridad duplicados")
        public_hashes = [sha256(der_public(load_ed_public_pem(a["public_key_pem"])))
                         for a in external_authorities]
        if len(set(public_hashes)) != len(public_hashes):
            raise ValueError("Cada autoridad debe aportar una clave pública independiente")
        authority_count = len(external_authorities)
    else:
        if authority_count < 2 or authority_count > 7:
            raise ValueError("Para este MVP, authority_count debe estar entre 2 y 7")
    if threshold < 2 or threshold > authority_count:
        raise ValueError("El threshold debe estar entre 2 y authority_count")

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)])
    now = now_utc().replace(tzinfo=None)
    ca_cert = (x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(ca_key, hashes.SHA256()))
    ledger_key = ed25519.Ed25519PrivateKey.generate()
    save_private(ca_key, workspace / CA_KEY)
    atomic_write(workspace / CA_CERT, ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    save_private(ledger_key, workspace / LEDGER_KEY)
    atomic_write(workspace / LEDGER_PUB, pem_public(ledger_key.public_key()), 0o644)
    (workspace / CERT_DIR).mkdir(exist_ok=True)
    (workspace / AUTH_DIR).mkdir(exist_ok=True)

    if external_authorities:
        # Only public descriptors enter the coordinator workspace. Authority
        # private keys remain on their respective independent devices.
        authorities = external_authorities
    else:
        authorities = []
        for i in range(1, authority_count + 1):
            authority_id = f"HUC-AUTH-{i:02d}"
            key = ed25519.Ed25519PrivateKey.generate()
            save_private(key, workspace / AUTH_DIR / f"{authority_id}-private.pem")
            authorities.append({
                "authority_id": authority_id,
                "public_key_pem": public_key_pem_text(key.public_key()),
                "permissions": ["ISSUE", "RENEW", "REVOKE"],
            })
    policy = {
        "schema": POLICY_SCHEMA,
        "protocol": "LAEV-HUC-CC",
        "version": "1",
        "policy_id": f"HUC-{threshold}-OF-{authority_count}",
        "signature_algorithm": "Ed25519",
        "threshold": threshold,
        "authority_count": authority_count,
        "authorities": authorities,
        "rules": {
            "issue_requires_threshold": True,
            "renew_requires_threshold": True,
            "revoke_requires_threshold": True,
            "utxo_double_spend_allowed": False,
            "revoked_certificate_reactivation_allowed": False,
        },
    }
    write_json(workspace / POLICY_FILE, policy, 0o644)
    atomic_write(workspace / LEDGER_FILE, b"", 0o600)
    anchor = {
        "schema": ANCHOR_SCHEMA,
        "protocol_version": VERSION,
        "created_at_utc": iso(),
        "ca_certificate_der_sha256": sha256(der_cert(ca_cert)),
        "ledger_public_key_der_sha256": sha256(der_public(ledger_key.public_key())),
        "consensus_policy_sha256": policy_hash(policy),
        "consensus_policy_id": policy["policy_id"],
    }
    write_json(workspace / ANCHOR_FILE, anchor, 0o644)
    return {"result": "initialized", "protocol_version": VERSION,
            "workspace": str(workspace), "threshold": f"{threshold}-of-{authority_count}",
            "trust_anchor_sha256": trust_anchor_hash(anchor),
            "policy_sha256": policy_hash(policy),
            "external_authorities": bool(external_authorities),
            "warning": ("Las claves privadas de autoridades permanecen fuera del workspace." if external_authorities
                        else "Claves privadas de autoridades generadas localmente para laboratorio; no usar en producción.")}


def generate_request(out_dir: Path, common_name: str, key_size: int = 2048) -> dict[str, Any]:
    if not common_name.strip():
        raise ValueError("El nombre del sujeto no puede estar vacío")
    if key_size < 2048 or key_size > 4096:
        raise ValueError("El tamaño de clave RSA debe estar entre 2048 y 4096 bits")
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", common_name.strip()).strip("._-") or "subject"
    stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name.strip())])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    key_path = out_dir / f"{safe}-{stamp}-private.pem"
    csr_path = out_dir / f"{safe}-{stamp}.csr.pem"
    save_private(key, key_path)
    atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM), 0o644)
    return {"csr_file": str(csr_path.resolve()), "private_key_file": str(key_path.resolve()),
            "subject": csr.subject.rfc4514_string(), "proof_of_possession": csr.is_signature_valid,
            "warning": "La clave privada pertenece al titular; no se entrega a la CA."}


def validate_csr(path: Path) -> x509.CertificateSigningRequest:
    csr = x509.load_pem_x509_csr(path.read_bytes())
    if not csr.is_signature_valid:
        raise ValueError("CSR: firma inválida, no demuestra posesión de clave")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn or not cn[0].value.strip():
        raise ValueError("CSR: se requiere Common Name")
    if not isinstance(csr.public_key(), rsa.RSAPublicKey) or csr.public_key().key_size < 2048:
        raise ValueError("CSR: se requiere clave pública RSA de al menos 2048 bits")
    if list(csr.extensions):
        raise ValueError("Este MVP no acepta extensiones de CSR sin aprobación de política")
    return csr


def make_certificate(csr: x509.CertificateSigningRequest, ca_key: rsa.RSAPrivateKey,
                     ca_cert: x509.Certificate, days: int) -> x509.Certificate:
    if not 1 <= days <= MAX_CERT_DAYS:
        raise ValueError(f"La vigencia debe estar entre 1 y {MAX_CERT_DAYS} días")
    now = now_utc().replace(tzinfo=None)
    return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject)
        .public_key(csr.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .sign(ca_key, hashes.SHA256()))


def sign_authority_payload(workspace: Path, payload: dict[str, Any],
                           signer_ids: list[str] | None = None) -> list[dict[str, str]]:
    policy = load_policy(workspace)
    threshold = policy["threshold"]
    by_id = {a["authority_id"]: a for a in policy["authorities"]}
    ids = signer_ids or [a["authority_id"] for a in policy["authorities"][:threshold]]
    if len(set(ids)) != len(ids) or len(ids) < threshold:
        raise ValueError("No se cumple el umbral de firmas o hay firmantes duplicados")
    signatures = []
    data = canonical_json(payload)
    for authority_id in ids:
        if authority_id not in by_id:
            raise ValueError(f"Autoridad no autorizada: {authority_id}")
        key_path = workspace / AUTH_DIR / f"{authority_id}-private.pem"
        if not key_path.exists():
            raise ValueError(f"No está disponible la clave del firmante {authority_id}")
        key = load_private(key_path)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("Clave de autoridad inválida")
        sig = base64.b64encode(key.sign(data)).decode("ascii")
        signatures.append({"authority_id": authority_id, "signature": sig})
    return signatures


def verify_authority_signatures(policy: dict[str, Any], payload: dict[str, Any],
                                signatures: list[dict[str, str]],
                                operation: str) -> dict[str, Any]:
    threshold = policy["threshold"]
    allowed = {a["authority_id"]: a for a in policy["authorities"]}
    seen: set[str] = set()
    valid: list[str] = []
    data = canonical_json(payload)
    for item in signatures:
        aid = item.get("authority_id")
        if not isinstance(aid, str) or aid in seen or aid not in allowed:
            continue
        seen.add(aid)
        authority = allowed[aid]
        if operation not in authority.get("permissions", []):
            continue
        try:
            signature = base64.b64decode(item.get("signature", ""), validate=True)
            load_ed_public_pem(authority["public_key_pem"]).verify(signature, data)
            valid.append(aid)
        except (ValueError, InvalidSignature, TypeError):
            continue
    if len(valid) < threshold:
        raise ValueError(f"Consenso insuficiente: {len(valid)} firmas válidas; se requieren {threshold}")
    return {"valid_signers": valid, "valid_signature_count": len(valid),
            "threshold": threshold, "consensus_reached": True}


def _ledger_state(workspace: Path, trust: dict[str, Any]) -> dict[str, Any]:
    path = workspace / LEDGER_FILE
    active: dict[str, dict[str, Any]] = {}
    statuses: dict[str, str] = {}
    known: set[str] = set()
    events: list[dict[str, Any]] = []
    previous_event_hash: str | None = None
    ledger_pub = trust["ledger_public"]
    policy = trust["policy"]
    if not path.exists():
        raise FileNotFoundError("No existe utxo_ledger.jsonl")
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = strict_json_loads(line)
            if not isinstance(event, dict):
                raise ValueError("evento no es objeto JSON")
            payload = event["payload"]
            if payload.get("schema") != LEDGER_SCHEMA or payload.get("sequence") != len(events):
                raise ValueError("schema o secuencia incorrectos")
            if payload.get("previous_event_hash") != previous_event_hash:
                raise ValueError("cadena de hashes rota")
            base_payload = {k: v for k, v in payload.items() if k != "output"}
            txid = sha256(canonical_json(base_payload))
            if event.get("txid") != txid:
                raise ValueError("txid incorrecto")
            event_hash = sha256(canonical_json(payload))
            if event.get("event_hash") != event_hash:
                raise ValueError("event_hash incorrecto")
            ledger_sig = base64.b64decode(event.get("ledger_signature", ""), validate=True)
            ledger_pub.verify(ledger_sig, bytes.fromhex(event_hash))
            action = payload.get("action")
            c_hash = payload.get("certificate_sha256_der")
            prev_hash = payload.get("previous_certificate_sha256_der")
            prev_outpoint = payload.get("previous_outpoint")
            output = payload.get("output")
            expected_output = {"txid": txid, "vout": 0}
            if not isinstance(c_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", c_hash):
                raise ValueError("hash de certificado inválido")
            consensus = verify_authority_signatures(policy, payload,
                event.get("consensus_signatures", []), action)
            if action == "ISSUE":
                if c_hash in known or prev_hash is not None or prev_outpoint is not None or output != expected_output:
                    raise ValueError("ISSUE inconsistente")
                active[c_hash] = expected_output
                statuses[c_hash] = "ACTIVE"
                known.add(c_hash)
            elif action == "RENEW":
                if (not isinstance(prev_hash, str) or prev_hash not in active
                        or active[prev_hash] != prev_outpoint or c_hash in known
                        or output != expected_output):
                    raise ValueError("RENEW no consume exactamente el UTXO anterior")
                del active[prev_hash]
                statuses[prev_hash] = "SUPERSEDED"
                active[c_hash] = expected_output
                statuses[c_hash] = "ACTIVE"
                known.add(c_hash)
            elif action == "REVOKE":
                if (c_hash not in active or active[c_hash] != prev_outpoint
                        or prev_hash is not None or output is not None
                        or not isinstance(payload.get("reason"), str)
                        or not payload["reason"].strip()):
                    raise ValueError("REVOKE no consume el UTXO activo")
                del active[c_hash]
                statuses[c_hash] = "REVOKED"
            else:
                raise ValueError(f"Acción desconocida: {action}")
            previous_event_hash = event_hash
            event["_consensus_result"] = consensus
            events.append(event)
        except (KeyError, ValueError, TypeError, InvalidSignature, json.JSONDecodeError) as exc:
            raise ValueError(f"Ledger inválido en línea {line_no}: {exc}") from exc
    return {"events": events, "active": active, "statuses": statuses,
            "last_event_hash": previous_event_hash, "event_count": len(events)}


def _append_transition(workspace: Path, action: str, certificate_sha: str,
                       previous_certificate_sha: str | None = None,
                       previous_outpoint: dict[str, Any] | None = None,
                       reason: str | None = None,
                       signer_ids: list[str] | None = None,
                       expected_anchor_sha256: str | None = None,
                       authority_signatures: list[dict[str, str]] | None = None,
                       prepared_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    lock = FileLock(str(workspace / (LEDGER_FILE + ".lock")), timeout=20)
    try:
        with lock:
            trust = trust_material(workspace, expected_anchor_sha256)
            state = _ledger_state(workspace, trust)
            if action == "ISSUE":
                if certificate_sha in state["statuses"] or previous_outpoint is not None or previous_certificate_sha is not None:
                    raise ValueError("ISSUE duplicado o con entrada previa")
            elif action == "RENEW":
                if not previous_certificate_sha or previous_certificate_sha not in state["active"]:
                    raise ValueError("El certificado anterior no tiene UTXO activo")
                if state["active"][previous_certificate_sha] != previous_outpoint:
                    raise ValueError("El UTXO anterior no coincide con el estado vigente")
                if certificate_sha in state["statuses"]:
                    raise ValueError("El nuevo certificado ya existe en el historial")
            elif action == "REVOKE":
                if certificate_sha not in state["active"] or state["active"][certificate_sha] != previous_outpoint:
                    raise ValueError("El certificado no tiene UTXO activo coincidente")
                if not reason or not reason.strip():
                    raise ValueError("La revocación requiere un motivo")
            else:
                raise ValueError("Operación UTXO desconocida")

            if prepared_payload is None:
                payload = {
                    "schema": LEDGER_SCHEMA,
                    "sequence": state["event_count"],
                    "previous_event_hash": state["last_event_hash"],
                    "action": action,
                    "certificate_sha256_der": certificate_sha,
                    "previous_certificate_sha256_der": previous_certificate_sha,
                    "previous_outpoint": previous_outpoint,
                    "output": None,
                    "created_at_utc": iso(),
                    "reason": reason,
                }
                txid = sha256(canonical_json({k: v for k, v in payload.items() if k != "output"}))
                if action in {"ISSUE", "RENEW"}:
                    payload["output"] = {"txid": txid, "vout": 0}
            else:
                payload = prepared_payload
                if (payload.get("schema") != LEDGER_SCHEMA
                        or payload.get("sequence") != state["event_count"]
                        or payload.get("previous_event_hash") != state["last_event_hash"]
                        or payload.get("action") != action
                        or payload.get("certificate_sha256_der") != certificate_sha
                        or payload.get("previous_certificate_sha256_der") != previous_certificate_sha
                        or payload.get("previous_outpoint") != previous_outpoint
                        or payload.get("reason") != reason):
                    raise ValueError("La propuesta está obsoleta o no coincide con el estado actual")
                txid = sha256(canonical_json({k: v for k, v in payload.items() if k != "output"}))
                expected_output = {"txid": txid, "vout": 0} if action in {"ISSUE", "RENEW"} else None
                if payload.get("output") != expected_output:
                    raise ValueError("La salida UTXO de la propuesta no es válida")
            event_hash = sha256(canonical_json(payload))
            signatures = (authority_signatures if authority_signatures is not None
                          else sign_authority_payload(workspace, payload, signer_ids))
            verify_authority_signatures(trust["policy"], payload, signatures, action)
            ledger_key = load_private(workspace / LEDGER_KEY)
            if not isinstance(ledger_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Clave del registro inválida")
            ledger_signature = base64.b64encode(ledger_key.sign(bytes.fromhex(event_hash))).decode("ascii")
            event = {"txid": txid, "event_hash": event_hash, "payload": payload,
                     "consensus_signatures": signatures, "ledger_signature": ledger_signature}
            with (workspace / LEDGER_FILE).open("ab") as f:
                f.write(canonical_json(event) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            _ledger_state(workspace, trust)
            return event
    except Timeout as exc:
        raise TimeoutError("No se obtuvo el bloqueo local del registro") from exc


def _build_cc_payload(workspace: Path, cert: x509.Certificate, outpoint: dict[str, Any],
                      action: str, sequence: int) -> dict[str, Any]:
    policy = load_policy(workspace)
    return {
        "consensus_certificate_id": "huc-cc:" + sha256(canonical_json({
            "certificate_sha256_der": cert_hash(cert), "outpoint": outpoint,
            "policy_sha256": policy_hash(policy), "action": action,
        })),
        "certificate_sha256_der": cert_hash(cert),
        "certificate_serial_number": str(cert.serial_number),
        "initial_utxo_outpoint": outpoint,
        "utxo_sequence_at_issuance": sequence,
        "policy_sha256": policy_hash(policy),
        "policy_id": policy["policy_id"],
        "consensus_mode": "MULTI_SIGNATURE",
        "threshold": policy["threshold"],
        "authority_count": policy["authority_count"],
        "operation": action,
        "authorized_state_at_issuance": "ACTIVE",
        "issued_at_utc": iso(),
        "not_after_utc": iso(cert_bounds(cert)[1]),
    }


def _make_cc(workspace: Path, cert: x509.Certificate, outpoint: dict[str, Any],
             action: str, sequence: int, signer_ids: list[str] | None = None,
             authority_signatures: list[dict[str, str]] | None = None,
             prepared_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = load_policy(workspace)
    payload = prepared_payload or _build_cc_payload(workspace, cert, outpoint, action, sequence)
    expected = _build_cc_payload(workspace, cert, outpoint, action, sequence)
    # issued_at_utc is fixed by the proposal; all other fields must match.
    for key, value in expected.items():
        if key != "issued_at_utc" and payload.get(key) != value:
            raise ValueError(f"HUC-CC propuesto contiene un campo incompatible: {key}")
    signatures = (authority_signatures if authority_signatures is not None
                  else sign_authority_payload(workspace, payload, signer_ids))
    verify_authority_signatures(policy, payload, signatures, action)
    return {"type": CC_TYPE, "version": CC_VERSION, "payload": payload, "signatures": signatures}


def issue_csr(workspace: Path, csr_path: Path, days: int = 365,
              signer_ids: list[str] | None = None,
              expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    workspace = workspace.resolve()
    csr = validate_csr(csr_path)
    trust = trust_material(workspace, expected_anchor_sha256)
    ca_key = load_private(workspace / CA_KEY)
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise ValueError("Clave privada CA inválida")
    cert = make_certificate(csr, ca_key, trust["ca_cert"], days)
    digest = cert_hash(cert)
    cert_path = workspace / CERT_DIR / f"certificate-{digest}.pem"
    atomic_write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    event = _append_transition(workspace, "ISSUE", digest, signer_ids=signer_ids,
                               expected_anchor_sha256=expected_anchor_sha256)
    cc = _make_cc(workspace, cert, event["payload"]["output"], "ISSUE",
                  event["payload"]["sequence"], signer_ids)
    cc_path = workspace / CERT_DIR / f"consensus-{digest}.json"
    write_json(cc_path, cc, 0o644)
    return {"action": "ISSUE", "certificate_sha256_der": digest,
            "serial_number": str(cert.serial_number), "certificate_file": str(cert_path),
            "consensus_certificate_file": str(cc_path), "utxo_outpoint": event["payload"]["output"],
            "consensus": f"{len(cc['signatures'])}/{cc['payload']['authority_count']} firmas de autoridades",
            "private_key_note": "La clave privada del titular no se entrega al emisor."}


def renew_csr(workspace: Path, old_certificate_path: Path, csr_path: Path,
              days: int = 365, signer_ids: list[str] | None = None,
              expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    old_cert = x509.load_pem_x509_certificate(old_certificate_path.read_bytes())
    csr = validate_csr(csr_path)
    if old_cert.subject != csr.subject:
        raise ValueError("El sujeto del CSR nuevo debe coincidir con el certificado anterior")
    trust = trust_material(workspace, expected_anchor_sha256)
    _verify_leaf_signature(old_cert, trust["ca_cert"])
    state = _ledger_state(workspace, trust)
    old_hash = cert_hash(old_cert)
    old_outpoint = state["active"].get(old_hash)
    if not old_outpoint:
        raise ValueError("El certificado anterior no está activo")
    ca_key = load_private(workspace / CA_KEY)
    cert = make_certificate(csr, ca_key, trust["ca_cert"], days)
    digest = cert_hash(cert)
    cert_path = workspace / CERT_DIR / f"certificate-{digest}.pem"
    atomic_write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    event = _append_transition(workspace, "RENEW", digest,
        previous_certificate_sha=old_hash, previous_outpoint=old_outpoint,
        signer_ids=signer_ids, expected_anchor_sha256=expected_anchor_sha256)
    cc = _make_cc(workspace, cert, event["payload"]["output"], "RENEW",
                  event["payload"]["sequence"], signer_ids)
    cc_path = workspace / CERT_DIR / f"consensus-{digest}.json"
    write_json(cc_path, cc, 0o644)
    return {"action": "RENEW", "previous_certificate_sha256_der": old_hash,
            "certificate_sha256_der": digest, "certificate_file": str(cert_path),
            "consensus_certificate_file": str(cc_path), "utxo_outpoint": event["payload"]["output"],
            "consensus": f"{len(cc['signatures'])}/{cc['payload']['authority_count']} firmas de autoridades"}


def revoke(workspace: Path, certificate_path: Path, reason: str,
           signer_ids: list[str] | None = None,
           expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    if not reason.strip():
        raise ValueError("Indique un motivo de revocación")
    cert = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    trust = trust_material(workspace, expected_anchor_sha256)
    _verify_leaf_signature(cert, trust["ca_cert"])
    state = _ledger_state(workspace, trust)
    digest = cert_hash(cert)
    outpoint = state["active"].get(digest)
    if not outpoint:
        raise ValueError("El certificado no está activo o ya fue revocado/sustituido")
    event = _append_transition(workspace, "REVOKE", digest, previous_outpoint=outpoint,
        reason=reason, signer_ids=signer_ids, expected_anchor_sha256=expected_anchor_sha256)
    return {"action": "REVOKE", "certificate_sha256_der": digest,
            "consumed_utxo": outpoint, "revocation_event_txid": event["txid"],
            "status": "REVOKED", "consensus_signatures": len(event["consensus_signatures"])}


def _verify_leaf_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    if cert.issuer != ca_cert.subject:
        raise ValueError("El issuer del certificado no coincide con la CA")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Certificado final sin BasicConstraints") from exc
    if bc.ca:
        raise ValueError("Un certificado final no puede ser CA")
    pub = ca_cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("La CA no utiliza RSA")
    try:
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                   padding.PKCS1v15(), cert.signature_hash_algorithm)
    except InvalidSignature as exc:
        raise ValueError("Firma X.509 inválida") from exc


def verify_certificate(workspace: Path, certificate_path: Path,
                       cc_path: Path | None = None,
                       expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    trust = trust_material(workspace, expected_anchor_sha256)
    ca_cert = trust["ca_cert"]
    _verify_ca(ca_cert)
    cert = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    _verify_leaf_signature(cert, ca_cert)
    before, after = cert_bounds(cert)
    ca_before, ca_after = cert_bounds(ca_cert)
    now = now_utc()
    cert_time_valid = before <= now <= after
    ca_time_valid = ca_before <= now <= ca_after
    digest = cert_hash(cert)
    state = _ledger_state(workspace, trust)
    status = state["statuses"].get(digest, "NOT_REGISTERED")
    active_outpoint = state["active"].get(digest)

    cc_path = cc_path or (workspace / CERT_DIR / f"consensus-{digest}.json")
    cc = read_json(cc_path)
    if cc.get("type") != CC_TYPE or cc.get("version") != CC_VERSION:
        raise ValueError("HUC-CC: formato o versión desconocidos")
    payload = cc.get("payload")
    signatures = cc.get("signatures")
    if not isinstance(payload, dict) or not isinstance(signatures, list):
        raise ValueError("HUC-CC: payload o firmas inválidas")
    if payload.get("certificate_sha256_der") != digest:
        raise ValueError("HUC-CC no está vinculado a este certificado X.509")
    if payload.get("policy_sha256") != trust["policy_sha256"]:
        raise ValueError("HUC-CC está vinculado a otra política de consenso")
    policy = trust["policy"]
    if (payload.get("policy_id") != policy.get("policy_id")
            or payload.get("threshold") != policy.get("threshold")
            or payload.get("authority_count") != policy.get("authority_count")
            or payload.get("consensus_mode") != "MULTI_SIGNATURE"
            or payload.get("certificate_serial_number") != str(cert.serial_number)):
        raise ValueError("HUC-CC contiene parámetros de consenso o identidad incompatibles")
    expected_cc_id = "huc-cc:" + sha256(canonical_json({
        "certificate_sha256_der": digest,
        "outpoint": payload.get("initial_utxo_outpoint"),
        "policy_sha256": trust["policy_sha256"],
        "action": payload.get("operation"),
    }))
    if payload.get("consensus_certificate_id") != expected_cc_id:
        raise ValueError("Identificador del certificado HUC-CC inválido")
    cc_consensus = verify_authority_signatures(trust["policy"], payload, signatures, payload.get("operation", "ISSUE"))
    # Match the CC's initial outpoint against the actual signed ISSUE/RENEW event.
    matching_event = None
    for event in state["events"]:
        ep = event["payload"]
        if ep.get("certificate_sha256_der") == digest and ep.get("action") in {"ISSUE", "RENEW"}:
            matching_event = event
            break
    if matching_event is None or payload.get("initial_utxo_outpoint") != matching_event["payload"].get("output"):
        raise ValueError("HUC-CC no coincide con el outpoint registrado")
    if payload.get("operation") != matching_event["payload"].get("action"):
        raise ValueError("HUC-CC no corresponde a la operación UTXO registrada")
    if payload.get("utxo_sequence_at_issuance") != matching_event["payload"].get("sequence"):
        raise ValueError("HUC-CC no coincide con la secuencia de emisión")
    if payload.get("authorized_state_at_issuance") != "ACTIVE":
        raise ValueError("HUC-CC no certifica el estado inicial ACTIVE")
    try:
        cc_expiry = datetime.fromisoformat(payload["not_after_utc"].replace("Z", "+00:00"))
        cc_expiry_valid = cc_expiry == after
    except Exception:
        cc_expiry_valid = False
    if not cc_expiry_valid:
        raise ValueError("Vigencia declarada por HUC-CC no coincide con X.509")

    hybrid_valid = bool(cert_time_valid and ca_time_valid and active_outpoint and status == "ACTIVE"
                        and cc_consensus["consensus_reached"])
    return {
        "subject": cert.subject.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "certificate_sha256_der": digest,
        "x509_signature_valid": True,
        "certificate_time_valid": cert_time_valid,
        "ca_time_valid": ca_time_valid,
        "huc_cc_valid": True,
        "consensus_reached": cc_consensus["consensus_reached"],
        "consensus_signers": cc_consensus["valid_signers"],
        "consensus_threshold": cc_consensus["threshold"],
        "utxo_status": status,
        "utxo_outpoint": active_outpoint or matching_event["payload"].get("output"),
        "trust_anchor_sha256": trust["anchor_sha256"],
        "external_trust_pin_supplied": bool(expected_anchor_sha256),
        "hybrid_valid": hybrid_valid,
        "ledger_event_count": state["event_count"],
        "result": "VALID" if hybrid_valid else ("INVALID" if status in {"REVOKED", "SUPERSEDED", "NOT_REGISTERED"} or not cert_time_valid or not ca_time_valid else "INDETERMINATE"),
    }


def audit(workspace: Path, expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    trust = trust_material(workspace, expected_anchor_sha256)
    state = _ledger_state(workspace, trust)
    return {"ledger_integrity": "VALID", "event_count": state["event_count"],
            "active_certificates": len(state["active"]), "statuses": state["statuses"],
            "last_event_hash": state["last_event_hash"],
            "trust_anchor_sha256": trust["anchor_sha256"]}


def export_bundle(workspace: Path, certificate_path: Path, output_path: Path) -> dict[str, Any]:
    trust = trust_material(workspace)
    state = _ledger_state(workspace, trust)
    cert = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    digest = cert_hash(cert)
    cc_path = workspace / CERT_DIR / f"consensus-{digest}.json"
    if not cc_path.is_file():
        raise FileNotFoundError("No se encuentra el HUC-CC asociado")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    files = [
        (workspace / CA_CERT, "ca_certificate.pem"),
        (workspace / LEDGER_PUB, "ledger_public.pem"),
        (workspace / POLICY_FILE, POLICY_FILE),
        (workspace / ANCHOR_FILE, ANCHOR_FILE),
        (workspace / LEDGER_FILE, LEDGER_FILE),
        (certificate_path, "certificate.pem"),
        (cc_path, "consensus_certificate.json"),
    ]
    manifest = {"format": "LAEV-HUC-PACKAGE", "version": VERSION,
                "certificate_sha256_der": digest,
                "certificate_file": "certificate.pem",
                "consensus_certificate_file": "consensus_certificate.json",
                "private_keys_included": False}
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for source, arcname in files:
            zf.write(source, arcname)
        zf.writestr("package_manifest.json", json.dumps(manifest, indent=2) + "\n")
    return {"package": str(output_path.resolve()), "certificate_sha256_der": digest,
            "trust_anchor_sha256": trust["anchor_sha256"], "private_keys_included": False,
            "ledger_event_count": state["event_count"]}


def verify_bundle(bundle_path: Path, expected_anchor_sha256: str) -> dict[str, Any]:
    if not expected_anchor_sha256:
        raise ValueError("Se requiere la huella del ancla obtenida por un canal independiente")
    with tempfile.TemporaryDirectory(prefix="huc-package-") as tmp:
        root = Path(tmp)
        with zipfile.ZipFile(bundle_path, "r") as zf:
            total = sum(i.file_size for i in zf.infolist())
            if total > 20 * 1024 * 1024:
                raise ValueError("El paquete excede el límite de 20 MiB")
            for info in zf.infolist():
                dest = (root / info.filename).resolve()
                if root.resolve() not in dest.parents and dest != root.resolve():
                    raise ValueError("Ruta no permitida dentro del paquete")
            zf.extractall(root)
        manifest = read_json(root / "package_manifest.json")
        if manifest.get("format") != "LAEV-HUC-PACKAGE":
            raise ValueError("Formato de paquete HUC desconocido")
        # Reconstruct the minimal verifier workspace from public package items.
        (root / CERT_DIR).mkdir(exist_ok=True)
        cert_path = root / manifest.get("certificate_file", "certificate.pem")
        cc_path = root / manifest.get("consensus_certificate_file", "consensus_certificate.json")
        digest = manifest.get("certificate_sha256_der")
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if cert_hash(cert) != digest:
            raise ValueError("Hash del certificado no coincide con el manifiesto del paquete")
        target_cc = root / CERT_DIR / f"consensus-{digest}.json"
        target_cc.write_bytes(cc_path.read_bytes())
        result = verify_certificate(root, cert_path, target_cc, expected_anchor_sha256)
        result["package_verified"] = True
        result["bundle_file"] = str(bundle_path)
        return result


def _parse_signers(text: str | None) -> list[str] | None:
    return [x.strip() for x in text.split(",") if x.strip()] if text else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LAEV HUC 0.4 — X.509 + HUC-CC + UTXO lógico")
    sp = p.add_subparsers(dest="cmd", required=True)
    x = sp.add_parser("init"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--threshold", type=int, default=2); x.add_argument("--authorities", type=int, default=3); x.add_argument("--authority-public", type=Path, nargs="+")
    x = sp.add_parser("request"); x.add_argument("--out-dir", type=Path, default=Path("./requests")); x.add_argument("--name", required=True); x.add_argument("--key-size", type=int, default=2048)
    x = sp.add_parser("issue"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--csr", type=Path, required=True); x.add_argument("--days", type=int, default=365); x.add_argument("--signers")
    x = sp.add_parser("renew"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--certificate", type=Path, required=True); x.add_argument("--csr", type=Path, required=True); x.add_argument("--days", type=int, default=365); x.add_argument("--signers")
    x = sp.add_parser("revoke"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--certificate", type=Path, required=True); x.add_argument("--reason", required=True); x.add_argument("--signers")
    x = sp.add_parser("verify"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--certificate", type=Path, required=True); x.add_argument("--cc", type=Path); x.add_argument("--trust-anchor-sha256", required=True)
    x = sp.add_parser("audit"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--trust-anchor-sha256", required=True)
    x = sp.add_parser("bundle"); x.add_argument("--workspace", type=Path, default=Path("./huc-workspace")); x.add_argument("--certificate", type=Path, required=True); x.add_argument("--output", type=Path, required=True)
    x = sp.add_parser("verify-bundle"); x.add_argument("--bundle", type=Path, required=True); x.add_argument("--trust-anchor-sha256", required=True)
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.cmd == "init":
            result = initialize(args.workspace, threshold=args.threshold,
                                authority_count=args.authorities,
                                authority_public_files=args.authority_public)
        elif args.cmd == "request":
            result = generate_request(args.out_dir, args.name, args.key_size)
        elif args.cmd == "issue":
            result = issue_csr(args.workspace, args.csr, args.days, _parse_signers(args.signers))
        elif args.cmd == "renew":
            result = renew_csr(args.workspace, args.certificate, args.csr, args.days, _parse_signers(args.signers))
        elif args.cmd == "revoke":
            result = revoke(args.workspace, args.certificate, args.reason, _parse_signers(args.signers))
        elif args.cmd == "verify":
            result = verify_certificate(args.workspace, args.certificate, args.cc, args.trust_anchor_sha256)
        elif args.cmd == "audit":
            result = audit(args.workspace, args.trust_anchor_sha256)
        elif args.cmd == "bundle":
            result = export_bundle(args.workspace, args.certificate, args.output)
        elif args.cmd == "verify-bundle":
            result = verify_bundle(args.bundle, args.trust_anchor_sha256)
        else:
            raise ValueError("Comando no reconocido")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.cmd in {"verify", "verify-bundle"} and not result.get("hybrid_valid"):
            return 1
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
