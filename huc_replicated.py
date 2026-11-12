#!/usr/bin/env python3
"""LAEV HUC 0.6 — leaderless quorum-certified replicated state prototype.

This module provides a fixed-membership, coordinatorless commit workflow:
any participant may propose, collect validator votes, assemble a commit
certificate, and distribute it. Each validator persists one vote per slot.
A 3-of-4 quorum is used for f=1. This is NOT a complete BFT/view-change
protocol; conflicting proposals can safely halt a slot until out-of-band
recovery is agreed. Transport is file/package exchange in this release.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import huc

VERSION = "0.7.0"
NETWORK_SCHEMA = "LAEV-HUC-RSP-NETWORK-1"
NODE_SCHEMA = "LAEV-HUC-RSP-NODE-1"
PROPOSAL_SCHEMA = "LAEV-HUC-RSP-PROPOSAL-1"
VOTE_SCHEMA = "LAEV-HUC-RSP-VOTE-1"
COMMIT_SCHEMA = "LAEV-HUC-RSP-COMMIT-1"
STATE_SCHEMA = "LAEV-HUC-RSP-STATE-1"
SYNC_SCHEMA = "LAEV-HUC-RSP-SYNC-1"
NODE_PRIVATE = "node-private.pem"
NODE_PUBLIC = "node-public.json"
NETWORK_FILE = "network.json"
NODE_TRUST = "node-trust.json"
VOTE_LOCKS = "vote-locks.json"
LEDGER_FILE = "replicated-ledger.jsonl"
STATE_FILE = "replicated-state.json"
CHECKPOINT_FILE = "epoch-checkpoint.json"
NODE_LOCK = "node-state.lock"
MAX_PROPOSAL_MINUTES = 30


def _canonical(obj: Any) -> bytes:
    return huc.canonical_json(obj)


def _hash(obj: Any) -> str:
    return huc.sha256(_canonical(obj))


def _read(path: Path) -> dict[str, Any]:
    return huc.read_json(path)


def _write(path: Path, obj: Any, mode: int = 0o600) -> None:
    huc.write_json(path, obj, mode)


def _parse_time(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError("Fecha UTC inválida") from exc
    if dt.tzinfo is None:
        raise ValueError("La fecha debe incluir zona horaria")
    return dt.astimezone(timezone.utc)


def _private(path: Path) -> ed25519.Ed25519PrivateKey:
    key = huc.load_private(path)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada del validador debe ser Ed25519")
    return key


def _pub_pem_text(key: ed25519.Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _verify_sig(public_pem: str, signature_b64: str, message: bytes) -> None:
    pub = huc.load_ed_public_pem(public_pem)
    signature = base64.b64decode(signature_b64, validate=True)
    pub.verify(signature, message)


def _network_core(network: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in network.items() if k not in {"network_id", "created_at_utc"}}


def network_hash(network: dict[str, Any]) -> str:
    return _hash(network)


def validate_network(network: dict[str, Any]) -> dict[str, Any]:
    if network.get("schema") != NETWORK_SCHEMA:
        raise ValueError("Esquema de red HUC-RSP no reconocido")
    validators = network.get("validators")
    f = network.get("fault_tolerance")
    quorum = network.get("quorum")
    if not isinstance(validators, list) or not validators:
        raise ValueError("La red no contiene validadores")
    if not isinstance(f, int) or f < 1:
        raise ValueError("fault_tolerance debe ser al menos 1; HUC no acepta una red de un solo validador")
    n = len(validators)
    if n != 3 * f + 1:
        raise ValueError("Este perfil requiere n = 3f + 1 validadores")
    if quorum != 2 * f + 1:
        raise ValueError("El quórum debe ser 2f + 1")
    ids: set[str] = set()
    key_hashes: set[str] = set()
    for item in validators:
        validator_id = item.get("validator_id")
        if not isinstance(validator_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", validator_id):
            raise ValueError("Identificador de validador inválido")
        if validator_id in ids:
            raise ValueError("Identificadores de validador duplicados")
        ids.add(validator_id)
        pub = huc.load_ed_public_pem(item.get("public_key_pem", ""))
        actual = huc.sha256(huc.der_public(pub))
        if item.get("public_key_sha256") != actual:
            raise ValueError("Huella de clave pública de validador incorrecta")
        if actual in key_hashes:
            raise ValueError("Dos validadores no pueden compartir una clave pública")
        key_hashes.add(actual)
    if "pki" in network:
        _validate_network_pki(network["pki"])
    expected_id = _hash(_network_core(network))
    if network.get("network_id") != expected_id:
        raise ValueError("network_id no corresponde al manifiesto")
    return network


def load_network(node_dir: Path, expected_pin: str | None = None) -> dict[str, Any]:
    network = validate_network(_read(node_dir / NETWORK_FILE))
    actual_pin = network_hash(network)
    trust = _read(node_dir / NODE_TRUST)
    if trust.get("network_sha256") != actual_pin:
        raise ValueError("La huella del manifiesto de red no coincide con el pin local")
    if expected_pin and actual_pin.lower() != expected_pin.strip().lower():
        raise ValueError("La huella externa de la red no coincide")
    return network


def _validator(network: dict[str, Any], validator_id: str) -> dict[str, Any]:
    match = next((v for v in network["validators"] if v["validator_id"] == validator_id), None)
    if match is None:
        raise ValueError(f"Validador no autorizado: {validator_id}")
    return match


def node_init(validator_id: str, out_dir: Path) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", validator_id):
        raise ValueError("validator_id debe tener entre 3 y 64 caracteres seguros")
    out_dir = out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError("El directorio del nodo ya contiene archivos")
    out_dir.mkdir(parents=True, exist_ok=True)
    key = ed25519.Ed25519PrivateKey.generate()
    public_pem = _pub_pem_text(key.public_key())
    descriptor = {
        "schema": NODE_SCHEMA,
        "validator_id": validator_id,
        "algorithm": "Ed25519",
        "public_key_pem": public_pem,
        "public_key_sha256": huc.sha256(huc.der_public(key.public_key())),
        "created_at_utc": huc.iso(),
    }
    huc.save_private(key, out_dir / NODE_PRIVATE)
    _write(out_dir / NODE_PUBLIC, descriptor, 0o644)
    return {
        "result": "validator_node_created",
        "validator_id": validator_id,
        "node_directory": str(out_dir),
        "public_descriptor": str(out_dir / NODE_PUBLIC),
        "private_key_file": str(out_dir / NODE_PRIVATE),
        "public_key_sha256": descriptor["public_key_sha256"],
        "warning": "La clave privada solo debe permanecer en el dispositivo de esta institución.",
    }


def _validate_consensus_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema") != huc.POLICY_SCHEMA:
        raise ValueError("Política de consenso HUC no reconocida")
    authorities = policy.get("authorities")
    threshold = policy.get("threshold")
    if not isinstance(authorities, list) or not authorities:
        raise ValueError("La política HUC no contiene autoridades")
    if not isinstance(threshold, int) or threshold < 2 or threshold > len(authorities):
        raise ValueError("Umbral de firmas HUC-CC inválido")
    ids, keys = set(), set()
    for authority in authorities:
        aid = authority.get("authority_id")
        if not isinstance(aid, str) or aid in ids:
            raise ValueError("Identificadores de autoridad HUC duplicados o inválidos")
        ids.add(aid)
        if not isinstance(authority.get("permissions"), list):
            raise ValueError("Permisos de autoridad HUC inválidos")
        pub = huc.load_ed_public_pem(authority.get("public_key_pem", ""))
        key_hash = huc.sha256(huc.der_public(pub))
        if key_hash in keys:
            raise ValueError("Autoridades HUC no pueden compartir clave pública")
        keys.add(key_hash)


def _validate_network_pki(pki: dict[str, Any]) -> None:
    ca_pem = pki.get("ca_certificate_pem")
    policy = pki.get("consensus_policy")
    if not isinstance(ca_pem, str) or not isinstance(policy, dict):
        raise ValueError("El perfil PKI de la red requiere certificado CA y política HUC")
    ca_cert = huc.x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    huc._verify_ca(ca_cert)
    if pki.get("ca_certificate_der_sha256") != huc.sha256(huc.der_cert(ca_cert)):
        raise ValueError("Hash del certificado CA incorrecto en perfil PKI")
    _validate_consensus_policy(policy)
    if pki.get("consensus_policy_sha256") != huc.policy_hash(policy):
        raise ValueError("Hash de política HUC incorrecto en perfil PKI")


def create_network(public_descriptors: list[Path], output: Path, fault_tolerance: int = 1,
                   ca_certificate_path: Path | None = None,
                   consensus_policy_path: Path | None = None) -> dict[str, Any]:
    if fault_tolerance < 1 or len(public_descriptors) != 3 * fault_tolerance + 1:
        raise ValueError("Se requiere n = 3f + 1 y f >= 1; para f=1 use cuatro nodos")
    if bool(ca_certificate_path) != bool(consensus_policy_path):
        raise ValueError("Para integrar HUC, proporcione ambos: CA pública y política de consenso")
    validators = []
    for path in public_descriptors:
        descriptor = _read(path)
        if descriptor.get("schema") != NODE_SCHEMA or descriptor.get("algorithm") != "Ed25519":
            raise ValueError(f"Descriptor de nodo no reconocido: {path}")
        pub = huc.load_ed_public_pem(descriptor.get("public_key_pem", ""))
        key_hash = huc.sha256(huc.der_public(pub))
        if descriptor.get("public_key_sha256") != key_hash:
            raise ValueError(f"Huella incorrecta en descriptor: {path}")
        validators.append({
            "validator_id": descriptor["validator_id"],
            "public_key_pem": descriptor["public_key_pem"],
            "public_key_sha256": key_hash,
        })
    validators.sort(key=lambda x: x["validator_id"])
    core = {
        "schema": NETWORK_SCHEMA,
        "protocol": "HUC-RSP/0.6",
        "fault_tolerance": fault_tolerance,
        "quorum": 2 * fault_tolerance + 1,
        "validators": validators,
    }
    if ca_certificate_path and consensus_policy_path:
        ca_pem = Path(ca_certificate_path).read_text(encoding="ascii")
        policy = _read(Path(consensus_policy_path))
        ca_cert = huc.x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
        pki = {
            "ca_certificate_pem": ca_pem,
            "ca_certificate_der_sha256": huc.sha256(huc.der_cert(ca_cert)),
            "consensus_policy": policy,
            "consensus_policy_sha256": huc.policy_hash(policy),
        }
        _validate_network_pki(pki)
        core["pki"] = pki
    network = dict(core)
    network["network_id"] = _hash(core)
    network["created_at_utc"] = huc.iso()
    validate_network(network)
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, network, 0o644)
    return {
        "result": "network_manifest_created",
        "network_id": network["network_id"],
        "network_sha256": network_hash(network),
        "validator_count": len(validators),
        "fault_tolerance": fault_tolerance,
        "quorum": network["quorum"],
        "manifest": str(output.resolve()),
    }


def _genesis_state(network: dict[str, Any]) -> dict[str, Any]:
    genesis_hash = _hash({"domain": "HUC-RSP-GENESIS/0.6", "network_id": network["network_id"]})
    return {
        "schema": STATE_SCHEMA,
        "network_id": network["network_id"],
        "epoch": 0,
        "sequence": 0,
        "head_hash": genesis_hash,
        "certificates": {},
        "commit_ids": [],
    }


def node_join(node_dir: Path, network_path: Path, expected_network_sha256: str) -> dict[str, Any]:
    node_dir = node_dir.resolve()
    descriptor = _read(node_dir / NODE_PUBLIC)
    key = _private(node_dir / NODE_PRIVATE)
    if _pub_pem_text(key.public_key()) != descriptor.get("public_key_pem"):
        raise ValueError("La clave privada local no corresponde al descriptor público")
    network = validate_network(_read(network_path))
    actual_pin = network_hash(network)
    if actual_pin.lower() != expected_network_sha256.strip().lower():
        raise ValueError("La huella externa del manifiesto no coincide")
    item = _validator(network, descriptor["validator_id"])
    if item["public_key_pem"] != descriptor["public_key_pem"]:
        raise ValueError("La clave pública local no está inscrita en esta red")
    if (node_dir / NETWORK_FILE).exists():
        raise FileExistsError("El nodo ya pertenece a una red; use sync-state para actualizarlo")
    huc.atomic_write(node_dir / NETWORK_FILE, _canonical(network) + b"\n", 0o644)
    _write(node_dir / NODE_TRUST, {
        "schema": "LAEV-HUC-RSP-NODE-TRUST-1",
        "validator_id": descriptor["validator_id"],
        "network_sha256": actual_pin,
        "joined_at_utc": huc.iso(),
    })
    huc.atomic_write(node_dir / VOTE_LOCKS, _canonical({"schema": "LAEV-HUC-RSP-VOTE-LOCKS-1", "locks": {}}) + b"\n")
    huc.atomic_write(node_dir / LEDGER_FILE, b"")
    _write(node_dir / STATE_FILE, _genesis_state(network))
    return {"result": "node_joined", "validator_id": descriptor["validator_id"],
            "network_id": network["network_id"], "network_sha256": actual_pin,
            "quorum": network["quorum"]}


def _node_context(node_dir: Path) -> tuple[dict[str, Any], dict[str, Any], ed25519.Ed25519PrivateKey]:
    network = load_network(node_dir)
    descriptor = _read(node_dir / NODE_PUBLIC)
    validator = _validator(network, descriptor["validator_id"])
    if validator["public_key_pem"] != descriptor["public_key_pem"]:
        raise ValueError("Descriptor de nodo no coincide con el manifiesto")
    key = _private(node_dir / NODE_PRIVATE)
    if _pub_pem_text(key.public_key()) != descriptor["public_key_pem"]:
        raise ValueError("La clave privada local no coincide con la identidad del nodo")
    return network, descriptor, key


def _proposal_payload(proposal: dict[str, Any]) -> dict[str, Any]:
    payload = proposal.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Propuesta sin payload")
    if proposal.get("proposal_id") != _hash(payload):
        raise ValueError("proposal_id incorrecto")
    if payload.get("schema") != PROPOSAL_SCHEMA:
        raise ValueError("Esquema de propuesta no reconocido")
    return payload


def _validate_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{label} debe ser SHA-256 hexadecimal de 64 caracteres")
    return value


def _validate_huc_evidence(network: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any] | None:
    """Validate the X.509 and HUC-CC contents pinned by a proposal.

    When the network has PKI material, every validator independently checks
    the certificate chain to the configured demo CA and the HUC-CC authority
    quorum before voting. The RSP commit quorum is a separate layer.
    """
    pki = network.get("pki")
    evidence = payload.get("evidence")
    if not pki:
        if evidence is not None:
            raise ValueError("La red no tiene perfil PKI para validar evidencia HUC")
        return None
    if not isinstance(evidence, dict):
        raise ValueError("Esta red exige evidencia X.509 y HUC-CC adjunta")
    try:
        cert_pem = base64.b64decode(evidence["certificate_pem_b64"], validate=True)
        cc = evidence["consensus_certificate"]
        cert = huc.x509.load_pem_x509_certificate(cert_pem)
    except Exception as exc:
        raise ValueError("Evidencia de certificado mal formada") from exc
    ca_cert = huc.x509.load_pem_x509_certificate(pki["ca_certificate_pem"].encode("ascii"))
    huc._verify_ca(ca_cert)
    huc._verify_leaf_signature(cert, ca_cert)
    cert_hash = huc.cert_hash(cert)
    cc_hash = huc.sha256(huc.canonical_json(cc))
    if cert_hash != payload.get("certificate_sha256"):
        raise ValueError("El X.509 adjunto no coincide con certificate_sha256")
    if cc_hash != payload.get("consensus_certificate_sha256"):
        raise ValueError("El HUC-CC adjunto no coincide con consensus_certificate_sha256")
    if cc.get("type") != huc.CC_TYPE or cc.get("version") != huc.CC_VERSION:
        raise ValueError("Tipo o versión de HUC-CC no reconocido")
    cc_payload = cc.get("payload")
    signatures = cc.get("signatures")
    if not isinstance(cc_payload, dict) or not isinstance(signatures, list):
        raise ValueError("HUC-CC sin payload o firmas válidas")
    policy = pki["consensus_policy"]
    policy_digest = huc.policy_hash(policy)
    if cc_payload.get("certificate_sha256_der") != cert_hash:
        raise ValueError("HUC-CC no está vinculado al X.509 adjunto")
    if cc_payload.get("policy_sha256") != policy_digest:
        raise ValueError("HUC-CC utiliza otra política de autoridades")
    if cc_payload.get("policy_id") != policy.get("policy_id"):
        raise ValueError("HUC-CC policy_id no coincide")
    if cc_payload.get("threshold") != policy.get("threshold") or cc_payload.get("authority_count") != len(policy["authorities"]):
        raise ValueError("HUC-CC umbral o cantidad de autoridades incorrectos")
    if cc_payload.get("certificate_serial_number") != str(cert.serial_number):
        raise ValueError("HUC-CC serial no coincide con X.509")
    if cc_payload.get("authorized_state_at_issuance") != "ACTIVE":
        raise ValueError("HUC-CC no certifica estado inicial ACTIVE")
    initial_outpoint = cc_payload.get("initial_utxo_outpoint")
    if not isinstance(initial_outpoint, dict) or not isinstance(initial_outpoint.get("txid"), str) or initial_outpoint.get("vout") != 0:
        raise ValueError("HUC-CC no contiene outpoint inicial válido")
    expected_cc_id = "huc-cc:" + huc.sha256(huc.canonical_json({
        "certificate_sha256_der": cert_hash,
        "outpoint": initial_outpoint,
        "policy_sha256": policy_digest,
        "action": cc_payload.get("operation"),
    }))
    if cc_payload.get("consensus_certificate_id") != expected_cc_id:
        raise ValueError("Identificador HUC-CC incorrecto")
    action = payload.get("action")
    if action in {"ISSUE", "RENEW"} and cc_payload.get("operation") != action:
        raise ValueError("La operación HUC-CC no coincide con la transición")
    if action == "REVOKE" and cc_payload.get("operation") not in {"ISSUE", "RENEW"}:
        raise ValueError("HUC-CC original de revocación no reconocido")
    before, after = huc.cert_bounds(cert)
    try:
        cc_after = _parse_time(cc_payload["not_after_utc"])
    except Exception as exc:
        raise ValueError("Fecha de expiración declarada por HUC-CC inválida") from exc
    if cc_after != after:
        raise ValueError("La vigencia HUC-CC no coincide con X.509")
    huc.verify_authority_signatures(policy, cc_payload, signatures, cc_payload.get("operation", "ISSUE"))
    ca_before, ca_after = huc.cert_bounds(ca_cert)
    now = huc.now_utc()
    if not ca_before <= now <= ca_after:
        raise ValueError("El certificado CA está fuera de vigencia")
    if not before <= now <= after:
        raise ValueError("El certificado X.509 está fuera de vigencia")
    return {"certificate_sha256": cert_hash, "consensus_certificate_sha256": cc_hash,
            "subject": cert.subject.rfc4514_string(), "serial_number": str(cert.serial_number),
            "huc_cc_signers": huc.verify_authority_signatures(policy, cc_payload, signatures, cc_payload.get("operation", "ISSUE"))["valid_signers"]}


def verify_certificate_on_node(node_dir: Path, certificate_path: Path,
                               consensus_certificate_path: Path) -> dict[str, Any]:
    network, _, _ = _node_context_without_state(node_dir)
    cert = huc.x509.load_pem_x509_certificate(Path(certificate_path).read_bytes())
    cc = _read(Path(consensus_certificate_path))
    cert_hash = huc.cert_hash(cert)
    cc_hash = huc.sha256(huc.canonical_json(cc))
    # For state lookup the operation is irrelevant; ISSUE/RENEW evidence is checked.
    evidence_payload = {
        "action": cc.get("payload", {}).get("operation"),
        "certificate_sha256": cert_hash,
        "consensus_certificate_sha256": cc_hash,
        "evidence": {"certificate_pem_b64": base64.b64encode(Path(certificate_path).read_bytes()).decode("ascii"),
                     "consensus_certificate": cc},
    }
    evidence_result = _validate_huc_evidence(network, evidence_payload)
    state = load_state(node_dir)
    item = state["certificates"].get(cert_hash)
    status = item["status"] if item else "NOT_REGISTERED"
    if item and item.get("consensus_certificate_sha256") != cc_hash:
        raise ValueError("El HUC-CC presentado no coincide con el certificado complementario registrado")
    active = status == "ACTIVE"
    result = "VALID" if active else ("INVALID" if status in {"REVOKED", "SUPERSEDED"} else "INDETERMINATE")
    return {"result": result, "hybrid_valid": active, "utxo_status": status,
            "certificate_sha256": cert_hash, "consensus_certificate_sha256": cc_hash,
            "outpoint": item.get("outpoint") if item else None,
            "subject": evidence_result["subject"], "serial_number": evidence_result["serial_number"],
            "huc_cc_signers": evidence_result["huc_cc_signers"],
            "replicated_sequence": state["sequence"], "network_id": network["network_id"]}


def _check_transition(state: dict[str, Any], payload: dict[str, Any]) -> None:
    action = payload.get("action")
    cert_hash = payload.get("certificate_sha256")
    cc_hash = payload.get("consensus_certificate_sha256")
    previous_hash = payload.get("previous_certificate_sha256")
    previous_outpoint = payload.get("previous_outpoint")
    certs = state["certificates"]
    _validate_hash(cert_hash, "certificate_sha256")
    _validate_hash(cc_hash, "consensus_certificate_sha256")
    if action == "ISSUE":
        if cert_hash in certs or previous_hash is not None or previous_outpoint is not None:
            raise ValueError("ISSUE inválido: certificado duplicado o entrada anterior inesperada")
    elif action == "RENEW":
        if not isinstance(previous_hash, str) or previous_hash not in certs:
            raise ValueError("RENEW requiere certificado anterior conocido")
        old = certs[previous_hash]
        if old.get("status") != "ACTIVE" or old.get("outpoint") != previous_outpoint:
            raise ValueError("RENEW no consume el outpoint activo exacto")
        if cert_hash in certs or cert_hash == previous_hash:
            raise ValueError("RENEW debe crear un certificado nuevo")
    elif action == "REVOKE":
        if cert_hash not in certs or previous_hash is not None:
            raise ValueError("REVOKE requiere un certificado activo existente")
        old = certs[cert_hash]
        if old.get("status") != "ACTIVE" or old.get("outpoint") != previous_outpoint:
            raise ValueError("REVOKE no consume el outpoint activo exacto")
        if old.get("consensus_certificate_sha256") != cc_hash:
            raise ValueError("REVOKE debe referenciar el HUC-CC vigente")
    else:
        raise ValueError(f"Acción no permitida: {action}")
    if not isinstance(payload.get("metadata"), dict):
        raise ValueError("metadata debe ser un objeto JSON")
    if action == "REVOKE":
        reason = payload["metadata"].get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("REVOKE requiere metadata.reason no vacío")


def create_proposal(node_dir: Path, action: str, certificate_sha256: str,
                    consensus_certificate_sha256: str, output: Path,
                    previous_certificate_sha256: str | None = None,
                    metadata: dict[str, Any] | None = None,
                    expires_minutes: int = 10,
                    certificate_path: Path | None = None,
                    consensus_certificate_path: Path | None = None) -> dict[str, Any]:
    if expires_minutes < 1 or expires_minutes > MAX_PROPOSAL_MINUTES:
        raise ValueError(f"La propuesta debe expirar entre 1 y {MAX_PROPOSAL_MINUTES} minutos")
    network, descriptor, _ = _node_context(node_dir)
    state = load_state(node_dir)
    cert_hash = _validate_hash(certificate_sha256, "certificate_sha256")
    cc_hash = _validate_hash(consensus_certificate_sha256, "consensus_certificate_sha256")
    previous_outpoint = None
    if action in {"RENEW", "REVOKE"}:
        source_hash = previous_certificate_sha256 if action == "RENEW" else cert_hash
        if source_hash not in state["certificates"]:
            raise ValueError("Certificado anterior no está en el estado replicado")
        previous_outpoint = state["certificates"][source_hash].get("outpoint")
    payload = {
        "schema": PROPOSAL_SCHEMA,
        "network_id": network["network_id"],
        "epoch": state["epoch"],
        "sequence": state["sequence"] + 1,
        "previous_state_hash": state["head_hash"],
        "action": action,
        "certificate_sha256": cert_hash,
        "consensus_certificate_sha256": cc_hash,
        "previous_certificate_sha256": previous_certificate_sha256,
        "previous_outpoint": previous_outpoint,
        "created_at_utc": huc.iso(),
        "expires_at_utc": huc.iso(huc.now_utc() + timedelta(minutes=expires_minutes)),
        "metadata": metadata or {},
    }
    if network.get("pki"):
        if not certificate_path or not consensus_certificate_path:
            raise ValueError("La red exige --certificate y --consensus-certificate para validar evidencia")
        cert_raw = Path(certificate_path).read_bytes()
        cc_obj = _read(Path(consensus_certificate_path))
        payload["evidence"] = {
            "certificate_pem_b64": base64.b64encode(cert_raw).decode("ascii"),
            "consensus_certificate": cc_obj,
        }
    _check_transition(state, payload)
    _validate_huc_evidence(network, payload)
    proposal = {"payload": payload, "proposal_id": _hash(payload)}
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, proposal, 0o644)
    return {"result": "proposal_created", "proposal_id": proposal["proposal_id"],
            "sequence": payload["sequence"], "action": action, "proposer": descriptor["validator_id"],
            "proposal_file": str(output.resolve()), "expires_at_utc": payload["expires_at_utc"]}


def _validate_proposal_for_state(proposal: dict[str, Any], network: dict[str, Any],
                                  state: dict[str, Any], check_expiry: bool) -> dict[str, Any]:
    payload = _proposal_payload(proposal)
    if payload.get("network_id") != network["network_id"]:
        raise ValueError("Propuesta de otra red")
    if payload.get("epoch") != state["epoch"] or payload.get("sequence") != state["sequence"] + 1:
        raise ValueError("Propuesta obsoleta: epoch o secuencia no coinciden")
    if payload.get("previous_state_hash") != state["head_hash"]:
        raise ValueError("Propuesta basada en un estado padre diferente")
    created = _parse_time(payload.get("created_at_utc", ""))
    expires = _parse_time(payload.get("expires_at_utc", ""))
    if expires <= created or expires - created > timedelta(minutes=MAX_PROPOSAL_MINUTES):
        raise ValueError("Ventana de expiración de propuesta inválida")
    if check_expiry:
        now = huc.now_utc()
        if created > now + timedelta(minutes=2):
            raise ValueError("Propuesta fechada en el futuro")
        if now > expires:
            raise ValueError("Propuesta expirada")
    _check_transition(state, payload)
    _validate_huc_evidence(network, payload)
    return payload


def _vote_message(vote_payload: dict[str, Any]) -> bytes:
    return _canonical({"domain": "LAEV-HUC-RSP-VOTE-SIGNATURE-0.6", "payload": vote_payload})


def vote_proposal(node_dir: Path, proposal_path: Path, output: Path) -> dict[str, Any]:
    network, descriptor, key = _node_context(node_dir)
    proposal = _read(proposal_path)
    validator_id = descriptor["validator_id"]
    lock_path = node_dir / NODE_LOCK
    try:
        with FileLock(str(lock_path), timeout=10):
            state = load_state(node_dir)
            payload = _validate_proposal_for_state(proposal, network, state, check_expiry=True)
            if (node_dir / "view-state.json").exists():
                import huc_view
                huc_view.validate_proposal_view(node_dir, proposal)
            slot = f"{payload['epoch']}:{payload['sequence']}"
            locks = _read(node_dir / VOTE_LOCKS)
            existing = locks.get("locks", {}).get(slot)
            if existing:
                if existing.get("proposal_id") != proposal["proposal_id"]:
                    raise ValueError("Anti-equivocación: este nodo ya votó otra propuesta para este slot")
                vote = existing["vote"]
            else:
                vote_payload = {
                    "schema": VOTE_SCHEMA,
                    "network_id": network["network_id"],
                    "epoch": payload["epoch"],
                    "sequence": payload["sequence"],
                    "previous_state_hash": payload["previous_state_hash"],
                    "proposal_id": proposal["proposal_id"],
                    "validator_id": validator_id,
                    "decision": "APPROVE",
                    "voted_at_utc": huc.iso(),
                }
                signature = base64.b64encode(key.sign(_vote_message(vote_payload))).decode("ascii")
                vote = {"payload": vote_payload, "signature": signature}
                locks.setdefault("locks", {})[slot] = {"proposal_id": proposal["proposal_id"], "vote": vote}
                _write(node_dir / VOTE_LOCKS, locks)
            output.parent.mkdir(parents=True, exist_ok=True)
            _write(output, vote, 0o644)
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear el almacén de votos") from exc
    return {"result": "vote_signed", "validator_id": validator_id,
            "proposal_id": proposal["proposal_id"], "vote_file": str(output.resolve())}


def verify_vote(network: dict[str, Any], proposal: dict[str, Any], vote: dict[str, Any]) -> None:
    payload = _proposal_payload(proposal)
    vp = vote.get("payload")
    if not isinstance(vp, dict) or vp.get("schema") != VOTE_SCHEMA:
        raise ValueError("Formato de voto no reconocido")
    validator_id = vp.get("validator_id")
    validator = _validator(network, validator_id)
    expected = {
        "network_id": payload["network_id"],
        "epoch": payload["epoch"],
        "sequence": payload["sequence"],
        "previous_state_hash": payload["previous_state_hash"],
        "proposal_id": proposal["proposal_id"],
        "decision": "APPROVE",
    }
    for key, value in expected.items():
        if vp.get(key) != value:
            raise ValueError(f"Voto no corresponde a propuesta: {key}")
    voted_at = _parse_time(vp.get("voted_at_utc", ""))
    created = _parse_time(payload["created_at_utc"])
    expires = _parse_time(payload["expires_at_utc"])
    if not created <= voted_at <= expires:
        raise ValueError("Voto fuera de la ventana temporal de la propuesta")
    _verify_sig(validator["public_key_pem"], vote.get("signature", ""), _vote_message(vp))


def assemble_commit(node_dir: Path, proposal_path: Path, vote_paths: list[Path], output: Path) -> dict[str, Any]:
    network, _, _ = _node_context(node_dir)
    state = load_state(node_dir)
    proposal = _read(proposal_path)
    _validate_proposal_for_state(proposal, network, state, check_expiry=False)
    votes = [_read(p) for p in vote_paths]
    seen: set[str] = set()
    valid_votes = []
    for vote in votes:
        verify_vote(network, proposal, vote)
        validator_id = vote["payload"]["validator_id"]
        if validator_id in seen:
            raise ValueError("Un validador no puede aportar dos votos al mismo quórum")
        seen.add(validator_id)
        valid_votes.append(vote)
    if len(valid_votes) < network["quorum"]:
        raise ValueError(f"Quórum insuficiente: se requieren {network['quorum']} votos distintos")
    valid_votes.sort(key=lambda item: item["payload"]["validator_id"])
    body = {
        "schema": COMMIT_SCHEMA,
        "network_id": network["network_id"],
        "proposal": proposal,
        "votes": valid_votes,
        "quorum": network["quorum"],
        "committed_at_utc": huc.iso(),
    }
    commit = {"body": body, "commit_id": _hash(body)}
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, commit, 0o644)
    return {"result": "commit_certificate_assembled", "commit_id": commit["commit_id"],
            "proposal_id": proposal["proposal_id"], "valid_votes": len(valid_votes),
            "quorum": network["quorum"], "commit_file": str(output.resolve())}


def _verify_commit(network: dict[str, Any], state: dict[str, Any], commit: dict[str, Any]) -> tuple[dict[str, Any], str]:
    body = commit.get("body")
    if not isinstance(body, dict) or body.get("schema") != COMMIT_SCHEMA:
        raise ValueError("Certificado de commit no reconocido")
    if commit.get("commit_id") != _hash(body):
        raise ValueError("commit_id inválido")
    if body.get("network_id") != network["network_id"] or body.get("quorum") != network["quorum"]:
        raise ValueError("Commit de otra red o con quórum incorrecto")
    proposal = body.get("proposal")
    payload = _validate_proposal_for_state(proposal, network, state, check_expiry=False)
    votes = body.get("votes")
    if not isinstance(votes, list):
        raise ValueError("Commit sin lista de votos")
    seen: set[str] = set()
    for vote in votes:
        verify_vote(network, proposal, vote)
        validator_id = vote["payload"]["validator_id"]
        if validator_id in seen:
            raise ValueError("Votos duplicados en commit")
        seen.add(validator_id)
    if len(seen) < network["quorum"]:
        raise ValueError("Commit sin quórum suficiente")
    return payload, commit["commit_id"]


def _apply_payload(state: dict[str, Any], payload: dict[str, Any], commit_id: str) -> dict[str, Any]:
    action = payload["action"]
    cert_hash = payload["certificate_sha256"]
    cc_hash = payload["consensus_certificate_sha256"]
    previous_hash = payload.get("previous_certificate_sha256")
    outpoint = {"txid": payload.get("proposal_id") or None, "vout": 0}
    # The proposal identifier is assigned by the caller through the payload wrapper.
    if action == "ISSUE":
        state["certificates"][cert_hash] = {
            "status": "ACTIVE", "consensus_certificate_sha256": cc_hash,
            "outpoint": outpoint,
        }
    elif action == "RENEW":
        old = state["certificates"][previous_hash]
        old["status"] = "SUPERSEDED"
        old["consumed_by_commit"] = commit_id
        old.pop("outpoint", None)
        state["certificates"][cert_hash] = {
            "status": "ACTIVE", "consensus_certificate_sha256": cc_hash,
            "outpoint": outpoint,
        }
    elif action == "REVOKE":
        old = state["certificates"][cert_hash]
        old["status"] = "REVOKED"
        old["consumed_by_commit"] = commit_id
        old.pop("outpoint", None)
    state["epoch"] = payload["epoch"]
    state["sequence"] = payload["sequence"]
    state["head_hash"] = commit_id
    state["commit_ids"].append(commit_id)
    return state


def _apply_commit_to_state(network: dict[str, Any], state: dict[str, Any], commit: dict[str, Any]) -> dict[str, Any]:
    payload, commit_id = _verify_commit(network, state, commit)
    # Make a copy to ensure validation failures never partially mutate caller state.
    next_state = json.loads(json.dumps(state))
    _check_transition(next_state, payload)
    transition_payload = dict(payload)
    transition_payload["proposal_id"] = commit["body"]["proposal"]["proposal_id"]
    return _apply_payload(next_state, transition_payload, commit_id)


def _read_commits(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"No existe el registro replicado: {path}")
    commits = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = huc.strict_json_loads(line)
        except Exception as exc:
            raise ValueError(f"Commit JSON inválido en línea {line_no}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"Commit inválido en línea {line_no}")
        commits.append(obj)
    return commits


def _replay(network: dict[str, Any], commits: list[dict[str, Any]],
            checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
    if checkpoint is not None:
        # Imported lazily to avoid a module cycle: membership uses this module
        # for the existing network/commit validation primitives.
        import huc_membership
        state = huc_membership.verify_epoch_checkpoint(network, checkpoint)
    else:
        state = _genesis_state(network)
    for commit in commits:
        state = _apply_commit_to_state(network, state, commit)
    return state


def load_state(node_dir: Path) -> dict[str, Any]:
    network, _, _ = _node_context_without_state(node_dir)
    commits = _read_commits(node_dir / LEDGER_FILE)
    checkpoint_path = node_dir / CHECKPOINT_FILE
    checkpoint = _read(checkpoint_path) if checkpoint_path.exists() else None
    state = _replay(network, commits, checkpoint)
    stored_path = node_dir / STATE_FILE
    if stored_path.exists():
        try:
            stored = _read(stored_path)
        except ValueError:
            stored = None
        if stored != state:
            # The signed commit log is authoritative; the snapshot is only a cache.
            _write(stored_path, state)
    else:
        _write(stored_path, state)
    return state


def _node_context_without_state(node_dir: Path) -> tuple[dict[str, Any], dict[str, Any], ed25519.Ed25519PrivateKey]:
    network = load_network(node_dir)
    descriptor = _read(node_dir / NODE_PUBLIC)
    validator = _validator(network, descriptor["validator_id"])
    if validator["public_key_pem"] != descriptor["public_key_pem"]:
        raise ValueError("Descriptor de nodo no coincide con manifiesto")
    key = _private(node_dir / NODE_PRIVATE)
    if _pub_pem_text(key.public_key()) != descriptor["public_key_pem"]:
        raise ValueError("Clave privada local no corresponde a nodo")
    return network, descriptor, key


def apply_commit(node_dir: Path, commit_path: Path) -> dict[str, Any]:
    node_dir = node_dir.resolve()
    network, descriptor, _ = _node_context_without_state(node_dir)
    lock = FileLock(str(node_dir / NODE_LOCK), timeout=15)
    try:
        with lock:
            commits = _read_commits(node_dir / LEDGER_FILE)
            checkpoint_path = node_dir / CHECKPOINT_FILE
            checkpoint = _read(checkpoint_path) if checkpoint_path.exists() else None
            state = _replay(network, commits, checkpoint)
            commit = _read(commit_path)
            commit_id = commit.get("commit_id")
            if commit_id in state["commit_ids"]:
                return {"result": "already_applied", "validator_id": descriptor["validator_id"],
                        "commit_id": commit_id, "sequence": state["sequence"]}
            next_state = _apply_commit_to_state(network, state, commit)
            with (node_dir / LEDGER_FILE).open("ab") as handle:
                handle.write(_canonical(commit) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            _write(node_dir / STATE_FILE, next_state)
            if (node_dir / "view-state.json").exists():
                import huc_view
                huc_view.clear_recovery_after_commit(node_dir, commit)
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear el ledger replicado") from exc
    return {"result": "commit_applied", "validator_id": descriptor["validator_id"],
            "commit_id": commit_id, "sequence": next_state["sequence"],
            "state_hash": next_state["head_hash"]}


def export_state(node_dir: Path, output: Path) -> dict[str, Any]:
    network, descriptor, _ = _node_context_without_state(node_dir)
    state = load_state(node_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": SYNC_SCHEMA,
        "network_id": network["network_id"],
        "network_sha256": network_hash(network),
        "sequence": state["sequence"],
        "head_hash": state["head_hash"],
        "exported_by": descriptor["validator_id"],
        "exported_at_utc": huc.iso(),
        "private_keys_included": False,
    }
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(node_dir / NETWORK_FILE, NETWORK_FILE)
        zf.write(node_dir / LEDGER_FILE, LEDGER_FILE)
        checkpoint_path = node_dir / CHECKPOINT_FILE
        if checkpoint_path.exists():
            zf.write(checkpoint_path, CHECKPOINT_FILE)
        zf.writestr("sync_manifest.json", json.dumps(manifest, indent=2) + "\n")
    return {"result": "state_package_created", "sequence": state["sequence"],
            "head_hash": state["head_hash"], "package": str(output.resolve()),
            "private_keys_included": False}


def _safe_extract(package: Path, target: Path) -> None:
    with zipfile.ZipFile(package, "r") as zf:
        total = sum(i.file_size for i in zf.infolist())
        if total > 50 * 1024 * 1024:
            raise ValueError("Paquete de sincronización supera 50 MiB")
        for info in zf.infolist():
            dest = (target / info.filename).resolve()
            if target.resolve() not in dest.parents and dest != target.resolve():
                raise ValueError("El paquete contiene una ruta no permitida")
        zf.extractall(target)


def sync_state(node_dir: Path, package: Path) -> dict[str, Any]:
    node_dir = node_dir.resolve()
    network, descriptor, _ = _node_context_without_state(node_dir)
    with tempfile.TemporaryDirectory(prefix="huc-rsp-sync-") as td:
        root = Path(td)
        _safe_extract(package, root)
        incoming_network = validate_network(_read(root / NETWORK_FILE))
        if (incoming_network["network_id"] != network["network_id"]
                or network_hash(incoming_network) != network_hash(network)):
            raise ValueError("El paquete de sincronización pertenece a otra red o manifiesto")
        manifest = _read(root / "sync_manifest.json")
        if manifest.get("schema") != SYNC_SCHEMA or manifest.get("network_id") != network["network_id"]:
            raise ValueError("Manifiesto de sincronización no reconocido")
        if manifest.get("network_sha256") != network_hash(network):
            raise ValueError("Huella de red del paquete no coincide")
        incoming_commits = _read_commits(root / LEDGER_FILE)
        incoming_checkpoint_path = root / CHECKPOINT_FILE
        incoming_checkpoint = _read(incoming_checkpoint_path) if incoming_checkpoint_path.exists() else None
    current_checkpoint_path = node_dir / CHECKPOINT_FILE
    current_checkpoint = _read(current_checkpoint_path) if current_checkpoint_path.exists() else None
    if ((incoming_checkpoint is None) != (current_checkpoint is None)
            or (incoming_checkpoint is not None and current_checkpoint is not None
                and incoming_checkpoint.get("membership_certificate_id") != current_checkpoint.get("membership_certificate_id"))):
        raise ValueError("Sync rechazado: checkpoint de época distinto; requiere reconfiguración autorizada")
    rebuilt = _replay(network, incoming_commits, incoming_checkpoint)
    if rebuilt["sequence"] != manifest.get("sequence") or rebuilt["head_hash"] != manifest.get("head_hash"):
        raise ValueError("Snapshot o manifiesto no coincide con el ledger")
    try:
        with FileLock(str(node_dir / NODE_LOCK), timeout=15):
            current_commits = _read_commits(node_dir / LEDGER_FILE)
            if len(incoming_commits) < len(current_commits):
                raise ValueError("Sync rechazada: rollback de estado")
            for index, local_commit in enumerate(current_commits):
                if local_commit.get("commit_id") != incoming_commits[index].get("commit_id"):
                    raise ValueError("Sync rechazada: bifurcación respecto del historial local")
            huc.atomic_write(node_dir / LEDGER_FILE,
                             b"".join(_canonical(c) + b"\n" for c in incoming_commits))
            _write(node_dir / STATE_FILE, rebuilt)
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear el estado local durante la sincronización") from exc
    return {"result": "state_synchronized", "validator_id": descriptor["validator_id"],
            "sequence": rebuilt["sequence"], "head_hash": rebuilt["head_hash"],
            "commit_count": len(incoming_commits)}


def node_status(node_dir: Path) -> dict[str, Any]:
    network, descriptor, _ = _node_context_without_state(node_dir)
    state = load_state(node_dir)
    return {
        "validator_id": descriptor["validator_id"],
        "network_id": network["network_id"],
        "validator_count": len(network["validators"]),
        "fault_tolerance": network["fault_tolerance"],
        "quorum": network["quorum"],
        "sequence": state["sequence"],
        "head_hash": state["head_hash"],
        "certificate_count": len(state["certificates"]),
        "active_certificates": sum(1 for x in state["certificates"].values() if x["status"] == "ACTIVE"),
        "replicated_commit_count": len(state["commit_ids"]),
    }


def _print_result(result: dict[str, Any]) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LAEV HUC 0.6: estado replicado sin coordinador fijo ni blockchain")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("node-init", help="Crear identidad criptográfica local de un validador")
    p.add_argument("--id", required=True)
    p.add_argument("--out-dir", type=Path, required=True)

    p = sub.add_parser("network-create", help="Crear manifiesto estático 3f+1 / 2f+1")
    p.add_argument("--validator-public", type=Path, nargs="+", required=True)
    p.add_argument("--fault-tolerance", type=int, default=1)
    p.add_argument("--ca-certificate", type=Path, help="Certificado raíz X.509 público de la CA HUC")
    p.add_argument("--consensus-policy", type=Path, help="Política pública HUC-CC")
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("join", help="Enrolar un nodo mediante un pin externo del manifiesto")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--network", type=Path, required=True)
    p.add_argument("--network-sha256", required=True)

    p = sub.add_parser("propose", help="Crear una transición; cualquier participante puede proponer")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--action", choices=["ISSUE", "RENEW", "REVOKE"], required=True)
    p.add_argument("--certificate-sha256", required=True)
    p.add_argument("--consensus-sha256", required=True)
    p.add_argument("--previous-certificate-sha256")
    p.add_argument("--metadata", default="{}")
    p.add_argument("--expires-minutes", type=int, default=10)
    p.add_argument("--certificate", type=Path, help="X.509 PEM asociado a la transición")
    p.add_argument("--consensus-certificate", type=Path, help="HUC-CC JSON asociado a la transición")
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("vote", help="Validar localmente y firmar como validador independiente")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("commit", help="Ensamblar certificado de quórum; no exige rol especial")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--vote", type=Path, nargs="+", required=True)
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("apply", help="Aplicar un commit válido al estado local replicado")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--commit", type=Path, required=True)

    p = sub.add_parser("export-state", help="Empaquetar ledger público para sincronización entre nodos")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("sync-state", help="Verificar y sincronizar un historial de otro nodo")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--package", type=Path, required=True)

    p = sub.add_parser("status", help="Mostrar estado replicado local")
    p.add_argument("--node-dir", type=Path, required=True)

    p = sub.add_parser("verify-certificate", help="Verificar X.509 + HUC-CC + estado replicado")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--certificate", type=Path, required=True)
    p.add_argument("--consensus-certificate", type=Path, required=True)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "node-init":
            result = node_init(args.id, args.out_dir)
        elif args.command == "network-create":
            result = create_network(args.validator_public, args.output, args.fault_tolerance,
                                    args.ca_certificate, args.consensus_policy)
        elif args.command == "join":
            result = node_join(args.node_dir, args.network, args.network_sha256)
        elif args.command == "propose":
            metadata = huc.strict_json_loads(args.metadata)
            if not isinstance(metadata, dict):
                raise ValueError("metadata debe ser un objeto JSON")
            result = create_proposal(args.node_dir, args.action, args.certificate_sha256,
                                     args.consensus_sha256, args.output,
                                     args.previous_certificate_sha256, metadata, args.expires_minutes,
                                     args.certificate, args.consensus_certificate)
        elif args.command == "vote":
            result = vote_proposal(args.node_dir, args.proposal, args.output)
        elif args.command == "commit":
            result = assemble_commit(args.node_dir, args.proposal, args.vote, args.output)
        elif args.command == "apply":
            result = apply_commit(args.node_dir, args.commit)
        elif args.command == "export-state":
            result = export_state(args.node_dir, args.output)
        elif args.command == "sync-state":
            result = sync_state(args.node_dir, args.package)
        elif args.command == "status":
            result = node_status(args.node_dir)
        elif args.command == "verify-certificate":
            result = verify_certificate_on_node(args.node_dir, args.certificate, args.consensus_certificate)
        else:
            parser.error("Comando desconocido")
            return 2
        _print_result(result)
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
