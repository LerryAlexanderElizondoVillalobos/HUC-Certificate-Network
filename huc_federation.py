#!/usr/bin/env python3
"""LAEV HUC 0.5 — independently-held authority signing workflow.

This module implements an offline/file-transfer federation workflow. Each
authority owns its Ed25519 private key in a separate authority directory.
The coordinator receives only public descriptors and signed approval files.
It is not a BFT consensus protocol or a distributed ledger network.
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

import huc
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

FED_VERSION = "0.5.0"
AUTHORITY_SCHEMA = "LAEV-HUC-AUTHORITY-1"
PROPOSAL_SCHEMA = "LAEV-HUC-DISTRIBUTED-PROPOSAL-1"
APPROVAL_SCHEMA = "LAEV-HUC-DISTRIBUTED-APPROVAL-1"
ENROLLMENT_SCHEMA = "LAEV-HUC-AUTHORITY-ENROLLMENT-1"
SYNC_SCHEMA = "LAEV-HUC-STATE-SYNC-1"
AUTHORITY_PUBLIC = "authority-public.json"
AUTHORITY_PRIVATE = "authority-private.pem"
AUTHORITY_TRUST = "authority-trust.json"
APPROVAL_LOCKS = "approval-locks.json"
TRUST_DIR = "trust"
MAX_PROPOSAL_MINUTES = 60


def _write_json(path: Path, obj: Any, mode: int = 0o600) -> None:
    huc.write_json(path, obj, mode)


def _read_json(path: Path) -> dict[str, Any]:
    return huc.read_json(path)


def _private(path: Path) -> ed25519.Ed25519PrivateKey:
    key = huc.load_private(path)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada de autoridad debe ser Ed25519")
    return key


def _utc_parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError("Fecha UTC inválida") from exc
    if parsed.tzinfo is None:
        raise ValueError("La fecha debe incluir zona horaria")
    return parsed.astimezone(timezone.utc)


def _proposal_core(proposal: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in proposal.items() if k != "proposal_id"}


def proposal_hash(proposal: dict[str, Any]) -> str:
    return huc.sha256(huc.canonical_json(_proposal_core(proposal)))


def _approval_domain(proposal: dict[str, Any]) -> bytes:
    return huc.canonical_json({
        "domain": "LAEV-HUC-AUTHORITY-APPROVAL-PROPOSAL-1",
        "proposal_id": proposal["proposal_id"],
    })


def _signing_envelope(domain: str, payload: dict[str, Any]) -> bytes:
    return huc.canonical_json({"domain": domain, "payload": payload})


def _verify_signature(public_pem: str, signature_b64: str, message: bytes) -> None:
    public_key = huc.load_ed_public_pem(public_pem)
    signature = base64.b64decode(signature_b64, validate=True)
    public_key.verify(signature, message)


def authority_init(authority_id: str, out_dir: Path,
                   permissions: list[str] | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", authority_id):
        raise ValueError("authority_id debe tener entre 3 y 64 caracteres seguros")
    permissions = sorted(set(permissions or ["ISSUE", "RENEW", "REVOKE"]))
    if not permissions or any(x not in {"ISSUE", "RENEW", "REVOKE"} for x in permissions):
        raise ValueError("Permisos permitidos: ISSUE, RENEW, REVOKE")
    out_dir = out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError("El directorio de autoridad ya contiene archivos; no se sobrescribe")
    out_dir.mkdir(parents=True, exist_ok=True)
    key = ed25519.Ed25519PrivateKey.generate()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    descriptor = {
        "schema": AUTHORITY_SCHEMA,
        "authority_id": authority_id,
        "algorithm": "Ed25519",
        "public_key_pem": public_pem,
        "public_key_sha256": huc.sha256(huc.der_public(key.public_key())),
        "permissions": permissions,
        "created_at_utc": huc.iso(),
    }
    huc.save_private(key, out_dir / AUTHORITY_PRIVATE)
    _write_json(out_dir / AUTHORITY_PUBLIC, descriptor, 0o644)
    _write_json(out_dir / APPROVAL_LOCKS, {"schema": "LAEV-HUC-APPROVAL-LOCKS-1", "locks": {}})
    return {
        "result": "authority_created",
        "authority_id": authority_id,
        "directory": str(out_dir),
        "public_descriptor": str(out_dir / AUTHORITY_PUBLIC),
        "private_key_file": str(out_dir / AUTHORITY_PRIVATE),
        "public_key_sha256": descriptor["public_key_sha256"],
        "warning": "La clave privada permanece en este dispositivo. No la envíes al coordinador ni la incluyas en paquetes.",
    }


def _safe_extract(package: Path, target: Path) -> None:
    with zipfile.ZipFile(package, "r") as zf:
        total = sum(info.file_size for info in zf.infolist())
        if total > 25 * 1024 * 1024:
            raise ValueError("El paquete supera el límite de 25 MiB")
        for info in zf.infolist():
            dest = (target / info.filename).resolve()
            if target.resolve() not in dest.parents and dest != target.resolve():
                raise ValueError("El paquete contiene una ruta no permitida")
        zf.extractall(target)


def _public_material_files(workspace: Path) -> list[tuple[Path, str]]:
    return [
        (workspace / huc.POLICY_FILE, huc.POLICY_FILE),
        (workspace / huc.ANCHOR_FILE, huc.ANCHOR_FILE),
        (workspace / huc.CA_CERT, huc.CA_CERT),
        (workspace / huc.LEDGER_PUB, huc.LEDGER_PUB),
        (workspace / huc.LEDGER_FILE, huc.LEDGER_FILE),
    ]


def export_enrollment(workspace: Path, authority_id: str, output: Path,
                      expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    trust = huc.trust_material(workspace, expected_anchor_sha256)
    authority = next((a for a in trust["policy"]["authorities"] if a["authority_id"] == authority_id), None)
    if authority is None:
        raise ValueError("La autoridad no figura en la política de consenso")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": ENROLLMENT_SCHEMA,
        "authority_id": authority_id,
        "trust_anchor_sha256": trust["anchor_sha256"],
        "policy_sha256": trust["policy_sha256"],
        "includes_private_keys": False,
    }
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for source, arcname in _public_material_files(workspace):
            zf.write(source, arcname)
        zf.writestr("enrollment_manifest.json", json.dumps(manifest, indent=2) + "\n")
    return {"enrollment_package": str(output.resolve()), "authority_id": authority_id,
            "trust_anchor_sha256": trust["anchor_sha256"], "private_keys_included": False}


def authority_enroll(authority_dir: Path, package: Path,
                     expected_anchor_sha256: str) -> dict[str, Any]:
    authority_dir = authority_dir.resolve()
    descriptor = _read_json(authority_dir / AUTHORITY_PUBLIC)
    key = _private(authority_dir / AUTHORITY_PRIVATE)
    derived_public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    if derived_public != descriptor.get("public_key_pem"):
        raise ValueError("La clave privada local no coincide con el descriptor público")
    trust_dir = authority_dir / TRUST_DIR
    if trust_dir.exists() and any(trust_dir.iterdir()):
        raise FileExistsError("La autoridad ya está enrolada; use sync para actualizar el estado")
    if trust_dir.exists():
        trust_dir.rmdir()
    with tempfile.TemporaryDirectory(prefix=".huc-enroll-", dir=authority_dir) as stage_root:
        staging = Path(stage_root) / TRUST_DIR
        staging.mkdir()
        with tempfile.TemporaryDirectory(prefix="huc-enroll-package-") as tmp:
            temp = Path(tmp)
            _safe_extract(package, temp)
            manifest = _read_json(temp / "enrollment_manifest.json")
            if manifest.get("schema") != ENROLLMENT_SCHEMA:
                raise ValueError("Paquete de enrolamiento no reconocido")
            if manifest.get("authority_id") != descriptor.get("authority_id"):
                raise ValueError("El paquete está dirigido a otra autoridad")
            for name in [huc.POLICY_FILE, huc.ANCHOR_FILE, huc.CA_CERT, huc.LEDGER_PUB, huc.LEDGER_FILE]:
                shutil.copyfile(temp / name, staging / name)
            trust = huc.trust_material(staging, expected_anchor_sha256)
            if trust["anchor_sha256"] != manifest.get("trust_anchor_sha256"):
                raise ValueError("Huella del ancla no coincide con el manifiesto")
            if trust["policy_sha256"] != manifest.get("policy_sha256"):
                raise ValueError("Hash de política no coincide con el manifiesto")
            matching = next((a for a in trust["policy"]["authorities"]
                             if a["authority_id"] == descriptor["authority_id"]), None)
            if not matching or matching["public_key_pem"] != descriptor["public_key_pem"]:
                raise ValueError("La clave pública local no está registrada en la política")
            huc._ledger_state(staging, trust)
            trust_record = {
                "schema": "LAEV-HUC-AUTHORITY-TRUST-1",
                "authority_id": descriptor["authority_id"],
                "trust_anchor_sha256": trust["anchor_sha256"],
                "policy_sha256": trust["policy_sha256"],
                "enrolled_at_utc": huc.iso(),
            }
            _write_json(authority_dir / AUTHORITY_TRUST, trust_record)
            os.replace(staging, trust_dir)
    return {"result": "authority_enrolled", "authority_id": descriptor["authority_id"],
            "trust_anchor_sha256": trust["anchor_sha256"],
            "policy_sha256": trust["policy_sha256"],
            "ledger_event_count": huc._ledger_state(trust_dir, trust)["event_count"]}


def export_state(workspace: Path, output: Path,
                 expected_anchor_sha256: str | None = None) -> dict[str, Any]:
    trust = huc.trust_material(workspace, expected_anchor_sha256)
    state = huc._ledger_state(workspace, trust)
    manifest = {
        "schema": SYNC_SCHEMA,
        "trust_anchor_sha256": trust["anchor_sha256"],
        "policy_sha256": trust["policy_sha256"],
        "event_count": state["event_count"],
        "last_event_hash": state["last_event_hash"],
        "includes_private_keys": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for source, arcname in _public_material_files(workspace):
            zf.write(source, arcname)
        zf.writestr("sync_manifest.json", json.dumps(manifest, indent=2) + "\n")
    return {"state_package": str(output.resolve()), "event_count": state["event_count"],
            "last_event_hash": state["last_event_hash"], "private_keys_included": False}


def _authority_sync_locked(authority_dir: Path, package: Path) -> dict[str, Any]:
    authority_dir = authority_dir.resolve()
    trust_record = _read_json(authority_dir / AUTHORITY_TRUST)
    trust_dir = authority_dir / TRUST_DIR
    with tempfile.TemporaryDirectory(prefix="huc-sync-") as tmp:
        temp = Path(tmp)
        _safe_extract(package, temp)
        manifest = _read_json(temp / "sync_manifest.json")
        if manifest.get("schema") != SYNC_SCHEMA:
            raise ValueError("Paquete de sincronización no reconocido")
        if manifest.get("trust_anchor_sha256") != trust_record.get("trust_anchor_sha256"):
            raise ValueError("El paquete pertenece a otra ancla de confianza")
        for name in [huc.POLICY_FILE, huc.ANCHOR_FILE, huc.CA_CERT, huc.LEDGER_PUB, huc.LEDGER_FILE]:
            shutil.copyfile(temp / name, temp / ("candidate-" + name))
        candidate_dir = temp / "candidate"
        candidate_dir.mkdir()
        for name in [huc.POLICY_FILE, huc.ANCHOR_FILE, huc.CA_CERT, huc.LEDGER_PUB, huc.LEDGER_FILE]:
            shutil.move(temp / ("candidate-" + name), candidate_dir / name)
        new_trust = huc.trust_material(candidate_dir, trust_record["trust_anchor_sha256"])
        if new_trust["policy_sha256"] != trust_record["policy_sha256"]:
            raise ValueError("La política cambió; requiere un procedimiento explícito de re-enrolamiento")
        old_lines = (trust_dir / huc.LEDGER_FILE).read_bytes().splitlines()
        new_lines = (candidate_dir / huc.LEDGER_FILE).read_bytes().splitlines()
        if len(new_lines) < len(old_lines) or new_lines[:len(old_lines)] != old_lines:
            raise ValueError("Se rechazó rollback o bifurcación del historial local")
        new_state = huc._ledger_state(candidate_dir, new_trust)
        if new_state["event_count"] != manifest.get("event_count") or new_state["last_event_hash"] != manifest.get("last_event_hash"):
            raise ValueError("Checkpoint del paquete no coincide con el ledger")
        old_state = huc._ledger_state(trust_dir, huc.trust_material(trust_dir, trust_record["trust_anchor_sha256"]))
        if new_state["event_count"] == old_state["event_count"] and new_state["last_event_hash"] != old_state["last_event_hash"]:
            raise ValueError("Checkpoint contradictorio")
        huc.atomic_write(trust_dir / huc.LEDGER_FILE,
                         (candidate_dir / huc.LEDGER_FILE).read_bytes(), 0o600)
        lock_path = authority_dir / APPROVAL_LOCKS
        if lock_path.exists():
            lock_data = _read_json(lock_path)
            retained = {}
            for key, item in lock_data.get("locks", {}).items():
                cp = item.get("checkpoint", {})
                if cp.get("event_count", new_state["event_count"]) >= new_state["event_count"]:
                    retained[key] = item
            _write_json(lock_path, {"schema": "LAEV-HUC-APPROVAL-LOCKS-1", "locks": retained})
    return {"result": "state_synchronized", "authority_id": trust_record["authority_id"],
            "event_count": new_state["event_count"], "last_event_hash": new_state["last_event_hash"]}


def authority_sync(authority_dir: Path, package: Path) -> dict[str, Any]:
    authority_dir = authority_dir.resolve()
    lock = huc.FileLock(str(authority_dir / ".authority-operation.lock"), timeout=20)
    try:
        with lock:
            return _authority_sync_locked(authority_dir, package)
    except huc.Timeout as exc:
        raise TimeoutError("No se pudo bloquear el almacén de autoridad para sincronización") from exc


def _build_transition_payload(workspace: Path, action: str, certificate_sha: str,
                              previous_certificate_sha: str | None = None,
                              previous_outpoint: dict[str, Any] | None = None,
                              reason: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    trust = huc.trust_material(workspace)
    state = huc._ledger_state(workspace, trust)
    if action == "ISSUE":
        if certificate_sha in state["statuses"] or previous_certificate_sha is not None or previous_outpoint is not None:
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
        raise ValueError("Operación desconocida")
    payload = {
        "schema": huc.LEDGER_SCHEMA,
        "sequence": state["event_count"],
        "previous_event_hash": state["last_event_hash"],
        "action": action,
        "certificate_sha256_der": certificate_sha,
        "previous_certificate_sha256_der": previous_certificate_sha,
        "previous_outpoint": previous_outpoint,
        "output": None,
        "created_at_utc": huc.iso(),
        "reason": reason,
    }
    txid = huc.sha256(huc.canonical_json({k: v for k, v in payload.items() if k != "output"}))
    if action in {"ISSUE", "RENEW"}:
        payload["output"] = {"txid": txid, "vout": 0}
    checkpoint = {"event_count": state["event_count"], "last_event_hash": state["last_event_hash"]}
    return payload, checkpoint


def _make_proposal(workspace: Path, action: str, cert: Any,
                   transition_payload: dict[str, Any], checkpoint: dict[str, Any],
                   cc_payload: dict[str, Any] | None, previous_certificate_sha: str | None,
                   expires_minutes: int,
                   previous_certificate_pem: str | None = None) -> dict[str, Any]:
    if not 1 <= expires_minutes <= MAX_PROPOSAL_MINUTES:
        raise ValueError(f"La propuesta debe expirar entre 1 y {MAX_PROPOSAL_MINUTES} minutos")
    trust = huc.trust_material(workspace)
    core = {
        "schema": PROPOSAL_SCHEMA,
        "protocol_version": FED_VERSION,
        "operation": action,
        "created_at_utc": huc.iso(),
        "expires_at_utc": huc.iso(datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)),
        "trust_anchor_sha256": trust["anchor_sha256"],
        "policy_sha256": trust["policy_sha256"],
        "policy_id": trust["policy"]["policy_id"],
        "ledger_checkpoint": checkpoint,
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "certificate_sha256_der": huc.cert_hash(cert),
        "previous_certificate_sha256_der": previous_certificate_sha,
        "previous_certificate_pem": previous_certificate_pem,
        "transition_payload": transition_payload,
        "consensus_certificate_payload": cc_payload,
    }
    proposal = {**core, "proposal_id": huc.sha256(huc.canonical_json(core))}
    return proposal


def prepare_issue(workspace: Path, csr_path: Path, output: Path,
                  days: int = 365, expires_minutes: int = 30) -> dict[str, Any]:
    csr = huc.validate_csr(csr_path)
    trust = huc.trust_material(workspace)
    ca_key = huc.load_private(workspace / huc.CA_KEY)
    cert = huc.make_certificate(csr, ca_key, trust["ca_cert"], days)
    digest = huc.cert_hash(cert)
    transition, checkpoint = _build_transition_payload(workspace, "ISSUE", digest)
    cc_payload = huc._build_cc_payload(workspace, cert, transition["output"], "ISSUE", transition["sequence"])
    proposal = _make_proposal(workspace, "ISSUE", cert, transition, checkpoint, cc_payload, None, expires_minutes)
    _write_json(output, proposal, 0o644)
    return {"proposal": str(output.resolve()), "proposal_id": proposal["proposal_id"],
            "operation": "ISSUE", "certificate_sha256_der": digest,
            "required_signatures": trust["policy"]["threshold"],
            "expires_at_utc": proposal["expires_at_utc"]}


def prepare_renew(workspace: Path, old_certificate_path: Path, csr_path: Path,
                  output: Path, days: int = 365, expires_minutes: int = 30) -> dict[str, Any]:
    old_cert = huc.x509.load_pem_x509_certificate(old_certificate_path.read_bytes())
    csr = huc.validate_csr(csr_path)
    if old_cert.subject != csr.subject:
        raise ValueError("El sujeto del CSR debe coincidir con el certificado anterior")
    trust = huc.trust_material(workspace)
    huc._verify_leaf_signature(old_cert, trust["ca_cert"])
    state = huc._ledger_state(workspace, trust)
    old_hash = huc.cert_hash(old_cert)
    old_outpoint = state["active"].get(old_hash)
    if not old_outpoint:
        raise ValueError("El certificado anterior no está activo")
    ca_key = huc.load_private(workspace / huc.CA_KEY)
    cert = huc.make_certificate(csr, ca_key, trust["ca_cert"], days)
    digest = huc.cert_hash(cert)
    transition, checkpoint = _build_transition_payload(workspace, "RENEW", digest,
                                                        old_hash, old_outpoint)
    cc_payload = huc._build_cc_payload(workspace, cert, transition["output"], "RENEW", transition["sequence"])
    old_pem = old_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    proposal = _make_proposal(workspace, "RENEW", cert, transition, checkpoint, cc_payload,
                              old_hash, expires_minutes, old_pem)
    _write_json(output, proposal, 0o644)
    return {"proposal": str(output.resolve()), "proposal_id": proposal["proposal_id"],
            "operation": "RENEW", "certificate_sha256_der": digest,
            "previous_certificate_sha256_der": old_hash,
            "required_signatures": trust["policy"]["threshold"],
            "expires_at_utc": proposal["expires_at_utc"]}


def prepare_revoke(workspace: Path, certificate_path: Path, reason: str,
                   output: Path, expires_minutes: int = 30) -> dict[str, Any]:
    if not reason.strip():
        raise ValueError("La revocación requiere un motivo")
    cert = huc.x509.load_pem_x509_certificate(certificate_path.read_bytes())
    trust = huc.trust_material(workspace)
    huc._verify_leaf_signature(cert, trust["ca_cert"])
    digest = huc.cert_hash(cert)
    state = huc._ledger_state(workspace, trust)
    outpoint = state["active"].get(digest)
    if not outpoint:
        raise ValueError("El certificado no está activo")
    transition, checkpoint = _build_transition_payload(workspace, "REVOKE", digest,
                                                        previous_outpoint=outpoint, reason=reason.strip())
    proposal = _make_proposal(workspace, "REVOKE", cert, transition, checkpoint, None,
                              None, expires_minutes)
    _write_json(output, proposal, 0o644)
    return {"proposal": str(output.resolve()), "proposal_id": proposal["proposal_id"],
            "operation": "REVOKE", "certificate_sha256_der": digest,
            "required_signatures": trust["policy"]["threshold"],
            "expires_at_utc": proposal["expires_at_utc"]}


def _validate_proposal(proposal: dict[str, Any]) -> None:
    if proposal.get("schema") != PROPOSAL_SCHEMA:
        raise ValueError("Formato de propuesta HUC distribuida desconocido")
    if proposal.get("proposal_id") != proposal_hash(proposal):
        raise ValueError("Hash de propuesta inválido")
    created = _utc_parse(proposal.get("created_at_utc", ""))
    expires = _utc_parse(proposal.get("expires_at_utc", ""))
    now = datetime.now(timezone.utc)
    if created > now + timedelta(minutes=2):
        raise ValueError("La propuesta tiene una fecha futura no válida")
    if expires <= now:
        raise ValueError("La propuesta expiró; debe generarse una nueva")
    if expires <= created or expires - created > timedelta(minutes=MAX_PROPOSAL_MINUTES):
        raise ValueError("La vigencia de la propuesta excede el límite protocolario")


def _authority_local_context(authority_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], ed25519.Ed25519PrivateKey]:
    descriptor = _read_json(authority_dir / AUTHORITY_PUBLIC)
    trust_record = _read_json(authority_dir / AUTHORITY_TRUST)
    private_key = _private(authority_dir / AUTHORITY_PRIVATE)
    trust_dir = authority_dir / TRUST_DIR
    trust = huc.trust_material(trust_dir, trust_record["trust_anchor_sha256"])
    if trust["policy_sha256"] != trust_record["policy_sha256"]:
        raise ValueError("La política local de la autoridad cambió")
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    if public_pem != descriptor.get("public_key_pem"):
        raise ValueError("Clave privada local no corresponde al descriptor público")
    authority = next((a for a in trust["policy"]["authorities"]
                      if a["authority_id"] == descriptor["authority_id"]), None)
    if not authority or authority["public_key_pem"] != public_pem:
        raise ValueError("La autoridad no está autorizada por la política fijada")
    return descriptor, trust_record, trust, private_key


def _authority_approve_locked(authority_dir: Path, proposal_path: Path, output: Path) -> dict[str, Any]:
    proposal = _read_json(proposal_path)
    _validate_proposal(proposal)
    descriptor, trust_record, trust, private_key = _authority_local_context(authority_dir)
    if proposal.get("trust_anchor_sha256") != trust_record["trust_anchor_sha256"]:
        raise ValueError("La propuesta pertenece a otro ancla de confianza")
    if proposal.get("policy_sha256") != trust_record["policy_sha256"]:
        raise ValueError("La propuesta utiliza otra política de consenso")
    operation = proposal.get("operation")
    if operation not in {"ISSUE", "RENEW", "REVOKE"}:
        raise ValueError("Operación no permitida")
    if operation not in descriptor.get("permissions", []):
        raise ValueError("Esta autoridad no tiene permiso para aprobar la operación")

    # Authorities must have the same verified, append-only state checkpoint.
    local_state = huc._ledger_state(authority_dir / TRUST_DIR, trust)
    checkpoint = proposal.get("ledger_checkpoint")
    if checkpoint != {"event_count": local_state["event_count"],
                      "last_event_hash": local_state["last_event_hash"]}:
        raise ValueError("Propuesta obsoleta: sincronice el ledger antes de aprobar")

    transition = proposal.get("transition_payload")
    if not isinstance(transition, dict) or transition.get("action") != operation:
        raise ValueError("Propuesta no contiene transición válida")
    cert = huc.x509.load_pem_x509_certificate(proposal["certificate_pem"].encode("ascii"))
    huc._verify_leaf_signature(cert, trust["ca_cert"])
    digest = huc.cert_hash(cert)
    if digest != proposal.get("certificate_sha256_der") or transition.get("certificate_sha256_der") != digest:
        raise ValueError("Hash del certificado no coincide con la propuesta")
    if transition.get("sequence") != local_state["event_count"] or transition.get("previous_event_hash") != local_state["last_event_hash"]:
        raise ValueError("La transición no corresponde al último checkpoint")
    txid = huc.sha256(huc.canonical_json({k: v for k, v in transition.items() if k != "output"}))
    expected_output = {"txid": txid, "vout": 0} if operation in {"ISSUE", "RENEW"} else None
    if transition.get("output") != expected_output:
        raise ValueError("Output UTXO incorrecto en la propuesta")

    if operation == "ISSUE":
        if digest in local_state["statuses"] or transition.get("previous_outpoint") is not None:
            raise ValueError("ISSUE duplicado o con entrada previa")
    elif operation == "RENEW":
        old_hash = proposal.get("previous_certificate_sha256_der")
        old_pem = proposal.get("previous_certificate_pem")
        if not isinstance(old_pem, str) or not old_pem:
            raise ValueError("RENEW no incluye el certificado anterior para revisión independiente")
        old_cert = huc.x509.load_pem_x509_certificate(old_pem.encode("ascii"))
        huc._verify_leaf_signature(old_cert, trust["ca_cert"])
        if huc.cert_hash(old_cert) != old_hash or old_cert.subject != cert.subject:
            raise ValueError("RENEW no demuestra continuidad del certificado anterior")
        if (old_hash != transition.get("previous_certificate_sha256_der")
                or local_state["active"].get(old_hash) != transition.get("previous_outpoint")):
            raise ValueError("RENEW no consume el UTXO activo local")
    elif operation == "REVOKE":
        if local_state["active"].get(digest) != transition.get("previous_outpoint"):
            raise ValueError("REVOKE no consume el UTXO activo local")
        if not isinstance(transition.get("reason"), str) or not transition["reason"].strip():
            raise ValueError("REVOKE requiere un motivo")

    cc_payload = proposal.get("consensus_certificate_payload")
    if operation in {"ISSUE", "RENEW"}:
        if not isinstance(cc_payload, dict):
            raise ValueError("Falta el payload HUC-CC")
        expected_cc = huc._build_cc_payload(authority_dir / TRUST_DIR, cert,
                                             transition["output"], operation,
                                             transition["sequence"])
        for key, value in expected_cc.items():
            if key != "issued_at_utc" and cc_payload.get(key) != value:
                raise ValueError(f"HUC-CC no coincide con transición: {key}")
    elif cc_payload is not None:
        raise ValueError("REVOKE no debe crear un nuevo HUC-CC")

    # Anti-equivocation guard: an authority does not sign two different
    # proposals for the same ledger checkpoint while the first is still live.
    checkpoint_key = huc.sha256(huc.canonical_json(checkpoint))
    locks_path = authority_dir / APPROVAL_LOCKS
    lock_data = _read_json(locks_path) if locks_path.exists() else {
        "schema": "LAEV-HUC-APPROVAL-LOCKS-1", "locks": {}
    }
    if lock_data.get("schema") != "LAEV-HUC-APPROVAL-LOCKS-1" or not isinstance(lock_data.get("locks"), dict):
        raise ValueError("Registro local de bloqueos de aprobación inválido")
    existing_lock = lock_data["locks"].get(checkpoint_key)
    if existing_lock and existing_lock.get("proposal_id") != proposal["proposal_id"]:
        old_expiry = _utc_parse(existing_lock.get("expires_at_utc", ""))
        if old_expiry > datetime.now(timezone.utc):
            raise ValueError("Anti-equivocación: ya existe una propuesta pendiente para este checkpoint")
    lock_data["locks"][checkpoint_key] = {
        "proposal_id": proposal["proposal_id"],
        "checkpoint": checkpoint,
        "operation": operation,
        "expires_at_utc": proposal["expires_at_utc"],
        "locked_at_utc": huc.iso(),
    }
    _write_json(locks_path, lock_data)

    proposal_sig = private_key.sign(_approval_domain(proposal))
    transition_sig = private_key.sign(huc.canonical_json(transition))
    cc_sig = (private_key.sign(huc.canonical_json(cc_payload))
              if cc_payload is not None else None)
    approval = {
        "schema": APPROVAL_SCHEMA,
        "proposal_id": proposal["proposal_id"],
        "authority_id": descriptor["authority_id"],
        "approved_at_utc": huc.iso(),
        "proposal_signature": base64.b64encode(proposal_sig).decode("ascii"),
        "transition_signature": base64.b64encode(transition_sig).decode("ascii"),
        "consensus_certificate_signature": base64.b64encode(cc_sig).decode("ascii") if cc_sig else None,
    }
    _write_json(output, approval, 0o644)
    return {"result": "approval_signed", "authority_id": descriptor["authority_id"],
            "proposal_id": proposal["proposal_id"], "approval_file": str(output.resolve()),
            "private_key_shared": False}


def authority_approve(authority_dir: Path, proposal_path: Path, output: Path) -> dict[str, Any]:
    authority_dir = authority_dir.resolve()
    lock = huc.FileLock(str(authority_dir / ".authority-operation.lock"), timeout=20)
    try:
        with lock:
            return _authority_approve_locked(authority_dir, proposal_path, output)
    except huc.Timeout as exc:
        raise TimeoutError("No se pudo bloquear el almacén de autoridad para aprobar") from exc


def _collect_approvals(workspace: Path, proposal: dict[str, Any], approval_paths: list[Path]
                       ) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    trust = huc.trust_material(workspace)
    policy = trust["policy"]
    by_id = {a["authority_id"]: a for a in policy["authorities"]}
    seen: set[str] = set()
    transition_signatures: list[dict[str, str]] = []
    cc_signatures: list[dict[str, str]] = []
    proposal_message = _approval_domain(proposal)
    transition_message = huc.canonical_json(proposal["transition_payload"])
    cc_payload = proposal.get("consensus_certificate_payload")
    cc_message = huc.canonical_json(cc_payload) if cc_payload is not None else None
    valid_ids: list[str] = []
    for path in approval_paths:
        approval = _read_json(path)
        if approval.get("schema") != APPROVAL_SCHEMA or approval.get("proposal_id") != proposal["proposal_id"]:
            raise ValueError(f"Aprobación inválida o de otra propuesta: {path}")
        authority_id = approval.get("authority_id")
        if authority_id not in by_id or authority_id in seen:
            raise ValueError(f"Autoridad desconocida o duplicada: {authority_id}")
        seen.add(authority_id)
        authority = by_id[authority_id]
        operation = proposal["operation"]
        if operation not in authority.get("permissions", []):
            raise ValueError(f"Autoridad sin permiso para {operation}: {authority_id}")
        try:
            _verify_signature(authority["public_key_pem"], approval["proposal_signature"], proposal_message)
            _verify_signature(authority["public_key_pem"], approval["transition_signature"], transition_message)
            if cc_message is not None:
                if not approval.get("consensus_certificate_signature"):
                    raise ValueError("Falta firma del HUC-CC")
                _verify_signature(authority["public_key_pem"], approval["consensus_certificate_signature"], cc_message)
            elif approval.get("consensus_certificate_signature") is not None:
                raise ValueError("No se esperaba firma HUC-CC en una revocación")
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValueError(f"Firma inválida de {authority_id}: {exc}") from exc
        valid_ids.append(authority_id)
        transition_signatures.append({"authority_id": authority_id,
                                      "signature": approval["transition_signature"]})
        if cc_message is not None:
            cc_signatures.append({"authority_id": authority_id,
                                  "signature": approval["consensus_certificate_signature"]})
    if len(valid_ids) < policy["threshold"]:
        raise ValueError(f"Quórum insuficiente: {len(valid_ids)}/{policy['threshold']} aprobaciones válidas")
    return transition_signatures, cc_signatures, valid_ids


def finalize_proposal(workspace: Path, proposal_path: Path, approval_paths: list[Path],
                      output_dir: Path, expected_anchor_sha256: str) -> dict[str, Any]:
    proposal = _read_json(proposal_path)
    _validate_proposal(proposal)
    if not expected_anchor_sha256:
        raise ValueError("Se requiere la huella del ancla obtenida por un canal independiente")
    trust = huc.trust_material(workspace, expected_anchor_sha256)
    if proposal.get("trust_anchor_sha256") != trust["anchor_sha256"]:
        raise ValueError("La propuesta pertenece a otra ancla de confianza")
    if proposal.get("policy_sha256") != trust["policy_sha256"]:
        raise ValueError("La propuesta utiliza una política distinta del coordinador")
    transition_sigs, cc_sigs, signer_ids = _collect_approvals(workspace, proposal, approval_paths)
    operation = proposal["operation"]
    cert = huc.x509.load_pem_x509_certificate(proposal["certificate_pem"].encode("ascii"))
    huc._verify_leaf_signature(cert, trust["ca_cert"])
    digest = huc.cert_hash(cert)
    if digest != proposal["certificate_sha256_der"]:
        raise ValueError("El certificado contenido en la propuesta fue alterado")
    transition = proposal["transition_payload"]
    output_dir.mkdir(parents=True, exist_ok=True)

    if operation in {"ISSUE", "RENEW"}:
        cert_path = workspace / huc.CERT_DIR / f"certificate-{digest}.pem"
        huc.atomic_write(cert_path, cert.public_bytes(huc.serialization.Encoding.PEM), 0o644)
        previous_hash = proposal.get("previous_certificate_sha256_der")
        event = huc._append_transition(
            workspace, operation, digest,
            previous_certificate_sha=previous_hash,
            previous_outpoint=transition.get("previous_outpoint"),
            reason=transition.get("reason"),
            expected_anchor_sha256=expected_anchor_sha256,
            authority_signatures=transition_sigs,
            prepared_payload=transition,
        )
        cc_payload = proposal["consensus_certificate_payload"]
        cc = huc._make_cc(workspace, cert, event["payload"]["output"], operation,
                          event["payload"]["sequence"], authority_signatures=cc_sigs,
                          prepared_payload=cc_payload)
        cc_path = workspace / huc.CERT_DIR / f"consensus-{digest}.json"
        huc.write_json(cc_path, cc, 0o644)
        result = {"action": operation, "certificate_sha256_der": digest,
                  "certificate_file": str(cert_path), "consensus_certificate_file": str(cc_path),
                  "utxo_outpoint": event["payload"]["output"]}
    elif operation == "REVOKE":
        event = huc._append_transition(
            workspace, "REVOKE", digest,
            previous_outpoint=transition.get("previous_outpoint"),
            reason=transition.get("reason"),
            expected_anchor_sha256=expected_anchor_sha256,
            authority_signatures=transition_sigs,
            prepared_payload=transition,
        )
        result = {"action": "REVOKE", "certificate_sha256_der": digest,
                  "consumed_utxo": transition.get("previous_outpoint"),
                  "revocation_event_txid": event["txid"], "status": "REVOKED"}
    else:
        raise ValueError("Operación de propuesta desconocida")

    # Export a public result bundle for the finalized certificate (not the signer secrets).
    if operation in {"ISSUE", "RENEW"}:
        bundle_path = output_dir / f"huc-{operation.lower()}-{digest[:12]}.zip"
        huc.export_bundle(workspace, Path(result["certificate_file"]), bundle_path)
        result["public_bundle"] = str(bundle_path)
    result.update({"proposal_id": proposal["proposal_id"], "valid_authorities": signer_ids,
                   "quorum": f"{len(signer_ids)}/{trust['policy']['authority_count']}",
                   "private_keys_transferred": False})
    return result



def _approval_review_text(proposal_path: Path) -> str:
    proposal = _read_json(proposal_path)
    _validate_proposal(proposal)
    cert = huc.x509.load_pem_x509_certificate(proposal["certificate_pem"].encode("ascii"))
    transition = proposal["transition_payload"]
    return "\n".join([
        "REVISIÓN DE PROPUESTA HUC — NO FIRME SIN VALIDARLA",
        f"Operación: {proposal['operation']}",
        f"Propuesta ID: {proposal['proposal_id']}",
        f"Sujeto X.509: {cert.subject.rfc4514_string()}",
        f"Serial X.509: {cert.serial_number}",
        f"Hash X.509 DER: {proposal['certificate_sha256_der']}",
        f"Política: {proposal['policy_id']} ({proposal['policy_sha256']})",
        f"Checkpoint: {proposal['ledger_checkpoint']['event_count']} eventos / {proposal['ledger_checkpoint']['last_event_hash']}",
        f"Secuencia propuesta: {transition.get('sequence')}",
        f"UTXO anterior: {transition.get('previous_outpoint')}",
        f"UTXO nuevo: {transition.get('output')}",
        f"Motivo: {transition.get('reason')}",
        f"Expira: {proposal['expires_at_utc']}",
    ])

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LAEV HUC 0.5 — autoridades independientes")
    sp = p.add_subparsers(dest="cmd", required=True)
    x = sp.add_parser("authority-init", help="Crear una autoridad en su propio dispositivo")
    x.add_argument("--id", required=True); x.add_argument("--out-dir", type=Path, required=True)
    x.add_argument("--permissions", default="ISSUE,RENEW,REVOKE")
    x = sp.add_parser("export-enrollment", help="Empaquetar material público de enrolamiento para una autoridad")
    x.add_argument("--workspace", type=Path, required=True); x.add_argument("--authority-id", required=True)
    x.add_argument("--output", type=Path, required=True); x.add_argument("--trust-anchor-sha256")
    x = sp.add_parser("enroll", help="Enrolar una autoridad sin transferir su clave privada")
    x.add_argument("--authority-dir", type=Path, required=True); x.add_argument("--package", type=Path, required=True)
    x.add_argument("--trust-anchor-sha256", required=True)
    x = sp.add_parser("export-state", help="Exportar actualización pública del ledger")
    x.add_argument("--workspace", type=Path, required=True); x.add_argument("--output", type=Path, required=True)
    x.add_argument("--trust-anchor-sha256")
    x = sp.add_parser("sync", help="Sincronizar el ledger público en un dispositivo de autoridad")
    x.add_argument("--authority-dir", type=Path, required=True); x.add_argument("--package", type=Path, required=True)
    x = sp.add_parser("propose-issue", help="Preparar propuesta de emisión para firmas externas")
    x.add_argument("--workspace", type=Path, required=True); x.add_argument("--csr", type=Path, required=True)
    x.add_argument("--days", type=int, default=365); x.add_argument("--expires-minutes", type=int, default=30)
    x.add_argument("--output", type=Path, required=True)
    x = sp.add_parser("propose-renew", help="Preparar propuesta de renovación para firmas externas")
    x.add_argument("--workspace", type=Path, required=True); x.add_argument("--certificate", type=Path, required=True)
    x.add_argument("--csr", type=Path, required=True); x.add_argument("--days", type=int, default=365)
    x.add_argument("--expires-minutes", type=int, default=30); x.add_argument("--output", type=Path, required=True)
    x = sp.add_parser("propose-revoke", help="Preparar propuesta de revocación para firmas externas")
    x.add_argument("--workspace", type=Path, required=True); x.add_argument("--certificate", type=Path, required=True)
    x.add_argument("--reason", required=True); x.add_argument("--expires-minutes", type=int, default=30)
    x.add_argument("--output", type=Path, required=True)
    x = sp.add_parser("approve", help="Revisar y firmar una propuesta desde el dispositivo de la autoridad")
    x.add_argument("--authority-dir", type=Path, required=True); x.add_argument("--proposal", type=Path, required=True)
    x.add_argument("--output", type=Path, required=True); x.add_argument("--yes", action="store_true", help="Omitir confirmación interactiva; usar solo en automatización controlada")
    x = sp.add_parser("finalize", help="Finalizar propuesta con aprobaciones independientes")
    x.add_argument("--workspace", type=Path, required=True); x.add_argument("--proposal", type=Path, required=True)
    x.add_argument("--approval", type=Path, action="append", required=True)
    x.add_argument("--trust-anchor-sha256", required=True)
    x.add_argument("--output-dir", type=Path, default=Path("./finalized"))
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.cmd == "authority-init":
            result = authority_init(args.id, args.out_dir, [x.strip() for x in args.permissions.split(",") if x.strip()])
        elif args.cmd == "export-enrollment":
            result = export_enrollment(args.workspace, args.authority_id, args.output, args.trust_anchor_sha256)
        elif args.cmd == "enroll":
            result = authority_enroll(args.authority_dir, args.package, args.trust_anchor_sha256)
        elif args.cmd == "export-state":
            result = export_state(args.workspace, args.output, args.trust_anchor_sha256)
        elif args.cmd == "sync":
            result = authority_sync(args.authority_dir, args.package)
        elif args.cmd == "propose-issue":
            result = prepare_issue(args.workspace, args.csr, args.output, args.days, args.expires_minutes)
        elif args.cmd == "propose-renew":
            result = prepare_renew(args.workspace, args.certificate, args.csr, args.output,
                                   args.days, args.expires_minutes)
        elif args.cmd == "propose-revoke":
            result = prepare_revoke(args.workspace, args.certificate, args.reason,
                                    args.output, args.expires_minutes)
        elif args.cmd == "approve":
            if not args.yes:
                if not sys.stdin.isatty():
                    raise ValueError("La aprobación requiere revisión interactiva; use --yes solo tras validar la propuesta")
                print(_approval_review_text(args.proposal))
                response = input("Escriba APROBAR para firmar esta propuesta: ").strip()
                if response != "APROBAR":
                    raise ValueError("Aprobación cancelada por el operador")
            result = authority_approve(args.authority_dir, args.proposal, args.output)
        elif args.cmd == "finalize":
            result = finalize_proposal(args.workspace, args.proposal, args.approval,
                                       args.output_dir, args.trust_anchor_sha256)
        else:
            raise ValueError("Comando desconocido")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
