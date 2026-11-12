#!/usr/bin/env python3
"""HUC 0.7 view-change certificates for rotating proposers.

This recovery layer rotates the preferred proposer after a quorum of signed
view-change messages. It preserves any single outstanding proposal lock and
never clears conflicting locks. This is a conservative recovery mechanism,
not a claim of full PBFT/HotStuff equivalence.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography.exceptions import InvalidSignature

import huc
import huc_replicated as rsp

VERSION = "0.7.0"
VIEW_STATE_FILE = "view-state.json"
VIEW_LOCK_FILE = "view-change-locks.json"
PENDING_DIR = "pending-proposals"
VIEW_CHANGE_SCHEMA = "LAEV-HUC-RSP-VIEW-CHANGE-1"
VIEW_CERT_SCHEMA = "LAEV-HUC-RSP-VIEW-CERTIFICATE-1"
VIEW_LOCK = "view-state.lock"


def _write(path: Path, obj: Any, mode: int = 0o600) -> None:
    rsp._write(path, obj, mode)


def _read(path: Path) -> dict[str, Any]:
    return rsp._read(path)


def _view_message(payload: dict[str, Any]) -> bytes:
    return rsp._canonical({"domain": "LAEV-HUC-VIEW-CHANGE-SIGNATURE-0.7", "payload": payload})


def _view_cert_id(body: dict[str, Any]) -> str:
    return rsp._hash(body)


def initialize_view_state(node_dir: Path) -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context_without_state(node_dir)
    path = node_dir / VIEW_STATE_FILE
    if path.exists():
        current = _read(path)
        if current.get("network_id") != network["network_id"]:
            raise ValueError("view-state pertenece a otra red")
        return current
    state = {
        "schema": "LAEV-HUC-RSP-VIEW-STATE-1",
        "network_id": network["network_id"],
        "validator_id": descriptor["validator_id"],
        "view": 0,
        "view_certificate_id": None,
        "recovery_proposal_id": None,
        "updated_at_utc": huc.iso(),
    }
    _write(path, state)
    _write(node_dir / VIEW_LOCK_FILE, {"schema": "LAEV-HUC-RSP-VIEW-LOCKS-1", "locks": {}})
    (node_dir / PENDING_DIR).mkdir(exist_ok=True)
    return state


def load_view_state(node_dir: Path) -> dict[str, Any]:
    state = initialize_view_state(node_dir)
    return state


def primary_for_view(network: dict[str, Any], view: int) -> str:
    validators = sorted(v["validator_id"] for v in network["validators"])
    if not isinstance(view, int) or view < 0:
        raise ValueError("view debe ser un entero no negativo")
    return validators[view % len(validators)]


def remember_proposal(node_dir: Path, proposal: dict[str, Any]) -> Path:
    payload = rsp._proposal_payload(proposal)
    path = node_dir / PENDING_DIR / f"{proposal['proposal_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    _write(path, proposal, 0o644)
    return path


def annotate_proposal_for_view(node_dir: Path, proposal_path: Path, output: Path) -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context(node_dir)
    view_state = load_view_state(node_dir)
    primary = primary_for_view(network, view_state["view"])
    if descriptor["validator_id"] != primary:
        raise ValueError(f"Solo el proponente de la vista actual ({primary}) puede crear una propuesta normal")
    proposal = _read(proposal_path)
    payload = dict(rsp._proposal_payload(proposal))
    payload["view"] = view_state["view"]
    payload["proposer_id"] = descriptor["validator_id"]
    payload["view_certificate_id"] = view_state.get("view_certificate_id")
    wrapped = {"payload": payload, "proposal_id": rsp._hash(payload)}
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, wrapped, 0o644)
    remember_proposal(node_dir, wrapped)
    return {
        "result": "view_proposal_created",
        "proposal_id": wrapped["proposal_id"],
        "view": view_state["view"],
        "proposer_id": descriptor["validator_id"],
        "proposal_file": str(output.resolve()),
    }


def validate_proposal_view(node_dir: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    network, _, _ = rsp._node_context_without_state(node_dir)
    view_state = load_view_state(node_dir)
    payload = rsp._proposal_payload(proposal)
    proposal_id = proposal["proposal_id"]
    view = payload.get("view")
    proposer = payload.get("proposer_id")
    if not isinstance(view, int) or view < 0 or not isinstance(proposer, str):
        raise ValueError("La propuesta HUC 0.7 requiere view y proposer_id")
    if view == view_state["view"]:
        expected_primary = primary_for_view(network, view)
        if proposer != expected_primary:
            raise ValueError("Propuesta de un proponente que no es primario de la vista actual")
        if payload.get("view_certificate_id") != view_state.get("view_certificate_id"):
            raise ValueError("La propuesta no referencia el certificado de vista vigente")
        if view_state.get("recovery_proposal_id") and proposal_id != view_state["recovery_proposal_id"]:
            raise ValueError("Existe una propuesta bloqueada que debe recuperarse antes de aceptar otra")
        return payload
    if (view < view_state["view"]
            and proposal_id == view_state.get("recovery_proposal_id")
            and view_state.get("recovery_proposal_id")):
        return payload
    raise ValueError("Propuesta de vista anterior o futura sin autorización de recuperación")


def _local_slot_lock(node_dir: Path) -> dict[str, Any] | None:
    state = rsp.load_state(node_dir)
    locks = _read(node_dir / rsp.VOTE_LOCKS)
    slot = f"{state['epoch']}:{state['sequence'] + 1}"
    entry = locks.get("locks", {}).get(slot)
    if not entry:
        return None
    proposal_id = entry.get("proposal_id")
    vote = entry.get("vote")
    proposal_path = node_dir / PENDING_DIR / f"{proposal_id}.json"
    proposal = _read(proposal_path) if proposal_path.exists() else None
    return {"proposal_id": proposal_id, "vote": vote, "proposal": proposal}


def create_view_change_message(node_dir: Path, target_view: int, reason: str = "timeout") -> dict[str, Any]:
    network, descriptor, key = rsp._node_context(node_dir)
    current = load_view_state(node_dir)
    if target_view != current["view"] + 1:
        raise ValueError("El cambio de vista debe avanzar exactamente una vista")
    if reason not in {"timeout", "unreachable-primary", "operator-request"}:
        raise ValueError("Motivo de cambio de vista no permitido")
    locks_file = node_dir / VIEW_LOCK_FILE
    slot_lock = _local_slot_lock(node_dir)
    state = rsp.load_state(node_dir)
    payload = {
        "schema": VIEW_CHANGE_SCHEMA,
        "network_id": network["network_id"],
        "validator_id": descriptor["validator_id"],
        "from_view": current["view"],
        "target_view": target_view,
        "last_sequence": state["sequence"],
        "last_head_hash": state["head_hash"],
        "slot_lock": slot_lock,
        "reason": reason,
        "created_at_utc": huc.iso(),
    }
    lock = FileLock(str(node_dir / VIEW_LOCK), timeout=10)
    try:
        with lock:
            saved = _read(locks_file)
            existing = saved.setdefault("locks", {}).get(str(target_view))
            if existing:
                old_payload = existing.get("payload", {})
                if old_payload.get("last_head_hash") != payload["last_head_hash"]:
                    raise ValueError("El estado cambió desde que se firmó el cambio de vista")
                return existing
            signature = base64.b64encode(key.sign(_view_message(payload))).decode("ascii")
            message = {"payload": payload, "signature": signature}
            saved["locks"][str(target_view)] = message
            _write(locks_file, saved)
            return message
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear el almacén de cambios de vista") from exc


def verify_view_change_message(network: dict[str, Any], message: dict[str, Any]) -> None:
    payload = message.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != VIEW_CHANGE_SCHEMA:
        raise ValueError("Mensaje VIEW_CHANGE no reconocido")
    if payload.get("network_id") != network["network_id"]:
        raise ValueError("VIEW_CHANGE pertenece a otra red")
    validator_id = payload.get("validator_id")
    validator = rsp._validator(network, validator_id)
    if not isinstance(payload.get("target_view"), int) or payload["target_view"] != payload.get("from_view", -2) + 1:
        raise ValueError("Secuencia de vistas inválida")
    if not isinstance(payload.get("last_sequence"), int) or payload["last_sequence"] < 0:
        raise ValueError("Secuencia comprometida inválida")
    rsp._validate_hash(payload.get("last_head_hash"), "last_head_hash")
    slot_lock = payload.get("slot_lock")
    if slot_lock is not None:
        if not isinstance(slot_lock, dict) or not isinstance(slot_lock.get("proposal_id"), str):
            raise ValueError("Slot lock inválido")
        vote = slot_lock.get("vote")
        if not isinstance(vote, dict):
            raise ValueError("Slot lock no contiene el voto firmado")
        vp = vote.get("payload", {})
        if (vp.get("validator_id") != validator_id
                or vp.get("proposal_id") != slot_lock["proposal_id"]
                or vp.get("network_id") != network["network_id"]
                or vp.get("decision") != "APPROVE"):
            raise ValueError("Voto bloqueado no corresponde al validador o slot")
        rsp._verify_sig(validator["public_key_pem"], vote.get("signature", ""), rsp._vote_message(vp))
        proposal = slot_lock.get("proposal")
        if proposal is not None:
            if proposal.get("proposal_id") != slot_lock["proposal_id"]:
                raise ValueError("Propuesta bloqueada no coincide con su identificador")
            pp = rsp._proposal_payload(proposal)
            if pp.get("sequence") != payload["last_sequence"] + 1:
                raise ValueError("Propuesta bloqueada no corresponde al siguiente slot")
    try:
        created = rsp._parse_time(payload.get("created_at_utc", ""))
        if abs((huc.now_utc() - created).total_seconds()) > 300:
            raise ValueError("VIEW_CHANGE fuera de la ventana temporal de 5 minutos")
        signature = base64.b64decode(message.get("signature", ""), validate=True)
        huc.load_ed_public_pem(validator["public_key_pem"]).verify(signature, _view_message(payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Firma o fecha de VIEW_CHANGE inválida") from exc


def assemble_view_certificate(node_dir: Path, messages: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    network, _, _ = rsp._node_context_without_state(node_dir)
    state = rsp.load_state(node_dir)
    current = load_view_state(node_dir)
    seen: set[str] = set()
    valid = []
    lock_ids: set[str] = set()
    for msg in messages:
        verify_view_change_message(network, msg)
        p = msg["payload"]
        if p["from_view"] != current["view"] or p["target_view"] != current["view"] + 1:
            raise ValueError("VIEW_CHANGE no corresponde a la siguiente vista")
        if p["last_sequence"] != state["sequence"] or p["last_head_hash"] != state["head_hash"]:
            raise ValueError("Los nodos no comparten el mismo último estado; sincronice antes del cambio de vista")
        if p["validator_id"] in seen:
            raise ValueError("VIEW_CHANGE duplicado del mismo validador")
        seen.add(p["validator_id"])
        lock_info = p.get("slot_lock")
        if lock_info:
            lock_ids.add(lock_info["proposal_id"])
        valid.append(msg)
    if len(valid) < network["quorum"]:
        raise ValueError(f"Quórum insuficiente para VIEW_CHANGE: se requieren {network['quorum']} mensajes")
    if len(lock_ids) > 1:
        raise ValueError("Conflicto de propuestas bloqueadas: se detiene la vista para preservar seguridad")
    recovery_id = next(iter(lock_ids), None)
    recovery_proposal = None
    if recovery_id:
        for msg in valid:
            lock_info = msg["payload"].get("slot_lock")
            if lock_info and lock_info["proposal_id"] == recovery_id and lock_info.get("proposal"):
                recovery_proposal = lock_info["proposal"]
                break
        if recovery_proposal is None:
            raise ValueError("Existe una propuesta bloqueada, pero el quórum no aportó su contenido")
        pp = rsp._proposal_payload(recovery_proposal)
        if pp.get("sequence") != state["sequence"] + 1 or pp.get("previous_state_hash") != state["head_hash"]:
            raise ValueError("La propuesta de recuperación no coincide con el estado actual")
        if rsp._parse_time(pp["expires_at_utc"]) <= huc.now_utc():
            raise ValueError("La propuesta bloqueada expiró; no se puede recuperar automáticamente")
    valid.sort(key=lambda x: x["payload"]["validator_id"])
    body = {
        "schema": VIEW_CERT_SCHEMA,
        "network_id": network["network_id"],
        "from_view": current["view"],
        "target_view": current["view"] + 1,
        "last_sequence": state["sequence"],
        "last_head_hash": state["head_hash"],
        "view_changes": valid,
        "quorum": network["quorum"],
        "recovery_proposal_id": recovery_id,
        "recovery_proposal": recovery_proposal,
        "created_at_utc": huc.iso(),
    }
    cert = {"body": body, "view_certificate_id": _view_cert_id(body)}
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, cert, 0o644)
    return {
        "result": "view_change_certificate_assembled",
        "view_certificate_id": cert["view_certificate_id"],
        "target_view": body["target_view"],
        "primary_id": primary_for_view(network, body["target_view"]),
        "valid_messages": len(valid),
        "recovery_proposal_id": recovery_id,
        "certificate_file": str(output.resolve()),
    }


def verify_view_certificate(network: dict[str, Any], cert: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    body = cert.get("body")
    if not isinstance(body, dict) or body.get("schema") != VIEW_CERT_SCHEMA:
        raise ValueError("Certificado NEW_VIEW no reconocido")
    if cert.get("view_certificate_id") != _view_cert_id(body):
        raise ValueError("Hash del certificado NEW_VIEW incorrecto")
    if body.get("network_id") != network["network_id"] or body.get("quorum") != network["quorum"]:
        raise ValueError("NEW_VIEW pertenece a otra red o quórum")
    if body.get("last_sequence") != state["sequence"] or body.get("last_head_hash") != state["head_hash"]:
        raise ValueError("NEW_VIEW se basa en un estado diferente")
    seen = set()
    locks = set()
    messages = body.get("view_changes")
    if not isinstance(messages, list):
        raise ValueError("NEW_VIEW sin mensajes de vista")
    for msg in messages:
        verify_view_change_message(network, msg)
        p = msg["payload"]
        if p.get("from_view") != body.get("from_view") or p.get("target_view") != body.get("target_view"):
            raise ValueError("VIEW_CHANGE no coincide con el certificado")
        if p.get("last_sequence") != state["sequence"] or p.get("last_head_hash") != state["head_hash"]:
            raise ValueError("VIEW_CHANGE contiene un estado divergente")
        vid = p["validator_id"]
        if vid in seen:
            raise ValueError("VIEW_CHANGE duplicado")
        seen.add(vid)
        if p.get("slot_lock"):
            locks.add(p["slot_lock"]["proposal_id"])
    if len(seen) < network["quorum"]:
        raise ValueError("NEW_VIEW no contiene quórum")
    if len(locks) > 1:
        raise ValueError("NEW_VIEW contiene locks incompatibles")
    expected_recovery = next(iter(locks), None)
    if body.get("recovery_proposal_id") != expected_recovery:
        raise ValueError("NEW_VIEW no preserva la propuesta bloqueada")
    if expected_recovery:
        proposal = body.get("recovery_proposal")
        if not isinstance(proposal, dict) or proposal.get("proposal_id") != expected_recovery:
            raise ValueError("NEW_VIEW no incluye la propuesta de recuperación")
        pp = rsp._proposal_payload(proposal)
        if pp.get("sequence") != state["sequence"] + 1 or pp.get("previous_state_hash") != state["head_hash"]:
            raise ValueError("Propuesta de recuperación inválida")
        if rsp._parse_time(pp["expires_at_utc"]) <= huc.now_utc():
            raise ValueError("La propuesta de recuperación expiró")
    return body


def install_view_certificate(node_dir: Path, certificate_path: Path) -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context_without_state(node_dir)
    cert = _read(certificate_path)
    state = rsp.load_state(node_dir)
    body = verify_view_certificate(network, cert, state)
    current = load_view_state(node_dir)
    if body["from_view"] != current["view"] or body["target_view"] != current["view"] + 1:
        if body["target_view"] == current["view"] and current.get("view_certificate_id") == cert["view_certificate_id"]:
            return {"result": "view_already_installed", "view": current["view"]}
        raise ValueError("NEW_VIEW no es el siguiente cambio de vista local")
    if body.get("recovery_proposal_id"):
        remember_proposal(node_dir, body["recovery_proposal"])
    updated = {
        "schema": "LAEV-HUC-RSP-VIEW-STATE-1",
        "network_id": network["network_id"],
        "validator_id": descriptor["validator_id"],
        "view": body["target_view"],
        "view_certificate_id": cert["view_certificate_id"],
        "recovery_proposal_id": body.get("recovery_proposal_id"),
        "updated_at_utc": huc.iso(),
    }
    _write(node_dir / VIEW_STATE_FILE, updated)
    return {
        "result": "view_installed",
        "view": updated["view"],
        "primary_id": primary_for_view(network, updated["view"]),
        "recovery_proposal_id": updated["recovery_proposal_id"],
    }


def clear_recovery_after_commit(node_dir: Path, commit: dict[str, Any]) -> None:
    current = load_view_state(node_dir)
    if not current.get("recovery_proposal_id"):
        return
    proposal_id = commit.get("body", {}).get("proposal", {}).get("proposal_id")
    if proposal_id == current["recovery_proposal_id"]:
        current["recovery_proposal_id"] = None
        current["updated_at_utc"] = huc.iso()
        _write(node_dir / VIEW_STATE_FILE, current)
