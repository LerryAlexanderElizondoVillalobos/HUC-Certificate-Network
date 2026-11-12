#!/usr/bin/env python3
"""LAEV HUC 0.8 — PBFT-inspired, certificate-based BFT state machine.

This implementation is a laboratory reference protocol layered over the HUC
0.7 node identities/network manifest and HUC UTXO transition validator.

Phases:
  PRE-PREPARE -> PREPARE quorum -> PREPARED/LOCK quorum -> COMMIT quorum.
A PreparedCertificate carries both the prepare QC and durable lock ACK QC.
This extra lock-ACK stage makes prepared state explicit in VIEW_CHANGE proofs.

It is not a formally verified or production-hardened PBFT implementation.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import sys
import tempfile
import zipfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography.exceptions import InvalidSignature

import huc
import huc_replicated as rsp

VERSION = "0.8.0"
BFT_SCHEMA = "LAEV-HUC-BFT-0.8"
PREPREPARE_SCHEMA = "LAEV-HUC-BFT-PREPREPARE-0.8"
PREPARE_SCHEMA = "LAEV-HUC-BFT-PREPARE-0.8"
PREPARE_CERT_SCHEMA = "LAEV-HUC-BFT-PREPARE-CERT-0.8"
LOCK_SCHEMA = "LAEV-HUC-BFT-PREPARED-LOCK-0.8"
PREPARED_CERT_SCHEMA = "LAEV-HUC-BFT-PREPARED-CERT-0.8"
COMMIT_SCHEMA = "LAEV-HUC-BFT-COMMIT-0.8"
COMMIT_CERT_SCHEMA = "LAEV-HUC-BFT-COMMIT-CERT-0.8"
VIEW_CHANGE_SCHEMA = "LAEV-HUC-BFT-VIEW-CHANGE-0.8"
NEW_VIEW_SCHEMA = "LAEV-HUC-BFT-NEW-VIEW-0.8"

CONTROL_FILE = "bft-control.json"
LOCKS_FILE = "bft-locks.json"
LEDGER_FILE = "bft-commit-ledger.jsonl"
BFT_LOCK = "bft-node.lock"
PENDING_DIR = "bft-pending"
MAX_CLOCK_SKEW_SECONDS = 300


def _canonical(obj: Any) -> bytes:
    return huc.canonical_json(obj)


def _hash(obj: Any) -> str:
    return huc.sha256(_canonical(obj))


def _msg(domain: str, payload: dict[str, Any]) -> bytes:
    return _canonical({"domain": domain, "payload": payload})


def _read(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    return huc.read_json(path)


def _write(path: Path, value: Any, mode: int = 0o600) -> None:
    huc.write_json(path, value, mode)


def _sign(key: Any, domain: str, payload: dict[str, Any]) -> str:
    return base64.b64encode(key.sign(_msg(domain, payload))).decode("ascii")


def _verify(public_pem: str, signature: str, domain: str, payload: dict[str, Any]) -> None:
    try:
        key = huc.load_ed_public_pem(public_pem)
        key.verify(base64.b64decode(signature, validate=True), _msg(domain, payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError(f"Firma inválida para {domain}") from exc


def _context(node_dir: Path):
    network, descriptor, key = rsp._node_context_without_state(node_dir)
    if network.get("quorum") != 2 * network.get("fault_tolerance", -1) + 1:
        raise ValueError("Red no cumple quórum 2f+1")
    return network, descriptor, key


def _primary(network: dict[str, Any], view: int) -> str:
    ids = sorted(x["validator_id"] for x in network["validators"])
    if not isinstance(view, int) or view < 0:
        raise ValueError("Vista inválida")
    return ids[view % len(ids)]


def _validator(network: dict[str, Any], validator_id: str) -> dict[str, Any]:
    return rsp._validator(network, validator_id)


def _initial_control(network: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": BFT_SCHEMA,
        "network_id": network["network_id"],
        "epoch": 0,
        "view": 0,
        "new_view_certificate": None,
        "view_certificates": [],
        "selected_prepared_certificate": None,
        "updated_at_utc": huc.iso(),
    }


def initialize_node(node_dir: Path) -> dict[str, Any]:
    network, descriptor, _ = _context(node_dir)
    control_path = node_dir / CONTROL_FILE
    if control_path.exists():
        control = _read(control_path)
        if control.get("network_id") != network["network_id"]:
            raise ValueError("El estado BFT pertenece a otra red")
    else:
        _write(control_path, _initial_control(network))
    locks_path = node_dir / LOCKS_FILE
    if not locks_path.exists():
        _write(locks_path, {
            "schema": "LAEV-HUC-BFT-LOCKS-0.8",
            "prepare": {},
            "prepared": {},
            "commit": {},
            "view_change": {},
        })
    ledger_path = node_dir / LEDGER_FILE
    if not ledger_path.exists():
        huc.atomic_write(ledger_path, b"")
    (node_dir / PENDING_DIR).mkdir(exist_ok=True)
    state = load_state(node_dir)
    return {"result": "bft_node_initialized", "validator_id": descriptor["validator_id"],
            "network_id": network["network_id"], "view": _read(control_path)["view"],
            "sequence": state["sequence"], "head_hash": state["head_hash"]}


def _load_control(node_dir: Path) -> dict[str, Any]:
    network, _, _ = _context(node_dir)
    initialize_node_if_missing(node_dir, network)
    control = _read(node_dir / CONTROL_FILE)
    if control.get("network_id") != network["network_id"]:
        raise ValueError("Estado de vista de otra red")
    return control


def initialize_node_if_missing(node_dir: Path, network: dict[str, Any]) -> None:
    if not (node_dir / CONTROL_FILE).exists() or not (node_dir / LOCKS_FILE).exists() or not (node_dir / LEDGER_FILE).exists():
        _write(node_dir / CONTROL_FILE, _initial_control(network))
        _write(node_dir / LOCKS_FILE, {
            "schema": "LAEV-HUC-BFT-LOCKS-0.8", "prepare": {}, "prepared": {},
            "commit": {}, "view_change": {},
        })
        if not (node_dir / LEDGER_FILE).exists():
            huc.atomic_write(node_dir / LEDGER_FILE, b"")
        (node_dir / PENDING_DIR).mkdir(exist_ok=True)


def _read_bft_commits(node_dir: Path) -> list[dict[str, Any]]:
    path = node_dir / LEDGER_FILE
    items = []
    if not path.exists():
        return items
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = huc.strict_json_loads(line)
        except Exception as exc:
            raise ValueError(f"Ledger BFT JSON inválido en línea {n}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"Commit BFT inválido en línea {n}")
        items.append(item)
    return items


def _commit_id(network_id: str, payload: dict[str, Any]) -> str:
    return _hash({
        "domain": "HUC-BFT-COMMIT-ID/0.8",
        "network_id": network_id,
        "epoch": payload["epoch"],
        "sequence": payload["sequence"],
        "request_hash": _hash(rsp._proposal_payload(payload["proposal"])),
        "parent_state_hash": payload["parent_state_hash"],
    })


def _verify_preprepare(network: dict[str, Any], state: dict[str, Any], pp: dict[str, Any],
                       expected_view: int | None = None, check_expiry: bool = True) -> dict[str, Any]:
    payload = pp.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != PREPREPARE_SCHEMA:
        raise ValueError("PRE-PREPARE con esquema desconocido")
    if pp.get("preprepare_id") != _hash(payload):
        raise ValueError("PRE-PREPARE ID inválido")
    if payload.get("network_id") != network["network_id"] or payload.get("epoch") != state["epoch"]:
        raise ValueError("PRE-PREPARE de otra red o época")
    view = payload.get("view")
    if not isinstance(view, int) or view < 0 or (expected_view is not None and view != expected_view):
        raise ValueError("PRE-PREPARE de vista incorrecta")
    primary = _primary(network, view)
    if payload.get("primary_id") != primary:
        raise ValueError("PRE-PREPARE no fue emitido por el proponente de la vista")
    if payload.get("sequence") != state["sequence"] + 1:
        raise ValueError("PRE-PREPARE con secuencia incorrecta")
    if payload.get("parent_state_hash") != state["head_hash"]:
        raise ValueError("PRE-PREPARE basado en un estado padre incorrecto")
    proposal = payload.get("proposal")
    if not isinstance(proposal, dict):
        raise ValueError("PRE-PREPARE no contiene propuesta")
    req_payload = rsp._validate_proposal_for_state(proposal, network, state, check_expiry=check_expiry)
    request_hash = _hash(req_payload)
    if payload.get("request_hash") != request_hash or payload.get("proposal_id") != proposal.get("proposal_id"):
        raise ValueError("Hash o ID de solicitud no coincide")
    _verify(network["validators"][[v["validator_id"] for v in network["validators"]].index(primary)]["public_key_pem"],
            pp.get("signature", ""), "HUC-BFT-PRE-PREPARE/0.8", payload)
    return payload


def create_operation_proposal(node_dir: Path, action: str, certificate_sha256: str,
                              consensus_certificate_sha256: str, output: Path,
                              previous_certificate_sha256: str | None = None,
                              metadata: dict[str, Any] | None = None,
                              certificate_path: Path | None = None,
                              consensus_certificate_path: Path | None = None,
                              expires_minutes: int = 10) -> dict[str, Any]:
    """Create an HUC UTXO transition against the BFT-replicated state."""
    if expires_minutes < 1 or expires_minutes > rsp.MAX_PROPOSAL_MINUTES:
        raise ValueError("Vigencia de propuesta fuera de rango")
    network, descriptor, _ = _context(node_dir)
    state = load_state(node_dir)
    cert_hash = rsp._validate_hash(certificate_sha256, "certificate_sha256")
    cc_hash = rsp._validate_hash(consensus_certificate_sha256, "consensus_certificate_sha256")
    previous_outpoint = None
    if action in {"RENEW", "REVOKE"}:
        source_hash = previous_certificate_sha256 if action == "RENEW" else cert_hash
        if source_hash not in state["certificates"]:
            raise ValueError("Certificado previo no está en estado BFT")
        previous_outpoint = state["certificates"][source_hash].get("outpoint")
    payload = {
        "schema": rsp.PROPOSAL_SCHEMA, "network_id": network["network_id"],
        "epoch": state["epoch"], "sequence": state["sequence"] + 1,
        "previous_state_hash": state["head_hash"], "action": action,
        "certificate_sha256": cert_hash, "consensus_certificate_sha256": cc_hash,
        "previous_certificate_sha256": previous_certificate_sha256,
        "previous_outpoint": previous_outpoint, "created_at_utc": huc.iso(),
        "expires_at_utc": huc.iso(huc.now_utc() + timedelta(minutes=expires_minutes)),
        "metadata": metadata or {},
    }
    if network.get("pki"):
        if not certificate_path or not consensus_certificate_path:
            raise ValueError("La red requiere X.509 y HUC-CC adjuntos")
        cert_raw = Path(certificate_path).read_bytes()
        cc_obj = rsp._read(Path(consensus_certificate_path))
        payload["evidence"] = {"certificate_pem_b64": base64.b64encode(cert_raw).decode("ascii"),
                               "consensus_certificate": cc_obj}
    rsp._check_transition(state, payload)
    rsp._validate_huc_evidence(network, payload)
    proposal = {"payload": payload, "proposal_id": _hash(payload)}
    _write(output, proposal, 0o644)
    return {"result": "bft_proposal_created", "validator_id": descriptor["validator_id"],
            "proposal_id": proposal["proposal_id"], "sequence": payload["sequence"],
            "action": action, "proposal_file": str(output.resolve())}


def create_preprepare(node_dir: Path, proposal_path: Path, output: Path) -> dict[str, Any]:
    network, descriptor, key = _context(node_dir)
    control = _load_control(node_dir)
    state = load_state(node_dir)
    view_no = control["view"]
    primary = _primary(network, view_no)
    if descriptor["validator_id"] != primary:
        raise ValueError(f"Solo {primary} puede emitir PRE-PREPARE en vista {view_no}")
    proposal = rsp._read(proposal_path)
    req = rsp._validate_proposal_for_state(proposal, network, state, check_expiry=True)
    request_hash = _hash(req)
    payload = {
        "schema": PREPREPARE_SCHEMA,
        "network_id": network["network_id"],
        "epoch": state["epoch"],
        "view": view_no,
        "sequence": state["sequence"] + 1,
        "primary_id": descriptor["validator_id"],
        "proposal_id": proposal["proposal_id"],
        "request_hash": request_hash,
        "parent_state_hash": state["head_hash"],
        "proposal": proposal,
        "created_at_utc": huc.iso(),
    }
    pp = {"payload": payload, "preprepare_id": _hash(payload),
          "signature": _sign(key, "HUC-BFT-PRE-PREPARE/0.8", payload)}
    _verify_preprepare(network, state, pp, view_no)
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, pp, 0o644)
    return {"result": "preprepare_created", "view": view_no, "sequence": payload["sequence"],
            "request_hash": request_hash, "preprepare_file": str(output.resolve())}


def _verify_prepare_vote(network: dict[str, Any], pp: dict[str, Any], vote: dict[str, Any]) -> None:
    p = pp["payload"]
    vp = vote.get("payload")
    if not isinstance(vp, dict) or vp.get("schema") != PREPARE_SCHEMA:
        raise ValueError("PREPARE con esquema desconocido")
    expected = {
        "network_id": p["network_id"], "epoch": p["epoch"], "view": p["view"],
        "sequence": p["sequence"], "preprepare_id": pp["preprepare_id"],
        "request_hash": p["request_hash"], "validator_id": vp.get("validator_id"),
    }
    for k, v in expected.items():
        if vp.get(k) != v:
            raise ValueError(f"PREPARE no coincide con PRE-PREPARE: {k}")
    validator = _validator(network, vp["validator_id"])
    _verify(validator["public_key_pem"], vote.get("signature", ""), "HUC-BFT-PREPARE/0.8", vp)


def accept_preprepare(node_dir: Path, pp: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, key = _context(node_dir)
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        # Serialize all read-check-sign-write operations on this replica. The
        # lock is shared with COMMIT/APPLY, prepared ACK, view change and sync.
        with lock:
            control = _load_control(node_dir)
            state = load_state(node_dir)
            raw_payload = pp.get("payload", {})
            recovery_id = raw_payload.get("recovery_of_prepared_certificate_id") if isinstance(raw_payload, dict) else None
            if recovery_id:
                selected = control.get("selected_prepared_certificate")
                if not selected or selected.get("prepared_certificate_id") != recovery_id:
                    raise ValueError("PRE-PREPARE de recuperación no está autorizado por NEW_VIEW")
                if selected["body"].get("request_hash") != raw_payload.get("request_hash"):
                    raise ValueError("PRE-PREPARE de recuperación no conserva la solicitud preparada")
            payload = _verify_preprepare(network, state, pp, control["view"], check_expiry=not bool(recovery_id))
            validator_id = descriptor["validator_id"]
            seq_key = str(payload["sequence"])
            request_hash = payload["request_hash"]
            locks = _read(node_dir / LOCKS_FILE)
            prepared = locks.setdefault("prepared", {}).get(seq_key)
            if prepared and prepared["request_hash"] != request_hash:
                raise ValueError("PRE-PREPARE contradice un prepared lock persistente")
            slot_key = f"{payload['view']}:{payload['sequence']}"
            existing = locks.setdefault("prepare", {}).get(slot_key)
            if existing and existing["request_hash"] != request_hash:
                raise ValueError("Equivocación: este nodo ya preparó otra solicitud en la misma vista/secuencia")
            if existing:
                return existing["vote"]
            vote_payload = {
                "schema": PREPARE_SCHEMA,
                "network_id": network["network_id"], "epoch": payload["epoch"],
                "view": payload["view"], "sequence": payload["sequence"],
                "preprepare_id": pp["preprepare_id"], "request_hash": request_hash,
                "validator_id": validator_id, "created_at_utc": huc.iso(),
            }
            vote = {"payload": vote_payload,
                    "signature": _sign(key, "HUC-BFT-PREPARE/0.8", vote_payload)}
            locks["prepare"][slot_key] = {"request_hash": request_hash, "vote": vote}
            _write(node_dir / LOCKS_FILE, locks)
            return vote
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear la réplica para PREPARE") from exc


def assemble_prepare_certificate(network: dict[str, Any], state: dict[str, Any],
                                  pp: dict[str, Any], prepare_votes: list[dict[str, Any]]) -> dict[str, Any]:
    p = _verify_preprepare(network, state, pp)
    seen = set()
    verified = []
    for vote in prepare_votes:
        _verify_prepare_vote(network, pp, vote)
        vid = vote["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("PREPARE duplicado del mismo validador")
        seen.add(vid)
        verified.append(vote)
    if len(verified) < network["quorum"]:
        raise ValueError(f"Quórum PREPARE insuficiente: {len(verified)}/{network['quorum']}")
    verified.sort(key=lambda x: x["payload"]["validator_id"])
    body = {"schema": PREPARE_CERT_SCHEMA, "preprepare": pp, "prepare_votes": verified,
            "network_id": network["network_id"], "view": p["view"],
            "sequence": p["sequence"], "request_hash": p["request_hash"]}
    return {"body": body, "prepare_certificate_id": _hash(body)}


def _verify_prepare_certificate(network: dict[str, Any], state: dict[str, Any],
                                 cert: dict[str, Any], expected_view: int | None = None) -> dict[str, Any]:
    body = cert.get("body")
    if not isinstance(body, dict) or body.get("schema") != PREPARE_CERT_SCHEMA:
        raise ValueError("PrepareCertificate no reconocido")
    if cert.get("prepare_certificate_id") != _hash(body):
        raise ValueError("PrepareCertificate hash inválido")
    pp = body.get("preprepare")
    raw = pp.get("payload", {})
    recovering = isinstance(raw, dict) and bool(raw.get("recovery_of_prepared_certificate_id"))
    p = _verify_preprepare(network, state, pp, expected_view, check_expiry=not recovering)
    if (body.get("network_id") != network["network_id"] or body.get("view") != p["view"]
            or body.get("sequence") != p["sequence"] or body.get("request_hash") != p["request_hash"]):
        raise ValueError("PrepareCertificate no coincide con PRE-PREPARE")
    votes = body.get("prepare_votes")
    if not isinstance(votes, list):
        raise ValueError("PrepareCertificate sin PREPARE votes")
    seen = set()
    for vote in votes:
        _verify_prepare_vote(network, pp, vote)
        vid = vote["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("PrepareCertificate contiene PREPARE duplicado")
        seen.add(vid)
    if len(seen) < network["quorum"]:
        raise ValueError("PrepareCertificate sin quórum")
    return p


def create_prepared_ack(node_dir: Path, prepare_cert: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, key = _context(node_dir)
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        with lock:
            control = _load_control(node_dir)
            state = load_state(node_dir)
            p = _verify_prepare_certificate(network, state, prepare_cert, control["view"])
            seq_key = str(p["sequence"])
            request_hash = p["request_hash"]
            locks = _read(node_dir / LOCKS_FILE)
            prepare_slot = f"{p['view']}:{p['sequence']}"
            local_prepare = locks.setdefault("prepare", {}).get(prepare_slot)
            if not local_prepare or local_prepare.get("request_hash") != request_hash:
                raise ValueError("No se puede firmar PREPARED sin haber firmado PREPARE para esta solicitud")
            existing = locks.setdefault("prepared", {}).get(seq_key)
            if existing and existing["request_hash"] != request_hash:
                raise ValueError("Prepared lock: no se permite bloquear otra solicitud para esta secuencia")
            if existing and existing.get("lock_ack") and existing.get("view") == p["view"]:
                return existing["lock_ack"]
            # Persist the full prepare certificate and lock before the ACK leaves
            # the process. A concurrent conflicting request sees this lock.
            lock_payload = {
                "schema": LOCK_SCHEMA, "network_id": network["network_id"],
                "epoch": p["epoch"], "view": p["view"], "sequence": p["sequence"],
                "request_hash": request_hash, "prepare_certificate_id": prepare_cert["prepare_certificate_id"],
                "validator_id": descriptor["validator_id"], "created_at_utc": huc.iso(),
            }
            ack = {"payload": lock_payload,
                   "signature": _sign(key, "HUC-BFT-PREPARED-LOCK/0.8", lock_payload)}
            locks["prepared"][seq_key] = {
                "view": p["view"], "request_hash": request_hash,
                "prepare_certificate": prepare_cert, "lock_ack": ack,
            }
            _write(node_dir / LOCKS_FILE, locks)
            return ack
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear la réplica para PREPARED ACK") from exc


def _verify_lock_ack(network: dict[str, Any], prepare_cert: dict[str, Any], ack: dict[str, Any]) -> None:
    p = prepare_cert["body"]
    ap = ack.get("payload")
    if not isinstance(ap, dict) or ap.get("schema") != LOCK_SCHEMA:
        raise ValueError("Prepared lock ACK desconocido")
    expected = {
        "network_id": network["network_id"], "epoch": p["preprepare"]["payload"]["epoch"],
        "view": p["view"], "sequence": p["sequence"],
        "request_hash": p["request_hash"],
        "prepare_certificate_id": prepare_cert["prepare_certificate_id"],
    }
    for k, v in expected.items():
        if ap.get(k) != v:
            raise ValueError(f"Prepared lock ACK no coincide: {k}")
    validator = _validator(network, ap.get("validator_id"))
    _verify(validator["public_key_pem"], ack.get("signature", ""), "HUC-BFT-PREPARED-LOCK/0.8", ap)


def assemble_prepared_certificate(network: dict[str, Any], state: dict[str, Any],
                                   prepare_cert: dict[str, Any], lock_acks: list[dict[str, Any]]) -> dict[str, Any]:
    _verify_prepare_certificate(network, state, prepare_cert)
    seen, valid = set(), []
    for ack in lock_acks:
        _verify_lock_ack(network, prepare_cert, ack)
        vid = ack["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("Prepared lock ACK duplicado")
        seen.add(vid)
        valid.append(ack)
    if len(valid) < network["quorum"]:
        raise ValueError(f"Quórum de prepared locks insuficiente: {len(valid)}/{network['quorum']}")
    valid.sort(key=lambda x: x["payload"]["validator_id"])
    body = {"schema": PREPARED_CERT_SCHEMA, "prepare_certificate": prepare_cert,
            "lock_acks": valid, "network_id": network["network_id"],
            "view": prepare_cert["body"]["view"], "sequence": prepare_cert["body"]["sequence"],
            "request_hash": prepare_cert["body"]["request_hash"]}
    return {"body": body, "prepared_certificate_id": _hash(body)}


def _verify_prepared_certificate(network: dict[str, Any], state: dict[str, Any],
                                  cert: dict[str, Any], require_quorum_locks: bool = True) -> dict[str, Any]:
    body = cert.get("body")
    if not isinstance(body, dict) or body.get("schema") != PREPARED_CERT_SCHEMA:
        raise ValueError("PreparedCertificate no reconocido")
    if cert.get("prepared_certificate_id") != _hash(body):
        raise ValueError("PreparedCertificate hash inválido")
    prepare_cert = body.get("prepare_certificate")
    p = _verify_prepare_certificate(network, state, prepare_cert)
    if (body.get("network_id") != network["network_id"] or body.get("view") != p["view"]
            or body.get("sequence") != p["sequence"] or body.get("request_hash") != p["request_hash"]):
        raise ValueError("PreparedCertificate no coincide con su PrepareCertificate")
    acks = body.get("lock_acks")
    if not isinstance(acks, list):
        raise ValueError("PreparedCertificate sin lock ACKs")
    seen = set()
    for ack in acks:
        _verify_lock_ack(network, prepare_cert, ack)
        vid = ack["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("PreparedCertificate contiene lock ACK duplicado")
        seen.add(vid)
    minimum = network["quorum"] if require_quorum_locks else 1
    if len(seen) < minimum:
        raise ValueError("PreparedCertificate sin evidencia de lock suficiente")
    return p


def accept_prepared_certificate(node_dir: Path, cert: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, _ = _context(node_dir)
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        with lock:
            control = _load_control(node_dir)
            state = load_state(node_dir)
            p = _verify_prepared_certificate(network, state, cert)
            if p["view"] != control["view"]:
                raise ValueError("PreparedCertificate pertenece a otra vista local")
            seq_key = str(p["sequence"])
            locks = _read(node_dir / LOCKS_FILE)
            old = locks.setdefault("prepared", {}).get(seq_key)
            if old and old["request_hash"] != p["request_hash"]:
                raise ValueError("El PreparedCertificate contradice el lock persistente")
            locks["prepared"][seq_key] = {
                "view": p["view"], "request_hash": p["request_hash"],
                "prepare_certificate": cert["body"]["prepare_certificate"],
                "prepared_certificate": cert,
                "lock_ack": old.get("lock_ack") if old else None,
            }
            _write(node_dir / LOCKS_FILE, locks)
            return {"result": "prepared_certificate_accepted", "validator_id": descriptor["validator_id"],
                    "sequence": p["sequence"], "view": p["view"], "request_hash": p["request_hash"]}
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear la réplica para aceptar PreparedCertificate") from exc


def create_commit_vote(node_dir: Path, prepared_cert: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, key = _context(node_dir)
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        with lock:
            control = _load_control(node_dir)
            state = load_state(node_dir)
            p = _verify_prepared_certificate(network, state, prepared_cert)
            if p["view"] != control["view"]:
                raise ValueError("No se puede votar COMMIT para una vista que no está instalada")
            seq_key = str(p["sequence"])
            request_hash = p["request_hash"]
            locks = _read(node_dir / LOCKS_FILE)
            prepared_lock = locks.setdefault("prepared", {}).get(seq_key)
            if prepared_lock and prepared_lock.get("request_hash") != request_hash:
                raise ValueError("PreparedCertificate contradice el lock local antes de COMMIT")
            if not prepared_lock or prepared_lock.get("prepared_certificate") != prepared_cert:
                # A full verified quorum certificate is sufficient evidence to
                # persist the prepared state before this replica signs COMMIT.
                locks["prepared"][seq_key] = {
                    "view": p["view"], "request_hash": request_hash,
                    "prepare_certificate": prepared_cert["body"]["prepare_certificate"],
                    "prepared_certificate": prepared_cert,
                    "lock_ack": prepared_lock.get("lock_ack") if prepared_lock else None,
                }
            old = locks.setdefault("commit", {}).get(seq_key)
            if old and old["request_hash"] != request_hash:
                raise ValueError("Anti-equivocación COMMIT: secuencia ya comprometida con otra solicitud")
            if old and old.get("view") == p["view"]:
                return old["vote"]
            payload = {
                "schema": COMMIT_SCHEMA, "network_id": network["network_id"],
                "epoch": p["epoch"], "view": p["view"], "sequence": p["sequence"],
                "request_hash": request_hash, "prepared_certificate_id": prepared_cert["prepared_certificate_id"],
                "validator_id": descriptor["validator_id"], "created_at_utc": huc.iso(),
            }
            vote = {"payload": payload, "signature": _sign(key, "HUC-BFT-COMMIT/0.8", payload)}
            locks["commit"][seq_key] = {"view": p["view"], "request_hash": request_hash, "vote": vote}
            _write(node_dir / LOCKS_FILE, locks)
            return vote
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear la réplica para COMMIT") from exc


def _verify_commit_vote(network: dict[str, Any], prepared_cert: dict[str, Any], vote: dict[str, Any]) -> None:
    p = prepared_cert["body"]
    vp = vote.get("payload")
    if not isinstance(vp, dict) or vp.get("schema") != COMMIT_SCHEMA:
        raise ValueError("COMMIT vote no reconocido")
    expected = {
        "network_id": network["network_id"], "epoch": p["prepare_certificate"]["body"]["preprepare"]["payload"]["epoch"],
        "view": p["view"], "sequence": p["sequence"],
        "request_hash": p["request_hash"],
        "prepared_certificate_id": prepared_cert["prepared_certificate_id"],
    }
    for k, v in expected.items():
        if vp.get(k) != v:
            raise ValueError(f"COMMIT vote no coincide: {k}")
    validator = _validator(network, vp.get("validator_id"))
    _verify(validator["public_key_pem"], vote.get("signature", ""), "HUC-BFT-COMMIT/0.8", vp)


def assemble_commit_certificate(network: dict[str, Any], state: dict[str, Any],
                                 prepared_cert: dict[str, Any], commit_votes: list[dict[str, Any]]) -> dict[str, Any]:
    p = _verify_prepared_certificate(network, state, prepared_cert)
    seen, valid = set(), []
    for vote in commit_votes:
        _verify_commit_vote(network, prepared_cert, vote)
        vid = vote["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("COMMIT duplicado del mismo validador")
        seen.add(vid)
        valid.append(vote)
    if len(valid) < network["quorum"]:
        raise ValueError(f"Quórum COMMIT insuficiente: {len(valid)}/{network['quorum']}")
    valid.sort(key=lambda x: x["payload"]["validator_id"])
    pre_payload = prepared_cert["body"]["prepare_certificate"]["body"]["preprepare"]["payload"]
    commit_id = _commit_id(network["network_id"], {
        "epoch": p["epoch"], "sequence": p["sequence"],
        "proposal": pre_payload["proposal"], "parent_state_hash": p["parent_state_hash"],
    })
    body = {
        "schema": COMMIT_CERT_SCHEMA, "network_id": network["network_id"],
        "epoch": p["epoch"], "view": p["view"], "sequence": p["sequence"],
        "request_hash": p["request_hash"], "parent_state_hash": p["parent_state_hash"],
        "prepared_certificate": prepared_cert, "commit_votes": valid,
        "commit_id": commit_id, "committed_at_utc": huc.iso(),
    }
    return {"body": body, "certificate_id": _hash(body)}


def _verify_commit_certificate(network: dict[str, Any], state: dict[str, Any],
                                cert: dict[str, Any]) -> tuple[dict[str, Any], str]:
    body = cert.get("body")
    if not isinstance(body, dict) or body.get("schema") != COMMIT_CERT_SCHEMA:
        raise ValueError("CommitCertificate no reconocido")
    if cert.get("certificate_id") != _hash(body):
        raise ValueError("CommitCertificate hash inválido")
    if body.get("network_id") != network["network_id"] or body.get("epoch") != state["epoch"]:
        raise ValueError("CommitCertificate de otra red o época")
    prepared = body.get("prepared_certificate")
    p = _verify_prepared_certificate(network, state, prepared)
    if (body.get("view") != p["view"] or body.get("sequence") != state["sequence"] + 1
            or body.get("sequence") != p["sequence"]
            or body.get("request_hash") != p["request_hash"]
            or body.get("parent_state_hash") != state["head_hash"]):
        raise ValueError("CommitCertificate no continúa el estado local")
    votes = body.get("commit_votes")
    if not isinstance(votes, list):
        raise ValueError("CommitCertificate sin votos COMMIT")
    seen = set()
    for vote in votes:
        _verify_commit_vote(network, prepared, vote)
        vid = vote["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("CommitCertificate con COMMIT duplicado")
        seen.add(vid)
    if len(seen) < network["quorum"]:
        raise ValueError("CommitCertificate sin quórum COMMIT")
    pp = prepared["body"]["prepare_certificate"]["body"]["preprepare"]["payload"]
    proposal = pp["proposal"]
    req = rsp._validate_proposal_for_state(proposal, network, state, check_expiry=False)
    commit_id = _commit_id(network["network_id"], {
        "epoch": p["epoch"], "sequence": p["sequence"],
        "proposal": proposal, "parent_state_hash": state["head_hash"],
    })
    if body.get("commit_id") != commit_id:
        raise ValueError("Commit ID determinista incorrecto")
    return req, commit_id


def load_state(node_dir: Path) -> dict[str, Any]:
    network, _, _ = _context(node_dir)
    initialize_node_if_missing(node_dir, network)
    state = rsp._genesis_state(network)
    for cert in _read_bft_commits(node_dir):
        req, commit_id = _verify_commit_certificate(network, state, cert)
        pp = cert["body"]["prepared_certificate"]["body"]["prepare_certificate"]["body"]["preprepare"]["payload"]
        transition = dict(req)
        transition["proposal_id"] = pp["proposal_id"]
        state = rsp._apply_payload(state, transition, commit_id)
    cache_path = node_dir / "bft-state.json"
    if cache_path.exists() and _read(cache_path) != state:
        _write(cache_path, state)
    elif not cache_path.exists():
        _write(cache_path, state)
    return state


def apply_commit_certificate(node_dir: Path, cert: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, _ = _context(node_dir)
    initialize_node(node_dir)
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        with lock:
            state = load_state(node_dir)
            ledger = _read_bft_commits(node_dir)
            supplied_body = cert.get("body", {}) if isinstance(cert, dict) else {}
            supplied_commit_id = supplied_body.get("commit_id")
            existing = next((x for x in ledger if x.get("body", {}).get("commit_id") == supplied_commit_id), None)
            if existing:
                if existing != cert:
                    raise ValueError("El mismo commit_id llegó con un certificado diferente")
                return {"result": "already_committed", "validator_id": descriptor["validator_id"],
                        "sequence": state["sequence"], "commit_id": supplied_commit_id}
            req, commit_id = _verify_commit_certificate(network, state, cert)
            pp = cert["body"]["prepared_certificate"]["body"]["prepare_certificate"]["body"]["preprepare"]["payload"]
            transition = dict(req)
            transition["proposal_id"] = pp["proposal_id"]
            next_state = rsp._apply_payload(copy.deepcopy(state), transition, commit_id)
            with (node_dir / LEDGER_FILE).open("ab") as handle:
                handle.write(_canonical(cert) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            _write(node_dir / "bft-state.json", next_state)
            locks = _read(node_dir / LOCKS_FILE)
            locks.setdefault("prepared", {}).pop(str(cert["body"]["sequence"]), None)
            # Keep PREPARE/COMMIT anti-equivocation records as durable history.
            _write(node_dir / LOCKS_FILE, locks)
            control = _load_control(node_dir)
            control["selected_prepared_certificate"] = None
            control["updated_at_utc"] = huc.iso()
            _write(node_dir / CONTROL_FILE, control)
            return {"result": "commit_applied", "validator_id": descriptor["validator_id"],
                    "sequence": next_state["sequence"], "commit_id": commit_id,
                    "head_hash": next_state["head_hash"]}
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear el estado BFT") from exc


def create_view_change(node_dir: Path, target_view: int, reason: str = "timeout") -> dict[str, Any]:
    network, descriptor, key = _context(node_dir)
    initialize_node(node_dir)
    if reason not in {"timeout", "primary-unreachable", "operator-request", "equivocation"}:
        raise ValueError("Motivo VIEW_CHANGE no permitido")
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        with lock:
            control = _load_control(node_dir)
            state = load_state(node_dir)
            if target_view != control["view"] + 1:
                raise ValueError("VIEW_CHANGE debe avanzar exactamente una vista")
            locks = _read(node_dir / LOCKS_FILE)
            prepared = locks.get("prepared", {}).get(str(state["sequence"] + 1))
            prepared_cert = None
            if prepared:
                if prepared.get("prepared_certificate"):
                    prepared_cert = prepared["prepared_certificate"]
                elif prepared.get("prepare_certificate") and prepared.get("lock_ack"):
                    # A single durable lock ACK carries the full PrepareCertificate.
                    pc = prepared["prepare_certificate"]
                    ack = prepared["lock_ack"]
                    body = {"schema": PREPARED_CERT_SCHEMA, "prepare_certificate": pc,
                            "lock_acks": [ack], "network_id": network["network_id"],
                            "view": pc["body"]["view"], "sequence": pc["body"]["sequence"],
                            "request_hash": pc["body"]["request_hash"]}
                    prepared_cert = {"body": body, "prepared_certificate_id": _hash(body)}
            payload = {
                "schema": VIEW_CHANGE_SCHEMA, "network_id": network["network_id"],
                "epoch": state["epoch"], "from_view": control["view"], "target_view": target_view,
                "validator_id": descriptor["validator_id"], "last_committed_sequence": state["sequence"],
                "last_committed_hash": state["head_hash"], "prepared_certificate": prepared_cert,
                "reason": reason, "created_at_utc": huc.iso(),
            }
            saved = _read(node_dir / LOCKS_FILE)
            old = saved.setdefault("view_change", {}).get(str(target_view))
            if old:
                if old["payload"].get("last_committed_hash") != payload["last_committed_hash"]:
                    raise ValueError("El estado cambió desde el VIEW_CHANGE persistido")
                return old
            message = {"payload": payload,
                       "signature": _sign(key, "HUC-BFT-VIEW-CHANGE/0.8", payload)}
            saved["view_change"][str(target_view)] = message
            _write(node_dir / LOCKS_FILE, saved)
            return message
    except Timeout as exc:
        raise TimeoutError("No se pudo persistir VIEW_CHANGE") from exc


def _verify_view_change(network: dict[str, Any], state: dict[str, Any], message: dict[str, Any],
                        target_view: int) -> dict[str, Any]:
    p = message.get("payload")
    if not isinstance(p, dict) or p.get("schema") != VIEW_CHANGE_SCHEMA:
        raise ValueError("VIEW_CHANGE inválido")
    if (p.get("network_id") != network["network_id"] or p.get("epoch") != state["epoch"]
            or p.get("target_view") != target_view or p.get("from_view") != target_view - 1):
        raise ValueError("VIEW_CHANGE de red, época o vista incorrecta")
    if p.get("last_committed_sequence") != state["sequence"] or p.get("last_committed_hash") != state["head_hash"]:
        raise ValueError("Los nodos no comparten el mismo checkpoint comprometido; sincronice antes del cambio de vista")
    validator = _validator(network, p.get("validator_id"))
    created = rsp._parse_time(p.get("created_at_utc", ""))
    if abs((huc.now_utc() - created).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("VIEW_CHANGE fuera de la ventana temporal permitida")
    _verify(validator["public_key_pem"], message.get("signature", ""), "HUC-BFT-VIEW-CHANGE/0.8", p)
    prepared_cert = p.get("prepared_certificate")
    if prepared_cert is not None:
        _verify_prepared_certificate(network, state, prepared_cert, require_quorum_locks=False)
    return p


def _select_highest_prepared(network: dict[str, Any], state: dict[str, Any],
                             view_changes: list[dict[str, Any]], target_view: int) -> dict[str, Any] | None:
    certs = []
    for message in view_changes:
        p = _verify_view_change(network, state, message, target_view)
        if p.get("prepared_certificate") is not None:
            certs.append(p["prepared_certificate"])
    if not certs:
        return None
    certs.sort(key=lambda c: (c["body"]["view"], c["prepared_certificate_id"]))
    highest_view = certs[-1]["body"]["view"]
    top = [c for c in certs if c["body"]["view"] == highest_view]
    digests = {c["body"]["request_hash"] for c in top}
    if len(digests) != 1:
        raise ValueError("Safety halt: certificados preparados conflictivos en la misma vista")
    # Deterministic pick among byte-identical logical prepared requests.
    return sorted(top, key=lambda c: c["prepared_certificate_id"])[0]


def assemble_new_view(node_dir: Path, view_changes: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    network, descriptor, key = _context(node_dir)
    control = _load_control(node_dir)
    state = load_state(node_dir)
    target = control["view"] + 1
    seen, valid = set(), []
    for message in view_changes:
        p = _verify_view_change(network, state, message, target)
        vid = p["validator_id"]
        if vid in seen:
            raise ValueError("VIEW_CHANGE duplicado")
        seen.add(vid)
        valid.append(message)
    if len(valid) < network["quorum"]:
        raise ValueError(f"Quórum VIEW_CHANGE insuficiente: {len(valid)}/{network['quorum']}")
    selected = _select_highest_prepared(network, state, valid, target)
    new_primary = _primary(network, target)
    if descriptor["validator_id"] != new_primary:
        raise ValueError(f"Solo {new_primary} puede ensamblar NEW_VIEW {target}")
    body = {
        "schema": NEW_VIEW_SCHEMA, "network_id": network["network_id"], "epoch": state["epoch"],
        "from_view": control["view"], "target_view": target, "primary_id": new_primary,
        "last_committed_sequence": state["sequence"], "last_committed_hash": state["head_hash"],
        "view_changes": sorted(valid, key=lambda x: x["payload"]["validator_id"]),
        "selected_prepared_certificate": selected,
        "selected_prepared_certificate_id": selected["prepared_certificate_id"] if selected else None,
        "created_at_utc": huc.iso(),
    }
    certificate = {"body": body,
                   "signature": _sign(key, "HUC-BFT-NEW-VIEW/0.8", body),
                   "new_view_id": _hash(body)}
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, certificate, 0o644)
    return {"result": "new_view_certificate_assembled", "view": target,
            "primary_id": new_primary, "view_changes": len(valid),
            "selected_prepared_certificate_id": body["selected_prepared_certificate_id"],
            "certificate_file": str(output.resolve())}


def _verify_new_view(network: dict[str, Any], state: dict[str, Any], control: dict[str, Any],
                     certificate: dict[str, Any]) -> dict[str, Any]:
    body = certificate.get("body")
    if not isinstance(body, dict) or body.get("schema") != NEW_VIEW_SCHEMA:
        raise ValueError("NEW_VIEW no reconocido")
    if certificate.get("new_view_id") != _hash(body):
        raise ValueError("NEW_VIEW ID inválido")
    target = control["view"] + 1
    if (body.get("network_id") != network["network_id"] or body.get("epoch") != state["epoch"]
            or body.get("from_view") != control["view"] or body.get("target_view") != target
            or body.get("last_committed_sequence") != state["sequence"]
            or body.get("last_committed_hash") != state["head_hash"]):
        raise ValueError("NEW_VIEW no continúa el estado/vista local")
    primary = _primary(network, target)
    if body.get("primary_id") != primary:
        raise ValueError("NEW_VIEW tiene primario incorrecto")
    validator = _validator(network, primary)
    _verify(validator["public_key_pem"], certificate.get("signature", ""), "HUC-BFT-NEW-VIEW/0.8", body)
    vcs = body.get("view_changes")
    if not isinstance(vcs, list):
        raise ValueError("NEW_VIEW sin VIEW_CHANGE")
    seen = set()
    for message in vcs:
        p = _verify_view_change(network, state, message, target)
        if p["validator_id"] in seen:
            raise ValueError("NEW_VIEW contiene VIEW_CHANGE duplicado")
        seen.add(p["validator_id"])
    if len(seen) < network["quorum"]:
        raise ValueError("NEW_VIEW no contiene quórum")
    selected = _select_highest_prepared(network, state, vcs, target)
    if body.get("selected_prepared_certificate_id") != (selected["prepared_certificate_id"] if selected else None):
        raise ValueError("NEW_VIEW no selecciona el PreparedCertificate de mayor vista")
    if body.get("selected_prepared_certificate") != selected:
        raise ValueError("NEW_VIEW altera la selección de PreparedCertificate")
    return body


def install_new_view(node_dir: Path, certificate: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, _ = _context(node_dir)
    initialize_node(node_dir)
    lock = FileLock(str(node_dir / BFT_LOCK), timeout=15)
    try:
        with lock:
            control = _load_control(node_dir)
            state = load_state(node_dir)
            body = _verify_new_view(network, state, control, certificate)
            locks = _read(node_dir / LOCKS_FILE)
            local_lock = locks.get("prepared", {}).get(str(state["sequence"] + 1))
            selected = body.get("selected_prepared_certificate")
            if local_lock:
                if selected is None:
                    # A local tentative lock without a quorum-certified PreparedCertificate
                    # may be released only after a valid 2f+1 NEW_VIEW proves no q-lock survived.
                    if local_lock.get("prepared_certificate") is not None:
                        raise ValueError("NEW_VIEW omite un PreparedCertificate completo local")
                    locks.setdefault("prepared", {}).pop(str(state["sequence"] + 1), None)
                else:
                    local_view = local_lock["view"]
                    selected_view = selected["body"]["view"]
                    local_digest = local_lock["request_hash"]
                    selected_digest = selected["body"]["request_hash"]
                    if selected_view < local_view:
                        raise ValueError("NEW_VIEW intenta retroceder un prepared lock")
                    if selected_view == local_view and selected_digest != local_digest:
                        raise ValueError("NEW_VIEW contradice prepared lock de igual vista")
            if selected:
                seq_key = str(state["sequence"] + 1)
                locks.setdefault("prepared", {})[seq_key] = {
                    "view": selected["body"]["view"], "request_hash": selected["body"]["request_hash"],
                    "prepare_certificate": selected["body"]["prepare_certificate"],
                    "prepared_certificate": selected, "lock_ack": None,
                }
            control["view"] = body["target_view"]
            control["new_view_certificate"] = certificate
            control.setdefault("view_certificates", []).append(certificate)
            control["selected_prepared_certificate"] = selected
            control["updated_at_utc"] = huc.iso()
            _write(node_dir / LOCKS_FILE, locks)
            _write(node_dir / CONTROL_FILE, control)
            return {"result": "new_view_installed", "validator_id": descriptor["validator_id"],
                    "view": control["view"], "primary_id": body["primary_id"],
                    "recovery_required": selected is not None,
                    "selected_prepared_certificate_id": body["selected_prepared_certificate_id"]}
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear la réplica para instalar NEW_VIEW") from exc


def repropose_selected(node_dir: Path, output: Path) -> dict[str, Any]:
    control = _load_control(node_dir)
    selected = control.get("selected_prepared_certificate")
    if selected is None:
        raise ValueError("La nueva vista no tiene solicitud preparada que recuperar")
    network, descriptor, key = _context(node_dir)
    if descriptor["validator_id"] != _primary(network, control["view"]):
        raise ValueError("Solo el nuevo primario puede recuperar la solicitud preparada")
    state = load_state(node_dir)
    old_pp = selected["body"]["prepare_certificate"]["body"]["preprepare"]
    proposal = old_pp["payload"]["proposal"]
    req = rsp._validate_proposal_for_state(proposal, network, state, check_expiry=False)
    payload = {
        "schema": PREPREPARE_SCHEMA, "network_id": network["network_id"],
        "epoch": state["epoch"], "view": control["view"],
        "sequence": state["sequence"] + 1, "primary_id": descriptor["validator_id"],
        "proposal_id": proposal["proposal_id"], "request_hash": _hash(req),
        "parent_state_hash": state["head_hash"], "proposal": proposal,
        "recovery_of_prepared_certificate_id": selected["prepared_certificate_id"],
        "created_at_utc": huc.iso(),
    }
    pp = {"payload": payload, "preprepare_id": _hash(payload),
          "signature": _sign(key, "HUC-BFT-PRE-PREPARE/0.8", payload)}
    _verify_preprepare(network, state, pp, control["view"])
    _write(output, pp, 0o644)
    return {"result": "prepared_request_reproposed", "view": control["view"],
            "proposal_id": proposal["proposal_id"], "preprepare_file": str(output.resolve())}



BFT_SYNC_SCHEMA = "LAEV-HUC-BFT-SYNC-0.8"


def _replay_state_at(network: dict[str, Any], commits: list[dict[str, Any]],
                     target_sequence: int | None = None) -> dict[str, Any]:
    state = rsp._genesis_state(network)
    target = len(commits) if target_sequence is None else target_sequence
    if target < 0 or target > len(commits):
        raise ValueError("Secuencia solicitada fuera del historial BFT")
    for index, cert in enumerate(commits[:target], 1):
        req, commit_id = _verify_commit_certificate(network, state, cert)
        pp = cert["body"]["prepared_certificate"]["body"]["prepare_certificate"]["body"]["preprepare"]["payload"]
        transition = dict(req)
        transition["proposal_id"] = pp["proposal_id"]
        state = rsp._apply_payload(copy.deepcopy(state), transition, commit_id)
        if state["sequence"] != index:
            raise ValueError("La secuencia reconstruida del ledger BFT no es consecutiva")
    return state


def export_state(node_dir: Path, output: Path) -> dict[str, Any]:
    network, descriptor, _ = _context(node_dir)
    state = load_state(node_dir)
    control = _load_control(node_dir)
    commits = _read_bft_commits(node_dir)
    manifest = {
        "schema": BFT_SYNC_SCHEMA,
        "protocol_version": VERSION,
        "network_id": network["network_id"],
        "network_sha256": rsp.network_hash(network),
        "sequence": state["sequence"],
        "head_hash": state["head_hash"],
        "view": control["view"],
        "exported_by": descriptor["validator_id"],
        "exported_at_utc": huc.iso(),
        "private_keys_included": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(node_dir / rsp.NETWORK_FILE, rsp.NETWORK_FILE)
        archive.write(node_dir / LEDGER_FILE, LEDGER_FILE)
        archive.writestr(CONTROL_FILE, _canonical(control) + b"\n")
        archive.writestr("bft-sync-manifest.json", _canonical(manifest) + b"\n")
    return {"result": "bft_state_package_created", "validator_id": descriptor["validator_id"],
            "sequence": state["sequence"], "head_hash": state["head_hash"],
            "view": control["view"], "package": str(output.resolve()),
            "private_keys_included": False}


def _safe_extract_bft(package: Path, destination: Path) -> None:
    with zipfile.ZipFile(package, "r") as archive:
        total = sum(info.file_size for info in archive.infolist())
        if total > 50 * 1024 * 1024:
            raise ValueError("Paquete BFT supera 50 MiB")
        for info in archive.infolist():
            target = (destination / info.filename).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError("Paquete BFT contiene una ruta no permitida")
        archive.extractall(destination)


def _verify_control_history(network: dict[str, Any], commits: list[dict[str, Any]],
                            incoming_control: dict[str, Any], final_state: dict[str, Any]) -> dict[str, Any]:
    certificates = incoming_control.get("view_certificates", [])
    if not isinstance(certificates, list):
        raise ValueError("Historial de certificados NEW_VIEW inválido")
    rolling = _initial_control(network)
    previous_target = 0
    for certificate in certificates:
        body = certificate.get("body", {})
        seq = body.get("last_committed_sequence")
        if not isinstance(seq, int):
            raise ValueError("NEW_VIEW sin secuencia de checkpoint")
        historical_state = _replay_state_at(network, commits, seq)
        verified = _verify_new_view(network, historical_state, rolling, certificate)
        if verified["target_view"] != previous_target + 1:
            raise ValueError("Historial NEW_VIEW no es continuo")
        rolling["view"] = verified["target_view"]
        rolling["new_view_certificate"] = certificate
        rolling["view_certificates"].append(certificate)
        rolling["selected_prepared_certificate"] = verified.get("selected_prepared_certificate")
        previous_target = verified["target_view"]
    if incoming_control.get("view") != rolling["view"]:
        raise ValueError("Vista del paquete no coincide con su cadena de certificados NEW_VIEW")
    rolling["updated_at_utc"] = incoming_control.get("updated_at_utc", huc.iso())
    selected = incoming_control.get("selected_prepared_certificate")
    if selected is not None:
        _verify_prepared_certificate(network, final_state, selected, require_quorum_locks=False)
        if selected["body"]["sequence"] != final_state["sequence"] + 1:
            raise ValueError("PreparedCertificate pendiente no corresponde a la siguiente secuencia")
    rolling["selected_prepared_certificate"] = selected
    return rolling


def sync_state(node_dir: Path, package: Path, expected_exporter_id: str | None = None) -> dict[str, Any]:
    node_dir = Path(node_dir).resolve()
    network, descriptor, _ = _context(node_dir)
    with tempfile.TemporaryDirectory(prefix="huc-bft-sync-") as temp:
        root = Path(temp)
        _safe_extract_bft(package, root)
        incoming_network = rsp.validate_network(_read(root / rsp.NETWORK_FILE))
        if (incoming_network["network_id"] != network["network_id"]
                or rsp.network_hash(incoming_network) != rsp.network_hash(network)):
            raise ValueError("Paquete BFT pertenece a otra red o configuración")
        manifest = _read(root / "bft-sync-manifest.json")
        if (manifest.get("schema") != BFT_SYNC_SCHEMA
                or manifest.get("network_id") != network["network_id"]
                or manifest.get("network_sha256") != rsp.network_hash(network)
                or manifest.get("private_keys_included") is not False):
            raise ValueError("Manifiesto BFT no válido")
        exporter_id = manifest.get("exported_by")
        _validator(network, exporter_id)
        if expected_exporter_id is not None and exporter_id != expected_exporter_id:
            raise ValueError("El paquete BFT no fue exportado por el peer esperado")
        incoming_control = _read(root / CONTROL_FILE)
        incoming_commits = []
        ledger_path = root / LEDGER_FILE
        for line_no, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                item = huc.strict_json_loads(line)
                if not isinstance(item, dict):
                    raise ValueError(f"Commit inválido en línea {line_no}")
                incoming_commits.append(item)
    rebuilt = _replay_state_at(network, incoming_commits)
    if (rebuilt["sequence"] != manifest.get("sequence")
            or rebuilt["head_hash"] != manifest.get("head_hash")):
        raise ValueError("Estado reconstruido no coincide con el manifiesto BFT")
    rebuilt_control = _verify_control_history(network, incoming_commits, incoming_control, rebuilt)
    if manifest.get("view") != rebuilt_control["view"]:
        raise ValueError("Vista del manifiesto no coincide con NEW_VIEW")

    try:
        with FileLock(str(node_dir / BFT_LOCK), timeout=15):
            local_commits = _read_bft_commits(node_dir)
            if len(incoming_commits) < len(local_commits):
                raise ValueError("Sincronización BFT rechazada: rollback de historial")
            for index, local_cert in enumerate(local_commits):
                incoming_cert = incoming_commits[index]
                if local_cert.get("body", {}).get("commit_id") != incoming_cert.get("body", {}).get("commit_id"):
                    raise ValueError("Sincronización BFT rechazada: bifurcación del historial")
            local_control = _load_control(node_dir)
            if rebuilt_control["view"] < local_control["view"]:
                raise ValueError("Sincronización BFT rechazada: rollback de vista")
            local_views = local_control.get("view_certificates", [])
            incoming_views = rebuilt_control.get("view_certificates", [])
            if len(incoming_views) < len(local_views):
                raise ValueError("Sincronización BFT rechazada: rollback de certificados NEW_VIEW")
            for index, old_view_cert in enumerate(local_views):
                if old_view_cert.get("new_view_id") != incoming_views[index].get("new_view_id"):
                    raise ValueError("Sincronización BFT rechazada: bifurcación del historial de vistas")

            # Preserve local anti-equivocation history and add only this replica's
            # own votes reconstructed from verified committed certificates.
            locks = _read(node_dir / LOCKS_FILE)
            for section in ("prepare", "prepared", "commit", "view_change"):
                locks.setdefault(section, {})
            local_id = descriptor["validator_id"]
            committed_request_by_sequence = {}
            for commit_cert in incoming_commits:
                commit_body = commit_cert["body"]
                prepared_cert = commit_body["prepared_certificate"]
                prepare_cert = prepared_cert["body"]["prepare_certificate"]
                pp_payload = prepare_cert["body"]["preprepare"]["payload"]
                slot = f"{pp_payload['view']}:{pp_payload['sequence']}"
                seq_key = str(pp_payload["sequence"])
                committed_request_by_sequence[seq_key] = pp_payload["request_hash"]
                for vote in prepare_cert["body"]["prepare_votes"]:
                    if vote["payload"].get("validator_id") == local_id:
                        existing = locks["prepare"].get(slot)
                        if existing and existing.get("request_hash") != pp_payload["request_hash"]:
                            raise ValueError("Sync BFT: el historial local de PREPARE contradice un commit certificado")
                        locks["prepare"][slot] = {"request_hash": pp_payload["request_hash"], "vote": vote}
                for vote in commit_body["commit_votes"]:
                    if vote["payload"].get("validator_id") == local_id:
                        existing = locks["commit"].get(seq_key)
                        if existing and existing.get("request_hash") != pp_payload["request_hash"]:
                            raise ValueError("Sync BFT: el historial local de COMMIT contradice un commit certificado")
                        locks["commit"][seq_key] = {"view": pp_payload["view"],
                                                     "request_hash": pp_payload["request_hash"], "vote": vote}
            for seq_key, local_prepared in list(locks["prepared"].items()):
                committed_hash = committed_request_by_sequence.get(seq_key)
                if int(seq_key) <= rebuilt["sequence"]:
                    if committed_hash is None or local_prepared.get("request_hash") != committed_hash:
                        raise ValueError("Sync BFT: el historial remoto contradice un prepared lock local")
                    locks["prepared"].pop(seq_key, None)
            for seq_key, local_commit in locks["commit"].items():
                if int(seq_key) <= rebuilt["sequence"]:
                    committed_hash = committed_request_by_sequence.get(seq_key)
                    if committed_hash is None or local_commit.get("request_hash") != committed_hash:
                        raise ValueError("Sync BFT: el historial remoto contradice un COMMIT local firmado")
            for certificate in incoming_views:
                for message in certificate["body"]["view_changes"]:
                    vid = message["payload"]["validator_id"]
                    target = str(message["payload"]["target_view"])
                    if vid == local_id:
                        locks["view_change"][target] = message
            selected = rebuilt_control.get("selected_prepared_certificate")
            if selected:
                body = selected["body"]
                ack = body.get("lock_acks", [None])[0]
                locks["prepared"][str(body["sequence"])] = {
                    "view": body["view"], "request_hash": body["request_hash"],
                    "prepare_certificate": body["prepare_certificate"],
                    "prepared_certificate": selected, "lock_ack": ack,
                }
            huc.atomic_write(node_dir / LEDGER_FILE,
                             b"".join(_canonical(cert) + b"\n" for cert in incoming_commits), 0o600)
            _write(node_dir / CONTROL_FILE, rebuilt_control)
            _write(node_dir / LOCKS_FILE, locks)
            _write(node_dir / "bft-state.json", rebuilt)
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear la réplica durante BFT sync") from exc
    return {"result": "bft_state_synchronized", "validator_id": descriptor["validator_id"],
            "source_validator_id": exporter_id,
            "sequence": rebuilt["sequence"], "head_hash": rebuilt["head_hash"],
            "view": rebuilt_control["view"], "commit_count": len(incoming_commits),
            "view_change_count": len(rebuilt_control["view_certificates"])}


def status(node_dir: Path) -> dict[str, Any]:
    network, descriptor, _ = _context(node_dir)
    control = _load_control(node_dir)
    state = load_state(node_dir)
    locks = _read(node_dir / LOCKS_FILE)
    return {"validator_id": descriptor["validator_id"], "network_id": network["network_id"],
            "view": control["view"], "sequence": state["sequence"],
            "head_hash": state["head_hash"], "prepared_locks": len(locks.get("prepared", {})),
            "quorum": network["quorum"], "fault_tolerance": network["fault_tolerance"]}


def _write_json(path: Path, value: Any) -> None:
    _write(path, value, 0o644)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LAEV HUC 0.8 — consenso BFT con PrepareCertificate, LockCertificate y ViewChange")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="Inicializar el motor BFT en un nodo HUC-RSP ya enrolado")
    p.add_argument("--node-dir", type=Path, required=True)
    p = sub.add_parser("propose", help="Crear una transición UTXO HUC contra el estado BFT")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--action", choices=["ISSUE", "RENEW", "REVOKE"], required=True)
    p.add_argument("--certificate-sha256", required=True); p.add_argument("--consensus-sha256", required=True)
    p.add_argument("--previous-certificate-sha256"); p.add_argument("--metadata", default="{}")
    p.add_argument("--certificate", type=Path); p.add_argument("--consensus-certificate", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("preprepare", help="Crear PRE-PREPARE como primario de la vista")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--proposal", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("prepare", help="Validar PRE-PREPARE y firmar PREPARE")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--preprepare", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("prepare-cert", help="Ensamblar quorum certificate de PREPARE")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--preprepare", type=Path, required=True); p.add_argument("--vote", type=Path, nargs="+", required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("prepared-ack", help="Persistir prepared lock y firmar ACK")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--prepare-cert", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("prepared-cert", help="Ensamblar PreparedCertificate con quorum de locks")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--prepare-cert", type=Path, required=True); p.add_argument("--ack", type=Path, nargs="+", required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("commit-vote", help="Validar PreparedCertificate y firmar COMMIT")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--prepared-cert", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("commit-cert", help="Ensamblar CommitCertificate")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--prepared-cert", type=Path, required=True); p.add_argument("--vote", type=Path, nargs="+", required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("apply", help="Verificar y aplicar CommitCertificate")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--commit-cert", type=Path, required=True)
    p = sub.add_parser("view-change", help="Crear mensaje VIEW_CHANGE")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--target-view", type=int, required=True); p.add_argument("--reason", default="timeout"); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("new-view", help="Ensamblar NEW_VIEW a partir de quórum VIEW_CHANGE")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--view-change", type=Path, nargs="+", required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("install-view", help="Verificar e instalar NEW_VIEW")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--certificate", type=Path, required=True)
    p = sub.add_parser("repropose", help="Re-proponer PreparedCertificate seleccionado por NEW_VIEW")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("export-state", help="Exportar paquete verificable de estado BFT sin claves privadas")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("sync-state", help="Sincronizar desde un paquete de estado BFT verificado")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--package", type=Path, required=True)
    p = sub.add_parser("status", help="Mostrar estado local del motor BFT")
    p.add_argument("--node-dir", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = initialize_node(args.node_dir)
        elif args.command == "propose":
            metadata = huc.strict_json_loads(args.metadata)
            if not isinstance(metadata, dict):
                raise ValueError("metadata debe ser un objeto JSON")
            result = create_operation_proposal(args.node_dir, args.action, args.certificate_sha256,
                                               args.consensus_sha256, args.output,
                                               args.previous_certificate_sha256, metadata,
                                               args.certificate, args.consensus_certificate)
        elif args.command == "preprepare":
            result = create_preprepare(args.node_dir, args.proposal, args.output)
        elif args.command == "prepare":
            pp = _read(args.preprepare); vote = accept_preprepare(args.node_dir, pp); _write_json(args.output, vote)
            result = {"result": "prepare_signed", "output": str(args.output)}
        elif args.command == "prepare-cert":
            network, _, _ = _context(args.node_dir); state = load_state(args.node_dir)
            result_cert = assemble_prepare_certificate(network, state, _read(args.preprepare), [_read(p) for p in args.vote]); _write_json(args.output, result_cert)
            result = {"result": "prepare_certificate_created", "output": str(args.output), "id": result_cert["prepare_certificate_id"]}
        elif args.command == "prepared-ack":
            ack = create_prepared_ack(args.node_dir, _read(args.prepare_cert)); _write_json(args.output, ack)
            result = {"result": "prepared_ack_signed", "output": str(args.output)}
        elif args.command == "prepared-cert":
            network, _, _ = _context(args.node_dir); state = load_state(args.node_dir)
            cert = assemble_prepared_certificate(network, state, _read(args.prepare_cert), [_read(p) for p in args.ack]); _write_json(args.output, cert)
            result = {"result": "prepared_certificate_created", "output": str(args.output), "id": cert["prepared_certificate_id"]}
        elif args.command == "commit-vote":
            vote = create_commit_vote(args.node_dir, _read(args.prepared_cert)); _write_json(args.output, vote)
            result = {"result": "commit_signed", "output": str(args.output)}
        elif args.command == "commit-cert":
            network, _, _ = _context(args.node_dir); state = load_state(args.node_dir)
            cert = assemble_commit_certificate(network, state, _read(args.prepared_cert), [_read(p) for p in args.vote]); _write_json(args.output, cert)
            result = {"result": "commit_certificate_created", "output": str(args.output), "commit_id": cert["body"]["commit_id"]}
        elif args.command == "apply":
            result = apply_commit_certificate(args.node_dir, _read(args.commit_cert))
        elif args.command == "view-change":
            msg = create_view_change(args.node_dir, args.target_view, args.reason); _write_json(args.output, msg)
            result = {"result": "view_change_signed", "output": str(args.output)}
        elif args.command == "new-view":
            net, _, _ = _context(args.node_dir)
            certs = [_read(p) for p in args.view_change]
            result = assemble_new_view(args.node_dir, certs, args.output)
        elif args.command == "install-view":
            result = install_new_view(args.node_dir, _read(args.certificate))
        elif args.command == "repropose":
            result = repropose_selected(args.node_dir, args.output)
        elif args.command == "export-state":
            result = export_state(args.node_dir, args.output)
        elif args.command == "sync-state":
            result = sync_state(args.node_dir, args.package)
        elif args.command == "status":
            result = status(args.node_dir)
        else:
            parser.error("Comando desconocido"); return 2
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
