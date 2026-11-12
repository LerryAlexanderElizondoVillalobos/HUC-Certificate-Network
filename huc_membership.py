#!/usr/bin/env python3
"""LAEV HUC 0.7 controlled validator membership and epoch handoff.

Membership changes are authorized by the CURRENT validator quorum. A
successful package creates a successor network manifest and a signed state
checkpoint. Existing validators must explicitly reconfigure; a new validator
joins using its own locally-generated private key. Removed validators cannot
activate the successor network.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import sys
import os
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import huc
import huc_replicated as rsp

VERSION = "0.7.0"
JOIN_SCHEMA = "LAEV-HUC-MEMBERSHIP-JOIN-REQUEST-1"
PROPOSAL_SCHEMA = "LAEV-HUC-MEMBERSHIP-PROPOSAL-1"
VOTE_SCHEMA = "LAEV-HUC-MEMBERSHIP-VOTE-1"
CERT_SCHEMA = "LAEV-HUC-MEMBERSHIP-CERTIFICATE-1"
CHECKPOINT_SCHEMA = "LAEV-HUC-EPOCH-CHECKPOINT-1"
PACKAGE_SCHEMA = "LAEV-HUC-MEMBERSHIP-PACKAGE-1"
LOCK_FILE = "membership-vote-locks.json"
NETWORK_FILE = rsp.NETWORK_FILE
NODE_TRUST = rsp.NODE_TRUST


def _canonical(obj: Any) -> bytes:
    return rsp._canonical(obj)


def _hash(obj: Any) -> str:
    return rsp._hash(obj)


def _signing_message(domain: str, payload: dict[str, Any]) -> bytes:
    return _canonical({"domain": domain, "payload": payload})


def _snapshot(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "LAEV-HUC-RSP-CHECKPOINT-STATE-1",
        "network_id": state["network_id"],
        "epoch": state["epoch"],
        "sequence": state["sequence"],
        "head_hash": state["head_hash"],
        "certificates": state["certificates"],
        "commit_ids": state["commit_ids"],
    }


def _validator_descriptor(path: Path) -> dict[str, Any]:
    descriptor = rsp._read(path)
    if descriptor.get("schema") != rsp.NODE_SCHEMA or descriptor.get("algorithm") != "Ed25519":
        raise ValueError("Descriptor de nuevo validador no reconocido")
    pub = huc.load_ed_public_pem(descriptor.get("public_key_pem", ""))
    key_hash = huc.sha256(huc.der_public(pub))
    if descriptor.get("public_key_sha256") != key_hash:
        raise ValueError("Hash de clave pública en descriptor incorrecto")
    return {
        "validator_id": descriptor["validator_id"],
        "public_key_pem": descriptor["public_key_pem"],
        "public_key_sha256": key_hash,
    }


def create_join_request(node_dir: Path, output: Path, network_path: Path) -> dict[str, Any]:
    descriptor = rsp._read(Path(node_dir) / rsp.NODE_PUBLIC)
    key = rsp._private(Path(node_dir) / rsp.NODE_PRIVATE)
    if rsp._pub_pem_text(key.public_key()) != descriptor.get("public_key_pem"):
        raise ValueError("La clave privada local no corresponde al descriptor")
    network = rsp.validate_network(rsp._read(network_path))
    payload = {
        "schema": JOIN_SCHEMA,
        "network_id": network["network_id"],
        "validator_id": descriptor["validator_id"],
        "public_key_sha256": descriptor["public_key_sha256"],
        "nonce": huc.sha256(huc.os.urandom(32)),
        "created_at_utc": huc.iso(),
    }
    signature = base64.b64encode(key.sign(_signing_message("HUC-MEMBERSHIP-JOIN-0.7", payload))).decode("ascii")
    request = {"payload": payload, "descriptor": _validator_descriptor(Path(node_dir) / rsp.NODE_PUBLIC),
               "signature": signature}
    output.parent.mkdir(parents=True, exist_ok=True)
    huc.write_json(output, request, 0o644)
    return {"result": "membership_join_request_created", "validator_id": descriptor["validator_id"],
            "join_request": str(output.resolve()), "private_key_included": False}


def _verify_join_request(network: dict[str, Any], request: dict[str, Any], check_age: bool = True) -> dict[str, Any]:
    payload = request.get("payload")
    descriptor = request.get("descriptor")
    if not isinstance(payload, dict) or payload.get("schema") != JOIN_SCHEMA or not isinstance(descriptor, dict):
        raise ValueError("Solicitud de incorporación no reconocida")
    desc_id = descriptor.get("validator_id")
    if payload.get("network_id") != network["network_id"] or payload.get("validator_id") != desc_id:
        raise ValueError("Solicitud de incorporación pertenece a otra red o identidad")
    if payload.get("public_key_sha256") != descriptor.get("public_key_sha256"):
        raise ValueError("La huella de la solicitud no coincide con el descriptor")
    # Validate descriptor and proof-of-possession using the proposed member's key.
    fake_path = None
    pub = huc.load_ed_public_pem(descriptor.get("public_key_pem", ""))
    if huc.sha256(huc.der_public(pub)) != descriptor.get("public_key_sha256"):
        raise ValueError("Descriptor de incorporación con clave pública incorrecta")
    try:
        sig = base64.b64decode(request.get("signature", ""), validate=True)
        pub.verify(sig, _signing_message("HUC-MEMBERSHIP-JOIN-0.7", payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Prueba de posesión de clave del nuevo miembro inválida") from exc
    created = rsp._parse_time(payload.get("created_at_utc", ""))
    if check_age and abs((huc.now_utc() - created).total_seconds()) > 86400:
        raise ValueError("Solicitud de incorporación expirada (máximo 24 horas)")
    if not isinstance(payload.get("nonce"), str) or len(payload["nonce"]) != 64:
        raise ValueError("Nonce de incorporación inválido")
    return descriptor


def _target_fault_tolerance(count: int) -> int:
    if count < 4 or (count - 1) % 3 != 0:
        raise ValueError("La membresía objetivo debe cumplir n=3f+1 (4, 7, 10, ...) ")
    return (count - 1) // 3


def _validate_target_validators(validators: list[dict[str, Any]], fault_tolerance: int) -> None:
    if len(validators) != 3 * fault_tolerance + 1:
        raise ValueError("Membresía objetivo no cumple n=3f+1")
    ids, keys = set(), set()
    for item in validators:
        validator_id = item.get("validator_id")
        if not isinstance(validator_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", validator_id):
            raise ValueError("Identificador de miembro objetivo inválido")
        if validator_id in ids:
            raise ValueError("IDs duplicados en membresía objetivo")
        ids.add(validator_id)
        pub = huc.load_ed_public_pem(item.get("public_key_pem", ""))
        actual = huc.sha256(huc.der_public(pub))
        if item.get("public_key_sha256") != actual or actual in keys:
            raise ValueError("Clave pública duplicada o hash incorrecto en membresía objetivo")
        keys.add(actual)


def create_membership_proposal(node_dir: Path, join_request_paths: list[Path],
                               remove_validator_ids: list[str], output: Path) -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context(node_dir)
    current_state = rsp.load_state(node_dir)
    if not join_request_paths and not remove_validator_ids:
        raise ValueError("La propuesta debe agregar o retirar al menos un miembro")
    current = {v["validator_id"]: dict(v) for v in network["validators"]}
    if len(set(remove_validator_ids)) != len(remove_validator_ids):
        raise ValueError("IDs de retiro duplicados")
    for validator_id in remove_validator_ids:
        if validator_id not in current:
            raise ValueError(f"No existe el validador a retirar: {validator_id}")
        del current[validator_id]
    additions = []
    for path in join_request_paths:
        request = rsp._read(path)
        item = _verify_join_request(network, request)
        validator_id = item["validator_id"]
        if validator_id in current or any(x["validator_id"] == validator_id for x in additions):
            raise ValueError("El nuevo validador ya existe en la membresía")
        additions.append(item)
        current[validator_id] = item
    target = sorted(current.values(), key=lambda x: x["validator_id"])
    f = _target_fault_tolerance(len(target))
    _validate_target_validators(target, f)
    state_snapshot = _snapshot(current_state)
    join_proofs = [rsp._read(path) for path in join_request_paths]
    payload = {
        "schema": PROPOSAL_SCHEMA,
        "previous_network_id": network["network_id"],
        "previous_network_sha256": rsp.network_hash(network),
        "membership_epoch": int(network.get("membership_epoch", 0)) + 1,
        "proposer_id": descriptor["validator_id"],
        "created_at_utc": huc.iso(),
        "previous_state_sha256": _hash(state_snapshot),
        "previous_state": state_snapshot,
        "additions": additions,
        "join_proofs": join_proofs,
        "removals": sorted(remove_validator_ids),
        "target_fault_tolerance": f,
        "target_quorum": 2 * f + 1,
        "target_validators": target,
    }
    proposal = {"payload": payload, "proposal_id": _hash(payload)}
    output.parent.mkdir(parents=True, exist_ok=True)
    huc.write_json(output, proposal, 0o644)
    return {"result": "membership_proposal_created", "proposal_id": proposal["proposal_id"],
            "old_validator_count": len(network["validators"]), "target_validator_count": len(target),
            "target_fault_tolerance": f, "target_quorum": 2 * f + 1,
            "additions": [x["validator_id"] for x in additions], "removals": sorted(remove_validator_ids),
            "proposal_file": str(output.resolve())}


def _validate_membership_proposal(network: dict[str, Any], state: dict[str, Any],
                                  proposal: dict[str, Any]) -> dict[str, Any]:
    payload = proposal.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != PROPOSAL_SCHEMA:
        raise ValueError("Propuesta de membresía no reconocida")
    if proposal.get("proposal_id") != _hash(payload):
        raise ValueError("proposal_id de membresía incorrecto")
    if payload.get("previous_network_id") != network["network_id"] or payload.get("previous_network_sha256") != rsp.network_hash(network):
        raise ValueError("Propuesta basada en otra membresía")
    snapshot = _snapshot(state)
    if payload.get("previous_state") != snapshot or payload.get("previous_state_sha256") != _hash(snapshot):
        raise ValueError("Estado cambió desde la propuesta de membresía")
    if payload.get("membership_epoch") != int(network.get("membership_epoch", 0)) + 1:
        raise ValueError("membership_epoch no es el siguiente")
    old = {v["validator_id"] for v in network["validators"]}
    removals = payload.get("removals")
    additions = payload.get("additions")
    target = payload.get("target_validators")
    if not isinstance(removals, list) or len(set(removals)) != len(removals) or not set(removals).issubset(old):
        raise ValueError("Lista de retiros inválida")
    if not isinstance(additions, list) or not isinstance(target, list):
        raise ValueError("Lista de altas o membresía objetivo inválida")
    expected = {v["validator_id"]: dict(v) for v in network["validators"] if v["validator_id"] not in removals}
    add_ids = set()
    for item in additions:
        add_ids.add(item.get("validator_id"))
        if item.get("validator_id") in expected:
            raise ValueError("Alta de un miembro que ya existe")
        pub = huc.load_ed_public_pem(item.get("public_key_pem", ""))
        if huc.sha256(huc.der_public(pub)) != item.get("public_key_sha256"):
            raise ValueError("Descriptor agregado inválido")
        expected[item["validator_id"]] = item
    normalized = sorted(expected.values(), key=lambda x: x["validator_id"])
    if normalized != target:
        raise ValueError("Membresía objetivo no coincide con altas y retiros")
    f = payload.get("target_fault_tolerance")
    if not isinstance(f, int) or f != _target_fault_tolerance(len(target)):
        raise ValueError("Tolerancia objetivo incorrecta")
    if payload.get("target_quorum") != 2 * f + 1:
        raise ValueError("Quórum objetivo incorrecto")
    _validate_target_validators(target, f)
    # The proposal creator supplies proof-of-possession envelopes for new IDs.
    join_proofs = payload.get("join_proofs", [])
    if not isinstance(join_proofs, list) or {x.get("payload", {}).get("validator_id") for x in join_proofs} != add_ids:
        raise ValueError("Faltan pruebas de posesión de los nuevos miembros")
    for proof in join_proofs:
        verified_descriptor = _verify_join_request(network, proof)
        target_item = next((x for x in additions if x["validator_id"] == verified_descriptor["validator_id"]), None)
        if target_item != verified_descriptor:
            raise ValueError("Prueba de posesión no coincide con el descriptor agregado")
    return payload


def membership_vote(node_dir: Path, proposal_path: Path, output: Path) -> dict[str, Any]:
    network, descriptor, key = rsp._node_context(node_dir)
    state = rsp.load_state(node_dir)
    proposal = rsp._read(proposal_path)
    payload = _validate_membership_proposal(network, state, proposal)
    vote_path = node_dir / LOCK_FILE
    lock = FileLock(str(vote_path) + ".lock", timeout=10)
    try:
        with lock:
            locks = rsp._read(vote_path) if vote_path.exists() else {"schema": "LAEV-HUC-MEMBERSHIP-LOCKS-1", "locks": {}}
            slot = str(payload["membership_epoch"])
            previous = locks.get("locks", {}).get(slot)
            if previous:
                if previous.get("proposal_id") != proposal["proposal_id"]:
                    raise ValueError("Anti-equivocación: ya se aprobó otra propuesta para esta época de membresía")
                vote = previous["vote"]
            else:
                vp = {
                    "schema": VOTE_SCHEMA,
                    "network_id": network["network_id"],
                    "membership_epoch": payload["membership_epoch"],
                    "proposal_id": proposal["proposal_id"],
                    "validator_id": descriptor["validator_id"],
                    "previous_state_sha256": payload["previous_state_sha256"],
                    "decision": "APPROVE",
                    "created_at_utc": huc.iso(),
                }
                sig = base64.b64encode(key.sign(_signing_message("HUC-MEMBERSHIP-VOTE-0.7", vp))).decode("ascii")
                vote = {"payload": vp, "signature": sig}
                locks.setdefault("locks", {})[slot] = {"proposal_id": proposal["proposal_id"], "vote": vote}
                huc.write_json(vote_path, locks)
            output.parent.mkdir(parents=True, exist_ok=True)
            huc.write_json(output, vote, 0o644)
    except Timeout as exc:
        raise TimeoutError("No se pudo bloquear voto de membresía") from exc
    return {"result": "membership_vote_signed", "validator_id": descriptor["validator_id"],
            "proposal_id": proposal["proposal_id"], "vote_file": str(output.resolve())}


def _verify_membership_vote(network: dict[str, Any], proposal: dict[str, Any], vote: dict[str, Any]) -> None:
    p = proposal["payload"]
    vp = vote.get("payload")
    if not isinstance(vp, dict) or vp.get("schema") != VOTE_SCHEMA:
        raise ValueError("Voto de membresía no reconocido")
    validator = rsp._validator(network, vp.get("validator_id"))
    expected = {
        "network_id": network["network_id"],
        "membership_epoch": p["membership_epoch"],
        "proposal_id": proposal["proposal_id"],
        "previous_state_sha256": p["previous_state_sha256"],
        "decision": "APPROVE",
    }
    for field, value in expected.items():
        if vp.get(field) != value:
            raise ValueError(f"Voto de membresía no corresponde a propuesta: {field}")
    created = rsp._parse_time(vp.get("created_at_utc", ""))
    prop_created = rsp._parse_time(p["created_at_utc"])
    if not prop_created <= created <= prop_created + huc.timedelta(hours=24):
        raise ValueError("Voto de membresía fuera de ventana temporal")
    rsp._verify_sig(validator["public_key_pem"], vote.get("signature", ""),
                    _signing_message("HUC-MEMBERSHIP-VOTE-0.7", vp))


def assemble_membership_certificate(node_dir: Path, proposal_path: Path,
                                    vote_paths: list[Path], output: Path) -> dict[str, Any]:
    old_network, _, _ = rsp._node_context(node_dir)
    state = rsp.load_state(node_dir)
    proposal = rsp._read(proposal_path)
    payload = _validate_membership_proposal(old_network, state, proposal)
    votes = [rsp._read(path) for path in vote_paths]
    seen = set()
    for vote in votes:
        _verify_membership_vote(old_network, proposal, vote)
        vid = vote["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("Voto de membresía duplicado")
        seen.add(vid)
    if len(seen) < old_network["quorum"]:
        raise ValueError(f"Quórum de membresía insuficiente: se requieren {old_network['quorum']} firmas")
    target_core = {
        "schema": rsp.NETWORK_SCHEMA,
        "protocol": "HUC-RSP/0.7",
        "fault_tolerance": payload["target_fault_tolerance"],
        "quorum": payload["target_quorum"],
        "validators": payload["target_validators"],
        "membership_epoch": payload["membership_epoch"],
        "previous_network_id": old_network["network_id"],
    }
    if "pki" in old_network:
        target_core["pki"] = old_network["pki"]
    target_network = dict(target_core)
    target_network["network_id"] = _hash(target_core)
    target_network["created_at_utc"] = huc.iso()
    rsp.validate_network(target_network)
    votes.sort(key=lambda x: x["payload"]["validator_id"])
    body = {
        "schema": CERT_SCHEMA,
        "previous_network": old_network,
        "target_network": target_network,
        "proposal": proposal,
        "votes": votes,
        "quorum": old_network["quorum"],
        "checkpoint_snapshot": payload["previous_state"],
        "checkpoint_snapshot_sha256": payload["previous_state_sha256"],
        "created_at_utc": huc.iso(),
    }
    certificate = {"body": body, "membership_certificate_id": _hash(body)}
    package = {
        "schema": PACKAGE_SCHEMA,
        "membership_certificate": certificate,
        "target_network": target_network,
        "checkpoint": {
            "schema": CHECKPOINT_SCHEMA,
            "membership_certificate_id": certificate["membership_certificate_id"],
            "membership_certificate": certificate,
            "snapshot": payload["previous_state"],
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    huc.write_json(output, package, 0o644)
    return {
        "result": "membership_transition_certified",
        "membership_certificate_id": certificate["membership_certificate_id"],
        "previous_network_id": old_network["network_id"],
        "target_network_id": target_network["network_id"],
        "target_validator_count": len(target_network["validators"]),
        "quorum_signatures": len(votes),
        "package": str(output.resolve()),
        "activation": "Requires explicit epoch handoff on each retained/new node; removed validators cannot join the successor network.",
    }


def verify_membership_package(package: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if package.get("schema") != PACKAGE_SCHEMA:
        raise ValueError("Paquete de membresía no reconocido")
    cert = package.get("membership_certificate")
    if not isinstance(cert, dict) or not isinstance(cert.get("body"), dict):
        raise ValueError("Paquete sin certificado de membresía")
    body = cert["body"]
    if body.get("schema") != CERT_SCHEMA or cert.get("membership_certificate_id") != _hash(body):
        raise ValueError("Hash del certificado de membresía incorrecto")
    old_network = rsp.validate_network(body["previous_network"])
    target_network = rsp.validate_network(body["target_network"])
    if package.get("target_network") != target_network:
        raise ValueError("Manifiesto objetivo no coincide con certificado")
    proposal = body["proposal"]
    if proposal.get("proposal_id") != _hash(proposal.get("payload", {})):
        raise ValueError("Hash de propuesta de membresía incorrecto")
    payload = proposal["payload"]
    if payload.get("previous_network_id") != old_network["network_id"]:
        raise ValueError("Membresía no enlaza red anterior")
    if target_network.get("previous_network_id") != old_network["network_id"]:
        raise ValueError("Red objetivo no enlaza red anterior")
    if target_network.get("membership_epoch") != payload.get("membership_epoch"):
        raise ValueError("Época de membresía objetivo incorrecta")
    if target_network["validators"] != payload.get("target_validators"):
        raise ValueError("Membresía objetivo no coincide con la propuesta")
    if (target_network.get("fault_tolerance") != payload.get("target_fault_tolerance")
            or target_network.get("quorum") != payload.get("target_quorum")
            or target_network.get("pki") != old_network.get("pki")):
        raise ValueError("La red objetivo altera parámetros de quórum o PKI no aprobados")
    if body.get("quorum") != old_network["quorum"]:
        raise ValueError("Quórum certificado incorrecto")
    snapshot = body.get("checkpoint_snapshot")
    if not isinstance(snapshot, dict) or body.get("checkpoint_snapshot_sha256") != _hash(snapshot):
        raise ValueError("Snapshot de checkpoint incorrecto")
    if snapshot.get("network_id") != old_network["network_id"]:
        raise ValueError("Snapshot pertenece a otra red")
    if payload.get("previous_state") != snapshot or payload.get("previous_state_sha256") != _hash(snapshot):
        raise ValueError("Snapshot no coincide con propuesta firmada")
    _validate_package_target(old_network, target_network, proposal)
    votes = body.get("votes")
    if not isinstance(votes, list):
        raise ValueError("Certificado de membresía sin votos")
    seen = set()
    for vote in votes:
        _verify_membership_vote(old_network, proposal, vote)
        vid = vote["payload"]["validator_id"]
        if vid in seen:
            raise ValueError("Votos de membresía duplicados")
        seen.add(vid)
    if len(seen) < old_network["quorum"]:
        raise ValueError("Certificado de membresía no alcanza quórum")
    checkpoint = package.get("checkpoint")
    if not isinstance(checkpoint, dict) or checkpoint.get("schema") != CHECKPOINT_SCHEMA:
        raise ValueError("Checkpoint de época no reconocido")
    if checkpoint.get("membership_certificate_id") != cert["membership_certificate_id"] or checkpoint.get("snapshot") != snapshot:
        raise ValueError("Checkpoint no coincide con el certificado de membresía")
    return old_network, target_network, checkpoint


def _validate_package_target(old_network: dict[str, Any], target_network: dict[str, Any], proposal: dict[str, Any]) -> None:
    payload = proposal["payload"]
    core = {k: v for k, v in target_network.items() if k not in {"network_id", "created_at_utc"}}
    if target_network["network_id"] != _hash(core):
        raise ValueError("Hash de manifiesto objetivo incorrecto")
    if target_network.get("membership_epoch") != int(old_network.get("membership_epoch", 0)) + 1:
        raise ValueError("La época objetivo no sigue a la red anterior")
    _validate_target_validators(target_network["validators"], target_network["fault_tolerance"])
    _validate_membership_proposal_against_old(old_network, proposal)


def _validate_membership_proposal_against_old(old_network: dict[str, Any], proposal: dict[str, Any]) -> None:
    payload = proposal["payload"]
    old_ids = {v["validator_id"] for v in old_network["validators"]}
    removals = payload["removals"]
    additions = payload["additions"]
    expected = {v["validator_id"]: v for v in old_network["validators"] if v["validator_id"] not in removals}
    for item in additions:
        expected[item["validator_id"]] = item
    target = sorted(expected.values(), key=lambda x: x["validator_id"])
    if target != payload["target_validators"]:
        raise ValueError("Propuesta de membresía modifica claves fuera de las altas y retiros")
    if not set(removals).issubset(old_ids):
        raise ValueError("La propuesta retira miembros que no pertenecen a la red anterior")
    # Proof of possession is checked again by each signer when they vote.
    proofs = payload.get("join_proofs", [])
    if {x.get("payload", {}).get("validator_id") for x in proofs} != {x["validator_id"] for x in additions}:
        raise ValueError("Las altas no tienen todas sus pruebas de posesión")
    for proof in proofs:
        verified = _verify_join_request(old_network, proof, check_age=False)
        if not any(verified == item for item in additions):
            raise ValueError("Prueba de posesión no corresponde a descriptor objetivo")


def verify_epoch_checkpoint(network: dict[str, Any], checkpoint: dict[str, Any]) -> dict[str, Any]:
    package = {
        "schema": PACKAGE_SCHEMA,
        "membership_certificate": checkpoint.get("membership_certificate"),
        "target_network": network,
        "checkpoint": checkpoint,
    }
    _, target_network, verified_checkpoint = verify_membership_package(package)
    if rsp.network_hash(target_network) != rsp.network_hash(network):
        raise ValueError("Checkpoint está autorizado para otra red objetivo")
    snapshot = verified_checkpoint["snapshot"]
    state = {
        "schema": rsp.STATE_SCHEMA,
        "network_id": network["network_id"],
        "epoch": snapshot["epoch"] + 1,
        "sequence": snapshot["sequence"],
        "head_hash": snapshot["head_hash"],
        "certificates": snapshot["certificates"],
        "commit_ids": snapshot["commit_ids"],
        "membership_epoch": network["membership_epoch"],
        "membership_certificate_id": verified_checkpoint["membership_certificate_id"],
    }
    return state


def _archive_current_node(node_dir: Path, epoch: int) -> Path:
    history = node_dir / "history" / f"membership-epoch-{epoch}"
    if history.exists():
        raise FileExistsError("El archivo histórico de esta época ya existe")
    history.mkdir(parents=True, exist_ok=False)
    for filename in (rsp.NETWORK_FILE, rsp.NODE_TRUST, rsp.LEDGER_FILE, rsp.STATE_FILE,
                     rsp.VOTE_LOCKS, "view-state.json", "view-change-locks.json", LOCK_FILE,
                     "peer-map.json", "peer-map-trust.json", "peer-replay-cache.json"):
        source = node_dir / filename
        if source.exists():
            shutil.copy2(source, history / filename)
    return history


def activate_membership(node_dir: Path, package_path: Path) -> dict[str, Any]:
    node_dir = Path(node_dir).resolve()
    old_network = rsp.load_network(node_dir)
    old_state = rsp.load_state(node_dir)
    package = rsp._read(package_path)
    verified_old, target_network, checkpoint = verify_membership_package(package)
    if verified_old["network_id"] != old_network["network_id"]:
        raise ValueError("El paquete no continúa la red actual de este nodo")
    descriptor = rsp._read(node_dir / rsp.NODE_PUBLIC)
    key = rsp._private(node_dir / rsp.NODE_PRIVATE)
    if rsp._pub_pem_text(key.public_key()) != descriptor["public_key_pem"]:
        raise ValueError("Clave privada local no corresponde al nodo")
    target_member = next((x for x in target_network["validators"] if x["validator_id"] == descriptor["validator_id"]), None)
    if not target_member or target_member["public_key_pem"] != descriptor["public_key_pem"]:
        raise ValueError("Este nodo fue retirado y no puede activar la nueva membresía")
    if _snapshot(old_state) != checkpoint["snapshot"]:
        raise ValueError("El estado local no coincide con el checkpoint aprobado")
    epoch = int(old_network.get("membership_epoch", 0))
    archive = _archive_current_node(node_dir, epoch)
    huc.atomic_write(node_dir / rsp.NETWORK_FILE, _canonical(target_network) + b"\n", 0o644)
    huc.write_json(node_dir / rsp.NODE_TRUST, {
        "schema": "LAEV-HUC-RSP-NODE-TRUST-1",
        "validator_id": descriptor["validator_id"],
        "network_sha256": rsp.network_hash(target_network),
        "joined_at_utc": huc.iso(),
        "membership_epoch": target_network["membership_epoch"],
    })
    huc.write_json(node_dir / rsp.CHECKPOINT_FILE, checkpoint)
    huc.atomic_write(node_dir / rsp.LEDGER_FILE, b"")
    huc.write_json(node_dir / rsp.VOTE_LOCKS, {"schema": "LAEV-HUC-RSP-VOTE-LOCKS-1", "locks": {}})
    state = rsp._replay(target_network, [], checkpoint)
    huc.write_json(node_dir / rsp.STATE_FILE, state)
    # The old peer map is tied to the predecessor network and must be re-pinned.
    for filename in ("peer-map.json", "peer-map-trust.json", "view-state.json",
                     "view-change-locks.json", "peer-replay-cache.json"):
        try:
            (node_dir / filename).unlink()
        except FileNotFoundError:
            pass
    import huc_view
    huc_view.initialize_view_state(node_dir)
    return {"result": "membership_activated", "validator_id": descriptor["validator_id"],
            "membership_epoch": target_network["membership_epoch"],
            "network_id": target_network["network_id"], "sequence": state["sequence"],
            "head_hash": state["head_hash"], "history_archive": str(archive)}


def join_successor_network(node_dir: Path, package_path: Path) -> dict[str, Any]:
    node_dir = Path(node_dir).resolve()
    if (node_dir / rsp.NETWORK_FILE).exists():
        raise FileExistsError("El nodo ya pertenece a una red; use membership-activate")
    package = rsp._read(package_path)
    _, target_network, checkpoint = verify_membership_package(package)
    descriptor = rsp._read(node_dir / rsp.NODE_PUBLIC)
    key = rsp._private(node_dir / rsp.NODE_PRIVATE)
    if rsp._pub_pem_text(key.public_key()) != descriptor["public_key_pem"]:
        raise ValueError("Clave privada del nuevo miembro no corresponde al descriptor")
    item = next((x for x in target_network["validators"] if x["validator_id"] == descriptor["validator_id"]), None)
    if item is None or item["public_key_pem"] != descriptor["public_key_pem"]:
        raise ValueError("Este dispositivo no fue aprobado como miembro de la red sucesora")
    huc.atomic_write(node_dir / rsp.NETWORK_FILE, _canonical(target_network) + b"\n", 0o644)
    huc.write_json(node_dir / rsp.NODE_TRUST, {
        "schema": "LAEV-HUC-RSP-NODE-TRUST-1",
        "validator_id": descriptor["validator_id"],
        "network_sha256": rsp.network_hash(target_network),
        "joined_at_utc": huc.iso(),
        "membership_epoch": target_network["membership_epoch"],
    })
    huc.write_json(node_dir / rsp.CHECKPOINT_FILE, checkpoint)
    huc.atomic_write(node_dir / rsp.LEDGER_FILE, b"")
    huc.write_json(node_dir / rsp.VOTE_LOCKS, {"schema": "LAEV-HUC-RSP-VOTE-LOCKS-1", "locks": {}})
    state = rsp._replay(target_network, [], checkpoint)
    huc.write_json(node_dir / rsp.STATE_FILE, state)
    import huc_view
    huc_view.initialize_view_state(node_dir)
    return {"result": "new_member_joined", "validator_id": descriptor["validator_id"],
            "membership_epoch": target_network["membership_epoch"],
            "network_id": target_network["network_id"], "sequence": state["sequence"],
            "head_hash": state["head_hash"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LAEV HUC 0.7 membership protocol")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("join-request")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--network", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("propose")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--join-request", type=Path, action="append", default=[])
    p.add_argument("--remove-validator", action="append", default=[])
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("vote")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("certify")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--vote", type=Path, nargs="+", required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("verify-package")
    p.add_argument("--package", type=Path, required=True)
    p = sub.add_parser("activate")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--package", type=Path, required=True)
    p = sub.add_parser("join-successor")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--package", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "join-request":
            result = create_join_request(args.node_dir, args.output, args.network)
        elif args.command == "propose":
            result = create_membership_proposal(args.node_dir, args.join_request, args.remove_validator, args.output)
        elif args.command == "vote":
            result = membership_vote(args.node_dir, args.proposal, args.output)
        elif args.command == "certify":
            result = assemble_membership_certificate(args.node_dir, args.proposal, args.vote, args.output)
        elif args.command == "verify-package":
            package = rsp._read(args.package)
            old, target, checkpoint = verify_membership_package(package)
            result = {"result": "membership_package_valid", "previous_network_id": old["network_id"],
                      "target_network_id": target["network_id"], "target_members": [x["validator_id"] for x in target["validators"]],
                      "checkpoint_sequence": checkpoint["snapshot"]["sequence"]}
        elif args.command == "activate":
            result = activate_membership(args.node_dir, args.package)
        elif args.command == "join-successor":
            result = join_successor_network(args.node_dir, args.package)
        else:
            parser.error("Comando desconocido")
            return 2
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
