#!/usr/bin/env python3
"""LAEV HUC 0.7 peer-to-peer transport over signed TCP messages.

The prototype uses direct TCP sockets, Ed25519 application signatures and
optional TLS 1.2+ transport encryption. For production, run with TLS or a
trusted VPN, fixed peer pins, rate limits and operational monitoring.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import ssl
import ipaddress
import tempfile
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography.hazmat.primitives import serialization

import huc
import huc_replicated as rsp
import huc_view as view
import huc_membership as membership

VERSION = "0.7.0"
PEER_MAP_SCHEMA = "LAEV-HUC-PEER-MAP-1"
PEER_MAP_FILE = "peer-map.json"
PEER_TRUST_FILE = "peer-map-trust.json"
REPLAY_FILE = "peer-replay-cache.json"
ENVELOPE_SCHEMA = "LAEV-HUC-PEER-ENVELOPE-1"
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_REPLAY_IDS = 5000
DEFAULT_TIMEOUT = 4.0


def _canonical(obj: Any) -> bytes:
    return rsp._canonical(obj)


def _hash(obj: Any) -> str:
    return rsp._hash(obj)


def _parse_endpoint(value: str) -> tuple[str, str, int]:
    if "=" not in value:
        raise ValueError("Endpoint debe tener formato ID=HOST:PORT")
    validator_id, address = value.split("=", 1)
    if ":" not in address:
        raise ValueError("Endpoint debe terminar en :PORT")
    host, port_text = address.rsplit(":", 1)
    if not validator_id or not host:
        raise ValueError("ID y host de endpoint son obligatorios")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("Puerto de endpoint inválido") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Puerto debe estar entre 1 y 65535")
    return validator_id, host, port


def create_peer_map(network_path: Path, expected_network_sha256: str,
                    endpoint_specs: list[str], output: Path) -> dict[str, Any]:
    network = rsp.validate_network(rsp._read(network_path))
    actual = rsp.network_hash(network)
    if actual.lower() != expected_network_sha256.strip().lower():
        raise ValueError("Pin de red incorrecto al crear peer-map")
    endpoints = {}
    for spec in endpoint_specs:
        validator_id, host, port = _parse_endpoint(spec)
        if validator_id in endpoints:
            raise ValueError(f"Endpoint duplicado: {validator_id}")
        rsp._validator(network, validator_id)
        endpoints[validator_id] = {"host": host, "port": port}
    expected_ids = {v["validator_id"] for v in network["validators"]}
    if set(endpoints) != expected_ids:
        missing = sorted(expected_ids - set(endpoints))
        extra = sorted(set(endpoints) - expected_ids)
        raise ValueError(f"Peer map debe contener exactamente todos los validadores; faltan={missing}, sobran={extra}")
    body = {
        "schema": PEER_MAP_SCHEMA,
        "protocol_version": VERSION,
        "network_id": network["network_id"],
        "network_sha256": actual,
        "endpoints": endpoints,
    }
    result = dict(body)
    result["peer_map_sha256"] = _hash(body)
    output.parent.mkdir(parents=True, exist_ok=True)
    huc.write_json(output, result, 0o644)
    return {"result": "peer_map_created", "peer_map_sha256": result["peer_map_sha256"],
            "peer_count": len(endpoints), "file": str(output.resolve())}


def validate_peer_map(peer_map: dict[str, Any], network: dict[str, Any]) -> str:
    if peer_map.get("schema") != PEER_MAP_SCHEMA:
        raise ValueError("Peer map no reconocido")
    if peer_map.get("network_id") != network["network_id"]:
        raise ValueError("Peer map pertenece a otra red")
    if peer_map.get("network_sha256") != rsp.network_hash(network):
        raise ValueError("Peer map referencia otra huella de red")
    endpoints = peer_map.get("endpoints")
    if not isinstance(endpoints, dict):
        raise ValueError("Peer map sin endpoints")
    expected = {v["validator_id"] for v in network["validators"]}
    if set(endpoints) != expected:
        raise ValueError("Peer map debe incluir exactamente los nodos de la membresía")
    for validator_id, endpoint in endpoints.items():
        rsp._validator(network, validator_id)
        if (not isinstance(endpoint, dict) or not isinstance(endpoint.get("host"), str)
                or not endpoint["host"] or not isinstance(endpoint.get("port"), int)
                or not 1 <= endpoint["port"] <= 65535):
            raise ValueError(f"Endpoint inválido para {validator_id}")
    body = {k: v for k, v in peer_map.items() if k != "peer_map_sha256"}
    expected_hash = _hash(body)
    if peer_map.get("peer_map_sha256") != expected_hash:
        raise ValueError("Hash de peer map incorrecto")
    return expected_hash


def install_peer_map(node_dir: Path, peer_map_path: Path, expected_peer_map_sha256: str) -> dict[str, Any]:
    network = rsp.load_network(node_dir)
    peer_map = rsp._read(peer_map_path)
    actual = validate_peer_map(peer_map, network)
    if actual.lower() != expected_peer_map_sha256.strip().lower():
        raise ValueError("Pin externo del peer map no coincide")
    huc.atomic_write(node_dir / PEER_MAP_FILE, _canonical(peer_map) + b"\n", 0o644)
    huc.write_json(node_dir / PEER_TRUST_FILE, {
        "schema": "LAEV-HUC-PEER-TRUST-1",
        "network_id": network["network_id"],
        "peer_map_sha256": actual,
        "pinned_at_utc": huc.iso(),
    })
    if not (node_dir / REPLAY_FILE).exists():
        huc.write_json(node_dir / REPLAY_FILE, {"schema": "LAEV-HUC-PEER-REPLAY-1", "message_ids": []})
    view.initialize_view_state(node_dir)
    return {"result": "peer_map_installed", "validator_id": rsp._read(node_dir / rsp.NODE_PUBLIC)["validator_id"],
            "peer_map_sha256": actual, "peer_count": len(peer_map["endpoints"])}


def load_peer_map(node_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    network = rsp.load_network(node_dir)
    peer_map = rsp._read(node_dir / PEER_MAP_FILE)
    trust = rsp._read(node_dir / PEER_TRUST_FILE)
    actual = validate_peer_map(peer_map, network)
    if trust.get("network_id") != network["network_id"] or trust.get("peer_map_sha256") != actual:
        raise ValueError("Peer map local no coincide con el pin instalado")
    return network, peer_map


def _message_bytes(payload: dict[str, Any]) -> bytes:
    return _canonical({"domain": "LAEV-HUC-PEER-MESSAGE-0.7", "payload": payload})


def _make_envelope(node_dir: Path, message_type: str, body: dict[str, Any]) -> dict[str, Any]:
    network, descriptor, key = rsp._node_context_without_state(node_dir)
    payload = {
        "schema": ENVELOPE_SCHEMA,
        "network_id": network["network_id"],
        "sender_id": descriptor["validator_id"],
        "message_id": str(uuid.uuid4()),
        "sent_at_utc": huc.iso(),
        "message_type": message_type,
        "body": body,
    }
    signature = base64.b64encode(key.sign(_message_bytes(payload))).decode("ascii")
    return {"payload": payload, "signature": signature}


def _verify_envelope(network: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != ENVELOPE_SCHEMA:
        raise ValueError("Sobre P2P no reconocido")
    if payload.get("network_id") != network["network_id"]:
        raise ValueError("Mensaje P2P de otra red")
    sender_id = payload.get("sender_id")
    validator = rsp._validator(network, sender_id)
    if not isinstance(payload.get("message_id"), str) or len(payload["message_id"]) > 64:
        raise ValueError("message_id inválido")
    sent = rsp._parse_time(payload.get("sent_at_utc", ""))
    if abs((huc.now_utc() - sent).total_seconds()) > 300:
        raise ValueError("Mensaje P2P fuera de ventana de 5 minutos")
    if not isinstance(payload.get("body"), dict):
        raise ValueError("body del mensaje debe ser un objeto")
    try:
        rsp._verify_sig(validator["public_key_pem"], envelope.get("signature", ""), _message_bytes(payload))
    except Exception as exc:
        raise ValueError("Firma de mensaje P2P inválida") from exc
    return payload


def _remember_message_id(node_dir: Path, message_id: str) -> None:
    path = node_dir / REPLAY_FILE
    lock = FileLock(str(path) + ".lock", timeout=5)
    try:
        with lock:
            data = rsp._read(path) if path.exists() else {"schema": "LAEV-HUC-PEER-REPLAY-1", "message_ids": []}
            ids = data.setdefault("message_ids", [])
            if message_id in ids:
                raise ValueError("Mensaje P2P repetido (anti-replay)")
            ids.append(message_id)
            data["message_ids"] = ids[-MAX_REPLAY_IDS:]
            huc.atomic_write(path, _canonical(data) + b"\n")
    except Timeout as exc:
        raise TimeoutError("No se pudo actualizar la caché anti-replay") from exc


def _response_envelope(node_dir: Path, request_id: str, ok: bool, body: dict[str, Any]) -> dict[str, Any]:
    envelope = _make_envelope(node_dir, "RESPONSE", {"request_id": request_id, "ok": ok, "result": body})
    return envelope


class PeerServer:
    def __init__(self, node_dir: Path, bind_host: str = "127.0.0.1", port: int | None = None,
                 tls_cert: Path | None = None, tls_key: Path | None = None,
                 allow_insecure_remote: bool = False):
        self.node_dir = Path(node_dir).resolve()
        self.network, self.peer_map = load_peer_map(self.node_dir)
        descriptor = rsp._read(self.node_dir / rsp.NODE_PUBLIC)
        endpoint = self.peer_map["endpoints"][descriptor["validator_id"]]
        self.bind_host = bind_host
        self.port = port if port is not None else endpoint["port"]
        self.server: asyncio.AbstractServer | None = None
        if bool(tls_cert) != bool(tls_key):
            raise ValueError("TLS requiere --tls-cert y --tls-key juntos")
        self.ssl_context = None
        try:
            is_loopback = ipaddress.ip_address(bind_host).is_loopback
        except ValueError:
            is_loopback = bind_host.lower() == "localhost"
        if not is_loopback and not tls_cert and not allow_insecure_remote:
            raise ValueError("Para escuchar fuera de loopback debe configurar TLS o indicar explícitamente --allow-insecure-remote solo en una VPN/red confiable")
        if tls_cert and tls_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(tls_cert), str(tls_key))
            self.ssl_context = context

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.bind_host, self.port,
                                                 limit=MAX_MESSAGE_BYTES, ssl=self.ssl_context)

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    async def close(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=10)
            if not raw or len(raw) > MAX_MESSAGE_BYTES:
                raise ValueError("Mensaje vacío o demasiado grande")
            envelope = json.loads(raw.decode("utf-8"))
            payload = _verify_envelope(self.network, envelope)
            _remember_message_id(self.node_dir, payload["message_id"])
            result = await self._dispatch(payload["message_type"], payload["body"])
            response = _response_envelope(self.node_dir, payload["message_id"], True, result)
        except Exception as exc:
            request_id = "unknown"
            try:
                request_id = payload.get("message_id", "unknown")  # type: ignore[name-defined]
            except Exception:
                pass
            response = _response_envelope(self.node_dir, request_id, False, {"error": str(exc)})
        try:
            writer.write(_canonical(response) + b"\n")
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def _dispatch(self, message_type: str, body: dict[str, Any]) -> dict[str, Any]:
        if message_type == "PING":
            result = rsp.node_status(self.node_dir)
            result["view_state"] = view.load_view_state(self.node_dir)
            return result
        if message_type == "PROPOSAL":
            proposal = body.get("proposal")
            if not isinstance(proposal, dict):
                raise ValueError("PROPOSAL requiere proposal")
            view.validate_proposal_view(self.node_dir, proposal)
            view.remember_proposal(self.node_dir, proposal)
            with tempfile.TemporaryDirectory(prefix="huc-peer-vote-") as td:
                p = Path(td) / "proposal.json"
                out = Path(td) / "vote.json"
                rsp._write(p, proposal, 0o600)
                rsp.vote_proposal(self.node_dir, p, out)
                return {"vote": rsp._read(out), "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "COMMIT":
            commit = body.get("commit")
            if not isinstance(commit, dict):
                raise ValueError("COMMIT requiere commit")
            with tempfile.TemporaryDirectory(prefix="huc-peer-commit-") as td:
                path = Path(td) / "commit.json"
                rsp._write(path, commit, 0o600)
                applied = rsp.apply_commit(self.node_dir, path)
            view.clear_recovery_after_commit(self.node_dir, commit)
            return applied
        if message_type == "VIEW_CHANGE_REQUEST":
            target = body.get("target_view")
            reason = body.get("reason", "timeout")
            message = view.create_view_change_message(self.node_dir, target, reason)
            return {"view_change": message, "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "NEW_VIEW_CERTIFICATE":
            certificate = body.get("certificate")
            if not isinstance(certificate, dict):
                raise ValueError("NEW_VIEW_CERTIFICATE requiere certificate")
            with tempfile.TemporaryDirectory(prefix="huc-peer-view-") as td:
                path = Path(td) / "view-certificate.json"
                rsp._write(path, certificate, 0o600)
                result = view.install_view_certificate(self.node_dir, path)
            return result
        if message_type == "STATE_EXPORT":
            with tempfile.TemporaryDirectory(prefix="huc-peer-export-") as td:
                path = Path(td) / "state.zip"
                result = rsp.export_state(self.node_dir, path)
                raw = path.read_bytes()
                if len(raw) > 10 * 1024 * 1024:
                    raise ValueError("Paquete de estado supera el límite P2P de 10 MiB")
                return {"state_package_b64": base64.b64encode(raw).decode("ascii"),
                        "sequence": result["sequence"], "head_hash": result["head_hash"]}
        if message_type == "MEMBERSHIP_PROPOSAL":
            proposal = body.get("proposal")
            if not isinstance(proposal, dict):
                raise ValueError("MEMBERSHIP_PROPOSAL requiere proposal")
            with tempfile.TemporaryDirectory(prefix="huc-peer-membership-vote-") as td:
                proposal_path = Path(td) / "membership-proposal.json"
                vote_path = Path(td) / "membership-vote.json"
                rsp._write(proposal_path, proposal, 0o600)
                membership.membership_vote(self.node_dir, proposal_path, vote_path)
                return {"vote": rsp._read(vote_path),
                        "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "MEMBERSHIP_STAGE":
            package = body.get("package")
            if not isinstance(package, dict):
                raise ValueError("MEMBERSHIP_STAGE requiere package")
            old_network, target_network, _ = membership.verify_membership_package(package)
            if old_network["network_id"] != self.network["network_id"]:
                raise ValueError("El paquete de membresía no continúa la red local")
            local_id = rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]
            if not any(x["validator_id"] == local_id for x in target_network["validators"]):
                return {"result": "member_removed", "staged": False, "validator_id": local_id}
            cert_id = package["membership_certificate"]["membership_certificate_id"]
            inbox = self.node_dir / "membership-inbox"
            inbox.mkdir(exist_ok=True)
            path = inbox / f"membership-{cert_id}.json"
            rsp._write(path, package, 0o644)
            return {"result": "membership_package_staged", "staged": True,
                    "validator_id": local_id, "package_path": str(path)}
        if message_type == "BFT_PRE_PREPARE":
            import huc_bft as bft
            preprepare = body.get("preprepare")
            if not isinstance(preprepare, dict):
                raise ValueError("BFT_PRE_PREPARE requiere preprepare")
            vote = bft.accept_preprepare(self.node_dir, preprepare)
            return {"prepare_vote": vote, "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "BFT_PREPARE_CERT":
            import huc_bft as bft
            prepare_cert = body.get("prepare_certificate")
            if not isinstance(prepare_cert, dict):
                raise ValueError("BFT_PREPARE_CERT requiere prepare_certificate")
            ack = bft.create_prepared_ack(self.node_dir, prepare_cert)
            return {"prepared_ack": ack, "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "BFT_PREPARED_CERT":
            import huc_bft as bft
            prepared_cert = body.get("prepared_certificate")
            if not isinstance(prepared_cert, dict):
                raise ValueError("BFT_PREPARED_CERT requiere prepared_certificate")
            accepted = bft.accept_prepared_certificate(self.node_dir, prepared_cert)
            vote = bft.create_commit_vote(self.node_dir, prepared_cert)
            return {"accepted": accepted, "commit_vote": vote,
                    "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "BFT_COMMIT_CERT":
            import huc_bft as bft
            commit_cert = body.get("commit_certificate")
            if not isinstance(commit_cert, dict):
                raise ValueError("BFT_COMMIT_CERT requiere commit_certificate")
            return bft.apply_commit_certificate(self.node_dir, commit_cert)
        if message_type == "BFT_VIEW_CHANGE_REQUEST":
            import huc_bft as bft
            target = body.get("target_view")
            reason = body.get("reason", "timeout")
            message = bft.create_view_change(self.node_dir, target, reason)
            return {"view_change": message,
                    "validator_id": rsp._read(self.node_dir / rsp.NODE_PUBLIC)["validator_id"]}
        if message_type == "BFT_NEW_VIEW_CERTIFICATE":
            import huc_bft as bft
            certificate = body.get("new_view_certificate")
            if not isinstance(certificate, dict):
                raise ValueError("BFT_NEW_VIEW_CERTIFICATE requiere new_view_certificate")
            return bft.install_new_view(self.node_dir, certificate)
        if message_type == "BFT_STATE_EXPORT":
            import huc_bft as bft
            with tempfile.TemporaryDirectory(prefix="huc-peer-bft-export-") as td:
                path = Path(td) / "bft-state.zip"
                result = bft.export_state(self.node_dir, path)
                raw = path.read_bytes()
                if len(raw) > 10 * 1024 * 1024:
                    raise ValueError("Paquete BFT supera el límite P2P de 10 MiB")
                return {"state_package_b64": base64.b64encode(raw).decode("ascii"),
                        "sequence": result["sequence"], "head_hash": result["head_hash"],
                        "view": result["view"]}
        if message_type == "BFT_STATE_SYNC":
            import huc_bft as bft
            data = body.get("state_package_b64")
            if not isinstance(data, str) or len(data) > 15 * 1024 * 1024:
                raise ValueError("Paquete BFT sync inválido o demasiado grande")
            raw = base64.b64decode(data, validate=True)
            with tempfile.TemporaryDirectory(prefix="huc-peer-bft-sync-") as td:
                path = Path(td) / "bft-state.zip"
                path.write_bytes(raw)
                return bft.sync_state(self.node_dir, path)
        if message_type == "STATE_SYNC":
            data = body.get("state_package_b64")
            if not isinstance(data, str) or len(data) > 15 * 1024 * 1024:
                raise ValueError("Paquete de sincronización P2P inválido o demasiado grande")
            raw = base64.b64decode(data, validate=True)
            with tempfile.TemporaryDirectory(prefix="huc-peer-sync-") as td:
                path = Path(td) / "state.zip"
                path.write_bytes(raw)
                return rsp.sync_state(self.node_dir, path)
        raise ValueError(f"Tipo de mensaje P2P desconocido: {message_type}")


def _client_tls_context(ca_file: Path | None, client_cert: Path | None, client_key: Path | None) -> ssl.SSLContext | None:
    if not ca_file:
        if client_cert or client_key:
            raise ValueError("Certificado/clave TLS cliente requiere --tls-ca")
        return None
    if bool(client_cert) != bool(client_key):
        raise ValueError("TLS cliente requiere --tls-client-cert y --tls-client-key juntos")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_cert and client_key:
        context.load_cert_chain(str(client_cert), str(client_key))
    return context


async def send_request(node_dir: Path, peer_id: str, message_type: str, body: dict[str, Any],
                       timeout: float = DEFAULT_TIMEOUT, tls_ca: Path | None = None,
                       tls_client_cert: Path | None = None, tls_client_key: Path | None = None) -> dict[str, Any]:
    network, peer_map = load_peer_map(node_dir)
    local_desc = rsp._read(Path(node_dir) / rsp.NODE_PUBLIC)
    if peer_id == local_desc["validator_id"]:
        raise ValueError("No envíe mensajes de red al mismo nodo; use su operación local")
    endpoint = peer_map["endpoints"].get(peer_id)
    if not endpoint:
        raise ValueError(f"No existe endpoint para {peer_id}")
    envelope = _make_envelope(node_dir, message_type, body)
    context = _client_tls_context(tls_ca, tls_client_cert, tls_client_key)
    host = endpoint["host"]
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, endpoint["port"], ssl=context,
                                server_hostname=host if context else None,
                                limit=MAX_MESSAGE_BYTES), timeout=timeout
    )
    try:
        writer.write(_canonical(envelope) + b"\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not raw or len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("Respuesta P2P vacía o demasiado grande")
        response = json.loads(raw.decode("utf-8"))
    finally:
        writer.close()
        await writer.wait_closed()
    response_payload = _verify_envelope(network, response)
    if response_payload.get("sender_id") != peer_id or response_payload.get("message_type") != "RESPONSE":
        raise ValueError("Respuesta P2P no corresponde al peer esperado")
    result = response_payload.get("body", {})
    if result.get("request_id") != envelope["payload"]["message_id"]:
        raise ValueError("Respuesta P2P no está vinculada a la solicitud")
    if not result.get("ok"):
        raise ValueError(result.get("result", {}).get("error", "Peer rechazó la solicitud"))
    return result.get("result", {})


async def peer_status(node_dir: Path, timeout: float, tls_ca: Path | None) -> dict[str, Any]:
    _, peer_map = load_peer_map(node_dir)
    results = {}
    for peer_id in sorted(peer_map["endpoints"]):
        try:
            if peer_id == rsp._read(Path(node_dir) / rsp.NODE_PUBLIC)["validator_id"]:
                results[peer_id] = {"status": "LOCAL", "node": rsp.node_status(node_dir)}
            else:
                response = await send_request(node_dir, peer_id, "PING", {}, timeout, tls_ca)
                results[peer_id] = {"status": "ONLINE", "node": response}
        except Exception as exc:
            results[peer_id] = {"status": "OFFLINE", "error": str(exc)}
    return results


async def broadcast_proposal(node_dir: Path, proposal_path: Path, output_commit: Path,
                             timeout: float, tls_ca: Path | None) -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context(node_dir)
    proposal = rsp._read(proposal_path)
    view.validate_proposal_view(node_dir, proposal)
    view.remember_proposal(node_dir, proposal)
    with tempfile.TemporaryDirectory(prefix="huc-broadcast-") as td:
        root = Path(td)
        proposal_copy = root / "proposal.json"
        local_vote_path = root / f"vote-{descriptor['validator_id']}.json"
        rsp._write(proposal_copy, proposal, 0o600)
        rsp.vote_proposal(node_dir, proposal_copy, local_vote_path)
        votes: list[Path] = [local_vote_path]
        errors = {}
        _, peer_map = load_peer_map(node_dir)
        for peer_id in sorted(peer_map["endpoints"]):
            if peer_id == descriptor["validator_id"]:
                continue
            try:
                response = await send_request(node_dir, peer_id, "PROPOSAL", {"proposal": proposal}, timeout, tls_ca)
                vote_path = root / f"vote-{peer_id}.json"
                rsp._write(vote_path, response["vote"], 0o600)
                votes.append(vote_path)
            except Exception as exc:
                errors[peer_id] = str(exc)
        if len(votes) < network["quorum"]:
            raise RuntimeError(f"No se alcanzó el quórum: {len(votes)}/{network['quorum']}; errores={errors}")
        rsp.assemble_commit(node_dir, proposal_copy, votes, output_commit)
    commit = rsp._read(output_commit)
    local_result = rsp.apply_commit(node_dir, output_commit)
    view.clear_recovery_after_commit(node_dir, commit)
    _, peer_map = load_peer_map(node_dir)
    delivered, delivery_errors = [], {}
    for peer_id in sorted(peer_map["endpoints"]):
        if peer_id == descriptor["validator_id"]:
            continue
        try:
            await send_request(node_dir, peer_id, "COMMIT", {"commit": commit}, timeout, tls_ca)
            delivered.append(peer_id)
        except Exception as exc:
            delivery_errors[peer_id] = str(exc)
    return {
        "result": "proposal_committed_and_broadcast",
        "proposal_id": proposal["proposal_id"],
        "commit_id": commit["commit_id"],
        "quorum": network["quorum"],
        "votes_collected": len(votes),
        "local_apply": local_result,
        "commit_delivered_to": delivered,
        "delivery_errors": delivery_errors,
    }


async def advance_view(node_dir: Path, output_certificate: Path, timeout: float,
                       tls_ca: Path | None, reason: str = "unreachable-primary") -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context(node_dir)
    current = view.load_view_state(node_dir)
    target = current["view"] + 1
    messages = [view.create_view_change_message(node_dir, target, reason)]
    errors = {}
    _, peer_map = load_peer_map(node_dir)
    for peer_id in sorted(peer_map["endpoints"]):
        if peer_id == descriptor["validator_id"]:
            continue
        try:
            response = await send_request(node_dir, peer_id, "VIEW_CHANGE_REQUEST",
                                          {"target_view": target, "reason": reason}, timeout, tls_ca)
            messages.append(response["view_change"])
        except Exception as exc:
            errors[peer_id] = str(exc)
    result = view.assemble_view_certificate(node_dir, messages, output_certificate)
    local_install = view.install_view_certificate(node_dir, output_certificate)
    cert = rsp._read(output_certificate)
    installed, install_errors = [], {}
    for peer_id in sorted(peer_map["endpoints"]):
        if peer_id == descriptor["validator_id"]:
            continue
        try:
            await send_request(node_dir, peer_id, "NEW_VIEW_CERTIFICATE", {"certificate": cert}, timeout, tls_ca)
            installed.append(peer_id)
        except Exception as exc:
            install_errors[peer_id] = str(exc)
    return {
        **result,
        "local_install": local_install,
        "new_view_delivered_to": installed,
        "view_change_errors": errors,
        "install_errors": install_errors,
    }


async def broadcast_membership_proposal(node_dir: Path, proposal_path: Path, output_package: Path,
                                          timeout: float, tls_ca: Path | None) -> dict[str, Any]:
    network, descriptor, _ = rsp._node_context(node_dir)
    proposal = rsp._read(proposal_path)
    payload = proposal.get("payload", {})
    if payload.get("previous_network_id") != network["network_id"]:
        raise ValueError("La propuesta de membresía no está basada en la red local")
    with tempfile.TemporaryDirectory(prefix="huc-membership-broadcast-") as td:
        root = Path(td)
        local_vote = root / f"vote-{descriptor['validator_id']}.json"
        membership.membership_vote(node_dir, proposal_path, local_vote)
        votes = [local_vote]
        errors = {}
        _, peer_map = load_peer_map(node_dir)
        for peer_id in sorted(peer_map["endpoints"]):
            if peer_id == descriptor["validator_id"]:
                continue
            try:
                response = await send_request(node_dir, peer_id, "MEMBERSHIP_PROPOSAL",
                                              {"proposal": proposal}, timeout, tls_ca)
                path = root / f"vote-{peer_id}.json"
                rsp._write(path, response["vote"], 0o600)
                votes.append(path)
            except Exception as exc:
                errors[peer_id] = str(exc)
        if len(votes) < network["quorum"]:
            raise RuntimeError(f"Quórum de membresía insuficiente: {len(votes)}/{network['quorum']}; errores={errors}")
        membership.assemble_membership_certificate(node_dir, proposal_path, votes, output_package)
    package = rsp._read(output_package)
    target_ids = {x["validator_id"] for x in package["target_network"]["validators"]}
    staged, stage_errors = [], {}
    for peer_id in sorted(peer_map["endpoints"]):
        if peer_id == descriptor["validator_id"] or peer_id not in target_ids:
            continue
        try:
            result = await send_request(node_dir, peer_id, "MEMBERSHIP_STAGE", {"package": package}, timeout, tls_ca)
            if result.get("staged"):
                staged.append(peer_id)
        except Exception as exc:
            stage_errors[peer_id] = str(exc)
    return {
        "result": "membership_certified_and_distributed",
        "membership_certificate_id": package["membership_certificate"]["membership_certificate_id"],
        "target_network_id": package["target_network"]["network_id"],
        "votes_collected": len(votes),
        "quorum": network["quorum"],
        "package": str(output_package.resolve()),
        "staged_on": staged,
        "vote_errors": errors,
        "stage_errors": stage_errors,
        "activation_note": "Retained nodes activate the staged package locally; the incoming member joins with the same certified package through an authenticated invitation channel.",
    }


async def sync_from_peer(node_dir: Path, peer_id: str, timeout: float, tls_ca: Path | None) -> dict[str, Any]:
    response = await send_request(node_dir, peer_id, "STATE_EXPORT", {}, timeout, tls_ca)
    raw = base64.b64decode(response["state_package_b64"], validate=True)
    with tempfile.TemporaryDirectory(prefix="huc-peer-sync-client-") as td:
        package = Path(td) / "state.zip"
        package.write_bytes(raw)
        result = rsp.sync_state(node_dir, package)
    return {"result": "peer_state_synchronized", "peer_id": peer_id, **result}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LAEV HUC 0.7 — P2P, view change y estado replicado")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("peer-map-create", help="Crear manifiesto público de endpoints P2P")
    p.add_argument("--network", type=Path, required=True)
    p.add_argument("--network-sha256", required=True)
    p.add_argument("--endpoint", action="append", required=True, help="ID=HOST:PORT (repetible)")
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("peer-map-install", help="Instalar y fijar el peer map localmente")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--peer-map", type=Path, required=True)
    p.add_argument("--peer-map-sha256", required=True)

    p = sub.add_parser("serve", help="Iniciar servidor P2P del nodo")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--bind-host", default="127.0.0.1")
    p.add_argument("--port", type=int)
    p.add_argument("--tls-cert", type=Path)
    p.add_argument("--tls-key", type=Path)
    p.add_argument("--allow-insecure-remote", action="store_true",
                   help="Permite TCP sin TLS fuera de loopback; úselo solo dentro de una VPN/red privada confiable")

    p = sub.add_parser("status", help="Consultar peers y su estado")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--tls-ca", type=Path)

    p = sub.add_parser("annotate-proposal", help="Vincular propuesta con la vista y el proponente actual")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)

    p = sub.add_parser("broadcast-proposal", help="Votar por P2P, reunir quórum, hacer commit y difundirlo")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--output-commit", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--tls-ca", type=Path)

    p = sub.add_parser("advance-view", help="Reunir un certificado de cambio de vista y propagarlo")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--reason", choices=["timeout", "unreachable-primary", "operator-request"], default="unreachable-primary")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--tls-ca", type=Path)

    p = sub.add_parser("broadcast-membership-proposal", help="Recoger firmas de membresía por P2P y distribuir el paquete")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--output-package", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--tls-ca", type=Path)

    p = sub.add_parser("sync-from-peer", help="Solicitar y verificar estado de otro peer")
    p.add_argument("--node-dir", type=Path, required=True)
    p.add_argument("--peer-id", required=True)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--tls-ca", type=Path)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "peer-map-create":
            result = create_peer_map(args.network, args.network_sha256, args.endpoint, args.output)
        elif args.command == "peer-map-install":
            result = install_peer_map(args.node_dir, args.peer_map, args.peer_map_sha256)
        elif args.command == "serve":
            server = PeerServer(args.node_dir, args.bind_host, args.port, args.tls_cert, args.tls_key,
                                args.allow_insecure_remote)
            asyncio.run(server.serve_forever())
            return 0
        elif args.command == "status":
            result = asyncio.run(peer_status(args.node_dir, args.timeout, args.tls_ca))
        elif args.command == "annotate-proposal":
            result = view.annotate_proposal_for_view(args.node_dir, args.proposal, args.output)
        elif args.command == "broadcast-proposal":
            result = asyncio.run(broadcast_proposal(args.node_dir, args.proposal, args.output_commit,
                                                    args.timeout, args.tls_ca))
        elif args.command == "advance-view":
            result = asyncio.run(advance_view(args.node_dir, args.output, args.timeout,
                                              args.tls_ca, args.reason))
        elif args.command == "broadcast-membership-proposal":
            result = asyncio.run(broadcast_membership_proposal(args.node_dir, args.proposal,
                                                               args.output_package, args.timeout, args.tls_ca))
        elif args.command == "sync-from-peer":
            result = asyncio.run(sync_from_peer(args.node_dir, args.peer_id, args.timeout, args.tls_ca))
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
