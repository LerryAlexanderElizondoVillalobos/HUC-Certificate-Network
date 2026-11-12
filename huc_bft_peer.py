#!/usr/bin/env python3
"""P2P orchestration for the HUC 0.8 BFT phases using the HUC 0.7 signed peer transport."""
from __future__ import annotations

import argparse
import base64
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import huc_bft as bft
import huc_peer as peer
import huc_replicated as rsp

DEFAULT_TIMEOUT = 3.0


async def _fanout(node_dir: Path, peer_ids: list[str], message_type: str,
                  body: dict[str, Any], timeout: float, tls_ca: Path | None) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, str]]:
    tasks = {}
    for peer_id in peer_ids:
        tasks[peer_id] = asyncio.create_task(
            peer.send_request(node_dir, peer_id, message_type, body, timeout, tls_ca)
        )
    successes: list[tuple[str, dict[str, Any]]] = []
    errors: dict[str, str] = {}
    for peer_id, task in tasks.items():
        try:
            successes.append((peer_id, await task))
        except Exception as exc:
            errors[peer_id] = str(exc)
    return successes, errors


def _members(node_dir: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    network, peer_map = peer.load_peer_map(node_dir)
    local_id = rsp._read(node_dir / rsp.NODE_PUBLIC)["validator_id"]
    peer_ids = sorted(x for x in peer_map["endpoints"] if x != local_id)
    return network, peer_map, local_id


async def broadcast_consensus(node_dir: Path, proposal_path: Path, output_commit: Path,
                              timeout: float = DEFAULT_TIMEOUT, tls_ca: Path | None = None,
                              preprepare_is_ready: bool = False) -> dict[str, Any]:
    network, _, local_id = _members(node_dir)
    control = bft._load_control(node_dir)
    if local_id != bft._primary(network, control["view"]):
        raise ValueError(f"Solo {bft._primary(network, control['view'])} puede iniciar PRE-PREPARE en vista {control['view']}")
    with tempfile.TemporaryDirectory(prefix="huc-bft-round-") as temp:
        root = Path(temp)
        pp_path = root / "preprepare.json"
        if preprepare_is_ready:
            pp = rsp._read(proposal_path)
            control_now = bft._load_control(node_dir)
            bft._verify_preprepare(network, bft.load_state(node_dir), pp,
                                   expected_view=control_now["view"], check_expiry=False)
        else:
            bft.create_preprepare(node_dir, proposal_path, pp_path)
            pp = rsp._read(pp_path)

        # Phase 1: PRE-PREPARE -> PREPARE votes.
        prepare_votes = [bft.accept_preprepare(node_dir, pp)]
        ok, errors_prepare = await _fanout(
            node_dir, sorted(x for x in peer.load_peer_map(node_dir)[1]["endpoints"] if x != local_id),
            "BFT_PRE_PREPARE", {"preprepare": pp}, timeout, tls_ca,
        )
        for peer_id, result in ok:
            prepare_votes.append(result["prepare_vote"])
        if len(prepare_votes) < network["quorum"]:
            raise RuntimeError(f"Quórum PREPARE insuficiente: {len(prepare_votes)}/{network['quorum']}; errores={errors_prepare}")
        state = bft.load_state(node_dir)
        prepare_cert = bft.assemble_prepare_certificate(network, state, pp, prepare_votes)

        # Phase 2: validators durably lock the prepared request and sign ACKs.
        lock_acks = [bft.create_prepared_ack(node_dir, prepare_cert)]
        prepared_ok, errors_prepared = await _fanout(
            node_dir, sorted(x for x in peer.load_peer_map(node_dir)[1]["endpoints"] if x != local_id),
            "BFT_PREPARE_CERT", {"prepare_certificate": prepare_cert}, timeout, tls_ca,
        )
        for _, result in prepared_ok:
            lock_acks.append(result["prepared_ack"])
        if len(lock_acks) < network["quorum"]:
            raise RuntimeError(f"Quórum PREPARED insuficiente: {len(lock_acks)}/{network['quorum']}; errores={errors_prepared}")
        prepared_cert = bft.assemble_prepared_certificate(network, state, prepare_cert, lock_acks)

        # Phase 3: disseminate complete PreparedCertificate; each validator persists it and signs COMMIT.
        bft.accept_prepared_certificate(node_dir, prepared_cert)
        commit_votes = [bft.create_commit_vote(node_dir, prepared_cert)]
        commit_ok, errors_commit = await _fanout(
            node_dir, sorted(x for x in peer.load_peer_map(node_dir)[1]["endpoints"] if x != local_id),
            "BFT_PREPARED_CERT", {"prepared_certificate": prepared_cert}, timeout, tls_ca,
        )
        for _, result in commit_ok:
            commit_votes.append(result["commit_vote"])
        if len(commit_votes) < network["quorum"]:
            raise RuntimeError(f"Quórum COMMIT insuficiente: {len(commit_votes)}/{network['quorum']}; errores={errors_commit}")
        commit_cert = bft.assemble_commit_certificate(network, state, prepared_cert, commit_votes)
        rsp._write(output_commit, commit_cert, 0o644)

        # Phase 4: COMMIT certificate is independently checked/applied on each replica.
        local_result = bft.apply_commit_certificate(node_dir, commit_cert)
        apply_ok, apply_errors = await _fanout(
            node_dir, sorted(x for x in peer.load_peer_map(node_dir)[1]["endpoints"] if x != local_id),
            "BFT_COMMIT_CERT", {"commit_certificate": commit_cert}, timeout, tls_ca,
        )
        return {
            "result": "bft_commit_replicated" if len(apply_ok) + 1 >= network["quorum"] else "bft_commit_quorum_committed_partial_delivery",
            "protocol": "HUC-BFT/0.8", "validator_id": local_id,
            "view": control["view"], "sequence": commit_cert["body"]["sequence"],
            "prepare_votes": len(prepare_votes), "prepared_lock_acks": len(lock_acks),
            "commit_votes": len(commit_votes), "quorum": network["quorum"],
            "commit_id": commit_cert["body"]["commit_id"],
            "local_apply": local_result,
            "commit_applied_by_peers": [pid for pid, _ in apply_ok],
            "prepare_errors": errors_prepare, "prepared_errors": errors_prepared,
            "commit_errors": errors_commit, "apply_errors": apply_errors,
            "commit_certificate_file": str(output_commit.resolve()),
        }


async def advance_view(node_dir: Path, output_certificate: Path,
                       timeout: float = DEFAULT_TIMEOUT, tls_ca: Path | None = None,
                       reason: str = "timeout") -> dict[str, Any]:
    network, _, local_id = _members(node_dir)
    control = bft._load_control(node_dir)
    target_view = control["view"] + 1
    primary = bft._primary(network, target_view)
    if local_id != primary:
        raise ValueError(f"El certificado NEW_VIEW debe ensamblarlo el nuevo primario {primary}; nodo local={local_id}")
    local_vc = bft.create_view_change(node_dir, target_view, reason)
    messages = [local_vc]
    peer_ids = sorted(x for x in peer.load_peer_map(node_dir)[1]["endpoints"] if x != local_id)
    responses, errors = await _fanout(
        node_dir, peer_ids, "BFT_VIEW_CHANGE_REQUEST",
        {"target_view": target_view, "reason": reason}, timeout, tls_ca,
    )
    messages.extend(result["view_change"] for _, result in responses)
    # Assemble using a 2f+1 signed VIEW_CHANGE set; no server is authoritative for the state.
    result = bft.assemble_new_view(node_dir, messages, output_certificate)
    certificate = rsp._read(output_certificate)
    local_install = bft.install_new_view(node_dir, certificate)
    installed, install_errors = await _fanout(
        node_dir, peer_ids, "BFT_NEW_VIEW_CERTIFICATE",
        {"new_view_certificate": certificate}, timeout, tls_ca,
    )
    return {**result, "local_install": local_install,
            "new_view_installed_on": [pid for pid, _ in installed],
            "view_change_errors": errors, "install_errors": install_errors}


async def recover_prepared(node_dir: Path, output_commit: Path,
                           timeout: float = DEFAULT_TIMEOUT, tls_ca: Path | None = None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="huc-bft-recover-") as temp:
        preprepare_path = Path(temp) / "recovered-preprepare.json"
        bft.repropose_selected(node_dir, preprepare_path)
        result = await broadcast_consensus(
            node_dir, preprepare_path, output_commit, timeout, tls_ca,
            preprepare_is_ready=True,
        )
        result["recovery"] = "re-proposed highest PreparedCertificate selected by NEW_VIEW"
        return result



async def sync_from_peer(node_dir: Path, peer_id: str,
                        timeout: float = DEFAULT_TIMEOUT,
                        tls_ca: Path | None = None) -> dict[str, Any]:
    exported = await peer.send_request(node_dir, peer_id, "BFT_STATE_EXPORT", {}, timeout, tls_ca)
    raw = base64.b64decode(exported.get("state_package_b64", ""), validate=True)
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("Paquete BFT recibido supera 10 MiB")
    with tempfile.TemporaryDirectory(prefix="huc-bft-peer-sync-") as temp:
        package = Path(temp) / "bft-state.zip"
        package.write_bytes(raw)
        result = bft.sync_state(node_dir, package, expected_exporter_id=peer_id)
    if (result["sequence"] != exported.get("sequence") or result["head_hash"] != exported.get("head_hash")
            or result["view"] != exported.get("view")):
        raise ValueError("Resultado de sincronización no coincide con el estado anunciado por el peer")
    return {**result, "source_peer": peer_id}

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HUC 0.8 P2P BFT phase orchestration")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("broadcast", help="Ejecutar PRE-PREPARE, PREPARE, PREPARED y COMMIT por P2P")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--proposal", type=Path, required=True)
    p.add_argument("--output-commit", type=Path, required=True); p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT); p.add_argument("--tls-ca", type=Path)
    p = sub.add_parser("advance-view", help="Crear NEW_VIEW usando quorum VIEW_CHANGE")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p.add_argument("--reason", default="timeout"); p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT); p.add_argument("--tls-ca", type=Path)
    p = sub.add_parser("recover", help="Reproponer y completar el PreparedCertificate elegido por NEW_VIEW")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--output-commit", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT); p.add_argument("--tls-ca", type=Path)
    p = sub.add_parser("sync", help="Sincronizar ledger y NEW_VIEW desde un peer autenticado")
    p.add_argument("--node-dir", type=Path, required=True); p.add_argument("--peer-id", required=True)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT); p.add_argument("--tls-ca", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "broadcast":
            result = asyncio.run(broadcast_consensus(args.node_dir, args.proposal, args.output_commit, args.timeout, args.tls_ca))
        elif args.command == "advance-view":
            result = asyncio.run(advance_view(args.node_dir, args.output, args.timeout, args.tls_ca, args.reason))
        elif args.command == "recover":
            result = asyncio.run(recover_prepared(args.node_dir, args.output_commit, args.timeout, args.tls_ca))
        else:
            result = asyncio.run(sync_from_peer(args.node_dir, args.peer_id, args.timeout, args.tls_ca))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
