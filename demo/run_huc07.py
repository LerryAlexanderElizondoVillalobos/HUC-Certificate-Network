#!/usr/bin/env python3
"""Integrated HUC 0.7 local multi-process-style network simulation.

Uses independent node directories and actual TCP sockets on loopback. Private
keys are created in a temporary directory and never copied to demo artifacts.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
import tempfile
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import huc
import huc_replicated as rsp
import huc_peer as peer
import huc_view as view
import huc_membership as membership

ROOT = Path(__file__).resolve().parent / "huc07"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def save_json(path: Path, value):
    huc.write_json(path, value, 0o644)


def artifact_copy(src: Path, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


async def run() -> dict:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    results = {"protocol": "LAEV-HUC/0.7", "transport": "signed TCP over loopback",
               "blockchain": False, "token": False, "payment_per_transaction": False,
               "scenarios": []}

    with tempfile.TemporaryDirectory(prefix="huc07-lab-") as temp_dir:
        work = Path(temp_dir)
        issuer = work / "issuer"
        huc.initialize(issuer, threshold=2, authority_count=3)
        holder = work / "holder"
        request = huc.generate_request(holder, "HUC 0.7 Demonstration Holder")
        issued = huc.issue_csr(issuer, Path(request["csr_file"]), 120)
        cert1 = Path(issued["certificate_file"])
        cc1 = Path(issued["consensus_certificate_file"])
        cert1_hash = issued["certificate_sha256_der"]
        cc1_obj = huc.read_json(cc1)
        cc1_hash = huc.sha256(huc.canonical_json(cc1_obj))

        node_dirs = {}
        descriptors = []
        for name in ("HUC-A", "HUC-B", "HUC-C", "HUC-D"):
            node_dir = work / name
            rsp.node_init(name, node_dir)
            node_dirs[name] = node_dir
            descriptors.append(node_dir / rsp.NODE_PUBLIC)
        network_path = work / "network-epoch0.json"
        created = rsp.create_network(descriptors, network_path, 1,
                                     issuer / huc.CA_CERT, issuer / huc.POLICY_FILE)
        pin0 = created["network_sha256"]
        for node_dir in node_dirs.values():
            rsp.node_join(node_dir, network_path, pin0)

        ports = {name: free_port() for name in node_dirs}
        peer_specs = [f"{name}=127.0.0.1:{port}" for name, port in ports.items()]
        peer_map0 = work / "peer-map-epoch0.json"
        map0 = peer.create_peer_map(network_path, pin0, peer_specs, peer_map0)
        for node_dir in node_dirs.values():
            peer.install_peer_map(node_dir, peer_map0, map0["peer_map_sha256"])

        servers = {}
        for name, node_dir in node_dirs.items():
            server = peer.PeerServer(node_dir, "127.0.0.1", ports[name])
            await server.start()
            servers[name] = server

        # Issue in view zero, primary HUC-A.
        issue_raw = work / "issue-raw.json"
        issue_proposal = work / "issue-proposal.json"
        rsp.create_proposal(node_dirs["HUC-A"], "ISSUE", cert1_hash, cc1_hash, issue_raw,
                            certificate_path=cert1, consensus_certificate_path=cc1)
        view.annotate_proposal_for_view(node_dirs["HUC-A"], issue_raw, issue_proposal)
        issue_commit_path = work / "issue-commit.json"
        issue_result = await peer.broadcast_proposal(node_dirs["HUC-A"], issue_proposal,
                                                      issue_commit_path, 2.0, None)
        results["scenarios"].append({"name": "ISSUE", "result": "COMMITTED",
                                      "votes": issue_result["votes_collected"],
                                      "sequence": issue_result["local_apply"]["sequence"]})

        # Simulate primary loss and quorum-based view rotation A -> B.
        await servers["HUC-A"].close()
        view_cert_path = work / "view-change-1.json"
        view_result = await peer.advance_view(node_dirs["HUC-B"], view_cert_path, 1.0, None,
                                              "unreachable-primary")
        results["scenarios"].append({"name": "VIEW_CHANGE", "result": "INSTALLED",
                                      "view": view_result["target_view"],
                                      "new_primary": view_result["primary_id"],
                                      "quorum_messages": view_result["valid_messages"]})
        # Former primary returns and receives the signed new-view certificate.
        server_a = peer.PeerServer(node_dirs["HUC-A"], "127.0.0.1", ports["HUC-A"])
        await server_a.start()
        servers["HUC-A"] = server_a
        await peer.send_request(node_dirs["HUC-B"], "HUC-A", "NEW_VIEW_CERTIFICATE",
                                {"certificate": rsp._read(view_cert_path)}, 2.0)

        # Renew from the newly selected proposer, HUC-B.
        holder2 = work / "holder-renewal"
        request2 = huc.generate_request(holder2, "HUC 0.7 Demonstration Holder")
        renewed = huc.renew_csr(issuer, cert1, Path(request2["csr_file"]), 120)
        cert2 = Path(renewed["certificate_file"])
        cc2 = Path(renewed["consensus_certificate_file"])
        cert2_hash = renewed["certificate_sha256_der"]
        cc2_hash = huc.sha256(huc.canonical_json(huc.read_json(cc2)))
        renew_raw = work / "renew-raw.json"
        renew_proposal = work / "renew-proposal.json"
        rsp.create_proposal(node_dirs["HUC-B"], "RENEW", cert2_hash, cc2_hash, renew_raw,
                            previous_certificate_sha256=cert1_hash,
                            certificate_path=cert2, consensus_certificate_path=cc2)
        view.annotate_proposal_for_view(node_dirs["HUC-B"], renew_raw, renew_proposal)
        renew_commit_path = work / "renew-commit.json"
        renew_result = await peer.broadcast_proposal(node_dirs["HUC-B"], renew_proposal,
                                                      renew_commit_path, 2.0, None)
        results["scenarios"].append({"name": "RENEW", "result": "COMMITTED",
                                      "votes": renew_result["votes_collected"],
                                      "sequence": renew_result["local_apply"]["sequence"]})

        # Stage a controlled validator replacement HUC-A -> HUC-E.
        new_node = work / "HUC-E"
        rsp.node_init("HUC-E", new_node)
        join_request = work / "HUC-E-join-request.json"
        membership.create_join_request(new_node, join_request, network_path)
        member_proposal = work / "membership-proposal.json"
        member_result = membership.create_membership_proposal(
            node_dirs["HUC-B"], [join_request], ["HUC-A"], member_proposal
        )
        membership_package = work / "membership-package.json"
        member_certificate_result = await peer.broadcast_membership_proposal(
            node_dirs["HUC-B"], member_proposal, membership_package, 2.0, None
        )
        staged_membership_peers = member_certificate_result["staged_on"]
        member_vote_count = member_certificate_result["votes_collected"]

        # Stop old sockets before applying the successor manifest.
        for server in servers.values():
            await server.close()
        for name in ("HUC-B", "HUC-C", "HUC-D"):
            membership.activate_membership(node_dirs[name], membership_package)
        membership.join_successor_network(new_node, membership_package)
        node_dirs.pop("HUC-A")
        node_dirs["HUC-E"] = new_node
        target_network = rsp._read(membership_package)["target_network"]
        target_network_path = work / "network-epoch1.json"
        save_json(target_network_path, target_network)
        pin1 = rsp.network_hash(target_network)

        # Rebuild P2P endpoint map for the successor membership epoch.
        ports1 = {name: free_port() for name in node_dirs}
        specs1 = [f"{name}=127.0.0.1:{port}" for name, port in ports1.items()]
        peer_map1 = work / "peer-map-epoch1.json"
        map1 = peer.create_peer_map(target_network_path, pin1, specs1, peer_map1)
        servers = {}
        for name, node_dir in node_dirs.items():
            peer.install_peer_map(node_dir, peer_map1, map1["peer_map_sha256"])
            server = peer.PeerServer(node_dir, "127.0.0.1", ports1[name])
            await server.start()
            servers[name] = server
        states_after_handoff = [rsp.node_status(node) for node in node_dirs.values()]
        results["scenarios"].append({
            "name": "MEMBERSHIP_HANDOFF", "result": "ACTIVATED",
            "removed": "HUC-A", "added": "HUC-E", "old_quorum_signatures": member_vote_count,
            "membership_package_staged_over_p2p": sorted(staged_membership_peers),
            "membership_epoch": target_network["membership_epoch"],
            "preserved_sequence": states_after_handoff[0]["sequence"],
            "replicas_agree": len({x["head_hash"] for x in states_after_handoff}) == 1,
        })

        # New membership continues the lifecycle and revokes the renewed certificate.
        revoke_raw = work / "revoke-raw.json"
        revoke_proposal = work / "revoke-proposal.json"
        rsp.create_proposal(node_dirs["HUC-B"], "REVOKE", cert2_hash, cc2_hash, revoke_raw,
                            metadata={"reason": "huc07-demonstration-revocation"},
                            certificate_path=cert2, consensus_certificate_path=cc2)
        view.annotate_proposal_for_view(node_dirs["HUC-B"], revoke_raw, revoke_proposal)
        revoke_commit_path = work / "revoke-commit.json"
        revoke_result = await peer.broadcast_proposal(node_dirs["HUC-B"], revoke_proposal,
                                                       revoke_commit_path, 2.0, None)
        results["scenarios"].append({"name": "REVOKE", "result": "COMMITTED",
                                      "votes": revoke_result["votes_collected"],
                                      "sequence": revoke_result["local_apply"]["sequence"]})

        final_nodes = {}
        for name, node_dir in node_dirs.items():
            final_nodes[name] = rsp.node_status(node_dir)
        final_head_hashes = {x["head_hash"] for x in final_nodes.values()}
        final_sequences = {x["sequence"] for x in final_nodes.values()}
        final_old_checks = [rsp.verify_certificate_on_node(node_dirs[name], cert1, cc1) for name in node_dirs]
        final_new_checks = [rsp.verify_certificate_on_node(node_dirs[name], cert2, cc2) for name in node_dirs]
        results["final_state"] = {
            "validator_ids": sorted(final_nodes),
            "membership_epoch": target_network["membership_epoch"],
            "sequence_values": sorted(final_sequences),
            "head_hash_count": len(final_head_hashes),
            "old_certificate_states": sorted({x["utxo_status"] for x in final_old_checks}),
            "new_certificate_states": sorted({x["utxo_status"] for x in final_new_checks}),
            "replicas_agree": len(final_head_hashes) == 1 and len(final_sequences) == 1,
        }

        # Save public-only artifacts. No private key or temporary authority directory is copied.
        pub = ROOT / "public-artifacts"
        pub.mkdir(parents=True)
        artifact_copy(issuer / huc.CA_CERT, pub / "ca_certificate.pem")
        artifact_copy(issuer / huc.POLICY_FILE, pub / "consensus_policy.json")
        artifact_copy(cert1, pub / "certificate-issued.pem")
        artifact_copy(cc1, pub / "consensus-issued.json")
        artifact_copy(cert2, pub / "certificate-renewed.pem")
        artifact_copy(cc2, pub / "consensus-renewed.json")
        artifact_copy(network_path, pub / "network-epoch0.json")
        artifact_copy(peer_map0, pub / "peer-map-epoch0.json")
        artifact_copy(issue_proposal, pub / "proposal-issue.json")
        artifact_copy(issue_commit_path, pub / "commit-issue.json")
        artifact_copy(view_cert_path, pub / "view-change-certificate.json")
        artifact_copy(renew_proposal, pub / "proposal-renew.json")
        artifact_copy(renew_commit_path, pub / "commit-renew.json")
        artifact_copy(join_request, pub / "join-request-HUC-E.json")
        artifact_copy(member_proposal, pub / "membership-proposal.json")
        artifact_copy(membership_package, pub / "membership-package.json")
        save_json(pub / "membership-broadcast-result.json", member_certificate_result)
        artifact_copy(target_network_path, pub / "network-epoch1.json")
        artifact_copy(peer_map1, pub / "peer-map-epoch1.json")
        artifact_copy(revoke_proposal, pub / "proposal-revoke.json")
        artifact_copy(revoke_commit_path, pub / "commit-revoke.json")
        for name, node_dir in node_dirs.items():
            artifact_copy(node_dir / rsp.NODE_PUBLIC, pub / f"node-public-{name}.json")
        save_json(pub / "final-node-status.json", final_nodes)
        save_json(pub / "scenario-results.json", results)

        for server in servers.values():
            await server.close()

    if not results["final_state"]["replicas_agree"]:
        raise RuntimeError("La demostración terminó con réplicas divergentes")
    if results["final_state"]["old_certificate_states"] != ["SUPERSEDED"]:
        raise RuntimeError("El certificado original no terminó SUPERSEDED")
    if results["final_state"]["new_certificate_states"] != ["REVOKED"]:
        raise RuntimeError("El certificado renovado no terminó REVOKED")
    return results


def main():
    result = asyncio.run(run())
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
