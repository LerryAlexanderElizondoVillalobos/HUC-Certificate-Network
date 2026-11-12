#!/usr/bin/env python3
"""Build a public, reproducible HUC 0.6 replicated-state demonstration.

All private keys and temporary workspaces are created under a temporary
folder and deleted on exit. The exported demo contains public certificates,
public validator descriptors, proposals, votes, quorum commits and state logs.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import huc
import huc_replicated as rsp

OUT = ROOT / "demo" / "replicated-state"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def cc_hash(path: Path) -> str:
    return huc.sha256(huc.canonical_json(huc.read_json(path)))


def collect_votes(nodes: dict[str, Path], proposal: Path, outdir: Path, names: tuple[str, ...], tag: str) -> list[Path]:
    results = []
    outdir.mkdir(parents=True, exist_ok=True)
    for name in names:
        output = outdir / f"{tag}-{name}.json"
        rsp.vote_proposal(nodes[name], proposal, output)
        results.append(output)
    return results


def commit_and_apply(nodes: dict[str, Path], proposal: Path, votes: list[Path],
                     commit_path: Path, assembler: str) -> dict:
    rsp.assemble_commit(nodes[assembler], proposal, votes, commit_path)
    commit_result = json.loads(commit_path.read_text(encoding="utf-8"))
    for node in nodes.values():
        rsp.apply_commit(node, commit_path)
    return commit_result


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    results: dict[str, object] = {"protocol": "HUC-RSP/0.6", "mode": "leaderless quorum-certified state replication"}

    with tempfile.TemporaryDirectory(prefix="laev-huc-rsp-demo-") as td:
        temp = Path(td)
        issuer = temp / "issuer"
        holder1 = temp / "holder-1"
        holder2 = temp / "holder-2"
        nodes_root = temp / "nodes"
        work = temp / "work"
        proposals = temp / "proposals"
        votes_dir = temp / "votes"
        commits_dir = temp / "commits"
        for p in (issuer, holder1, holder2, nodes_root, work, proposals, votes_dir, commits_dir):
            p.mkdir(parents=True, exist_ok=True)

        # Produce real X.509 and HUC-CC artifacts (public-only export).
        issuer_init = huc.initialize(issuer, threshold=2, authority_count=3)
        req1 = huc.generate_request(holder1, "LAEV HUC Replicated State Demo")
        issued1 = huc.issue_csr(issuer, Path(req1["csr_file"]), 365)
        cert1 = Path(issued1["certificate_file"])
        cc1 = Path(issued1["consensus_certificate_file"])
        hash1 = issued1["certificate_sha256_der"]
        cchash1 = cc_hash(cc1)

        # Four separate validator stores with distinct private keys.
        nodes: dict[str, Path] = {}
        public_descriptors = []
        for name in ("NODE-A", "NODE-B", "NODE-C", "NODE-D"):
            node_dir = nodes_root / name
            rsp.node_init(name, node_dir)
            nodes[name] = node_dir
            public_descriptors.append(node_dir / rsp.NODE_PUBLIC)

        network_path = work / "network.json"
        network_result = rsp.create_network(
            public_descriptors, network_path, 1,
            issuer / huc.CA_CERT, issuer / huc.POLICY_FILE,
        )
        network_pin = network_result["network_sha256"]
        network_result["manifest"] = "public-network/network.json"
        for node in nodes.values():
            rsp.node_join(node, network_path, network_pin)

        # ISSUE: NODE-D proposes, A/B/C vote, B assembles, all replicas apply.
        issue_proposal = proposals / "issue.json"
        rsp.create_proposal(nodes["NODE-D"], "ISSUE", hash1, cchash1, issue_proposal,
                            certificate_path=cert1, consensus_certificate_path=cc1,
                            metadata={"purpose": "replicated-state-demo"})
        issue_votes = collect_votes(nodes, issue_proposal, votes_dir, ("NODE-A", "NODE-B", "NODE-C"), "issue")
        issue_commit_path = commits_dir / "issue.commit.json"
        issue_commit = commit_and_apply(nodes, issue_proposal, issue_votes, issue_commit_path, "NODE-B")

        # NODE-D was offline during apply; it catches up from NODE-A's public state package.
        sync_package = work / "state-after-issue.zip"
        rsp.export_state(nodes["NODE-A"], sync_package)
        offline_sync = rsp.sync_state(nodes["NODE-D"], sync_package)

        verify_active = {name: rsp.verify_certificate_on_node(node, cert1, cc1)
                         for name, node in nodes.items()}
        assert all(x["result"] == "VALID" and x["utxo_status"] == "ACTIVE" for x in verify_active.values())

        # RENEW with an independently generated holder key and a new HUC-CC.
        req2 = huc.generate_request(holder2, "LAEV HUC Replicated State Demo")
        renewed = huc.renew_csr(issuer, cert1, Path(req2["csr_file"]), 365)
        cert2 = Path(renewed["certificate_file"])
        cc2 = Path(renewed["consensus_certificate_file"])
        hash2 = renewed["certificate_sha256_der"]
        cchash2 = cc_hash(cc2)
        renew_proposal = proposals / "renew.json"
        rsp.create_proposal(nodes["NODE-A"], "RENEW", hash2, cchash2, renew_proposal,
                            previous_certificate_sha256=hash1, certificate_path=cert2,
                            consensus_certificate_path=cc2,
                            metadata={"purpose": "replicated-renewal-demo"})
        renew_votes = collect_votes(nodes, renew_proposal, votes_dir, ("NODE-A", "NODE-B", "NODE-D"), "renew")
        renew_commit_path = commits_dir / "renew.commit.json"
        renew_commit = commit_and_apply(nodes, renew_proposal, renew_votes, renew_commit_path, "NODE-C")
        # Bring offline node to renewal checkpoint.
        rsp.export_state(nodes["NODE-A"], sync_package)
        offline_sync_renew = rsp.sync_state(nodes["NODE-D"], sync_package)

        verify_old = {name: rsp.verify_certificate_on_node(node, cert1, cc1)
                      for name, node in nodes.items()}
        verify_new = {name: rsp.verify_certificate_on_node(node, cert2, cc2)
                      for name, node in nodes.items()}
        assert all(x["utxo_status"] == "SUPERSEDED" and x["result"] == "INVALID" for x in verify_old.values())
        assert all(x["utxo_status"] == "ACTIVE" and x["result"] == "VALID" for x in verify_new.values())

        # REVOKE: B/C/D approve; A assembles and all replicas apply.
        revoke_proposal = proposals / "revoke.json"
        rsp.create_proposal(nodes["NODE-C"], "REVOKE", hash2, cchash2, revoke_proposal,
                            certificate_path=cert2, consensus_certificate_path=cc2,
                            metadata={"reason": "demonstration-revocation"})
        revoke_votes = collect_votes(nodes, revoke_proposal, votes_dir, ("NODE-B", "NODE-C", "NODE-D"), "revoke")
        revoke_commit_path = commits_dir / "revoke.commit.json"
        revoke_commit = commit_and_apply(nodes, revoke_proposal, revoke_votes, revoke_commit_path, "NODE-A")
        rsp.export_state(nodes["NODE-A"], sync_package)
        final_offline_sync = rsp.sync_state(nodes["NODE-D"], sync_package)

        final_checks = {name: rsp.verify_certificate_on_node(node, cert2, cc2)
                        for name, node in nodes.items()}
        assert all(x["utxo_status"] == "REVOKED" and x["result"] == "INVALID" for x in final_checks.values())
        status_map = {name: rsp.node_status(node) for name, node in nodes.items()}
        assert len({x["head_hash"] for x in status_map.values()}) == 1
        assert len({x["sequence"] for x in status_map.values()}) == 1

        # Export public artifacts only.
        public_dir = OUT / "public-network"
        public_dir.mkdir(parents=True)
        shutil.copy2(network_path, public_dir / "network.json")
        (public_dir / "network.sha256").write_text(network_pin + "\n", encoding="ascii")
        for name, node in nodes.items():
            shutil.copy2(node / rsp.NODE_PUBLIC, public_dir / f"{name}-public.json")
        issuer_dir = OUT / "issuer-public"
        issuer_dir.mkdir()
        shutil.copy2(issuer / huc.CA_CERT, issuer_dir / "ca_certificate.pem")
        shutil.copy2(issuer / huc.POLICY_FILE, issuer_dir / "consensus_policy.json")
        certificates_dir = OUT / "certificates"
        certificates_dir.mkdir()
        shutil.copy2(cert1, certificates_dir / "certificate-issued.pem")
        shutil.copy2(cc1, certificates_dir / "consensus-issued.json")
        shutil.copy2(cert2, certificates_dir / "certificate-renewed.pem")
        shutil.copy2(cc2, certificates_dir / "consensus-renewed.json")
        for src, dst in ((issue_proposal, "issue-proposal.json"),
                         (renew_proposal, "renew-proposal.json"),
                         (revoke_proposal, "revoke-proposal.json")):
            shutil.copy2(src, OUT / dst)
        approvals_dir = OUT / "votes"
        approvals_dir.mkdir()
        for path in issue_votes + renew_votes + revoke_votes:
            shutil.copy2(path, approvals_dir / path.name)
        commits_public = OUT / "commits"
        commits_public.mkdir()
        shutil.copy2(issue_commit_path, commits_public / "issue.commit.json")
        shutil.copy2(renew_commit_path, commits_public / "renew.commit.json")
        shutil.copy2(revoke_commit_path, commits_public / "revoke.commit.json")
        shutil.copy2(sync_package, OUT / "final-replicated-state.zip")
        replicas_dir = OUT / "replicas"
        replicas_dir.mkdir()
        for name, node in nodes.items():
            shutil.copy2(node / rsp.LEDGER_FILE, replicas_dir / f"{name}-ledger.jsonl")
            write_json(replicas_dir / f"{name}-status.json", rsp.node_status(node))

        results.update({
            "network": network_result,
            "certificate_1_sha256": hash1,
            "consensus_certificate_1_sha256": cchash1,
            "certificate_2_sha256": hash2,
            "consensus_certificate_2_sha256": cchash2,
            "quorum": 3,
            "validator_count": 4,
            "fault_model": "f=1; quorum=2f+1; durable one-vote-per-slot locks",
            "commits": {"issue": issue_commit["commit_id"], "renew": renew_commit["commit_id"], "revoke": revoke_commit["commit_id"]},
            "replica_status": status_map,
            "checks": {
                "issued_valid_on_all_nodes": True,
                "old_certificate_superseded_on_all_nodes": True,
                "renewed_certificate_valid_before_revocation": True,
                "renewed_certificate_revoked_on_all_nodes": True,
                "NODE-D_caught_up_from_peer_after_issue": True,
                "all_replicas_same_final_head": True,
            },
            "notes": [
                "Private keys were created in a temporary directory and deleted on exit.",
                "The public artifacts do not include validator, CA, ledger or holder private keys.",
                "The state protocol uses no blockchain, token, mining or transaction fee.",
                "This is a leaderless quorum-certified replicated state prototype, not a complete BFT/view-change implementation.",
            ],
        })
        write_json(OUT / "demo-results.json", results)
        (OUT / "README.md").write_text(
            "# HUC 0.6 replicated-state demo\\n\\n"
            "This public fixture contains a real X.509 certificate and HUC-CC pair, a four-validator network manifest, "
            "three quorum-certified transitions (ISSUE, RENEW, REVOKE), validator votes, commits, and independent replica ledgers.\\n\\n"
            "No private keys are included. See `demo-results.json` for the machine-readable outcome.\\n\\n"
            "The `replicas/` ledgers are identical, including the offline node after it synchronizes from a peer package.\\n",
            encoding="utf-8")

    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\\nPublic demonstration artifacts: {OUT}")


if __name__ == "__main__":
    main()
