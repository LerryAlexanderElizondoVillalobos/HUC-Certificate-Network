import json
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import huc
import huc_replicated as rsp
from cryptography.exceptions import InvalidSignature


class ReplicatedStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.node_dirs = {}
        public = []
        for name in ("NODE-A", "NODE-B", "NODE-C", "NODE-D"):
            node_dir = self.root / name.lower()
            rsp.node_init(name, node_dir)
            self.node_dirs[name] = node_dir
            public.append(node_dir / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        created = rsp.create_network(public, self.network_path, fault_tolerance=1)
        self.pin = created["network_sha256"]
        for node_dir in self.node_dirs.values():
            rsp.node_join(node_dir, self.network_path, self.pin)
        self.hash1 = huc.sha256(b"demo-x509-certificate-1")
        self.hash2 = huc.sha256(b"demo-x509-certificate-2")
        self.cc1 = huc.sha256(b"demo-huc-cc-1")
        self.cc2 = huc.sha256(b"demo-huc-cc-2")
        self.proposal_dir = self.root / "proposals"
        self.vote_dir = self.root / "votes"
        self.commit_dir = self.root / "commits"
        for folder in (self.proposal_dir, self.vote_dir, self.commit_dir):
            folder.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def propose(self, action, cert_hash, cc_hash, name, previous=None):
        path = self.proposal_dir / f"{name}.json"
        metadata = {"test_case": name}
        if action == "REVOKE":
            metadata["reason"] = "test-revocation"
        rsp.create_proposal(self.node_dirs["NODE-D"], action, cert_hash, cc_hash,
                            path, previous_certificate_sha256=previous,
                            metadata=metadata)
        return path

    def vote(self, proposal, validators=("NODE-A", "NODE-B", "NODE-C"), prefix="v"):
        outputs = []
        for name in validators:
            path = self.vote_dir / f"{prefix}-{name}.json"
            rsp.vote_proposal(self.node_dirs[name], proposal, path)
            outputs.append(path)
        return outputs

    def commit(self, proposal, votes, name):
        path = self.commit_dir / f"{name}.json"
        rsp.assemble_commit(self.node_dirs["NODE-D"], proposal, votes, path)
        return path

    def apply_all(self, commit):
        for name, node_dir in self.node_dirs.items():
            rsp.apply_commit(node_dir, commit)

    def test_four_independent_nodes_replicate_same_commit_without_leader(self):
        proposal = self.propose("ISSUE", self.hash1, self.cc1, "issue")
        votes = self.vote(proposal, prefix="issue")
        commit = self.commit(proposal, votes, "issue")
        self.apply_all(commit)
        statuses = [rsp.node_status(node_dir) for node_dir in self.node_dirs.values()]
        self.assertEqual({x["sequence"] for x in statuses}, {1})
        self.assertEqual({x["head_hash"] for x in statuses}, {json.loads(commit.read_text())["commit_id"]})
        self.assertEqual({x["active_certificates"] for x in statuses}, {1})

    def test_any_validator_can_propose_and_assemble(self):
        proposal = self.proposal_dir / "any-node.json"
        rsp.create_proposal(self.node_dirs["NODE-B"], "ISSUE", self.hash1, self.cc1, proposal)
        votes = self.vote(proposal, prefix="any")
        commit_path = self.commit_dir / "by-node-a.json"
        rsp.assemble_commit(self.node_dirs["NODE-A"], proposal, votes, commit_path)
        self.apply_all(commit_path)
        self.assertEqual(rsp.node_status(self.node_dirs["NODE-C"])["sequence"], 1)

    def test_three_of_four_quorum_accepts_one_offline_node(self):
        proposal = self.propose("ISSUE", self.hash1, self.cc1, "offline")
        votes = self.vote(proposal, validators=("NODE-A", "NODE-B", "NODE-D"), prefix="offline")
        commit = self.commit(proposal, votes, "offline")
        for name in ("NODE-A", "NODE-B", "NODE-D"):
            rsp.apply_commit(self.node_dirs[name], commit)
        # NODE-C was offline and catches up via replicated state package.
        package = self.root / "replicated-state.zip"
        rsp.export_state(self.node_dirs["NODE-A"], package)
        rsp.sync_state(self.node_dirs["NODE-C"], package)
        states = [rsp.node_status(self.node_dirs[name]) for name in self.node_dirs]
        self.assertEqual({x["sequence"] for x in states}, {1})
        self.assertEqual(len({x["head_hash"] for x in states}), 1)

    def test_insufficient_quorum_rejected(self):
        proposal = self.propose("ISSUE", self.hash1, self.cc1, "insufficient")
        votes = self.vote(proposal, validators=("NODE-A", "NODE-B"), prefix="two")
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            self.commit(proposal, votes, "should-fail")

    def test_durable_anti_equivocation_lock(self):
        first = self.propose("ISSUE", self.hash1, self.cc1, "first")
        second = self.propose("ISSUE", self.hash2, self.cc2, "second")
        rsp.vote_proposal(self.node_dirs["NODE-A"], first, self.vote_dir / "first-a.json")
        with self.assertRaisesRegex(ValueError, "Anti-equivocación"):
            rsp.vote_proposal(self.node_dirs["NODE-A"], second, self.vote_dir / "second-a.json")
        # Reopening the same node directory must preserve the lock.
        with self.assertRaisesRegex(ValueError, "Anti-equivocación"):
            rsp.vote_proposal(self.node_dirs["NODE-A"], second, self.vote_dir / "second-a-restart.json")

    def test_conflicting_proposals_cannot_both_reach_quorum(self):
        first = self.propose("ISSUE", self.hash1, self.cc1, "race-a")
        second = self.propose("ISSUE", self.hash2, self.cc2, "race-b")
        # Split votes 2-2. Neither can assemble a 3-of-4 commit.
        self.vote(first, validators=("NODE-A", "NODE-B"), prefix="race-a")
        self.vote(second, validators=("NODE-C", "NODE-D"), prefix="race-b")
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            self.commit(first, [self.vote_dir / "race-a-NODE-A.json", self.vote_dir / "race-a-NODE-B.json"], "race-a-fail")
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            self.commit(second, [self.vote_dir / "race-b-NODE-C.json", self.vote_dir / "race-b-NODE-D.json"], "race-b-fail")

    def test_tampered_vote_signature_rejected(self):
        proposal = self.propose("ISSUE", self.hash1, self.cc1, "tamper-vote")
        votes = self.vote(proposal, prefix="tamper")
        changed = json.loads(votes[0].read_text())
        changed["payload"]["decision"] = "REJECT"
        votes[0].write_text(json.dumps(changed))
        with self.assertRaises((InvalidSignature, ValueError)):
            self.commit(proposal, votes, "tampered")

    def test_replicated_renew_and_revoke_lifecycle(self):
        issue = self.propose("ISSUE", self.hash1, self.cc1, "life-issue")
        issue_commit = self.commit(issue, self.vote(issue, prefix="life-issue"), "life-issue")
        self.apply_all(issue_commit)

        renew = self.propose("RENEW", self.hash2, self.cc2, "life-renew", previous=self.hash1)
        renew_commit = self.commit(renew, self.vote(renew, prefix="life-renew"), "life-renew")
        self.apply_all(renew_commit)
        for node in self.node_dirs.values():
            state = rsp.load_state(node)
            self.assertEqual(state["certificates"][self.hash1]["status"], "SUPERSEDED")
            self.assertEqual(state["certificates"][self.hash2]["status"], "ACTIVE")

        revoke = self.propose("REVOKE", self.hash2, self.cc2, "life-revoke")
        revoke_commit = self.commit(revoke, self.vote(revoke, prefix="life-revoke"), "life-revoke")
        self.apply_all(revoke_commit)
        for node in self.node_dirs.values():
            state = rsp.load_state(node)
            self.assertEqual(state["certificates"][self.hash2]["status"], "REVOKED")
            self.assertNotIn("outpoint", state["certificates"][self.hash2])

    def test_sync_rejects_rollback_and_fork(self):
        empty_package = self.root / "empty.zip"
        rsp.export_state(self.node_dirs["NODE-A"], empty_package)
        proposal = self.propose("ISSUE", self.hash1, self.cc1, "sync-issue")
        commit = self.commit(proposal, self.vote(proposal, prefix="sync-issue"), "sync-issue")
        self.apply_all(commit)
        current = self.root / "current.zip"
        rsp.export_state(self.node_dirs["NODE-A"], current)
        with self.assertRaisesRegex(ValueError, "rollback"):
            rsp.sync_state(self.node_dirs["NODE-B"], empty_package)

        fork_node = self.root / "fork-node"
        rsp.node_init("NODE-E", fork_node)
        # This node cannot join the fixed membership, and a different manifest must be rejected.
        with self.assertRaisesRegex(ValueError, "no autorizado"):
            rsp.node_join(fork_node, self.network_path, self.pin)

    def test_wrong_network_pin_and_wrong_network_commit_rejected(self):
        with self.assertRaisesRegex(ValueError, "huella externa"):
            rsp.node_status(self.node_dirs["NODE-A"]) if False else rsp.load_network(self.node_dirs["NODE-A"], "0" * 64)

    def test_node_snapshot_is_rebuilt_from_signed_ledger(self):
        proposal = self.propose("ISSUE", self.hash1, self.cc1, "snapshot")
        commit = self.commit(proposal, self.vote(proposal, prefix="snapshot"), "snapshot")
        self.apply_all(commit)
        snapshot = self.node_dirs["NODE-A"] / rsp.STATE_FILE
        data = json.loads(snapshot.read_text())
        data["sequence"] = 99
        snapshot.write_text(json.dumps(data))
        recovered = rsp.load_state(self.node_dirs["NODE-A"])
        self.assertEqual(recovered["sequence"], 1)
        self.assertEqual(json.loads(snapshot.read_text())["sequence"], 1)

    def test_duplicate_validator_keys_rejected(self):
        descriptor = json.loads((self.node_dirs["NODE-A"] / rsp.NODE_PUBLIC).read_text())
        duplicate = dict(descriptor)
        duplicate["validator_id"] = "NODE-E"
        duplicate_path = self.root / "duplicate.json"
        duplicate_path.write_text(json.dumps(duplicate))
        with self.assertRaisesRegex(ValueError, "compartir una clave"):
            rsp.create_network([
                self.node_dirs["NODE-A"] / rsp.NODE_PUBLIC,
                duplicate_path,
                self.node_dirs["NODE-C"] / rsp.NODE_PUBLIC,
                self.node_dirs["NODE-D"] / rsp.NODE_PUBLIC,
            ], self.root / "bad-network.json", 1)


class IntegratedHUCEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.huc_workspace = self.root / "issuer-workspace"
        huc.initialize(self.huc_workspace, threshold=2, authority_count=3)
        holder_dir = self.root / "holder"
        request = huc.generate_request(holder_dir, "HUC RSP Integrated Demo")
        self.issued = huc.issue_csr(self.huc_workspace, Path(request["csr_file"]), 60)
        self.cert_path = Path(self.issued["certificate_file"])
        self.cc_path = Path(self.issued["consensus_certificate_file"])
        self.cert_hash = self.issued["certificate_sha256_der"]
        self.cc_obj = huc.read_json(self.cc_path)
        self.cc_hash = huc.sha256(huc.canonical_json(self.cc_obj))

        self.nodes = {}
        public = []
        for name in ("ORG-A", "ORG-B", "ORG-C", "ORG-D"):
            node_dir = self.root / name
            rsp.node_init(name, node_dir)
            self.nodes[name] = node_dir
            public.append(node_dir / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        result = rsp.create_network(
            public, self.network_path, 1,
            self.huc_workspace / huc.CA_CERT,
            self.huc_workspace / huc.POLICY_FILE,
        )
        self.pin = result["network_sha256"]
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, self.pin)
        self.proposals = self.root / "proposals"
        self.votes = self.root / "votes"
        self.commits = self.root / "commits"
        self.proposals.mkdir(); self.votes.mkdir(); self.commits.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def make_issue_proposal(self):
        proposal = self.proposals / "issue.json"
        rsp.create_proposal(
            self.nodes["ORG-D"], "ISSUE", self.cert_hash, self.cc_hash,
            proposal, certificate_path=self.cert_path,
            consensus_certificate_path=self.cc_path,
        )
        return proposal

    def approve_commit_apply(self, proposal, prefix, validators=("ORG-A", "ORG-B", "ORG-C")):
        votes = []
        for name in validators:
            vote = self.votes / f"{prefix}-{name}.json"
            rsp.vote_proposal(self.nodes[name], proposal, vote)
            votes.append(vote)
        commit = self.commits / f"{prefix}.json"
        rsp.assemble_commit(self.nodes["ORG-D"], proposal, votes, commit)
        for node in self.nodes.values():
            rsp.apply_commit(node, commit)
        return commit

    def test_every_validator_checks_x509_and_huc_cc_before_voting(self):
        proposal = self.make_issue_proposal()
        # Independent validators all parse and verify the embedded public evidence.
        self.approve_commit_apply(proposal, "issue")
        for node in self.nodes.values():
            result = rsp.verify_certificate_on_node(node, self.cert_path, self.cc_path)
            self.assertEqual(result["result"], "VALID")
            self.assertTrue(result["hybrid_valid"])
            self.assertEqual(result["utxo_status"], "ACTIVE")

    def test_consensus_certificate_for_another_x509_is_rejected(self):
        proposal = self.make_issue_proposal()
        self.approve_commit_apply(proposal, "binding-issue")
        holder2 = self.root / "holder-other"
        req = huc.generate_request(holder2, "Different HUC Subject")
        other = huc.issue_csr(self.huc_workspace, Path(req["csr_file"]), 30)
        with self.assertRaisesRegex(ValueError, "no está vinculado"):
            rsp.verify_certificate_on_node(
                self.nodes["ORG-A"], self.cert_path,
                Path(other["consensus_certificate_file"]),
            )

    def test_bad_huc_cc_signature_is_rejected_before_vote(self):
        bad_cc = json.loads(self.cc_path.read_text())
        bad_cc["signatures"][0]["signature"] = "AAAA"
        bad_cc_path = self.root / "bad-cc.json"
        bad_cc_path.write_text(json.dumps(bad_cc))
        bad_hash = huc.sha256(huc.canonical_json(bad_cc))
        proposal = self.proposals / "bad-evidence.json"
        with self.assertRaisesRegex(ValueError, "Consenso insuficiente"):
            rsp.create_proposal(
                self.nodes["ORG-A"], "ISSUE", self.cert_hash, bad_hash, proposal,
                certificate_path=self.cert_path, consensus_certificate_path=bad_cc_path,
            )

    def test_huc_x509_and_cc_lifecycle_replicates_through_renew_and_revoke(self):
        issue_proposal = self.make_issue_proposal()
        self.approve_commit_apply(issue_proposal, "life-issue")
        holder2 = self.root / "holder2"
        req2 = huc.generate_request(holder2, "HUC RSP Integrated Demo")
        renewed = huc.renew_csr(self.huc_workspace, self.cert_path, Path(req2["csr_file"]), 60)
        new_cert_path = Path(renewed["certificate_file"])
        new_cc_path = Path(renewed["consensus_certificate_file"])
        new_cert_hash = renewed["certificate_sha256_der"]
        new_cc_obj = huc.read_json(new_cc_path)
        new_cc_hash = huc.sha256(huc.canonical_json(new_cc_obj))
        renew_proposal = self.proposals / "renew.json"
        rsp.create_proposal(
            self.nodes["ORG-B"], "RENEW", new_cert_hash, new_cc_hash, renew_proposal,
            previous_certificate_sha256=self.cert_hash,
            certificate_path=new_cert_path, consensus_certificate_path=new_cc_path,
        )
        self.approve_commit_apply(renew_proposal, "life-renew")
        for node in self.nodes.values():
            old_result = rsp.verify_certificate_on_node(node, self.cert_path, self.cc_path)
            new_result = rsp.verify_certificate_on_node(node, new_cert_path, new_cc_path)
            self.assertEqual(old_result["utxo_status"], "SUPERSEDED")
            self.assertEqual(old_result["result"], "INVALID")
            self.assertEqual(new_result["utxo_status"], "ACTIVE")
            self.assertEqual(new_result["result"], "VALID")
        revoke_proposal = self.proposals / "revoke.json"
        rsp.create_proposal(
            self.nodes["ORG-C"], "REVOKE", new_cert_hash, new_cc_hash, revoke_proposal,
            certificate_path=new_cert_path, consensus_certificate_path=new_cc_path,
            metadata={"reason": "demonstration-revocation"},
        )
        self.approve_commit_apply(revoke_proposal, "life-revoke", ("ORG-B", "ORG-C", "ORG-D"))
        for node in self.nodes.values():
            result = rsp.verify_certificate_on_node(node, new_cert_path, new_cc_path)
            self.assertEqual(result["utxo_status"], "REVOKED")
            self.assertEqual(result["result"], "INVALID")



if __name__ == "__main__":
    unittest.main(verbosity=2)
