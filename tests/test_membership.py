import tempfile
import unittest
from pathlib import Path

import huc
import huc_replicated as rsp
import huc_membership as membership
import huc_view as view


class MembershipProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.nodes = {}
        public = []
        for name in ("MEM-A", "MEM-B", "MEM-C", "MEM-D"):
            node = self.root / name
            rsp.node_init(name, node)
            self.nodes[name] = node
            public.append(node / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        result = rsp.create_network(public, self.network_path, 1)
        self.pin = result["network_sha256"]
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, self.pin)
        self.proposals = self.root / "membership-proposals"
        self.votes = self.root / "membership-votes"
        self.proposals.mkdir(); self.votes.mkdir()
        self.new_node = self.root / "MEM-E"
        rsp.node_init("MEM-E", self.new_node)
        self.join_request_path = self.root / "join-request.json"
        membership.create_join_request(self.new_node, self.join_request_path, self.network_path)

    def tearDown(self):
        self.tmp.cleanup()

    def seed_certificate_state(self):
        proposal = self.root / "seed-proposal.json"
        vote_paths = []
        rsp.create_proposal(self.nodes["MEM-A"], "ISSUE", "1" * 64, "a" * 64, proposal)
        for name in ("MEM-A", "MEM-B", "MEM-C"):
            path = self.root / f"seed-{name}.json"
            rsp.vote_proposal(self.nodes[name], proposal, path)
            vote_paths.append(path)
        commit = self.root / "seed-commit.json"
        rsp.assemble_commit(self.nodes["MEM-A"], proposal, vote_paths, commit)
        for node in self.nodes.values():
            rsp.apply_commit(node, commit)

    def make_membership_proposal(self):
        proposal = self.proposals / "replace-A-with-E.json"
        membership.create_membership_proposal(
            self.nodes["MEM-B"], [self.join_request_path], ["MEM-A"], proposal
        )
        return proposal

    def test_join_request_proves_new_member_key_possession(self):
        request = rsp._read(self.join_request_path)
        descriptor = membership._verify_join_request(rsp.load_network(self.nodes["MEM-B"]), request)
        self.assertEqual(descriptor["validator_id"], "MEM-E")
        request["signature"] = "AAAA"
        with self.assertRaises(ValueError):
            membership._verify_join_request(rsp.load_network(self.nodes["MEM-B"]), request)

    def test_replacement_membership_requires_old_quorum_and_generates_successor_network(self):
        self.seed_certificate_state()
        proposal = self.make_membership_proposal()
        votes = []
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            vote_path = self.votes / f"vote-{name}.json"
            membership.membership_vote(self.nodes[name], proposal, vote_path)
            votes.append(vote_path)
        package_path = self.root / "membership-package.json"
        result = membership.assemble_membership_certificate(self.nodes["MEM-B"], proposal, votes, package_path)
        package = rsp._read(package_path)
        old, target, checkpoint = membership.verify_membership_package(package)
        self.assertEqual(result["target_validator_count"], 4)
        self.assertEqual(old["network_id"], rsp.load_network(self.nodes["MEM-B"])["network_id"])
        self.assertEqual({x["validator_id"] for x in target["validators"]}, {"MEM-B", "MEM-C", "MEM-D", "MEM-E"})
        self.assertEqual(checkpoint["snapshot"]["sequence"], 1)

    def test_insufficient_membership_quorum_rejected(self):
        proposal = self.make_membership_proposal()
        vote_paths = []
        for name in ("MEM-B", "MEM-C"):
            vote_path = self.votes / f"small-{name}.json"
            membership.membership_vote(self.nodes[name], proposal, vote_path)
            vote_paths.append(vote_path)
        with self.assertRaisesRegex(ValueError, "Quórum de membresía insuficiente"):
            membership.assemble_membership_certificate(self.nodes["MEM-B"], proposal, vote_paths,
                                                       self.root / "insufficient.json")

    def test_membership_activation_preserves_replicated_utxo_state(self):
        self.seed_certificate_state()
        proposal = self.make_membership_proposal()
        votes = []
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            path = self.votes / f"activate-{name}.json"
            membership.membership_vote(self.nodes[name], proposal, path)
            votes.append(path)
        package = self.root / "activation-package.json"
        membership.assemble_membership_certificate(self.nodes["MEM-B"], proposal, votes, package)
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            result = membership.activate_membership(self.nodes[name], package)
            self.assertEqual(result["membership_epoch"], 1)
        joined = membership.join_successor_network(self.new_node, package)
        self.assertEqual(joined["membership_epoch"], 1)
        states = [rsp.load_state(self.nodes[n]) for n in ("MEM-B", "MEM-C", "MEM-D")]
        states.append(rsp.load_state(self.new_node))
        self.assertEqual({s["network_id"] for s in states}, {states[0]["network_id"]})
        self.assertEqual({s["sequence"] for s in states}, {1})
        self.assertEqual({s["certificates"]["1" * 64]["status"] for s in states}, {"ACTIVE"})
        self.assertEqual(len({s["head_hash"] for s in states}), 1)

    def test_successor_membership_continues_accepting_utxo_transitions(self):
        self.seed_certificate_state()
        proposal = self.make_membership_proposal()
        votes = []
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            path = self.votes / f"continue-{name}.json"
            membership.membership_vote(self.nodes[name], proposal, path)
            votes.append(path)
        package = self.root / "continue-package.json"
        membership.assemble_membership_certificate(self.nodes["MEM-B"], proposal, votes, package)
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            membership.activate_membership(self.nodes[name], package)
        membership.join_successor_network(self.new_node, package)

        next_raw = self.root / "post-reconfigure-proposal-raw.json"
        next_proposal = self.root / "post-reconfigure-proposal.json"
        rsp.create_proposal(self.nodes["MEM-B"], "ISSUE", "3" * 64, "c" * 64, next_raw)
        view.annotate_proposal_for_view(self.nodes["MEM-B"], next_raw, next_proposal)
        next_votes = []
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            path = self.root / f"post-reconfigure-{name}.json"
            rsp.vote_proposal(self.nodes[name], next_proposal, path)
            next_votes.append(path)
        next_commit = self.root / "post-reconfigure-commit.json"
        rsp.assemble_commit(self.nodes["MEM-B"], next_proposal, next_votes, next_commit)
        for node in (self.nodes["MEM-B"], self.nodes["MEM-C"], self.nodes["MEM-D"], self.new_node):
            rsp.apply_commit(node, next_commit)
        states = [rsp.load_state(node) for node in (self.nodes["MEM-B"], self.nodes["MEM-C"], self.nodes["MEM-D"], self.new_node)]
        self.assertEqual({s["epoch"] for s in states}, {1})
        self.assertEqual({s["sequence"] for s in states}, {2})
        self.assertEqual({s["certificates"]["3" * 64]["status"] for s in states}, {"ACTIVE"})
        self.assertEqual(len({s["head_hash"] for s in states}), 1)

    def test_removed_member_cannot_activate_successor_network(self):
        proposal = self.make_membership_proposal()
        votes = []
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            path = self.votes / f"removed-{name}.json"
            membership.membership_vote(self.nodes[name], proposal, path)
            votes.append(path)
        package = self.root / "removed-package.json"
        membership.assemble_membership_certificate(self.nodes["MEM-B"], proposal, votes, package)
        with self.assertRaisesRegex(ValueError, "fue retirado"):
            membership.activate_membership(self.nodes["MEM-A"], package)

    def test_network_cannot_shrink_to_invalid_three_member_set(self):
        with self.assertRaisesRegex(ValueError, r"n=3f\+1"):
            membership.create_membership_proposal(
                self.nodes["MEM-B"], [], ["MEM-A"], self.proposals / "invalid-remove.json"
            )

    def test_old_checkpoint_does_not_authorize_different_target_network(self):
        self.seed_certificate_state()
        proposal = self.make_membership_proposal()
        votes = []
        for name in ("MEM-B", "MEM-C", "MEM-D"):
            path = self.votes / f"tamper-{name}.json"
            membership.membership_vote(self.nodes[name], proposal, path)
            votes.append(path)
        package_path = self.root / "tamper-package.json"
        membership.assemble_membership_certificate(self.nodes["MEM-B"], proposal, votes, package_path)
        package = rsp._read(package_path)
        package["target_network"]["quorum"] = 2
        with self.assertRaises(ValueError):
            membership.verify_membership_package(package)


if __name__ == "__main__":
    unittest.main(verbosity=2)
